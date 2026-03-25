#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <winioctl.h>
#include <cstdio>
#include <string>
#include <vector>
#include <map>
#include <utility>
#include "globals.h"
#include "jutil.h"
#include "ansi.h"

// ─── /handles [drive] ────────────────────────────────────────────────────────
// Enumerate all open file handles system-wide.
// Optional filter: drive letter (e.g. "E" or "E:") narrows to that volume only.
//
// Technique:
//   1. NtQuerySystemInformation(SystemHandleInformation) — full system handle table
//   2. Identify File object type index by probing a known handle in our own process
//   3. For each foreign File handle: DuplicateHandle + GetFinalPathNameByHandle
//      a. Path found  -> file handle on the volume
//      b. Path empty  -> try IOCTL_STORAGE_GET_DEVICE_NUMBER (calibrated volume map)
//         Match       -> volume device handle (e.g. \\.\E: opened directly)
//         No match    -> pipe / unnamed device / other — skip, no timeout risk
//   4. Filter by NT device path (QueryDosDevice resolves "E:" -> \Device\HarddiskVolumeN)

typedef NTSTATUS (NTAPI *PFN_NtQSI)(ULONG, PVOID, ULONG, PULONG);

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define SystemHandleInformation 16

#pragma pack(push, 1)
struct SysHandleEntry {
    USHORT ProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
};
struct SysHandleInfo {
    ULONG Count;
    SysHandleEntry Handles[1];
};
#pragma pack(pop)

// ── Helpers ──────────────────────────────────────────────────────────────────

static std::map<DWORD, std::string> s_pidMap;

static void BuildPidMap() {
    s_pidMap.clear();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe{ sizeof(pe) };
    if (Process32First(snap, &pe))
        do { s_pidMap[(DWORD)pe.th32ProcessID] = pe.szExeFile; }
        while (Process32Next(snap, &pe));
    CloseHandle(snap);
}

static const char* ProcName(DWORD pid) {
    auto it = s_pidMap.find(pid);
    return it != s_pidMap.end() ? it->second.c_str() : "?";
}

// Resolve "E" or "E:" -> NT device path like \Device\HarddiskVolume7
static std::string ResolveVolume(char letter) {
    char dos[3] = { (char)toupper((unsigned char)letter), ':', '\0' };
    char nt[512]{};
    if (QueryDosDeviceA(dos, nt, sizeof(nt))) return nt;
    return {};
}

// Probe our own process to find which ObjectTypeIndex Windows assigns to File objects.
// Opens a known file, scans the handle table for our PID+handle, reads type index.
static UCHAR FindFileTypeIndex(PFN_NtQSI NtQSI, const std::vector<BYTE>& buf) {
    HANDLE hProbe = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hProbe == INVALID_HANDLE_VALUE) return 0;

    UCHAR idx = 0;
    DWORD curPid = GetCurrentProcessId();
    USHORT hVal  = (USHORT)(ULONG_PTR)hProbe;
    auto*  info  = (const SysHandleInfo*)buf.data();

    for (ULONG i = 0; i < info->Count; i++) {
        auto& e = info->Handles[i];
        if ((DWORD)e.ProcessId == curPid && e.HandleValue == hVal) {
            idx = e.ObjectTypeIndex;
            break;
        }
    }
    CloseHandle(hProbe);
    return idx;
}

// Calibrate: open every drive letter as a volume device, query
// IOCTL_STORAGE_GET_DEVICE_NUMBER, build map (DeviceNumber,PartitionNumber)->letter.
// Used to identify volume device handles (\\.\X:) without NtQueryObject.
// IOCTL fails instantly on pipes/sockets/unnamed devices → zero timeout risk.
static std::map<std::pair<DWORD,DWORD>, char> BuildVolumeMap() {
    std::map<std::pair<DWORD,DWORD>, char> m;
    for (char c = 'A'; c <= 'Z'; c++) {
        char path[8] = { '\\','\\','.','\\', c, ':', '\0' };
        HANDLE h = CreateFileA(path, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;
        STORAGE_DEVICE_NUMBER sdn{};
        DWORD bytes = 0;
        if (DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER,
                            nullptr, 0, &sdn, sizeof(sdn), &bytes, nullptr))
            m[{sdn.DeviceNumber, sdn.PartitionNumber}] = c;
        CloseHandle(h);
    }
    return m;
}

// ── Main command ─────────────────────────────────────────────────────────────

void CmdHandles(const char* filter) {
    auto* NtQSI = (PFN_NtQSI)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) {
        printf("%s[!]%s NtQuerySystemInformation not found in ntdll\n", A_RED, A_RESET);
        return;
    }

    // Resolve optional volume filter
    std::string filterPath;
    char filterDrive = 0;
    if (filter && filter[0] && filter[0] != '?') {
        filterDrive = (char)toupper((unsigned char)filter[0]);
        filterPath  = ResolveVolume(filterDrive);
        if (filterPath.empty()) {
            printf("%s[!]%s Cannot resolve NT device path for %c:\n",
                   A_RED, A_RESET, filterDrive);
            return;
        }
        if (!g_jsonMode)
            printf("%s[*]%s %c: -> %s\n\n", A_CYAN, A_RESET, filterDrive, filterPath.c_str());
    }

    // Fetch full system handle table (grows until buffer is large enough)
    std::vector<BYTE> buf(sizeof(SysHandleInfo) + 65536 * sizeof(SysHandleEntry));
    ULONG needed = 0;
    NTSTATUS st;
    while ((st = NtQSI(SystemHandleInformation, buf.data(), (ULONG)buf.size(), &needed))
           == STATUS_INFO_LENGTH_MISMATCH) {
        buf.resize(needed + 4096 * sizeof(SysHandleEntry));
    }
    if (st != 0) {
        printf("%s[!]%s NtQuerySystemInformation failed: 0x%08lX\n", A_RED, A_RESET, st);
        return;
    }

    BuildPidMap();

    // Identify File object type index
    UCHAR fileTypeIdx = FindFileTypeIndex(NtQSI, buf);
    if (g_debug)
        printf("[DBG] File object type index = %u\n", fileTypeIdx);

    // Calibrate volume device handles: (diskNo,partNo) -> drive letter
    auto volumeMap = BuildVolumeMap();
    if (g_debug)
        printf("[DBG] Calibrated %zu volume(s)\n", volumeMap.size());

    auto*  info   = (const SysHandleInfo*)buf.data();
    DWORD  curPid = GetCurrentProcessId();
    DWORD  lastPid = 0;
    HANDLE hProc   = nullptr;
    int    count   = 0;
    bool   jsonFirst = true;

    if (g_jsonMode)
        printf("{\"command\":\"handles\",\"filter\":%s,\"handles\":[\n",
               filterDrive ? JEscape((std::string(1, filterDrive) + ":").c_str()).c_str() : "null");
    else {
        printf("%-8s  %-24s  %s\n", "PID", "Process", "Path");
        printf("%s\n", std::string(120, '-').c_str());
    }

    for (ULONG i = 0; i < info->Count; i++) {
        const auto& e = info->Handles[i];
        DWORD pid = (DWORD)e.ProcessId;

        if (pid == 4 || pid == curPid) continue;

        // Skip non-File handles early if we have a valid type index
        if (fileTypeIdx && e.ObjectTypeIndex != fileTypeIdx) continue;

        // Open/reuse process handle (cache across consecutive entries for same PID)
        if (pid != lastPid) {
            if (hProc) { CloseHandle(hProc); hProc = nullptr; }
            hProc   = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
            lastPid = pid;
        }
        if (!hProc) continue;

        // Duplicate handle into our address space
        HANDLE hDup = nullptr;
        if (!DuplicateHandle(hProc, (HANDLE)(ULONG_PTR)e.HandleValue,
                             GetCurrentProcess(), &hDup,
                             0, FALSE, DUPLICATE_SAME_ACCESS))
            continue;

        // Must be a disk file (not socket, pipe, etc.)
        if (GetFileType(hDup) != FILE_TYPE_DISK) { CloseHandle(hDup); continue; }

        // Resolve NT path (\Device\HarddiskVolumeN\...)
        char pathBuf[2048]{};
        DWORD pathLen = GetFinalPathNameByHandleA(
            hDup, pathBuf, (DWORD)sizeof(pathBuf) - 1, VOLUME_NAME_NT);

        bool isDevHandle = false;
        if (pathLen == 0) {
            // No file path: probe IOCTL_STORAGE_GET_DEVICE_NUMBER (calibrated volume map).
            // Fails instantly on pipes/unnamed devices — no timeout risk.
            STORAGE_DEVICE_NUMBER sdn{};
            DWORD bytes = 0;
            if (DeviceIoControl(hDup, IOCTL_STORAGE_GET_DEVICE_NUMBER,
                                nullptr, 0, &sdn, sizeof(sdn), &bytes, nullptr)) {
                auto it = volumeMap.find({sdn.DeviceNumber, sdn.PartitionNumber});
                if (it != volumeMap.end()) {
                    // It's a volume device handle (e.g. \\.\E: opened directly)
                    snprintf(pathBuf, sizeof(pathBuf), "\\\\.\\%c: (device handle)", it->second);
                    pathLen  = (DWORD)strlen(pathBuf);
                    isDevHandle = true;
                    if (filterDrive && it->second != filterDrive)
                        pathLen = 0; // filtered out
                }
            }
        }

        CloseHandle(hDup);
        if (pathLen == 0) continue;

        // Apply volume filter (file handles)
        if (!isDevHandle && !filterPath.empty() &&
            _strnicmp(pathBuf, filterPath.c_str(), filterPath.size()) != 0)
            continue;

        const char* proc = ProcName(pid);
        count++;

        if (g_jsonMode) {
            if (!jsonFirst) printf(",\n");
            jsonFirst = false;
            printf(" {\"pid\":%u,\"process\":%s,\"handle\":\"0x%X\",\"path\":%s%s}",
                   pid, JEscape(proc).c_str(), (unsigned)e.HandleValue,
                   JEscape(pathBuf).c_str(),
                   isDevHandle ? ",\"type\":\"device\"" : "");
        } else {
            printf("%s%-8u%s  %-24s  %s\n", A_YELLOW, pid, A_RESET, proc, pathBuf);
        }
    }

    if (hProc) CloseHandle(hProc);

    if (g_jsonMode)
        printf("\n],\"total\":%d}\n", count);
    else
        printf("\n%s[*]%s %d handle(s) found\n", A_CYAN, A_RESET, count);
}

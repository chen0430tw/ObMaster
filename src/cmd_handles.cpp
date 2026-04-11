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

// ─── /handles [drive|path] [--close] ─────────────────────────────────────────
// Enumerate all open file handles system-wide.
//
// ⚠️ Evil handle note (ppm-engine v0.2.1 cross-verification, 2026-04-11):
//   ksafecenter64.sys ObOpenObjectByPointer uses DesiredAccess=0x200
//   (PROCESS_QUERY_LIMITED_INFORMATION), NOT 0x1FFFFF (ALL_ACCESS).
//   Evil handles seen by VBoxSup are TRANSIENT race-condition artifacts:
//     ObOpenObjectByPointer(0x200) -> ZwQueryInformationProcess -> ZwClose
//   The handle only exists during the ~microsecond query window.
//   /handle-close targeting persistent 0x1FFFFF handles will NOT catch these.
// Filter modes:
//   "E" or "E:"             → all handles on that volume
//   "C:\path\to\dir"        → handles whose NT path starts with that prefix
//   "C:\path\to\file.txt"   → handles to that exact file (prefix match)
// --close: forcibly close every matching handle via DuplicateHandle(CLOSE_SOURCE)
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

void CmdHandles(const char* filter, bool doClose) {
    auto* NtQSI = (PFN_NtQSI)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) {
        printf("%s[!]%s NtQuerySystemInformation not found in ntdll\n", A_RED, A_RESET);
        return;
    }

    // ── Resolve filter ────────────────────────────────────────────────────────
    // Mode A: single letter (or "X:") → volume filter
    // Mode B: longer string           → path prefix filter (converted to NT device path)
    std::string filterNT;    // NT device path prefix used for matching
    char filterDrive = 0;    // set only in mode A for display
    bool isPathFilter = false;

    if (filter && filter[0] && filter[0] != '?') {
        size_t flen = strlen(filter);
        bool isDriveLetter = (flen == 1) ||
                             (flen == 2 && (filter[1] == ':' || filter[1] == '\\'));

        if (isDriveLetter) {
            filterDrive = (char)toupper((unsigned char)filter[0]);
            filterNT    = ResolveVolume(filterDrive);
            if (filterNT.empty()) {
                printf("%s[!]%s Cannot resolve NT device path for %c:\n",
                       A_RED, A_RESET, filterDrive);
                return;
            }
            if (!g_jsonMode)
                printf("%s[*]%s %c: -> %s\n\n", A_CYAN, A_RESET, filterDrive, filterNT.c_str());
        } else {
            // Path filter: "C:\foo\bar" or "C:/foo/bar"
            isPathFilter = true;
            char dl = (char)toupper((unsigned char)filter[0]);
            std::string ntBase = ResolveVolume(dl);
            if (ntBase.empty()) {
                printf("%s[!]%s Cannot resolve NT device path for %c:\n",
                       A_RED, A_RESET, dl);
                return;
            }
            // Skip "C:" or "C:\" prefix, normalize separators
            const char* rest = filter + (flen > 1 && filter[1] == ':' ? 2 : 1);
            std::string restStr(rest);
            for (char& c : restStr) if (c == '/') c = '\\';
            // Ensure single leading backslash
            if (!restStr.empty() && restStr[0] != '\\') restStr = "\\" + restStr;
            // Remove trailing separator for prefix matching
            while (restStr.size() > 1 && restStr.back() == '\\') restStr.pop_back();
            filterNT = ntBase + restStr;
            if (!g_jsonMode)
                printf("%s[*]%s Path filter: %s\n\n", A_CYAN, A_RESET, filterNT.c_str());
        }
    }

    if (doClose && filterNT.empty()) {
        printf("%s[!]%s --close requires a path or drive filter\n", A_RED, A_RESET);
        return;
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

    if (g_jsonMode) {
        const char* fkey = filterNT.empty() ? "null" : JEscape(filterNT.c_str()).c_str();
        printf("{\"command\":\"handles\",\"filter\":%s,\"close\":%s,\"handles\":[\n",
               filterNT.empty() ? "null" : JEscape(filterNT.c_str()).c_str(),
               doClose ? "true" : "false");
    }
    else {
        printf("%-8s  %-24s  %-8s  %s\n", "PID", "Process", "Handle", "Path");
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

        // Apply path/volume filter (file handles)
        if (!isDevHandle && !filterNT.empty()) {
            // Prefix match: handle path must start with filterNT
            // Also accept exact match (filterNT == pathBuf)
            size_t flen = filterNT.size();
            bool match = _strnicmp(pathBuf, filterNT.c_str(), flen) == 0 &&
                         (pathBuf[flen] == '\0' || pathBuf[flen] == '\\');
            if (!match) continue;
        }
        if (isDevHandle && !filterNT.empty()) continue; // path filter → skip device handles

        const char* proc = ProcName(pid);
        count++;

        // ── Close handle if requested ─────────────────────────────────────────
        bool closed = false;
        if (doClose) {
            HANDLE hClose = nullptr;
            if (DuplicateHandle(hProc, (HANDLE)(ULONG_PTR)e.HandleValue,
                                GetCurrentProcess(), &hClose,
                                0, FALSE, DUPLICATE_CLOSE_SOURCE)) {
                if (hClose) CloseHandle(hClose);
                closed = true;
            }
        }

        if (g_jsonMode) {
            if (!jsonFirst) printf(",\n");
            jsonFirst = false;
            printf(" {\"pid\":%u,\"process\":%s,\"handle\":\"0x%X\",\"path\":%s%s%s}",
                   pid, JEscape(proc).c_str(), (unsigned)e.HandleValue,
                   JEscape(pathBuf).c_str(),
                   isDevHandle ? ",\"type\":\"device\"" : "",
                   doClose ? (closed ? ",\"closed\":true" : ",\"closed\":false") : "");
        } else {
            printf("%s%-8u%s  %-24s  0x%-6X  %s",
                   A_YELLOW, pid, A_RESET, proc, (unsigned)e.HandleValue, pathBuf);
            if (doClose)
                printf("  %s", closed ? "\x1b[32m[closed]\x1b[0m" : "\x1b[31m[close failed]\x1b[0m");
            printf("\n");
        }
    }

    if (hProc) CloseHandle(hProc);

    if (g_jsonMode)
        printf("\n],\"total\":%d%s}\n", count, doClose ? ",\"closed\":true" : "");
    else
        printf("\n%s[*]%s %d handle(s) found%s\n", A_CYAN, A_RESET, count,
               doClose ? " (closed)" : "");
}

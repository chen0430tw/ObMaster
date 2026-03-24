// cmd_memscan.cpp — /memscan and /memrestore
//
// /memscan <pid>            Compare every loaded DLL's sections against its on-disk image.
//                           Reports sections that differ and the number of modified bytes.
//
// /memrestore <pid> <dll>   Restore modified sections of a DLL in a process by writing the
//                           original on-disk bytes back via VirtualProtectEx + WriteProcessMemory.
//                           Creates a private CoW copy for the target process.
//
// Neither command requires the kernel driver; they use standard Win32 process APIs.

#include "globals.h"
#include "ansi.h"
#include "jutil.h"
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <cstdio>
#include <cstring>
#include <algorithm>

// ─── Helpers ─────────────────────────────────────────────────────────────────

static std::vector<BYTE> ReadDllFromDisk(const wchar_t* path)
{
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return {};
    DWORD sz = GetFileSize(f, nullptr);
    std::vector<BYTE> buf(sz);
    DWORD rd = 0;
    if (!ReadFile(f, buf.data(), sz, &rd, nullptr) || rd != sz) buf.clear();
    CloseHandle(f);
    return buf;
}

struct SectionInfo {
    char  name[9];
    DWORD rva;
    DWORD vsize;
    DWORD rawOff;
    DWORD rawSize;
};

static bool ParsePEHeaders(HANDLE hProc, DWORD64 base,
                            std::vector<SectionInfo>& sections)
{
    BYTE hdr[0x1000];
    SIZE_T got = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)base, hdr, sizeof(hdr), &got) || got < 0x40)
        return false;

    auto* dos = (IMAGE_DOS_HEADER*)hdr;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    DWORD ntOff = dos->e_lfanew;
    if (ntOff + sizeof(IMAGE_NT_HEADERS64) > sizeof(hdr)) return false;

    auto* nt = (IMAGE_NT_HEADERS64*)(hdr + ntOff);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;

    WORD nSec = nt->FileHeader.NumberOfSections;
    auto* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nSec && i < 64; i++) {
        SectionInfo si{};
        memcpy(si.name, sec[i].Name, 8);
        si.name[8]  = 0;
        si.rva      = sec[i].VirtualAddress;
        si.vsize    = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        si.rawOff   = sec[i].PointerToRawData;
        si.rawSize  = sec[i].SizeOfRawData;
        sections.push_back(si);
    }
    return !sections.empty();
}

struct SectionDiff {
    SectionInfo si;
    DWORD       modBytes;   // number of bytes that differ
};

static std::vector<SectionDiff> DiffDll(HANDLE hProc, DWORD64 base, const wchar_t* path)
{
    std::vector<SectionDiff> result;

    std::vector<SectionInfo> sections;
    if (!ParsePEHeaders(hProc, base, sections)) return result;

    auto disk = ReadDllFromDisk(path);
    if (disk.empty()) return result;

    for (auto& si : sections) {
        if (si.vsize == 0 || si.rawSize == 0) continue;
        if ((SIZE_T)(si.rawOff + si.rawSize) > disk.size()) continue;

        DWORD cmpLen = (std::min)(si.vsize, si.rawSize);
        std::vector<BYTE> mem(cmpLen, 0);
        SIZE_T got = 0;
        ReadProcessMemory(hProc, (LPCVOID)(base + si.rva), mem.data(), cmpLen, &got);
        if (got == 0) continue;

        DWORD mod = 0;
        DWORD check = (DWORD)(std::min)((SIZE_T)cmpLen, got);
        for (DWORD b = 0; b < check; b++) {
            if (mem[b] != disk[si.rawOff + b]) mod++;
        }
        if (mod > 0)
            result.push_back({ si, mod });
    }
    return result;
}

// ─── /memscan ────────────────────────────────────────────────────────────────

void CmdMemScan(DWORD pid)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        printf("%s[!]%s OpenProcess(%lu) failed: %lu\n", A_RED, A_RESET, pid, GetLastError());
        return;
    }

    HMODULE mods[512];
    DWORD needed = 0;
    if (!EnumProcessModules(hProc, mods, sizeof(mods), &needed)) {
        printf("%s[!]%s EnumProcessModules failed: %lu\n", A_RED, A_RESET, GetLastError());
        CloseHandle(hProc); return;
    }

    DWORD nMods = needed / sizeof(HMODULE);

    if (g_jsonMode) {
        printf("{\"pid\":%lu,\"modules\":[", pid);
    } else {
        printf("=== MemScan PID %lu (%lu modules) ===\n\n", pid, nMods);
    }

    bool anyDiff = false;
    bool first   = true;
    for (DWORD i = 0; i < nMods; i++) {
        wchar_t path[MAX_PATH];
        if (!GetModuleFileNameExW(hProc, mods[i], path, MAX_PATH)) continue;

        auto diffs = DiffDll(hProc, (DWORD64)mods[i], path);
        if (diffs.empty()) continue;

        wchar_t* slash = wcsrchr(path, L'\\');
        wchar_t* fname = slash ? slash + 1 : path;
        anyDiff = true;

        if (g_jsonMode) {
            if (!first) printf(",");
            first = false;
            printf("{\"module\":\"%ls\",\"base\":\"0x%llX\",\"sections\":[",
                   fname, (DWORD64)mods[i]);
            bool sf = true;
            for (auto& d : diffs) {
                if (!sf) printf(",");
                sf = false;
                printf("{\"name\":\"%s\",\"rva\":\"0x%X\",\"size\":%u,\"modified\":%u}",
                       d.si.name, d.si.rva, d.si.vsize, d.modBytes);
            }
            printf("]}");
        } else {
            printf("  %s%ls%s  base=%016llX\n",
                   A_YELLOW, fname, A_RESET, (DWORD64)mods[i]);
            for (auto& d : diffs) {
                printf("    %s%-8s%s  RVA=%08X  size=%6u  %s%u modified bytes%s\n",
                       A_CYAN, d.si.name, A_RESET,
                       d.si.rva, d.si.vsize,
                       A_RED, d.modBytes, A_RESET);
            }
            printf("\n");
        }
    }

    if (g_jsonMode) {
        printf("]}\n");
    } else if (!anyDiff) {
        printf("  %s[+]%s No in-memory modifications detected.\n", A_GREEN, A_RESET);
    }

    CloseHandle(hProc);
}

// ─── /memrestore ─────────────────────────────────────────────────────────────

void CmdMemRestore(DWORD pid, const char* dllFilter)
{
    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE, pid);
    if (!hProc) {
        printf("%s[!]%s OpenProcess(%lu) failed: %lu\n", A_RED, A_RESET, pid, GetLastError());
        return;
    }

    HMODULE mods[512];
    DWORD needed = 0;
    if (!EnumProcessModules(hProc, mods, sizeof(mods), &needed)) {
        printf("%s[!]%s EnumProcessModules failed: %lu\n", A_RED, A_RESET, GetLastError());
        CloseHandle(hProc); return;
    }

    DWORD nMods = needed / sizeof(HMODULE);

    // Convert filter to wide for comparison
    wchar_t wFilter[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, dllFilter, -1, wFilter, MAX_PATH);

    bool found = false;
    for (DWORD i = 0; i < nMods; i++) {
        wchar_t path[MAX_PATH];
        if (!GetModuleFileNameExW(hProc, mods[i], path, MAX_PATH)) continue;

        wchar_t* slash = wcsrchr(path, L'\\');
        wchar_t* fname = slash ? slash + 1 : path;

        // Match by full filename or substring (case-insensitive)
        if (_wcsicmp(fname, wFilter) != 0) {
            // Try without extension (e.g. "ntdll" matches "ntdll.dll")
            wchar_t stripped[MAX_PATH];
            wcscpy_s(stripped, fname);
            wchar_t* dot = wcsrchr(stripped, L'.');
            if (dot) *dot = 0;
            if (_wcsicmp(stripped, wFilter) != 0) continue;
        }

        found = true;
        DWORD64 base = (DWORD64)mods[i];
        printf("[*] Restoring %ls  base=%016llX  PID=%lu\n", fname, base, pid);

        std::vector<SectionInfo> sections;
        if (!ParsePEHeaders(hProc, base, sections)) {
            printf("%s[!]%s Failed to parse PE headers\n", A_RED, A_RESET);
            break;
        }

        auto disk = ReadDllFromDisk(path);
        if (disk.empty()) {
            printf("%s[!]%s Cannot read %ls from disk\n", A_RED, A_RESET, path);
            break;
        }

        int restored = 0, failed = 0;
        for (auto& si : sections) {
            if (si.vsize == 0 || si.rawSize == 0) continue;
            if ((SIZE_T)(si.rawOff + si.rawSize) > disk.size()) continue;

            DWORD64 secVA  = base + si.rva;
            DWORD   cmpLen = (std::min)(si.vsize, si.rawSize);

            // Read current memory
            std::vector<BYTE> mem(cmpLen, 0);
            SIZE_T got = 0;
            ReadProcessMemory(hProc, (LPCVOID)secVA, mem.data(), cmpLen, &got);
            if (got == 0) continue;

            // Count differences
            DWORD mod = 0;
            for (DWORD b = 0; b < (DWORD)(std::min)((SIZE_T)cmpLen, got); b++) {
                if (mem[b] != disk[si.rawOff + b]) mod++;
            }
            if (mod == 0) continue;

            printf("  [*] %-8s  RVA=%08X  %u modified bytes -> restoring...",
                   si.name, si.rva, mod);

            // Unlock + write + relock
            DWORD oldProt = 0;
            VirtualProtectEx(hProc, (LPVOID)secVA, cmpLen, PAGE_EXECUTE_READWRITE, &oldProt);

            SIZE_T written = 0;
            BOOL ok = WriteProcessMemory(hProc, (LPVOID)secVA,
                                         disk.data() + si.rawOff, cmpLen, &written);

            VirtualProtectEx(hProc, (LPVOID)secVA, cmpLen, oldProt, &oldProt);

            if (ok) {
                printf(" %s[+] OK (%zu bytes)%s\n", A_GREEN, written, A_RESET);
                restored++;
            } else {
                printf(" %s[!] FAILED (err %lu)%s\n", A_RED, GetLastError(), A_RESET);
                failed++;
            }
        }

        if (restored == 0 && failed == 0)
            printf("  %s[+]%s No modifications found — nothing to restore.\n", A_GREEN, A_RESET);
        else
            printf("\n  Restored %d section(s), %d failed.\n", restored, failed);

        break;
    }

    if (!found)
        printf("%s[!]%s '%s' not found in PID %lu\n", A_RED, A_RESET, dllFilter, pid);

    CloseHandle(hProc);
}

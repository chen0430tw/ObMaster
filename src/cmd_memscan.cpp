// cmd_memscan.cpp — /memscan and /memrestore
//
// /memscan <pid> [all]         Compare every loaded DLL's sections against its on-disk image.
//                              Reports sections that differ and the number of modified bytes.
//                              Default: skip noisy sections (.rdata/.data/etc). Pass 'all' for everything.
//
// /memrestore <pid> <dll> [sec] Restore modified sections of a DLL in a process by writing the
//                              original on-disk bytes back via VirtualProtectEx + WriteProcessMemory.
//                              Pass an optional section name (e.g. .00cfg) to limit the restore.
//                              Creates a private CoW copy for the target process.

#include "globals.h"
#include "ansi.h"
#include "jutil.h"
#include <windows.h>
#include <tlhelp32.h>
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

// Sections that are legitimately modified at runtime (IAT, globals, relocs, resources).
// Skipped by default to reduce noise; pass showAll=true to include them.
static bool IsNoisySection(const char* name)
{
    static const char* skip[] = {
        ".rdata", ".data", ".mrdata", ".didat", ".tls", ".rsrc", ".reloc", ".edata"
    };
    for (auto s : skip)
        if (_stricmp(name, s) == 0) return true;
    return false;
}

struct SectionDiff {
    SectionInfo si;
    DWORD       modBytes;
};

static std::vector<SectionDiff> DiffDll(HANDLE hProc, DWORD64 base, const wchar_t* path,
                                         bool showAll = false)
{
    std::vector<SectionDiff> result;

    std::vector<SectionInfo> sections;
    if (!ParsePEHeaders(hProc, base, sections)) return result;

    auto disk = ReadDllFromDisk(path);
    if (disk.empty()) return result;

    for (auto& si : sections) {
        if (si.vsize == 0 || si.rawSize == 0) continue;
        if ((SIZE_T)(si.rawOff + si.rawSize) > disk.size()) continue;
        if (!showAll && IsNoisySection(si.name)) {
            DBG("[memscan]   section %-8s  skipped (noisy)\n", si.name); continue;
        }

        DWORD cmpLen = (std::min)(si.vsize, si.rawSize);
        std::vector<BYTE> mem(cmpLen, 0);
        SIZE_T got = 0;
        ReadProcessMemory(hProc, (LPCVOID)(base + si.rva), mem.data(), cmpLen, &got);
        DBG("[memscan]   section %-8s  RVA=%08X  cmpLen=%u  got=%zu\n",
            si.name, si.rva, cmpLen, got);
        if (got == 0) continue;

        DWORD mod = 0;
        DWORD check = (DWORD)(std::min)((SIZE_T)cmpLen, got);
        for (DWORD b = 0; b < check; b++) {
            if (mem[b] != disk[si.rawOff + b]) mod++;
        }
        DBG("[memscan]   section %-8s  modified=%u bytes\n", si.name, mod);
        if (mod > 0)
            result.push_back({ si, mod });
    }
    return result;
}

// ─── Module enumeration via Toolhelp32 (avoids ERROR_PARTIAL_COPY from EnumProcessModules) ──

struct ModEntry {
    DWORD64      base;
    std::wstring path;
    std::wstring name;
};

static std::vector<ModEntry> EnumModules(DWORD pid)
{
    std::vector<ModEntry> result;
    // TH32CS_SNAPMODULE32 causes ERROR_PARTIAL_COPY on some 64-bit targets; use SNAPMODULE only
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    DBG("[memscan] CreateToolhelp32Snapshot(pid=%lu) -> %s (err=%lu)\n",
        pid, hSnap == INVALID_HANDLE_VALUE ? "INVALID" : "OK", GetLastError());
    if (hSnap == INVALID_HANDLE_VALUE) return result;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    BOOL ok = Module32FirstW(hSnap, &me);
    DBG("[memscan] Module32FirstW -> %s (err=%lu)\n", ok ? "OK" : "FAIL", GetLastError());
    if (ok) {
        do {
            ModEntry e;
            e.base = (DWORD64)me.modBaseAddr;
            e.path = me.szExePath;
            e.name = me.szModule;
            DBG("[memscan]   mod: %ls @ %016llX\n", e.name.c_str(), e.base);
            result.push_back(std::move(e));
        } while (Module32NextW(hSnap, &me));
    }
    CloseHandle(hSnap);
    DBG("[memscan] EnumModules: %zu entries\n", result.size());
    return result;
}

// ─── /memscan ────────────────────────────────────────────────────────────────

void CmdMemScan(DWORD pid, bool showAll)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        printf("%s[!]%s OpenProcess(%lu) failed: %lu\n", A_RED, A_RESET, pid, GetLastError());
        return;
    }

    auto mods = EnumModules(pid);
    if (mods.empty()) {
        printf("%s[!]%s Failed to enumerate modules for PID %lu (err %lu)\n",
               A_RED, A_RESET, pid, GetLastError());
        CloseHandle(hProc); return;
    }

    if (g_jsonMode) {
        printf("{\"pid\":%lu,\"modules\":[", pid);
    } else {
        printf("=== MemScan PID %lu (%zu modules) ===\n\n", pid, mods.size());
    }

    bool anyDiff = false;
    bool first   = true;
    for (auto& mod : mods) {
        auto diffs = DiffDll(hProc, mod.base, mod.path.c_str(), showAll);
        if (diffs.empty()) continue;

        anyDiff = true;

        if (g_jsonMode) {
            if (!first) printf(",");
            first = false;
            printf("{\"module\":\"%ls\",\"base\":\"0x%llX\",\"sections\":[",
                   mod.name.c_str(), mod.base);
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
                   A_YELLOW, mod.name.c_str(), A_RESET, mod.base);
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

// sectionFilter: optional section name to restore (e.g. ".00cfg"); nullptr = all non-noisy
void CmdMemRestore(DWORD pid, const char* dllFilter, const char* sectionFilter)
{
    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE, pid);
    if (!hProc) {
        printf("%s[!]%s OpenProcess(%lu) failed: %lu\n", A_RED, A_RESET, pid, GetLastError());
        return;
    }

    auto mods = EnumModules(pid);
    if (mods.empty()) {
        printf("%s[!]%s Failed to enumerate modules for PID %lu (err %lu)\n",
               A_RED, A_RESET, pid, GetLastError());
        CloseHandle(hProc); return;
    }

    // Convert filter to wide
    wchar_t wFilter[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, dllFilter, -1, wFilter, MAX_PATH);

    bool found = false;
    for (auto& mod : mods) {
        // Match by full filename or without extension (case-insensitive)
        if (_wcsicmp(mod.name.c_str(), wFilter) != 0) {
            wchar_t stripped[MAX_PATH];
            wcscpy_s(stripped, mod.name.c_str());
            wchar_t* dot = wcsrchr(stripped, L'.');
            if (dot) *dot = 0;
            if (_wcsicmp(stripped, wFilter) != 0) continue;
        }

        found = true;
        printf("[*] Restoring %ls  base=%016llX  PID=%lu\n",
               mod.name.c_str(), mod.base, pid);

        std::vector<SectionInfo> sections;
        if (!ParsePEHeaders(hProc, mod.base, sections)) {
            printf("%s[!]%s Failed to parse PE headers\n", A_RED, A_RESET);
            break;
        }

        auto disk = ReadDllFromDisk(mod.path.c_str());
        if (disk.empty()) {
            printf("%s[!]%s Cannot read from disk: %ls\n", A_RED, A_RESET, mod.path.c_str());
            break;
        }

        int restored = 0, failed = 0;
        for (auto& si : sections) {
            if (si.vsize == 0 || si.rawSize == 0) continue;
            if ((SIZE_T)(si.rawOff + si.rawSize) > disk.size()) continue;

            // Filter by section name if specified
            if (sectionFilter && _stricmp(si.name, sectionFilter) != 0) continue;
            // Default: skip noisy sections to avoid overwriting IAT / globals
            if (!sectionFilter && IsNoisySection(si.name)) continue;

            DWORD64 secVA  = mod.base + si.rva;
            DWORD   cmpLen = (std::min)(si.vsize, si.rawSize);

            // Read current memory
            std::vector<BYTE> mem(cmpLen, 0);
            SIZE_T got = 0;
            ReadProcessMemory(hProc, (LPCVOID)secVA, mem.data(), cmpLen, &got);
            if (got == 0) continue;

            // Count differences
            DWORD mod_count = 0;
            for (DWORD b = 0; b < (DWORD)(std::min)((SIZE_T)cmpLen, got); b++) {
                if (mem[b] != disk[si.rawOff + b]) mod_count++;
            }
            if (mod_count == 0) continue;

            printf("  [*] %-8s  RVA=%08X  %u modified bytes -> restoring...",
                   si.name, si.rva, mod_count);

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

// ─── /watchfix ───────────────────────────────────────────────────────────────
//
// Poll for every new instance of <procName>, then immediately run CmdMemRestore
// for each <dll>[:<section>] target on the new PID before hardening fires.
//
// Usage: /watchfix <process.exe> <dll>[:<section>] [<dll>[:<section>] ...]
//   e.g. /watchfix VirtualBoxVM.exe ntdll.dll:.00cfg VirtualBoxVM.exe:.00cfg
//
// Press Ctrl-C to stop.

struct WatchTarget {
    std::string dll;
    std::string section;  // empty = restore all non-noisy sections
};

void CmdWatchFix(const char* procName,
                 const std::vector<WatchTarget>& targets)
{
    wchar_t wProcName[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, procName, -1, wProcName, MAX_PATH);

    printf("[*] Watching for %s%s%s — %zu fix target(s) per instance\n",
           A_YELLOW, procName, A_RESET, targets.size());
    for (auto& t : targets)
        printf("      %s%s%s  section=%s\n",
               A_CYAN, t.dll.c_str(), A_RESET,
               t.section.empty() ? "(non-noisy)" : t.section.c_str());
    printf("    Press Ctrl-C to stop.\n\n");
    fflush(stdout);

    std::vector<DWORD> fixed;

    while (true) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, wProcName) != 0) continue;
                    DWORD pid = pe.th32ProcessID;

                    bool seen = false;
                    for (DWORD p : fixed) if (p == pid) { seen = true; break; }
                    if (seen) continue;

                    printf("[+] New %s%s%s  PID=%lu\n",
                           A_YELLOW, procName, A_RESET, pid);
                    fflush(stdout);

                    Sleep(20);  // let the process load its DLLs

                    for (auto& t : targets) {
                        CmdMemRestore(pid, t.dll.c_str(),
                                      t.section.empty() ? nullptr : t.section.c_str());
                        fflush(stdout);
                    }
                    fixed.push_back(pid);

                    printf("  [*] Post-fix scan:\n");
                    fflush(stdout);
                    CmdMemScan(pid, false);
                    fflush(stdout);

                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }

        if (fixed.size() > 256) fixed.erase(fixed.begin(), fixed.begin() + 128);
        Sleep(50);
    }
}

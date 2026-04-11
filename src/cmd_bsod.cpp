// cmd_bsod.cpp -- /bsod [dump_path]
//
// One-shot BSOD diagnosis: read minidump/full dump header, extract BugCheck
// code and parameters, resolve faulting address to driver, print diagnosis.
//
// If no path given, auto-finds the latest dump in C:\Windows\Minidump\.
//
// Dump header offsets (DUMP_HEADER64, starts with "PAGE"):
//   +0x000  Signature       "PAGE"
//   +0x004  ValidDump       "DU64" or "DUMP"
//   +0x038  BugCheckCode    ULONG
//   +0x040  BugCheckParameter1  ULONG64
//   +0x048  BugCheckParameter2  ULONG64
//   +0x050  BugCheckParameter3  ULONG64
//   +0x058  BugCheckParameter4  ULONG64
//   +0x060  KdDebuggerDataBlock ULONG64
//
// The shift operations used here (>> 12 for PFN, << 39 for PML4 index,
// >> 9 for PTE offset) are dimensional translations -- moving data between
// physical, virtual, and index coordinate systems. The same principle
// that makes PTE self-map work also makes dump header parsing work:
// fixed-offset reads are just zero-dimensional shifts.

#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <Psapi.h>
#include "kutil.h"
#include "ansi.h"

// Known BugCheck codes and their meaning
struct BugCheckInfo {
    DWORD code;
    const char* name;
    const char* p1_desc;
    const char* p2_desc;
    const char* p3_desc;
    const char* p4_desc;
};

static const BugCheckInfo g_bugchecks[] = {
    { 0x0018, "REFERENCE_BY_POINTER",
      "Object type", "Object address", "Expected refcount", "Actual refcount" },
    { 0x001E, "KMODE_EXCEPTION_NOT_HANDLED",
      "Exception code", "Faulting RIP", "Exception parameter 0", "Exception parameter 1" },
    { 0x003B, "SYSTEM_SERVICE_EXCEPTION",
      "Exception code", "Faulting RIP", "Exception context", "Reserved" },
    { 0x0050, "PAGE_FAULT_IN_NONPAGED_AREA",
      "Faulting VA", "Read(0)/Write(1)", "Faulting RIP", "Page table level(0-4)" },
    { 0x007E, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
      "Exception code", "Faulting RIP", "Exception record", "Context record" },
    { 0x007F, "UNEXPECTED_KERNEL_MODE_TRAP",
      "Trap number", "Reserved", "Reserved", "Reserved" },
    { 0x00BE, "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
      "Target VA", "PTE value", "Faulting RIP", "Reserved" },
    { 0x00D1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
      "Faulting VA", "IRQL", "Read(0)/Write(1)", "Faulting RIP" },
    { 0x00FC, "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY",
      "Faulting VA", "PTE value", "Reserved", "Reserved" },
    { 0x0189, "BAD_OBJECT_HEADER",
      "Object header VA", "Object VA", "Bad field", "Reserved" },
    { 0x019B, "TTM_FATAL_ERROR",
      "Reason", "Reserved", "Reserved", "Reserved" },
    { 0x0000, nullptr, nullptr, nullptr, nullptr, nullptr }
};

static const BugCheckInfo* FindBugCheck(DWORD code) {
    for (int i = 0; g_bugchecks[i].name; i++)
        if (g_bugchecks[i].code == code) return &g_bugchecks[i];
    return nullptr;
}

// Resolve a kernel VA to a driver name using EnumDeviceDrivers
static std::string ResolveAddress(DWORD64 addr) {
    if (!addr || addr < 0xFFFF800000000000ULL) return "";

    LPVOID drivers[2048];
    DWORD cb;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cb)) return "";

    int count = cb / sizeof(LPVOID);
    // Sort by base address descending to find containing module
    struct Mod { DWORD64 base; wchar_t name[64]; };
    std::vector<Mod> mods;
    for (int i = 0; i < count && i < 2048; i++) {
        Mod m;
        m.base = (DWORD64)drivers[i];
        if (!GetDeviceDriverBaseNameW(drivers[i], m.name, 64)) m.name[0] = 0;
        mods.push_back(m);
    }
    std::sort(mods.begin(), mods.end(), [](const Mod& a, const Mod& b) { return a.base < b.base; });

    for (int i = (int)mods.size() - 1; i >= 0; i--) {
        if (addr >= mods[i].base) {
            char buf[256];
            snprintf(buf, sizeof(buf), "%ls +0x%llX",
                     mods[i].name, (unsigned long long)(addr - mods[i].base));
            return buf;
        }
    }
    return "";
}

// Find latest .dmp file in a directory
static std::string FindLatestDump(const char* dir) {
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*.dmp", dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return "";

    std::string best;
    FILETIME bestTime = {};

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (CompareFileTime(&fd.ftLastWriteTime, &bestTime) > 0) {
            bestTime = fd.ftLastWriteTime;
            char full[MAX_PATH];
            snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName);
            best = full;
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
    return best;
}

// ── Time filter (doc_searcher.py style shortcuts) ────────────────────────────
// Supports: td yd 3d 7d 1h tw lw tm @timestamp YYYY-MM-DD
static bool ParseTimeFilter(const char* spec, FILETIME* outFt) {
    if (!spec || !spec[0]) return false;

    SYSTEMTIME now;
    GetLocalTime(&now);

    // Convert to FILETIME for arithmetic
    FILETIME nowFt;
    SystemTimeToFileTime(&now, &nowFt);
    ULARGE_INTEGER nowU;
    nowU.LowPart = nowFt.dwLowDateTime;
    nowU.HighPart = nowFt.dwHighDateTime;

    // 100-nanosecond units
    const ULONGLONG HOUR = 36000000000ULL;
    const ULONGLONG DAY  = 864000000000ULL;
    const ULONGLONG WEEK = DAY * 7;

    std::string s = spec;
    for (auto& c : s) c = (char)tolower((unsigned char)c);

    ULARGE_INTEGER result = nowU;

    if (s == "td" || s == "today") {
        // Today 00:00
        SYSTEMTIME start = now;
        start.wHour = start.wMinute = start.wSecond = start.wMilliseconds = 0;
        SystemTimeToFileTime(&start, outFt);
        return true;
    }
    if (s == "yd" || s == "yesterday") { result.QuadPart = nowU.QuadPart - DAY; }
    else if (s == "tw" || s == "thisweek") { result.QuadPart = nowU.QuadPart - (ULONGLONG)now.wDayOfWeek * DAY; }
    else if (s == "lw" || s == "lastweek") { result.QuadPart = nowU.QuadPart - ((ULONGLONG)now.wDayOfWeek + 7) * DAY; }
    else if (s[0] == '@' && s.size() > 1) {
        // Unix timestamp
        ULONGLONG ts = strtoull(s.c_str() + 1, nullptr, 10);
        result.QuadPart = (ts + 11644473600ULL) * 10000000ULL;
    }
    else {
        // YYYY-MM-DD (check first — "2026-04-10" would match %d%c as n=2026 unit='-')
        SYSTEMTIME st = {};
        if (sscanf(s.c_str(), "%hu-%hu-%hu", &st.wYear, &st.wMonth, &st.wDay) == 3
            && st.wYear > 1970) {
            SystemTimeToFileTime(&st, outFt);
            return true;
        }
        // Nd / Nh / Nw
        char unit = 0;
        int n = 0;
        if (sscanf(s.c_str(), "%d%c", &n, &unit) == 2 && n > 0) {
            if (unit == 'd') result.QuadPart = nowU.QuadPart - (ULONGLONG)n * DAY;
            else if (unit == 'h') result.QuadPart = nowU.QuadPart - (ULONGLONG)n * HOUR;
            else if (unit == 'w') result.QuadPart = nowU.QuadPart - (ULONGLONG)n * WEEK;
            else return false;
        }
        else return false;
    }

    outFt->dwLowDateTime = result.LowPart;
    outFt->dwHighDateTime = result.HighPart;
    return true;
}

// Find all .dmp files in a directory, optionally filtered by time
static std::vector<std::string> FindDumps(const char* dir,
                                           FILETIME* afterFt = nullptr,
                                           FILETIME* beforeFt = nullptr)
{
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*.dmp", dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return {};

    std::vector<std::pair<FILETIME, std::string>> entries;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        // Convert file's UTC time to local time for comparison
        // (ParseTimeFilter produces local time values)
        FILETIME localFt;
        FileTimeToLocalFileTime(&fd.ftLastWriteTime, &localFt);
        if (afterFt && CompareFileTime(&localFt, afterFt) < 0) continue;
        if (beforeFt && CompareFileTime(&localFt, beforeFt) > 0) continue;

        char full[MAX_PATH];
        snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName);
        entries.push_back({localFt, full});
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    // Sort by time descending (newest first)
    std::sort(entries.begin(), entries.end(),
              [](const auto& a, const auto& b) {
                  return CompareFileTime(&a.first, &b.first) > 0;
              });

    std::vector<std::string> result;
    for (auto& e : entries) result.push_back(e.second);
    return result;
}

void CmdBsod(const char* dumpPath, const char* afterSpec, const char* beforeSpec) {
    std::string path;
    bool listMode = false;
    bool analyzeAll = false;

    if (dumpPath) {
        if (_stricmp(dumpPath, "--list") == 0) listMode = true;
        else if (_stricmp(dumpPath, "--all") == 0) analyzeAll = true;
        else path = dumpPath;
    }

    // Time filter (doc_searcher.py style: td yd 3d 7d 1h tw lw tm @ts YYYY-MM-DD)
    FILETIME afterFt = {}, beforeFt = {};
    FILETIME* pAfter = nullptr;
    FILETIME* pBefore = nullptr;
    if (afterSpec && ParseTimeFilter(afterSpec, &afterFt)) {
        pAfter = &afterFt;
        SYSTEMTIME st; FileTimeToSystemTime(&afterFt, &st);
        printf("[*] Filter: after %04d-%02d-%02d %02d:%02d\n",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    }
    if (beforeSpec && ParseTimeFilter(beforeSpec, &beforeFt)) {
        pBefore = &beforeFt;
        SYSTEMTIME st; FileTimeToSystemTime(&beforeFt, &st);
        printf("[*] Filter: before %04d-%02d-%02d %02d:%02d\n",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    }

    if (path.empty() && !listMode && !analyzeAll) {
        // Auto-find latest dump
        auto dumps = FindDumps("C:\\Windows\\Minidump", pAfter, pBefore);
        if (dumps.empty()) dumps = FindDumps("C:\\Windows", pAfter, pBefore);
        if (dumps.empty()) {
            printf("%s[!]%s No dump file found in C:\\Windows\\Minidump\\\n"
                   "    Run as admin, or specify path: /bsod <path.dmp>\n"
                   "    List all: /bsod --list\n",
                   A_RED, A_RESET);
            return;
        }
        path = dumps[0]; // latest
    }

    if (listMode || analyzeAll) {
        auto dumps = FindDumps("C:\\Windows\\Minidump", pAfter, pBefore);
        if (dumps.empty()) dumps = FindDumps("C:\\Windows", pAfter, pBefore);
        if (dumps.empty()) {
            printf("  No dump files found.\n");
            return;
        }

        printf("  Found %zu dump(s):\n\n", dumps.size());
        for (auto& d : dumps) {
            if (analyzeAll) {
                // Analyze each dump inline
                // (recursive call with specific path)
                CmdBsod(d.c_str(), nullptr, nullptr);
                printf("  %s--%s\n\n", A_DIM, A_RESET);
            } else {
                // List mode: one line per dump with quick header read
                HANDLE hf = CreateFileA(d.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                        nullptr, OPEN_EXISTING, 0, nullptr);
                if (hf != INVALID_HANDLE_VALUE) {
                    BYTE hdr[0x80]; DWORD rd;
                    ReadFile(hf, hdr, sizeof(hdr), &rd, nullptr);
                    LARGE_INTEGER sz; GetFileSizeEx(hf, &sz);
                    CloseHandle(hf);

                    if (rd >= 0x60 && memcmp(hdr, "PAGE", 4) == 0) {
                        DWORD bc = *(DWORD*)(hdr + 0x38);
                        const BugCheckInfo* info = FindBugCheck(bc);
                        printf("  %-50s %6.1fMB  0x%08X %s\n",
                               d.c_str(), sz.QuadPart / (1024.0*1024.0),
                               bc, info ? info->name : "");
                    } else {
                        printf("  %-50s %6.1fMB  (unknown format)\n",
                               d.c_str(), sz.QuadPart / (1024.0*1024.0));
                    }
                }
            }
        }
        return;
    }

    printf("[*] Reading: %s\n\n", path.c_str());

    // Read dump header
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("%s[!]%s Cannot open dump: error %lu\n"
               "    Try: sudo ObMaster /bsod\n",
               A_RED, A_RESET, GetLastError());
        return;
    }

    BYTE header[0x2000];
    DWORD bytesRead;
    ReadFile(hFile, header, sizeof(header), &bytesRead, nullptr);

    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);
    CloseHandle(hFile);

    if (bytesRead < 0x100) {
        printf("%s[!]%s Dump file too small (%lu bytes)\n", A_RED, A_RESET, bytesRead);
        return;
    }

    // Check signature
    char sig[5] = {};
    memcpy(sig, header, 4);

    if (strcmp(sig, "PAGE") != 0 && strcmp(sig, "MDMP") != 0) {
        printf("%s[!]%s Unknown dump signature: %s\n", A_RED, A_RESET, sig);
        return;
    }

    printf("  Format:    %s (%s)\n", sig,
           strcmp(sig, "PAGE") == 0 ? "Full kernel dump" : "Minidump");
    printf("  Size:      %.1f MB\n", fileSize.QuadPart / (1024.0 * 1024.0));

    if (strcmp(sig, "PAGE") == 0) {
        // DUMP_HEADER64 format
        DWORD  bugcheck = *(DWORD*)(header + 0x038);
        DWORD64 p1      = *(DWORD64*)(header + 0x040);
        DWORD64 p2      = *(DWORD64*)(header + 0x048);
        DWORD64 p3      = *(DWORD64*)(header + 0x050);
        DWORD64 p4      = *(DWORD64*)(header + 0x058);

        const BugCheckInfo* info = FindBugCheck(bugcheck);

        printf("\n  %s*** BugCheck 0x%08X%s", A_RED, bugcheck, A_RESET);
        if (info) printf(" (%s%s%s)", A_BOLD, info->name, A_RESET);
        printf("\n\n");

        // Print parameters with descriptions
        const char* descs[4] = {
            info ? info->p1_desc : "P1",
            info ? info->p2_desc : "P2",
            info ? info->p3_desc : "P3",
            info ? info->p4_desc : "P4"
        };
        DWORD64 params[4] = { p1, p2, p3, p4 };

        for (int i = 0; i < 4; i++) {
            printf("  P%d: 0x%016llX", i + 1, (unsigned long long)params[i]);
            if (descs[i]) printf("  (%s)", descs[i]);

            // Try to resolve kernel addresses
            std::string resolved = ResolveAddress(params[i]);
            if (!resolved.empty())
                printf("\n      %s-> %s%s", A_CYAN, resolved.c_str(), A_RESET);
            printf("\n");
        }

        // Specific diagnosis based on BugCheck code
        printf("\n  %s--- Diagnosis ---%s\n", A_BOLD, A_RESET);

        if (bugcheck == 0x50) {
            std::string faultMod = ResolveAddress(p3);
            printf("  Page fault reading VA 0x%llX (not mapped / not present)\n",
                   (unsigned long long)p1);
            if (p2 == 0) printf("  Operation: READ\n");
            else         printf("  Operation: WRITE\n");
            if (!faultMod.empty())
                printf("  Faulting code: %s\n", faultMod.c_str());
            if (p1 >= 0xFFFF000000000000ULL && (p1 & 0x7) == 0) {
                printf("  %s[!] Faulting VA looks like a PTE self-map address%s\n",
                       A_YELLOW, A_RESET);
                printf("      Likely cause: wrong MmPteBase → computed bad PTE VA → read fault\n");
                printf("      Fix: use /ptebase-set with known-good value from WinDbg\n");
            }
        }
        else if (bugcheck == 0xBE) {
            printf("  Tried to write to read-only kernel page at 0x%llX\n",
                   (unsigned long long)p1);
            printf("  PTE value: 0x%llX (Write bit = %d)\n",
                   (unsigned long long)p2, (int)((p2 >> 1) & 1));
            std::string faultMod = ResolveAddress(p3);
            if (!faultMod.empty())
                printf("  Faulting code: %s\n", faultMod.c_str());
            printf("  Likely cause: /safepatch without shadow page, or large page target\n");
        }
        else if (bugcheck == 0x189) {
            printf("  Bad OBJECT_HEADER at 0x%llX for object 0x%llX\n",
                   (unsigned long long)p1, (unsigned long long)p2);
            printf("  %s[!] NEVER write NULL to OBJECT_HEADER.SecurityDescriptor%s\n",
                   A_RED, A_RESET);
        }
        else if (bugcheck == 0x18) {
            printf("  Reference count mismatch on object 0x%llX\n",
                   (unsigned long long)p2);
            printf("  Likely cause: token steal without incrementing PointerCount\n");
            printf("  Fix: ensure Wr64(tokenPtr - 0x30, PointerCount + 1) before token write\n");
        }
        else if (bugcheck == 0x3B) {
            std::string faultMod = ResolveAddress(p2);
            printf("  System service exception (0x%llX) at RIP\n",
                   (unsigned long long)p1);
            if (!faultMod.empty())
                printf("  Faulting code: %s\n", faultMod.c_str());
        }
        else if (bugcheck == 0x1E) {
            std::string faultMod = ResolveAddress(p2);
            printf("  Unhandled kernel exception 0x%llX\n", (unsigned long long)p1);
            if (!faultMod.empty())
                printf("  Faulting code: %s\n", faultMod.c_str());
        }

        // ObMaster-specific advice
        printf("\n  %s--- ObMaster Notes ---%s\n", A_BOLD, A_RESET);
        if (bugcheck == 0x50 && p1 >= 0xFFFF000000000000ULL) {
            printf("  This is a PTE/MmPteBase-related crash.\n");
            printf("  The PteSafetyCheck should have prevented this.\n");
            printf("  If it didn't fire, the crash happened before validation.\n");
        }
        if (bugcheck == 0xBE) {
            printf("  /safepatch PteSafetyCheck should block this now.\n");
            printf("  If still happening, target may be on a 2MB large page.\n");
        }
        if (bugcheck == 0x189) {
            printf("  OBJECT_HEADER.SecurityDescriptor = NULL is FORBIDDEN.\n");
            printf("  This is documented in MET0006 and CLAUDE.md.\n");
        }

    } else {
        // MDMP (minidump) — basic parsing
        printf("  Minidump format — limited info available.\n");
        printf("  For full analysis, enable full kernel dumps:\n");
        printf("    SystemPropertiesAdvanced → Startup and Recovery → Complete memory dump\n");
    }

    printf("\n");
}

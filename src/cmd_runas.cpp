#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include "ansi.h"

// ─── /runas system|ti <cmdline> ───────────────────────────────────────────────
// Elevate a new process to SYSTEM or TrustedInstaller via token duplication.
//
// Technique (admin -> SYSTEM):
//   1. Enable SeDebugPrivilege  (admin has it, just need to activate)
//   2. OpenProcess(PROCESS_QUERY_INFORMATION) on a SYSTEM process
//   3. OpenProcessToken + DuplicateTokenEx -> primary token
//   4. CreateProcessWithTokenW with the cloned token
//
// Technique (SYSTEM -> TrustedInstaller):
//   Same, but first start the TrustedInstaller service and steal its token.
//   TrustedInstaller is a svchost-hosted service with SeTakeOwnershipPrivilege
//   and can modify protected system files that SYSTEM cannot.

static bool EnablePrivilege(const wchar_t* name) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid)
           && AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)
           && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
    CloseHandle(hToken);
    return ok;
}

static DWORD FindProcessByName(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{ sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe))
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return pid;
}

static bool LaunchWithToken(DWORD sourcePid, const wchar_t* cmdline) {
    printf("%s[*]%s Opening PID=%u for token duplication...\n", A_CYAN, A_RESET, sourcePid);

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, sourcePid);
    if (!hProc) {
        printf("%s[!]%s OpenProcess(%u) failed (%lu)\n", A_RED, A_RESET, sourcePid, GetLastError());
        return false;
    }

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken)) {
        printf("%s[!]%s OpenProcessToken failed (%lu)\n", A_RED, A_RESET, GetLastError());
        CloseHandle(hProc);
        return false;
    }
    CloseHandle(hProc);

    HANDLE hDup = nullptr;
    SECURITY_ATTRIBUTES sa{ sizeof(sa) };
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, &sa,
            SecurityImpersonation, TokenPrimary, &hDup)) {
        printf("%s[!]%s DuplicateTokenEx failed (%lu)\n", A_RED, A_RESET, GetLastError());
        CloseHandle(hToken);
        return false;
    }
    CloseHandle(hToken);

    printf("%s[*]%s Launching: %ls\n", A_CYAN, A_RESET, cmdline);

    STARTUPINFOW si{ sizeof(si) };
    si.dwFlags    = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;
    PROCESS_INFORMATION pi{};

    wchar_t cmd[MAX_PATH * 4];
    wcsncpy_s(cmd, cmdline, MAX_PATH * 4 - 1);

    if (!CreateProcessWithTokenW(hDup, LOGON_WITH_PROFILE, nullptr, cmd,
            CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
        printf("%s[!]%s CreateProcessWithTokenW failed (%lu)\n", A_RED, A_RESET, GetLastError());
        CloseHandle(hDup);
        return false;
    }

    printf("%s[+]%s Process launched — PID=%u\n", A_GREEN, A_RESET, pi.dwProcessId);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hDup);
    return true;
}

void CmdRunAs(const char* level, const char* cmdlineA) {
    // Convert cmdline to wide
    wchar_t cmdline[MAX_PATH * 4]{};
    MultiByteToWideChar(CP_ACP, 0, cmdlineA, -1, cmdline, MAX_PATH * 4 - 1);

    printf("%s[*]%s Enabling SeDebugPrivilege...\n", A_CYAN, A_RESET);
    if (EnablePrivilege(L"SeDebugPrivilege"))
        printf("%s[+]%s SeDebugPrivilege active.\n", A_GREEN, A_RESET);
    else
        printf("%s[!]%s Warning: SeDebugPrivilege not granted — token theft may fail.\n", A_YELLOW, A_RESET);

    if (_stricmp(level, "system") == 0 || _stricmp(level, "sys") == 0) {
        // Prefer winlogon (always SYSTEM, non-critical to interrogate)
        printf("%s[*]%s Locating SYSTEM process...\n", A_CYAN, A_RESET);
        DWORD pid = FindProcessByName(L"winlogon.exe");
        if (!pid) pid = FindProcessByName(L"wininit.exe");
        if (!pid) pid = FindProcessByName(L"lsass.exe");
        if (!pid) {
            printf("%s[!]%s No suitable SYSTEM process found.\n", A_RED, A_RESET);
            return;
        }
        printf("%s[+]%s Using PID=%u as token source.\n", A_GREEN, A_RESET, pid);
        LaunchWithToken(pid, cmdline);
    }
    else if (_stricmp(level, "ti") == 0 || _stricmp(level, "trustedinstaller") == 0) {
        printf("%s[*]%s Starting TrustedInstaller service...\n", A_CYAN, A_RESET);

        SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hScm) {
            printf("%s[!]%s OpenSCManager failed (%lu)\n", A_RED, A_RESET, GetLastError());
            return;
        }
        SC_HANDLE hSvc = OpenServiceW(hScm, L"TrustedInstaller",
            SERVICE_START | SERVICE_QUERY_STATUS);
        if (!hSvc) {
            printf("%s[!]%s Cannot open TrustedInstaller service (%lu)\n", A_RED, A_RESET, GetLastError());
            CloseServiceHandle(hScm);
            return;
        }

        StartServiceW(hSvc, 0, nullptr); // ignore error if already running

        // Poll until running (max 10s)
        DWORD pid = 0;
        for (int i = 0; i < 20 && !pid; i++) {
            DWORD needed;
            SERVICE_STATUS_PROCESS ssp{};
            if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                    (LPBYTE)&ssp, sizeof(ssp), &needed)
                && ssp.dwCurrentState == SERVICE_RUNNING)
                pid = ssp.dwProcessId;
            else
                Sleep(500);
        }
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hScm);

        if (!pid) {
            printf("%s[!]%s TrustedInstaller did not start.\n", A_RED, A_RESET);
            return;
        }
        printf("%s[+]%s TrustedInstaller PID=%u\n", A_GREEN, A_RESET, pid);
        LaunchWithToken(pid, cmdline);
    }
    else {
        printf("%s[!]%s Unknown level '%s'  —  use: system  or  ti\n", A_RED, A_RESET, level);
    }
}

// SimKsafe.cpp — simulate ksafecenter64.sys evil handle behavior
//
// Opens PROCESS_ALL_ACCESS handle to the target process and keeps it open,
// exactly like ksafecenter64.sys does from kernel mode (PID 4 context).
//
// Usage:
//   SimKsafe.exe <pid>           target by PID
//   SimKsafe.exe <name>          target by process name (e.g. SimVBox.exe)
//
// Press Enter to release the handle and exit.

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <cstring>

static DWORD FindPidByName(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe{ sizeof(pe) };
    DWORD pid = 0;
    if (Process32First(snap, &pe))
        do {
            if (_stricmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return pid;
}

int main(int argc, char* argv[]) {
    printf("=== SimKsafe — evil handle injector ===\n\n");

    if (argc < 2) {
        printf("Usage: SimKsafe.exe <pid|name>\n");
        printf("  SimKsafe.exe 1234\n");
        printf("  SimKsafe.exe SimVBox.exe\n");
        return 1;
    }

    // Resolve target PID
    DWORD targetPid = 0;
    if (argv[1][0] >= '0' && argv[1][0] <= '9') {
        targetPid = (DWORD)atoi(argv[1]);
    } else {
        targetPid = FindPidByName(argv[1]);
        if (!targetPid) {
            printf("[!] Process not found: %s\n", argv[1]);
            return 1;
        }
    }
    printf("[*] Target PID: %lu\n", targetPid);

    // Open PROCESS_ALL_ACCESS — this is what ksafecenter does from kernel
    HANDLE hEvil = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hEvil) {
        printf("[!] OpenProcess failed: error %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Evil handle opened: 0x%p\n", hEvil);
    printf("[+] My PID: %lu  (handle lives in this process's table)\n", GetCurrentProcessId());
    printf("\n    Handle will remain open until you press Enter...\n");
    printf("    Run SimVBox.exe in another window to see it detected.\n\n");

    getchar();

    CloseHandle(hEvil);
    printf("[*] Handle closed — exiting\n");
    return 0;
}

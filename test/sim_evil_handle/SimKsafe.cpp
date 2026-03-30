// SimKsafe.cpp — simulate ksafecenter64.sys evil handle behavior
//
// Opens PROCESS_ALL_ACCESS handle to the target process and keeps it open,
// exactly like ksafecenter64.sys does from kernel mode (PID 4 context).
//
// Modes:
//   SimKsafe.exe <pid|name>                     hold one handle, release on Enter
//   SimKsafe.exe <pid|name> --persist           re-open immediately when closed (simulates
//                                               kernel ObRegisterCallbacks re-open behavior)
//   SimKsafe.exe <pid|name> --persist --interval <ms>   poll interval (default 10ms)
//
// Memory safety:
//   - Every HANDLE acquired via OpenProcess is tracked in hEvil.
//   - On external close (ObMaster zeroes the table entry), GetHandleInformation
//     returns ERROR_INVALID_HANDLE; we discard the stale value and reopen.
//   - On clean exit (Ctrl+C / Enter), CloseHandle is always called if valid.
//   - FindPidByName always closes its snapshot handle.

#include <Windows.h>
#include <TlHelp32.h>
#include <conio.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>

// ── Globals ──────────────────────────────────────────────────────────────────

static volatile bool g_stop = false;

static BOOL WINAPI CtrlHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT ||
        type == CTRL_CLOSE_EVENT) {
        g_stop = true;
        return TRUE;
    }
    return FALSE;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

static DWORD FindPidByName(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe{ sizeof(pe) };
    DWORD pid = 0;
    if (Process32First(snap, &pe))
        do {
            if (_stricmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    CloseHandle(snap);  // always closed regardless of branch
    return pid;
}

// Returns true if h is still a live handle in this process's table.
// Uses GetHandleInformation — zero kernel cost, no syscall for the object itself.
static bool HandleAlive(HANDLE h) {
    DWORD flags = 0;
    return GetHandleInformation(h, &flags) != 0;
}

// Open PROCESS_ALL_ACCESS to targetPid.  Returns NULL and prints error on failure.
static HANDLE OpenEvil(DWORD targetPid) {
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!h)
        printf("[!] OpenProcess(%lu) failed: error %lu\n", targetPid, GetLastError());
    return h;
}

// Safely close hEvil and zero the caller's variable.
// Skips CloseHandle if the entry was externally zeroed (would return ERROR_INVALID_HANDLE).
static void SafeClose(HANDLE& h) {
    if (!h) return;
    if (HandleAlive(h))
        CloseHandle(h);
    // If not alive, the entry was already zeroed by ObMaster — nothing to close.
    h = NULL;
}

// ── One-shot mode ─────────────────────────────────────────────────────────────

static void RunOnce(DWORD targetPid) {
    HANDLE hEvil = OpenEvil(targetPid);
    if (!hEvil) return;

    printf("[+] Evil handle: 0x%p\n", hEvil);
    printf("[+] My PID: %lu  (handle in this process's table)\n", GetCurrentProcessId());
    printf("\n    Handle held until Enter or Ctrl+C...\n");
    printf("    Run SimVBox.exe in another window to observe.\n\n");

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    // Wait for Enter or Ctrl+C
    while (!g_stop) {
        if (_kbhit()) {
            int c = _getche();
            if (c == '\r' || c == '\n') break;
        }
        Sleep(50);
    }

    SafeClose(hEvil);
    printf("[*] Handle closed — exiting\n");
}

// ── Persist mode ──────────────────────────────────────────────────────────────
//
// Continuously holds the evil handle.  When ObMaster (or anything) zeroes/closes
// the entry, we detect it within `intervalMs` and immediately reopen, simulating
// the ksafecenter kernel callback that fires on every new-process event.

static void RunPersist(DWORD targetPid, int intervalMs) {
    printf("[persist] Re-open interval: %dms  (Ctrl+C to stop)\n\n", intervalMs);

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    HANDLE hEvil     = OpenEvil(targetPid);
    if (!hEvil) return;

    int reopens = 0;
    printf("[+] Evil handle #0: 0x%p  pid=%lu\n", hEvil, GetCurrentProcessId());
    fflush(stdout);

    while (!g_stop) {
        Sleep(intervalMs);

        if (!HandleAlive(hEvil)) {
            // Handle was externally zeroed — entry is gone, don't CloseHandle.
            hEvil = NULL;

            // Reopen immediately (simulate kernel callback)
            hEvil = OpenEvil(targetPid);
            if (!hEvil) {
                // Target process died — stop.
                printf("[!] Target PID %lu gone, stopping.\n", targetPid);
                break;
            }
            reopens++;
            printf("[reopen #%d] new handle: 0x%p\n", reopens, hEvil);
            fflush(stdout);
        }
    }

    printf("\n[*] Stopping (reopens=%d)...\n", reopens);
    SafeClose(hEvil);
    printf("[*] Done\n");
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    printf("=== SimKsafe — evil handle injector ===\n\n");

    if (argc < 2) {
        printf("Usage:\n");
        printf("  SimKsafe.exe <pid|name>                    hold once, release on Enter\n");
        printf("  SimKsafe.exe <pid|name> --persist          re-open when closed\n");
        printf("  SimKsafe.exe <pid|name> --persist --interval <ms>\n");
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

    // Parse flags
    bool persist     = false;
    int  intervalMs  = 10;
    for (int i = 2; i < argc; i++) {
        if (_stricmp(argv[i], "--persist") == 0) {
            persist = true;
        } else if (_stricmp(argv[i], "--interval") == 0 && i + 1 < argc) {
            intervalMs = atoi(argv[++i]);
            if (intervalMs < 1) intervalMs = 1;
        }
    }

    if (persist)
        RunPersist(targetPid, intervalMs);
    else
        RunOnce(targetPid);

    return 0;
}

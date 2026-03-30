// SimKshutdown.cpp — simulate kshutdown64.sys behavior
//
// Reverse-engineered attack chain (kshutdown64.sys, 2026-03-30):
//   1. CreateProcess notify (+0x1D3C): fires on every new process
//   2. ZwOpenProcess(target, 0x10000000=GENERIC_ALL) → PROCESS_ALL_ACCESS handle
//      → lands in System (PID 4) Level-2 handle table (index >65535)
//   3. APC-injects kshut64.dll → DllMain calls TerminateProcess(self, 0xC0000409)
//
// This simulator:
//   Phase 1  Fill: open FILL_COUNT dummy handles so the evil handle lands in Level 2
//   Phase 2  Hold: keep the Level-2 evil handle alive
//   Phase 3  Kill: after --kill-delay ms, TerminateProcess(target, 0xC0000409)
//            (simulates kshut64.dll DllMain; skipped if evil handle was already closed)
//
// Usage:
//   SimKshutdown.exe <pid|name>
//   SimKshutdown.exe <pid|name> --persist [--interval <ms>]
//   SimKshutdown.exe <pid|name> --kill-delay <ms>
//   SimKshutdown.exe <pid|name> --persist --kill-delay <ms> [--interval <ms>]
//
// Memory safety:
//   - All filler handles are tracked in a vector; always freed on exit.
//   - Evil handle is closed (or skipped if externally zeroed) on exit.
//   - Ctrl+C sets g_stop; cleanup runs before process exits.

#include <Windows.h>
#include <TlHelp32.h>
#include <conio.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>

// ── Constants ─────────────────────────────────────────────────────────────────

// Minimum handles to open before the evil handle so it lands in Level 2.
// Level 0+1 max = 512*256 = 131072 entries.  We open one page past that.
static const int FILL_COUNT = 131076;

// ── Globals ───────────────────────────────────────────────────────────────────

static volatile bool g_stop = false;

static BOOL WINAPI CtrlHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        g_stop = true;
        return TRUE;
    }
    return FALSE;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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

static bool HandleAlive(HANDLE h) {
    DWORD flags = 0;
    return GetHandleInformation(h, &flags) != 0;
}

static HANDLE OpenEvil(DWORD targetPid) {
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!h)
        printf("[!] OpenProcess(%lu) failed: error %lu\n", targetPid, GetLastError());
    return h;
}

static void SafeClose(HANDLE& h) {
    if (!h) return;
    if (HandleAlive(h)) CloseHandle(h);
    h = NULL;
}

static void CloseFillers(std::vector<HANDLE>& fillers) {
    for (HANDLE& h : fillers) {
        if (h && HandleAlive(h)) CloseHandle(h);
        h = NULL;
    }
    fillers.clear();
}

// Open FILL_COUNT cheap self-duplicate handles so the NEXT handle allocation
// falls into Level-2 of the handle table (index > 65535).
// Returns false if filling failed.
static bool FillToLevel2(std::vector<HANDLE>& fillers) {
    fillers.reserve(FILL_COUNT);
    HANDLE hSelf = GetCurrentProcess();  // pseudo-handle, always valid
    printf("[fill] Opening %d dummy handles to reach Level-2...\n", FILL_COUNT);
    for (int i = 0; i < FILL_COUNT; i++) {
        HANDLE h = NULL;
        if (!DuplicateHandle(hSelf, hSelf, hSelf, &h, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            printf("[!] DuplicateHandle failed at filler %d: error %lu\n",
                   i, GetLastError());
            CloseFillers(fillers);
            return false;
        }
        fillers.push_back(h);
        if (i > 0 && i % 32768 == 0)
            printf("[fill] %d / %d...\n", i, FILL_COUNT);
    }
    printf("[fill] Done — %d handles open\n", FILL_COUNT);
    return true;
}

// Open the evil handle AFTER fillers are in place so it lands in Level 2.
// On success, prints the handle value and estimated level.
static HANDLE OpenEvilLevel2(DWORD targetPid) {
    HANDLE h = OpenEvil(targetPid);
    if (!h) return NULL;

    ULONG_PTR hv  = (ULONG_PTR)h;
    DWORD     idx = (DWORD)(hv >> 2);
    int       lvl = (idx < 256) ? 0 : (idx < 65536) ? 1 : 2;
    printf("[+] Evil handle: 0x%p  idx=%u  level=%d%s\n",
           h, idx, lvl,
           lvl == 2 ? "  ✓ Level-2" : "  ✗ NOT Level-2 (fill may have failed)");
    return h;
}

// ── One-shot mode ─────────────────────────────────────────────────────────────

static void RunOnce(DWORD targetPid, int killDelayMs) {
    printf("[*] Filling handle table to Level-2 (%d dummy handles)...\n", FILL_COUNT);
    std::vector<HANDLE> fillers;
    if (!FillToLevel2(fillers)) return;
    printf("[+] Fill done (%d handles)\n", FILL_COUNT);

    HANDLE hEvil = OpenEvilLevel2(targetPid);
    if (!hEvil) { CloseFillers(fillers); return; }

    // Fillers no longer needed — evil handle stays in its Level-2 slot.
    CloseFillers(fillers);
    printf("[*] Fillers released; evil handle remains at its Level-2 index.\n");
    printf("[*] My PID: %lu\n", GetCurrentProcessId());
    if (killDelayMs > 0)
        printf("[*] Will kill target in %dms (simulating kshut64.dll APC).\n", killDelayMs);
    printf("\n    Handle held until Enter or Ctrl+C...\n\n");

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    DWORD elapsed = 0;
    while (!g_stop) {
        if (_kbhit()) { int c = _getche(); if (c == '\r' || c == '\n') break; }
        Sleep(50);
        elapsed += 50;

        if (killDelayMs > 0 && (int)elapsed >= killDelayMs) {
            if (HandleAlive(hEvil)) {
                printf("\n[kill] %dms elapsed — simulating kshut64.dll TerminateProcess(0xC0000409)...\n",
                       killDelayMs);
                HANDLE hTarget = OpenProcess(PROCESS_TERMINATE, FALSE, targetPid);
                if (hTarget) {
                    TerminateProcess(hTarget, 0xC0000409);
                    CloseHandle(hTarget);
                    printf("[kill] TerminateProcess sent.\n");
                } else {
                    printf("[kill] OpenProcess(TERMINATE) failed: %lu\n", GetLastError());
                }
            } else {
                printf("\n[kill] %dms elapsed but evil handle already closed — kill aborted.\n",
                       killDelayMs);
            }
            break;
        }
    }

    SafeClose(hEvil);
    printf("[*] Done\n");
}

// ── Persist mode ──────────────────────────────────────────────────────────────

static void RunPersist(DWORD targetPid, int intervalMs, int killDelayMs) {
    printf("[persist] Interval=%dms  KillDelay=%s\n",
           intervalMs, killDelayMs > 0 ? std::to_string(killDelayMs).append("ms").c_str() : "none");

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    auto doFillAndOpen = [&](std::vector<HANDLE>& fillers) -> HANDLE {
        if (!FillToLevel2(fillers)) return NULL;
        HANDLE h = OpenEvilLevel2(targetPid);
        CloseFillers(fillers);   // release fillers; slot stays in Level-2
        return h;
    };

    printf("[*] Initial fill + open...\n");
    std::vector<HANDLE> fillers;
    HANDLE hEvil = doFillAndOpen(fillers);
    if (!hEvil) return;

    int reopens = 0;
    DWORD elapsed = 0;
    bool killed = false;

    while (!g_stop) {
        Sleep(intervalMs);
        elapsed += (DWORD)intervalMs;

        // Kill check (fires once)
        if (!killed && killDelayMs > 0 && (int)elapsed >= killDelayMs) {
            killed = true;
            if (HandleAlive(hEvil)) {
                printf("\n[kill] %dms — simulating kshut64.dll TerminateProcess(0xC0000409)...\n",
                       killDelayMs);
                HANDLE hTarget = OpenProcess(PROCESS_TERMINATE, FALSE, targetPid);
                if (hTarget) {
                    TerminateProcess(hTarget, 0xC0000409);
                    CloseHandle(hTarget);
                    printf("[kill] TerminateProcess sent.\n");
                } else {
                    printf("[kill] OpenProcess(TERMINATE) failed: %lu\n", GetLastError());
                }
            } else {
                printf("\n[kill] %dms — evil handle already closed, kill aborted (ObMaster won!).\n",
                       killDelayMs);
            }
        }

        // Reopen if externally closed
        if (!HandleAlive(hEvil)) {
            hEvil = NULL;
            std::vector<HANDLE> rf;
            hEvil = doFillAndOpen(rf);
            if (!hEvil) {
                printf("[!] Target PID %lu gone, stopping.\n", targetPid);
                break;
            }
            reopens++;
            printf("[reopen #%d] new handle: 0x%p  elapsed=%lums\n",
                   reopens, hEvil, (unsigned long)elapsed);
            fflush(stdout);
        }
    }

    printf("\n[*] Stopping (reopens=%d)...\n", reopens);
    SafeClose(hEvil);
    printf("[*] Done\n");
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    setbuf(stdout, NULL);  // disable buffering so output appears even on crash
    printf("=== SimKshutdown — kshutdown64.sys simulator ===\n");
    printf("    (Level-2 handle fill + optional kill delay)\n\n");

    if (argc < 2) {
        printf("Usage:\n");
        printf("  SimKshutdown.exe <pid|name>\n");
        printf("  SimKshutdown.exe <pid|name> --persist [--interval <ms>]\n");
        printf("  SimKshutdown.exe <pid|name> --kill-delay <ms>\n");
        printf("  SimKshutdown.exe <pid|name> --persist --kill-delay <ms>\n");
        return 1;
    }

    DWORD targetPid = 0;
    if (argv[1][0] >= '0' && argv[1][0] <= '9') {
        targetPid = (DWORD)atoi(argv[1]);
    } else {
        targetPid = FindPidByName(argv[1]);
        if (!targetPid) { printf("[!] Process not found: %s\n", argv[1]); return 1; }
    }
    printf("[*] Target PID: %lu\n", targetPid);

    bool persist    = false;
    int  intervalMs = 10;
    int  killDelay  = 0;

    for (int i = 2; i < argc; i++) {
        if (_stricmp(argv[i], "--persist") == 0) {
            persist = true;
        } else if (_stricmp(argv[i], "--interval") == 0 && i+1 < argc) {
            int v = atoi(argv[++i]);
            intervalMs = v >= 1 ? v : 1;
        } else if (_stricmp(argv[i], "--kill-delay") == 0 && i+1 < argc) {
            int v = atoi(argv[++i]);
            killDelay = v >= 0 ? v : 0;
        }
    }

    if (persist)
        RunPersist(targetPid, intervalMs, killDelay);
    else
        RunOnce(targetPid, killDelay);

    return 0;
}

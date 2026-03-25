#include <Windows.h>
#include <winternl.h>
#include <cstdio>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include "ansi.h"

// NtQuerySystemInformation class 64 = SystemExtendedHandleInformation
typedef struct _SYSTEM_HANDLE_EX {
    PVOID   Object;
    ULONG64 UniqueProcessId;
    ULONG64 HandleValue;
    ULONG   GrantedAccess;
    USHORT  CreatorBackTraceIndex;
    USHORT  ObjectTypeIndex;
    ULONG   HandleAttributes;
    ULONG   Reserved;
} SYSTEM_HANDLE_EX;

typedef struct _SYSTEM_HANDLE_INFO_EX {
    ULONG64        NumberOfHandles;
    ULONG64        Reserved;
    SYSTEM_HANDLE_EX Handles[1];
} SYSTEM_HANDLE_INFO_EX;

typedef NTSTATUS(NTAPI* FnNtQSI)(ULONG, PVOID, ULONG, PULONG);

// Timing statistics helper
struct TimingStat {
    LONGLONG minUs = LLONG_MAX;
    LONGLONG maxUs = 0;
    LONGLONG sumUs = 0;
    int      count = 0;

    void record(LONGLONG us) {
        if (us < minUs) minUs = us;
        if (us > maxUs) maxUs = us;
        sumUs += us;
        count++;
    }
    double avgUs() const { return count ? (double)sumUs / count : 0.0; }
};

// ─────────────────────────────────────────────────────────────────────────────
// /timedelta <pid> [duration_ms]
//
// Polls SystemExtendedHandleInformation at high frequency.
// For each snapshot, looks for System (pid=4) handles pointing to the same
// kernel object as handles already seen from <pid>.  When such a handle
// appears and then disappears, record the window duration.
//
// Use case: measure how long ksafecenter's transient OBJ_KERNEL_HANDLE lives,
// confirming whether VBoxSup can race it.
// ─────────────────────────────────────────────────────────────────────────────
void CmdTimeDelta(DWORD targetPid, int durationMs) {
    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    auto NtQSI = (FnNtQSI)GetProcAddress(hNt, "NtQuerySystemInformation");
    if (!NtQSI) { printf("[!] NtQuerySystemInformation not found\n"); return; }

    if (durationMs <= 0) durationMs = 3000;

    // Pre-allocate 16 MB snapshot buffer
    DWORD bufSize = 1u << 24;
    std::vector<BYTE> buf(bufSize);

    printf("[*] /timedelta — watching PID %u handles for %d ms\n", targetPid, durationMs);
    printf("    Looking for transient System-process (PID 4) handles\n");
    printf("    to the same object owned by PID %u\n\n", targetPid);

    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);

    // First: find the Object pointers owned by targetPid
    // (we re-check each snapshot)

    // Per-poll state: set of {Object, HandleValue} pairs from PID 4
    struct HKey { PVOID obj; ULONG64 hval; ULONG acc; };
    // Active PID-4 handles this snapshot
    std::map<ULONG64, HKey>  prevSys;   // HandleValue → HKey (previous snapshot)
    TimingStat               stat;

    // Track when a System handle appeared
    struct AppearRecord { LONGLONG tick; ULONG access; };
    std::map<ULONG64, AppearRecord> active; // HandleValue → appear time

    LONGLONG startTick, nowTick;
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li); startTick = li.QuadPart;

    DWORD64 pollCount = 0;
    int     evtCount  = 0;

    while (true) {
        QueryPerformanceCounter(&li); nowTick = li.QuadPart;
        LONGLONG elapsedMs = (nowTick - startTick) * 1000 / freq.QuadPart;
        if (elapsedMs >= durationMs) break;

        ULONG retLen = 0;
        NTSTATUS st = NtQSI(64, buf.data(), bufSize, &retLen);
        if (st != 0 && st != (NTSTATUS)0x80000005) continue;
        pollCount++;

        auto* info = (SYSTEM_HANDLE_INFO_EX*)buf.data();

        // Collect objects belonging to targetPid (to identify cross-pid handles)
        std::set<PVOID> targetObjs;
        std::map<ULONG64, HKey> curSys;

        for (ULONG64 i = 0; i < info->NumberOfHandles; i++) {
            auto& h = info->Handles[i];
            if ((DWORD)h.UniqueProcessId == targetPid)
                targetObjs.insert(h.Object);
        }

        LARGE_INTEGER snap;
        QueryPerformanceCounter(&snap);

        for (ULONG64 i = 0; i < info->NumberOfHandles; i++) {
            auto& h = info->Handles[i];
            if ((DWORD)h.UniqueProcessId != 4) continue;
            if (h.ObjectTypeIndex != 7) continue;     // Process object type
            if (!targetObjs.count(h.Object)) continue; // Must be our target's object

            HKey k{ h.Object, h.HandleValue, h.GrantedAccess };
            curSys[h.HandleValue] = k;

            if (!active.count(h.HandleValue)) {
                // New transient handle appeared
                active[h.HandleValue] = { snap.QuadPart, h.GrantedAccess };
                printf("  %s[+]%s Handle 0x%llX appeared  acc=0x%X\n",
                       A_GREEN, A_RESET, h.HandleValue, h.GrantedAccess);
                evtCount++;
            }
        }

        // Detect disappeared handles
        for (auto it = active.begin(); it != active.end(); ) {
            if (!curSys.count(it->first)) {
                QueryPerformanceCounter(&snap);
                LONGLONG windowTick = snap.QuadPart - it->second.tick;
                LONGLONG windowUs   = windowTick * 1000000 / freq.QuadPart;

                printf("  %s[-]%s Handle 0x%llX gone      window = %lld µs",
                       A_RED, A_RESET, it->first, windowUs);

                if (windowUs < 100)        printf("  %s[race-able!]%s", A_RED,    A_RESET);
                else if (windowUs < 1000)  printf("  [tight]");
                else                       printf("  [wide]");
                printf("\n");

                stat.record(windowUs);
                it = active.erase(it);
            } else {
                ++it;
            }
        }
    }

    printf("\n[*] Summary  (%llu polls  ~%.0f polls/sec)\n",
           pollCount, (double)pollCount * 1000.0 / durationMs);
    printf("    Events seen: %d\n", evtCount);

    if (stat.count > 0) {
        printf("    Window: min=%.1f µs  avg=%.1f µs  max=%.1f µs  (%d samples)\n",
               (double)stat.minUs, stat.avgUs(), (double)stat.maxUs, stat.count);

        printf("\n    Race risk: ");
        if (stat.minUs < 200)
            printf("%sHIGH%s — VBoxSup scan CAN catch the handle\n", A_RED, A_RESET);
        else if (stat.minUs < 2000)
            printf("%sMEDIUM%s — occasional catches possible\n", A_RED, A_RESET);
        else
            printf("%sLOW%s — window too wide to race reliably\n", A_GREEN, A_RESET);
    } else {
        printf("    No transient System→target handles detected\n");
        printf("    (%s driver not loaded, or /disable already applied%s)\n",
               A_GREEN, A_RESET);
    }
}

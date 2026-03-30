// SimVBox.cpp — simulate VBoxSup evil handle check
//
// Loops every 1 second (or once with --once).
//
// Technique:
//   1. SystemExtendedHandleInformation (class 64) — full 64-bit handle values,
//      ObjectTypeIndex, GrantedAccess for all system handles
//   2. Open self, find our Object pointer in the table (unambiguous because
//      handle values are now 64-bit, no USHORT truncation)
//   3. Also record our own ObjectTypeIndex
//   4. Scan for handles from unexpected PIDs with the SAME ObjectTypeIndex and
//      Object pointer → evil handle
//
// No DuplicateHandle needed. Fast O(N) scan.

#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <cstdio>
#include <cstring>
#include <string>

typedef NTSTATUS (NTAPI *PFN_NtQSI)(ULONG, PVOID, ULONG, PULONG);
static PFN_NtQSI NtQSI;

#define STATUS_INFO_LENGTH_MISMATCH  ((NTSTATUS)0xC0000004L)
#define SystemExtHandleInformation   64

// Full-fidelity handle entry (64-bit handle values)
struct SysHandleEntryEx {
    PVOID      Object;
    ULONG_PTR  ProcessId;
    ULONG_PTR  HandleValue;
    ULONG      GrantedAccess;
    USHORT     CreatorBackTraceIndex;
    USHORT     ObjectTypeIndex;
    ULONG      HandleAttributes;
    ULONG      Reserved;
};
struct SysHandleInfoEx {
    ULONG_PTR       Count;
    ULONG_PTR       Reserved;
    SysHandleEntryEx Handles[1];
};

static SysHandleInfoEx* QueryAllHandles() {
    ULONG size = 1 << 20;
    SysHandleInfoEx* buf = nullptr;
    NTSTATUS st;
    do {
        buf = (SysHandleInfoEx*)realloc(buf, size);
        st  = NtQSI(SystemExtHandleInformation, buf, size, nullptr);
        size *= 2;
    } while (st == STATUS_INFO_LENGTH_MISMATCH);
    if (st != 0) { free(buf); return nullptr; }
    return buf;
}

static DWORD GetParentPid(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe{ sizeof(pe) };
    DWORD parent = 0;
    if (Process32First(snap, &pe))
        do {
            if (pe.th32ProcessID == pid) { parent = pe.th32ParentProcessID; break; }
        } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return parent;
}

static std::string PidToName(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return "?";
    PROCESSENTRY32 pe{ sizeof(pe) };
    std::string name = "?";
    if (Process32First(snap, &pe))
        do {
            if (pe.th32ProcessID == pid) { name = pe.szExeFile; break; }
        } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return name;
}

// ── One scan pass ─────────────────────────────────────────────────────────────

static int ScanOnce(DWORD myPid, DWORD parentPid) {
    // Open a real handle to ourselves FIRST so it appears in the snapshot
    HANDLE hSelf = OpenProcess(PROCESS_ALL_ACCESS, FALSE, myPid);
    if (!hSelf) {
        printf("  [!] OpenProcess(self) failed: %lu\n", GetLastError());
        fflush(stdout);
        return -1;
    }
    ULONG_PTR hSelfVal = (ULONG_PTR)hSelf;  // full 64-bit value, no truncation

    SysHandleInfoEx* shi = QueryAllHandles();
    if (!shi) {
        CloseHandle(hSelf);
        printf("  [!] NtQuerySystemInformation failed\n");
        fflush(stdout);
        return -1;
    }

    // Find our own entry: ProcessId == myPid && HandleValue == hSelfVal
    PVOID  ourObject   = nullptr;
    USHORT ourTypeIdx  = 0;
    for (ULONG_PTR i = 0; i < shi->Count; i++) {
        if (shi->Handles[i].ProcessId  == (ULONG_PTR)myPid &&
            shi->Handles[i].HandleValue == hSelfVal) {
            ourObject  = shi->Handles[i].Object;
            ourTypeIdx = shi->Handles[i].ObjectTypeIndex;
            break;
        }
    }
    CloseHandle(hSelf);

    if (!ourObject) {
        free(shi);
        printf("  [!] Cannot locate own EPROCESS (hSelf=0x%p, pid=%lu)\n",
               (void*)hSelfVal, myPid);
        fflush(stdout);
        return -1;
    }

    // Scan: same object + same type index from an unexpected process
    int evil = 0;
    for (ULONG_PTR i = 0; i < shi->Count; i++) {
        auto& e = shi->Handles[i];
        if ((DWORD)e.ProcessId == myPid)     continue;
        if ((DWORD)e.ProcessId == parentPid) continue;
        if (e.ObjectTypeIndex  != ourTypeIdx) continue;
        if (e.Object           != ourObject)  continue;

        printf("  [!] Evil handle:\n");
        printf("      pid=%-6lu  (%s)\n", (DWORD)e.ProcessId,
               PidToName((DWORD)e.ProcessId).c_str());
        printf("      h=0x%llX  acc=0x%lx  type=%u\n",
               (unsigned long long)e.HandleValue,
               (ULONG)e.GrantedAccess, (UINT)e.ObjectTypeIndex);
        fflush(stdout);
        evil++;
    }

    free(shi);
    return evil;
}

// ── main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    bool once        = false;
    int  killTimeout = 0;   // ms; 0 = disabled.  Simulates kshut64.dll kill deadline.

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--once") == 0 || strcmp(argv[i], "-once") == 0)
            once = true;
        else if (strcmp(argv[i], "--kill-timeout") == 0 && i + 1 < argc)
            killTimeout = atoi(argv[++i]);
    }

    NtQSI = (PFN_NtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                       "NtQuerySystemInformation");
    if (!NtQSI) {
        printf("[!] NtQuerySystemInformation not found\n");
        return 1;
    }

    DWORD myPid     = GetCurrentProcessId();
    DWORD parentPid = GetParentPid(myPid);

    printf("=== SimVBox — evil handle detector ===\n");
    printf("    PID: %lu    Parent: %lu\n", myPid, parentPid);
    if (killTimeout > 0)
        printf("    Kill timeout: %dms (simulates kshut64.dll APC deadline)\n", killTimeout);
    if (!once) printf("    Ctrl+C to exit\n");
    printf("\n");
    fflush(stdout);

    DWORD startMs = GetTickCount();
    int   pass    = 0;

    for (;;) {
        pass++;
        printf("[pass %d] Scanning...\n", pass);
        fflush(stdout);

        int found = ScanOnce(myPid, parentPid);
        if (found == 0) {
            printf("  [+] No evil handles — OK\n");
        } else if (found > 0) {
            printf("\n  VERR_SUP_VP_FOUND_EVIL_HANDLE (-3738) — %d handle(s)\n", found);
        }

        // Deadline check: if evil handles still present when timeout fires,
        // simulate being killed by kshut64.dll (TerminateProcess 0xC0000409).
        if (killTimeout > 0) {
            DWORD elapsed = GetTickCount() - startMs;
            if ((int)elapsed >= killTimeout) {
                if (found > 0) {
                    printf("\n  [DEAD] kshut64.dll deadline reached (%dms) — "
                           "evil handles still present.\n", killTimeout);
                    printf("  [DEAD] Simulating TerminateProcess(self, 0xC0000409).\n");
                    fflush(stdout);
                    ExitProcess(0xC0000409);
                } else {
                    printf("  [SAFE] Deadline reached but no evil handles — "
                           "ObMaster won in time!\n");
                    fflush(stdout);
                    break;
                }
            }
            printf("  [timer] %lums / %dms\n", (unsigned long)elapsed, killTimeout);
        }

        printf("\n");
        fflush(stdout);

        if (once) break;
        Sleep(1000);
    }
    return 0;
}

#include <Windows.h>
#include <cstdio>
#include "kutil.h"
#include "ansi.h"
#include "driver/IDriverBackend.h"

// ─── /handle-close <pid> <handle_hex> ────────────────────────────────────────
// Close a handle held by any process, including the System (pid=4) process.
//
// Two paths:
//   pid != 4  → DuplicateHandle(DUPLICATE_CLOSE_SOURCE)
//               Works for same-session user-mode processes without admin.
//
//   pid == 4  → Kernel HANDLE_TABLE walk + zero HANDLE_TABLE_ENTRY
//               Removes the entry from the System process's handle table via
//               RTCore64 kernel R/W.  Does NOT call ExDestroyHandle, so the
//               object's reference count is not decremented (minor kernel leak).
//               Safe in practice: WdFilter/ksafecenter64 hold their own refs
//               internally; removing the System-table handle just hides it from
//               NtQuerySystemInformation, which is exactly what VirtualBox checks.
//
// HANDLE_TABLE layout (Win10 19045 x64, verified via WinDbg dt nt!_HANDLE_TABLE):
//   +0x000 NextHandleNeedingPool  ULONG
//   +0x004 ExtraInfoPages         LONG
//   +0x008 TableCode              ULONGLONG   ← pointer + level (low 2 bits)
//   ...
//
// HANDLE_TABLE_ENTRY (16 bytes):
//   +0x000 ObjectPointer   ULONGLONG  (ptr to OBJECT_HEADER, lock bit in bit 0)
//   +0x008 GrantedAccess   ULONGLONG
//
// Handle index = handle_value >> 2
// Level 0: direct array, entry = TableBase + index * 16
// Level 1: array of sub-table ptrs (256 entries each)
// Level 2: two-level indirection

static const DWORD HT_TableCode = 0x008;
static const DWORD HTE_Size     = 16;

static DWORD64 FindHandleEntry(DWORD64 handleTable, DWORD handleVal) {
    DWORD64 tableCode = g_drv->Rd64(handleTable + HT_TableCode);
    int     level     = (int)(tableCode & 3);
    DWORD64 base      = tableCode & ~3ULL;
    DWORD   idx       = handleVal >> 2;

    if (level == 0) {
        return base + (DWORD64)idx * HTE_Size;
    } else if (level == 1) {
        DWORD64 sub = g_drv->Rd64(base + (idx / 256) * 8);
        if (!sub) return 0;
        return sub + (DWORD64)(idx % 256) * HTE_Size;
    } else if (level == 2) {
        DWORD64 l2  = g_drv->Rd64(base + (idx / (256 * 256)) * 8);
        if (!l2) return 0;
        DWORD64 l1  = g_drv->Rd64(l2 + ((idx / 256) % 256) * 8);
        if (!l1) return 0;
        return l1 + (DWORD64)(idx % 256) * HTE_Size;
    }
    return 0;
}

void CmdHandleClose(DWORD pid, DWORD64 handleVal) {
    // ── User-mode process ─────────────────────────────────────────────────────
    if (pid != 4) {
        HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
        if (!hProc) {
            printf("%s[!]%s OpenProcess(DUP_HANDLE, pid=%u) failed: %lu\n",
                   A_RED, A_RESET, pid, GetLastError());
            return;
        }
        HANDLE hDup = nullptr;
        BOOL ok = DuplicateHandle(hProc, (HANDLE)(ULONG_PTR)handleVal,
                                  GetCurrentProcess(), &hDup,
                                  0, FALSE, DUPLICATE_CLOSE_SOURCE);
        if (ok) {
            printf("%s[+]%s pid=%-6u  h=0x%llX  closed (DuplicateHandle CLOSE_SOURCE).\n",
                   A_GREEN, A_RESET, pid, handleVal);
            if (hDup) CloseHandle(hDup);
        } else {
            printf("%s[!]%s DuplicateHandle failed: %lu\n", A_RED, A_RESET, GetLastError());
        }
        CloseHandle(hProc);
        return;
    }

    // ── System (pid=4): kernel handle table ──────────────────────────────────
    printf("%s[*]%s pid=4 (System) — kernel HANDLE_TABLE walk\n", A_CYAN, A_RESET);

    DWORD64 sysEP = KUtil::FindEPROCESS(4);
    if (!sysEP) { printf("%s[!]%s System EPROCESS not found.\n", A_RED, A_RESET); return; }
    printf("%s[*]%s System EPROCESS = 0x%llX\n", A_CYAN, A_RESET, sysEP);

    DWORD64 ht = g_drv->Rd64(sysEP + KUtil::EP_HandleTable);
    if (!ht) { printf("%s[!]%s HandleTable ptr is null.\n", A_RED, A_RESET); return; }

    DWORD64 tableCode = g_drv->Rd64(ht + HT_TableCode);
    printf("%s[*]%s HandleTable=0x%llX  TableCode=0x%llX (level=%llu)\n",
           A_CYAN, A_RESET, ht, tableCode, (unsigned long long)(tableCode & 3));

    DWORD64 entry = FindHandleEntry(ht, (DWORD)handleVal);
    if (!entry) {
        printf("%s[!]%s h=0x%llX not found in System handle table.\n",
               A_RED, A_RESET, handleVal);
        return;
    }
    printf("%s[*]%s HANDLE_TABLE_ENTRY @ 0x%llX\n", A_CYAN, A_RESET, entry);

    DWORD64 objPtr = g_drv->Rd64(entry);
    DWORD64 access = g_drv->Rd64(entry + 8);
    printf("%s[*]%s  ObjectPointer = 0x%llX\n", A_CYAN, A_RESET, objPtr);
    printf("%s[*]%s  GrantedAccess = 0x%llX\n", A_CYAN, A_RESET, access);

    if (!objPtr) {
        printf("%s[!]%s Entry already empty.\n", A_YELLOW, A_RESET);
        return;
    }

    g_drv->Wr64(entry,     0);
    g_drv->Wr64(entry + 8, 0);

    DWORD64 verify = g_drv->Rd64(entry);
    if (verify == 0) {
        printf("%s[+]%s h=0x%llX in System process zeroed — removed from handle table.\n",
               A_GREEN, A_RESET, handleVal);
        printf("%s[~]%s Refcount not decremented (raw zero); minor kernel object leak.\n",
               A_YELLOW, A_RESET);
    } else {
        printf("%s[!]%s Zero did not stick (0x%llX) — possible lock/race.\n",
               A_RED, A_RESET, verify);
    }
}

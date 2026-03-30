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

static const DWORD HT_NextPool  = 0x000;   // NextHandleNeedingPool  (ULONG)
static const DWORD HT_TableCode = 0x008;   // TableCode  (ULONGLONG, low 2 bits = level)
static const DWORD HTE_Size     = 16;

// ─── Walk all allocated entries in a HANDLE_TABLE ────────────────────────────
// Calls cb(entryVA, slotIdx, objPtr, accessQw) for every non-null entry.
// Returns early if cb returns false.
static void WalkHandleTable(DWORD64 ht,
    bool (*cb)(DWORD64 entryVA, DWORD idx, DWORD64 obj, DWORD64 acc, void* ctx),
    void* ctx)
{
    DWORD   nextPool  = (DWORD)g_drv->Rd64(ht + HT_NextPool); // next unallocated handle value
    DWORD   maxIdx    = nextPool >> 2;
    if (maxIdx == 0 || maxIdx > 0x20000) maxIdx = 0x4000;     // sanity cap ~64K handles

    DWORD64 tableCode = g_drv->Rd64(ht + HT_TableCode);
    int     level     = (int)(tableCode & 3);
    DWORD64 base      = tableCode & ~3ULL;

    if (level == 0) {
        for (DWORD idx = 1; idx < maxIdx && idx < 256; idx++) {
            DWORD64 e   = base + (DWORD64)idx * HTE_Size;
            DWORD64 obj = g_drv->Rd64(e);
            if (!obj) continue;
            if (!(obj & 1)) continue;  // bit 0 = valid/lock bit; 0 = free-list entry
            DWORD64 acc = g_drv->Rd64(e + 8);
            if (!cb(e, idx, obj, acc, ctx)) return;
        }
    } else if (level == 1) {
        for (DWORD outer = 0; outer < 256; outer++) {
            DWORD64 sub = g_drv->Rd64(base + outer * 8);
            if (!sub) continue;
            for (DWORD inner = 0; inner < 256; inner++) {
                DWORD idx = outer * 256 + inner;
                if (idx == 0) continue;
                if (idx >= maxIdx) return;
                DWORD64 e   = sub + (DWORD64)inner * HTE_Size;
                DWORD64 obj = g_drv->Rd64(e);
                if (!obj) continue;
                if (!(obj & 1)) continue;  // bit 0 = valid/lock bit; 0 = free-list entry
                DWORD64 acc = g_drv->Rd64(e + 8);
                if (!cb(e, idx, obj, acc, ctx)) return;
            }
        }
    } else if (level == 2) {
        for (DWORD top = 0; top < 256 && top * 256 * 256 < maxIdx; top++) {
            DWORD64 l2 = g_drv->Rd64(base + top * 8);
            if (!l2) continue;
            for (DWORD mid = 0; mid < 256; mid++) {
                DWORD64 l1 = g_drv->Rd64(l2 + mid * 8);
                if (!l1) continue;
                for (DWORD inner = 0; inner < 256; inner++) {
                    DWORD idx = top * 256 * 256 + mid * 256 + inner;
                    if (idx == 0) continue;
                    if (idx >= maxIdx) return;
                    DWORD64 e   = l1 + (DWORD64)inner * HTE_Size;
                    DWORD64 obj = g_drv->Rd64(e);
                    if (!obj) continue;
                    if (!(obj & 1)) continue;  // bit 0 = valid/lock bit; 0 = free-list entry
                    DWORD64 acc = g_drv->Rd64(e + 8);
                    if (!cb(e, idx, obj, acc, ctx)) return;
                }
            }
        }
    }
}

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

// ─── /handle-scan <pid> [--access <mask>] [--target-pid <pid>] [--close] ──────
// Walk <pid>'s kernel HANDLE_TABLE and list every entry whose GrantedAccess
// matches <mask> (default: PROCESS_ALL_ACCESS = 0x1fffff).
//
// --target-pid <t>  : only match entries pointing to process <t>'s EPROCESS.
//   ObjectPointer encoding in Win10 19045 HANDLE_TABLE_ENTRY.VolatileLowValue:
//     OBJECT_HEADER = (raw >> 16) | 0xFFFF000000000000
//     EPROCESS      = OBJECT_HEADER + 0x30
//   Verified from live scan: System h=0x4 raw=0xC98326AA7010FE9F,
//   System EPROCESS=0xFFFFC98326AA7040, OBJECT_HEADER=0xFFFFC98326AA7010 ✓
//
// --close : zero each matching entry (same mechanics as /handle-close).
//
// Safe usage: always pair --close with --target-pid to avoid closing
// legitimate System handles to csrss/lsass/etc.
void CmdHandleScan(DWORD pid, DWORD64 accessMask, DWORD targetPid, bool doClose) {
    if (!accessMask) accessMask = 0x001FFFFF;  // PROCESS_ALL_ACCESS

    DWORD64 ep = KUtil::FindEPROCESS(pid);
    if (!ep) { printf("%s[!]%s EPROCESS for PID %u not found.\n", A_RED, A_RESET, pid); return; }
    printf("%s[*]%s PID %-6u  EPROCESS=0x%llX\n", A_CYAN, A_RESET, pid, ep);

    // Optional: resolve target PID's OBJECT_HEADER for precise filtering
    DWORD64 targetObjHdr = 0;
    if (targetPid) {
        DWORD64 targetEP = KUtil::FindEPROCESS(targetPid);
        if (!targetEP) {
            printf("%s[!]%s --target-pid %u: EPROCESS not found.\n", A_RED, A_RESET, targetPid);
            return;
        }
        targetObjHdr = targetEP - 0x30;  // OBJECT_HEADER is 0x30 bytes before body
        printf("%s[*]%s target PID %-6u  EPROCESS=0x%llX  OBJECT_HEADER=0x%llX\n",
               A_CYAN, A_RESET, targetPid, targetEP, targetObjHdr);
    }

    DWORD64 ht = g_drv->Rd64(ep + KUtil::EP_HandleTable);
    if (!ht) { printf("%s[!]%s HandleTable ptr is null.\n", A_RED, A_RESET); return; }

    DWORD64 tableCode = g_drv->Rd64(ht + HT_TableCode);
    printf("%s[*]%s HandleTable=0x%llX  TableCode=0x%llX (level=%llu)  "
           "access=0x%llX%s%s\n",
           A_CYAN, A_RESET, ht, tableCode, (unsigned long long)(tableCode & 3),
           accessMask,
           targetPid ? "  [--target-pid filtered]" : "  [all processes]",
           doClose   ? "  [--close]" : "");

    struct ScanCtx {
        DWORD64 mask;
        DWORD64 targetObjHdr;  // 0 = no filter
        bool    doClose;
        int     found;
        int     closed;
    } ctx = { accessMask, targetObjHdr, doClose, 0, 0 };

    WalkHandleTable(ht, [](DWORD64 entryVA, DWORD idx, DWORD64 obj, DWORD64 acc, void* pctx) -> bool {
        auto* c = (ScanCtx*)pctx;

        // Access mask filter
        if ((acc & c->mask) != c->mask) return true;

        // Target-PID filter: decode ObjectPointer and compare to target OBJECT_HEADER
        // Win10 19045 encoding: OBJECT_HEADER = (raw >> 16) | 0xFFFF000000000000
        if (c->targetObjHdr) {
            DWORD64 decoded = (obj >> 16) | 0xFFFF000000000000ULL;
            if (decoded != c->targetObjHdr) return true;
        }

        DWORD hval = idx * 4;
        c->found++;
        printf("  %s[+]%s h=0x%08X  acc=0x%08llX  obj=0x%llX\n",
               A_GREEN, A_RESET, hval, acc, obj);

        if (c->doClose) {
            g_drv->Wr64(entryVA,     0);
            g_drv->Wr64(entryVA + 8, 0);
            DWORD64 verify = g_drv->Rd64(entryVA);
            if (verify == 0) {
                printf("  %s[x]%s h=0x%08X zeroed.\n", A_GREEN, A_RESET, hval);
                c->closed++;
            } else {
                printf("  %s[!]%s h=0x%08X zero did not stick (0x%llX).\n",
                       A_RED, A_RESET, hval, verify);
            }
        }
        return true;
    }, &ctx);

    printf("\n%s[*]%s Scan complete — %d match(es) found",
           A_CYAN, A_RESET, ctx.found);
    if (doClose)
        printf(", %d closed", ctx.closed);
    printf(".\n");
}

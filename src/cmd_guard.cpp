#define NOMINMAX
#include <Windows.h>
#include <cstdio>
#include <atomic>
#include <cstring>
#include <algorithm>
#include "driver/IDriverBackend.h"
#include "globals.h"
#include "ansi.h"
#include "pte.h"
#include "patch_store.h"
#include "kutil.h"

// ─────────────────────────────────────────────────────────────────────────────
// Guard subsystem
//
// Runs a background thread that periodically verifies each guarded patch.
// If the patched bytes changed (e.g. PatchGuard restored them, or the driver
// has a self-repair routine), the guard logs the event and re-applies.
//
// For shadow-page patches: also checks whether the PTE still points at our
// shadow page.  If someone restored the original PTE, re-swaps it.
// ─────────────────────────────────────────────────────────────────────────────

static HANDLE            g_guardThread  = nullptr;
static std::atomic<bool> g_guardRunning { false };
static int               g_guardIntervalMs = 500;

static void ReapplyPatch(PatchRecord& rec) {
    if (rec.has_shadow) {
        // Re-swap PTE: reconstruct new PTE from shadow PA + original flags
        DWORD64 newPte = (rec.orig_pte_val & PTE_FLAG_MASK)
                       | (rec.shadow_pa    & PTE_PA_MASK);
        newPte &= ~PTE_USER;
        newPte &= ~PTE_NX;
        newPte |=  PTE_PRESENT;
        WritePte(rec.page_start, newPte);
        Sleep(5);
    } else {
        // Aligned Wr32 fallback
        DWORD64 alignedBase = rec.addr & ~3ULL;
        DWORD64 alignedEnd  = (rec.addr + rec.len + 3) & ~3ULL;
        for (DWORD64 waddr = alignedBase; waddr < alignedEnd; waddr += 4) {
            DWORD cur  = g_drv->Rd32(waddr);
            DWORD newV = cur;
            DWORD64 lo = (rec.addr > waddr) ? rec.addr - waddr : 0;
            DWORD64 hi = std::min((DWORD64)4, rec.addr + rec.len - waddr);
            for (DWORD64 b = lo; b < hi; b++)
                ((BYTE*)&newV)[b] = rec.patched[(waddr + b) - rec.addr];
            g_drv->Wr32(waddr, newV);
        }
    }
}

static DWORD WINAPI GuardThread(LPVOID) {
    printf("[guard] Watchdog started  interval=%d ms\n", g_guardIntervalMs);
    fflush(stdout);

    while (g_guardRunning) {
        Sleep(g_guardIntervalMs);

        for (auto& rec : g_patches) {
            if (!rec.guarded || !rec.active) continue;

            bool mismatch = false;

            if (rec.has_shadow) {
                // Check PTE still points to shadow PA
                PteInfo cur = ReadPte(rec.page_start);
                if (cur.valid && (cur.page_pa != rec.shadow_pa)) {
                    SYSTEMTIME t; GetLocalTime(&t);
                    printf("[guard %02d:%02d:%02d] 0x%016llX PTE reverted"
                           " (expected PA=0x%012llX, got 0x%012llX) — re-swapping\n",
                           t.wHour, t.wMinute, t.wSecond,
                           rec.addr, rec.shadow_pa, cur.page_pa);
                    mismatch = true;
                }
            } else {
                // Byte-by-byte check of patched region
                for (size_t i = 0; i < rec.len; i++) {
                    if (g_drv->Rd8(rec.addr + i) != rec.patched[i]) {
                        mismatch = true;
                        break;
                    }
                }
                if (mismatch) {
                    SYSTEMTIME t; GetLocalTime(&t);
                    printf("[guard %02d:%02d:%02d] 0x%016llX bytes reverted — re-applying\n",
                           t.wHour, t.wMinute, t.wSecond, rec.addr);
                }
            }

            if (mismatch) {
                ReapplyPatch(rec);
                printf("[guard] Re-apply done\n");
                fflush(stdout);
            }
        }
    }

    printf("[guard] Watchdog stopped\n");
    fflush(stdout);
    return 0;
}

// ── /guard-add <addr>  (the patch must already exist via /safepatch) ─────────
void CmdGuardAdd(DWORD64 addr) {
    PatchRecord* rec = FindPatch(addr);
    if (!rec) {
        printf("[!] No patch record for 0x%016llX — run /safepatch first\n", addr);
        return;
    }
    rec->guarded = true;
    printf("[+] 0x%016llX added to guard\n", rec->addr);
}

// ── /guard-start [interval_ms] ───────────────────────────────────────────────
void CmdGuardStart(int intervalMs) {
    if (g_guardRunning) { printf("[!] Guard already running\n"); return; }
    g_guardIntervalMs = (intervalMs > 0) ? intervalMs : 500;
    g_guardRunning    = true;
    g_guardThread     = CreateThread(nullptr, 0, GuardThread, nullptr, 0, nullptr);
    if (!g_guardThread) {
        g_guardRunning = false;
        printf("[!] CreateThread failed: %u\n", GetLastError());
    } else {
        printf("[+] Guard watchdog started  interval=%d ms\n", g_guardIntervalMs);
    }
}

// ── /guard-stop ───────────────────────────────────────────────────────────────
void CmdGuardStop() {
    if (!g_guardRunning) { printf("[!] Guard not running\n"); return; }
    g_guardRunning = false;
    WaitForSingleObject(g_guardThread, 5000);
    CloseHandle(g_guardThread);
    g_guardThread = nullptr;
}

// ── /guard-list ───────────────────────────────────────────────────────────────
void CmdGuardList() {
    bool any = false;
    for (auto& rec : g_patches) {
        if (!rec.guarded) continue;
        any = true;
        const wchar_t* name = nullptr; DWORD64 off = 0;
        KUtil::FindDriverByAddr(rec.addr, &name, &off);
        printf("  0x%016llX  %ws+0x%llX  len=%zu  shadow=%s  %s\n",
               rec.addr, name, off, rec.len,
               rec.has_shadow ? "yes" : "no",
               rec.active     ? "ACTIVE" : "inactive");
    }
    if (!any) printf("  (no guarded patches)\n");
    printf("  Watchdog: %s  interval=%d ms\n",
           g_guardRunning ? "RUNNING" : "stopped", g_guardIntervalMs);
}

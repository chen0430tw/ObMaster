#define NOMINMAX
#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include "driver/IDriverBackend.h"
#include "globals.h"
#include "ansi.h"
#include "kutil.h"
#include "pte.h"
#include "patch_store.h"

// ── Read 4096 bytes from a kernel VA using 1024 x Rd32 ───────────────────────
static void ReadKernelPage(DWORD64 pageVA, BYTE* buf) {
    for (int i = 0; i < 1024; i++) {
        DWORD v = g_drv->Rd32(pageVA + (DWORD64)i * 4);
        memcpy(buf + i * 4, &v, 4);
    }
}

// ── Parse hex string into byte array, return byte count (0 on error) ─────────
static size_t ParseHex(const char* hexStr, BYTE* out, size_t maxLen) {
    size_t hexLen = strlen(hexStr);
    if (hexLen == 0 || hexLen % 2 != 0) return 0;
    size_t n = hexLen / 2;
    if (n > maxLen) return 0;
    for (size_t i = 0; i < n; i++) {
        char buf[3] = { hexStr[i*2], hexStr[i*2+1], 0 };
        out[i] = (BYTE)strtoul(buf, nullptr, 16);
    }
    return n;
}

// ─────────────────────────────────────────────────────────────────────────────
// /safepatch <addr> <hexbytes>
//
// Strategy:
//   1. Read the PTE for the target page.
//   2. Allocate a user-mode shadow page and copy the entire 4KB kernel page.
//   3. Apply the patch to the shadow page copy.
//   4. Swap the target page's PTE to point at the shadow page's physical frame.
//      This is a DATA write (to a PTE), not a CODE write — no race window.
//   5. If shadow setup fails, fall back to a single aligned Wr32 per chunk
//      (much safer than the old byte-by-byte Wr8 approach).
// ─────────────────────────────────────────────────────────────────────────────
void CmdSafePatch(DWORD64 addr, const char* hexStr) {
    // ── Parse patch bytes ──────────────────────────────────────────────────
    BYTE patchBytes[16]{};
    size_t byteCount = ParseHex(hexStr, patchBytes, 16);
    if (byteCount == 0) {
        printf("[!] Bad hex string (must be even-length, max 16 bytes)\n");
        return;
    }

    if (!g_drv->IsKernelVA(addr)) {
        printf("[!] 0x%016llX is not a kernel VA\n", addr);
        return;
    }

    // ── Pre-flight safety check (validates MmPteBase + large page + DKOM) ──
    if (!PteSafetyCheck(addr)) {
        printf("[!] Aborting safepatch — safety check failed.\n");
        return;
    }

    // ── Identify driver ───────────────────────────────────────────────────
    KUtil::BuildDriverCache();
    const wchar_t* drvName = nullptr;
    DWORD64 drvOffset = 0;
    KUtil::FindDriverByAddr(addr, &drvName, &drvOffset);
    printf("[*] Target: %ws +0x%llX\n", drvName, drvOffset);

    // ── Read PTE ──────────────────────────────────────────────────────────
    PteInfo pte = ReadPte(addr);
    if (pte.valid) {
        printf("[*] PTE @ 0x%016llX = 0x%016llX  PA=0x%012llX  [%s%s%s%s]\n",
            pte.pte_va, pte.pte_val, pte.page_pa,
            pte.present    ? "P " : "!P ",
            pte.writable   ? "W " : "R ",
            pte.executable ? "X"  : "NX",
            pte.user       ? " U" : " K");
        if (!pte.present) {
            printf("[!] Page not present — abort\n");
            return;
        }
    } else {
        printf("[!] PTE walk failed (MmPteBase unavailable)\n");
    }

    // ── Read original bytes ───────────────────────────────────────────────
    BYTE origBytes[16]{};
    for (size_t i = 0; i < byteCount; i++)
        origBytes[i] = g_drv->Rd8(addr + i);

    printf("[*] Patching %zu byte(s) @ 0x%016llX\n", byteCount, addr);
    printf("    Before: "); for (size_t i=0;i<byteCount;i++) printf("%02X ",origBytes[i]); printf("\n");
    printf("    After:  "); for (size_t i=0;i<byteCount;i++) printf("%02X ",patchBytes[i]); printf("\n");

    // ── Attempt shadow page + PTE swap ────────────────────────────────────
    bool usedShadow = false;
    LPVOID shadowVA  = nullptr;
    DWORD64 origPteVal = pte.valid ? pte.pte_val : 0;
    DWORD64 shadowPA   = 0;

    if (pte.valid && pte.present) {
        DWORD64 pageVA = addr & ~0xFFFULL;
        DWORD64 patchOffset = addr - pageVA;

        // 1. Allocate and lock a user-mode shadow page
        shadowVA = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!shadowVA) {
            printf("[!] VirtualAlloc shadow page failed: %u\n", GetLastError());
            goto fallback;
        }
        if (!VirtualLock(shadowVA, 4096)) {
            printf("[!] VirtualLock shadow page failed: %u — aborting shadow\n", GetLastError());
            VirtualFree(shadowVA, 0, MEM_RELEASE);
            shadowVA = nullptr;
            goto fallback;
        }

        // 2. Copy original kernel page into shadow
        printf("[*] Copying kernel page (1024 reads)... ");
        fflush(stdout);
        BYTE pageBuf[4096];
        ReadKernelPage(pageVA, pageBuf);
        memcpy(shadowVA, pageBuf, 4096);
        printf("done\n");

        // 3. Apply our patch to the shadow copy
        memcpy((BYTE*)shadowVA + patchOffset, patchBytes, byteCount);

        // 4. Read shadow page PTE to find its physical address
        PteInfo spte = ReadPte((DWORD64)shadowVA);
        if (!spte.valid || !spte.present) {
            printf("[!] Cannot read shadow page PTE — aborting shadow\n");
            VirtualUnlock(shadowVA, 4096);
            VirtualFree(shadowVA, 0, MEM_RELEASE);
            shadowVA = nullptr;
            goto fallback;
        }
        shadowPA = spte.page_pa;
        printf("[*] Shadow: user_VA=0x%p  PA=0x%012llX\n", shadowVA, shadowPA);

        // 5. Build new PTE: keep original flags, replace physical address
        DWORD64 newPteVal = (origPteVal & PTE_FLAG_MASK) | (shadowPA & PTE_PA_MASK);
        // Ensure kernel-only + executable (our shadow has kernel code)
        newPteVal &= ~PTE_USER;
        newPteVal &= ~PTE_NX;
        newPteVal |=  PTE_PRESENT;

        printf("[*] PTE swap:\n");
        printf("    old PTE: 0x%016llX  (PA=0x%012llX)\n", origPteVal, origPteVal & PTE_PA_MASK);
        printf("    new PTE: 0x%016llX  (PA=0x%012llX)\n", newPteVal,  shadowPA);
        printf("[*] Writing new PTE (data write, not code write)...\n");

        WritePte(pageVA, newPteVal);

        // 6. Protect shadow page from accidental user-mode writes
        DWORD old;
        VirtualProtect(shadowVA, 4096, PAGE_EXECUTE_READ, &old);

        // 7. Flush TLB: MapPhys(shadow PA) + WRITE IOCTL + UnmapPhys.
        FlushTlb(pageVA);

        usedShadow = true;
        printf("  %s[+] Shadow page mapped over kernel code page%s\n", A_GREEN, A_RESET);
    }

fallback:
    if (!usedShadow) {
        // Do NOT fall back to direct virtual write — kernel code pages have PTE.Write=0
        // and any direct Wr32 will cause STOP 0xBE (ATTEMPTED_WRITE_TO_READONLY_MEMORY).
        printf("[!] Shadow page setup failed — REFUSING direct write to avoid BSOD.\n");
        printf("[!] Fix: ensure MmPteBase is resolved (check [pte] scan output above).\n");
        if (shadowVA) { VirtualUnlock(shadowVA, 4096); VirtualFree(shadowVA, 0, MEM_RELEASE); }
        return;
    }

    // ── Verify ────────────────────────────────────────────────────────────
    printf("[*] Verify: ");
    bool ok = true;
    for (size_t i = 0; i < byteCount; i++) {
        BYTE got = g_drv->Rd8(addr + i);
        printf("%02X ", got);
        if (got != patchBytes[i]) ok = false;
    }
    printf("\n");

    if (ok)
        printf("  %s[+] Patch OK%s\n", A_GREEN, A_RESET);
    else
        printf("  %s[!] Verify mismatch%s\n", A_RED, A_RESET);

    // ── Save record ───────────────────────────────────────────────────────
    PatchRecord rec{};
    rec.addr       = addr;
    rec.page_start = addr & ~0xFFFULL;
    memcpy(rec.orig,         origBytes,  byteCount);
    memcpy(rec.patched,      patchBytes, byteCount);
    rec.len          = byteCount;
    rec.has_shadow   = usedShadow;
    rec.shadow_va    = shadowVA;
    rec.orig_pte_val = origPteVal;
    rec.shadow_pa    = shadowPA;
    rec.active       = ok;
    g_patches.push_back(rec);
}

// ─────────────────────────────────────────────────────────────────────────────
// /restore <addr>  — undo a safepatch
// ─────────────────────────────────────────────────────────────────────────────
void CmdSafePatchRestore(DWORD64 addr) {
    PatchRecord* rec = FindPatch(addr);
    if (!rec) {
        printf("[!] No patch record for 0x%016llX\n", addr);
        return;
    }

    if (rec->has_shadow) {
        printf("[*] Restoring original PTE (PA=0x%012llX)...\n",
               rec->orig_pte_val & PTE_PA_MASK);
        WritePte(rec->page_start, rec->orig_pte_val);
        FlushTlb(rec->page_start);
        // Re-allow writes to shadow page before freeing
        DWORD old;
        VirtualProtect(rec->shadow_va, 4096, PAGE_EXECUTE_READWRITE, &old);
        FreePatchShadow(*rec);
    } else {
        // Restore bytes via aligned Wr32
        DWORD64 alignedBase = rec->addr & ~3ULL;
        DWORD64 alignedEnd  = (rec->addr + rec->len + 3) & ~3ULL;
        for (DWORD64 waddr = alignedBase; waddr < alignedEnd; waddr += 4) {
            DWORD cur = g_drv->Rd32(waddr);
            DWORD newV = cur;
            DWORD64 lo = (rec->addr > waddr) ? rec->addr - waddr : 0;
            DWORD64 hi = std::min((DWORD64)4, rec->addr + rec->len - waddr);
            for (DWORD64 b = lo; b < hi; b++)
                ((BYTE*)&newV)[b] = rec->orig[(waddr + b) - rec->addr];
            g_drv->Wr32(waddr, newV);
        }
    }

    rec->active = false;
    printf("  %s[+] Restored 0x%016llX%s\n", A_GREEN, addr, A_RESET);
}

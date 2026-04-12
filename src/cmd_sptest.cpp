#include <Windows.h>
#include <cstdio>
#include "driver/IDriverBackend.h"
#include "globals.h"
#include "ansi.h"
#include "kutil.h"
#include "pte.h"

// ─── /sp-test <addr> ──────────────────────────────────────────────────────────
// Diagnose why safepatch BSODs.  Four stages, each independent:
//
//  Stage 0  Check HVCI / VBS status (registry + CPUID)
//  Stage 1  Read PTE at <addr> — pure read, zero write
//  Stage 2  Write the SAME PTE value back (no-op content, but tests write path)
//  Stage 3  Full shadow page swap with canary value 0xAA then immediate restore
//
// Each stage prints PASS / FAIL / SKIP.  If a stage BSODs the system, the
// remaining stages were never printed → you know exactly where the fault is.

// ── Stage 0: VBS / HVCI ───────────────────────────────────────────────────────
static void StageVBS() {
    printf("\n%s[Stage 0]%s  VBS / HVCI detection\n", A_CYAN, A_RESET);

    // Registry: HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard
    HKEY hk = nullptr;
    DWORD vbs = 0, hvci = 0;
    bool gotVbs = false, gotHvci = false;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
            0, KEY_READ, &hk) == ERROR_SUCCESS) {
        DWORD sz = sizeof(DWORD);
        if (RegQueryValueExA(hk, "EnableVirtualizationBasedSecurity",
                             nullptr, nullptr, (LPBYTE)&vbs, &sz) == ERROR_SUCCESS)
            gotVbs = true;
        sz = sizeof(DWORD);
        if (RegQueryValueExA(hk, "HypervisorEnforcedCodeIntegrity",
                             nullptr, nullptr, (LPBYTE)&hvci, &sz) == ERROR_SUCCESS)
            gotHvci = true;
        RegCloseKey(hk);
    }

    // Also check ConfiguredFeatures / RunningFeatures
    DWORD runFeatures = 0;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
            0, KEY_READ, &hk) == ERROR_SUCCESS) {
        DWORD sz = sizeof(DWORD);
        DWORD running = 0;
        if (RegQueryValueExA(hk, "WasEnabledBy", nullptr, nullptr,
                             (LPBYTE)&running, &sz) == ERROR_SUCCESS)
            runFeatures = running;
        RegCloseKey(hk);
    }

    printf("  VBS enabled (registry) : %s\n", gotVbs  ? (vbs  ? "YES" : "no") : "key not found");
    printf("  HVCI enabled (registry): %s\n", gotHvci ? (hvci ? "YES" : "no") : "key not found");

    // Check running HVCI via SystemCodeIntegrityInformation (class 103)
    typedef NTSTATUS(NTAPI* PFN_NtQSI)(ULONG, PVOID, ULONG, PULONG);
    auto NtQSI = (PFN_NtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                            "NtQuerySystemInformation");
    if (NtQSI) {
        struct { ULONG Length; ULONG CodeIntegrityOptions; } ci = { sizeof(ci), 0 };
        if (NtQSI(103, &ci, sizeof(ci), nullptr) == 0) {
            // Bit 0x02 = CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED
            // Bit 0x400 = CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED
            bool hvciRunning = (ci.CodeIntegrityOptions & 0x402) != 0;
            printf("  HVCI running (CI opts 0x%08X): %s\n",
                   ci.CodeIntegrityOptions,
                   hvciRunning ? "%s[!] YES — PTE writes will BSOD%s" : "no");
            if (hvciRunning)
                printf("  %s[!] HVCI active: hypervisor owns page tables, WritePte will fail%s\n",
                       A_RED, A_RESET);
        }
    }
}

// ── Stage 1: Read PTE ─────────────────────────────────────────────────────────
static bool Stage1(DWORD64 addr) {
    printf("\n%s[Stage 1]%s  Read PTE @ 0x%016llX (no write)\n",
           A_CYAN, A_RESET, addr);

    // Large page check — MUST be before ReadPte, because ReadPte on a large
    // page returns garbage (PteVaOf points into PDE region, not PTE region).
    if (IsLargePage(addr)) {
        printf("  %s[SKIP]%s  Target is on a 2MB large page (PDE.PS=1)\n", A_YELLOW, A_RESET);
        printf("           No 4KB PTE exists — safepatch cannot work here.\n");
        printf("           Choose an address on a 4KB page (e.g. a third-party driver).\n");
        return false;
    }

    PteInfo pte = ReadPte(addr);
    if (!pte.valid) {
        printf("  %s[FAIL]%s  MmPteBase unavailable — PTE read failed\n", A_RED, A_RESET);
        return false;
    }
    printf("  PTE VA    : 0x%016llX\n", pte.pte_va);
    printf("  PTE value : 0x%016llX\n", pte.pte_val);
    printf("  Page PA   : 0x%012llX\n", pte.page_pa);
    printf("  Flags     : %s%s%s%s\n",
           pte.present    ? "PRESENT " : "!PRESENT ",
           pte.writable   ? "W " : "R ",
           pte.executable ? "X " : "NX ",
           pte.user       ? "U" : "K");

    if (!pte.present) {
        printf("  %s[FAIL]%s  Page not present\n", A_RED, A_RESET);
        return false;
    }
    printf("  %s[PASS]%s  PTE read OK (4KB page confirmed)\n", A_GREEN, A_RESET);
    return true;
}

// ── Stage 2: No-op PTE write (same value) ────────────────────────────────────
static bool Stage2(DWORD64 addr) {
    printf("\n%s[Stage 2]%s  No-op PTE write (write same value back)\n",
           A_CYAN, A_RESET);
    printf("  If this causes BSOD → PTE page is read-only or HVCI blocks writes\n");

    // Stage 1 already checked large page, but guard again in case Stage2
    // is called independently in the future.
    if (IsLargePage(addr)) {
        printf("  %s[SKIP]%s  Large page — no PTE to write\n", A_YELLOW, A_RESET);
        return false;
    }

    PteInfo pte = ReadPte(addr);
    if (!pte.valid || !pte.present) {
        printf("  %s[SKIP]%s  PTE not valid/present\n", A_YELLOW, A_RESET);
        return false;
    }

    printf("  Writing PTE 0x%016llX back to 0x%016llX ... ",
           pte.pte_val, pte.pte_va);
    fflush(stdout);

    bool ok = WritePte(addr, pte.pte_val);
    DWORD64 readback = g_drv->Rd64(pte.pte_va);

    printf("readback=0x%016llX\n", readback);

    if (readback == pte.pte_val) {
        printf("  %s[PASS]%s  No-op write succeeded — PTE write path works\n",
               A_GREEN, A_RESET);
        return true;
    } else {
        printf("  %s[FAIL]%s  Readback mismatch (expected 0x%016llX got 0x%016llX)\n",
               A_RED, A_RESET, pte.pte_val, readback);
        printf("          Likely: PTE page is read-only (Win10 19041+) or HVCI active\n");
        return false;
    }
}

// ── Stage 3: Shadow page swap with canary ────────────────────────────────────
static void Stage3(DWORD64 addr) {
    printf("\n%s[Stage 3]%s  Shadow page swap — canary 0xAA then immediate restore\n",
           A_CYAN, A_RESET);
    printf("  If this causes BSOD → issue is in shadow physical mapping / TLB\n");

    PteInfo pte = ReadPte(addr);
    if (!pte.valid || !pte.present) {
        printf("  %s[SKIP]%s  PTE not valid/present\n", A_YELLOW, A_RESET);
        return;
    }

    // Check for 2MB large page: read the PDE (= PTE of pte.pte_va).
    // If PDE has PS bit (bit 7) set, there is no 4KB PTE to swap.
    // PteVaOf(pte.pte_va) gives us the PDE VA in the self-map.
    DWORD64 pdeVA  = PteVaOf(pte.pte_va);
    DWORD64 pdeVal = (pdeVA && g_drv->IsKernelVA(pdeVA)) ? g_drv->Rd64(pdeVA) : 0;
    if (pdeVal & (1ULL << 7)) {  // PS=1 → 2MB large page
        printf("  %s[SKIP]%s  Target is in a 2MB large page (PDE PS=1, PDE=0x%016llX)\n",
               A_YELLOW, A_RESET, pdeVal);
        printf("           No 4KB PTE exists — shadow PTE swap cannot work here.\n");
        printf("           For writable data in NonPagedPool, use /wr64 directly.\n");
        return;
    }
    printf("  PDE @ 0x%016llX = 0x%016llX  (4KB page confirmed)\n", pdeVA, pdeVal);

    DWORD64 pageVA     = addr & ~0xFFFULL;
    DWORD64 patchOff   = addr - pageVA;
    DWORD64 origPteVal = pte.pte_val;

    // 1. Read original byte at target
    BYTE origByte = g_drv->Rd8(addr);
    printf("  Original byte @ 0x%016llX = 0x%02X\n", addr, origByte);

    // 2. Allocate shadow page
    LPVOID shadow = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE,
                                 PAGE_EXECUTE_READWRITE);
    if (!shadow) {
        printf("  %s[FAIL]%s  VirtualAlloc failed: %u\n", A_RED, A_RESET, GetLastError());
        return;
    }
    if (!VirtualLock(shadow, 4096)) {
        printf("  %s[FAIL]%s  VirtualLock failed: %u\n", A_RED, A_RESET, GetLastError());
        VirtualFree(shadow, 0, MEM_RELEASE);
        return;
    }

    // 3. Copy kernel page + apply canary
    for (int i = 0; i < 1024; i++) {
        DWORD v = g_drv->Rd32(pageVA + (DWORD64)i * 4);
        memcpy((BYTE*)shadow + i * 4, &v, 4);
    }
    ((BYTE*)shadow)[patchOff] = 0xAA;  // canary

    // 4. Get shadow PA
    PteInfo spte = ReadPte((DWORD64)shadow);
    if (!spte.valid || !spte.present) {
        printf("  %s[FAIL]%s  Cannot read shadow PTE\n", A_RED, A_RESET);
        VirtualUnlock(shadow, 4096);
        VirtualFree(shadow, 0, MEM_RELEASE);
        return;
    }
    printf("  Shadow VA=0x%p  PA=0x%012llX\n", shadow, spte.page_pa);

    // 5. Build new PTE (keep flags, replace PA, clear NX + User)
    //    TLB flush is handled by FlushTlb() (MapPhys+WRITE+UnmapPhys) after
    //    WritePte — no need to clear G bit or wait for context switch.
    DWORD64 newPte = (origPteVal & PTE_FLAG_MASK) | (spte.page_pa & PTE_PA_MASK);
    newPte &= ~PTE_USER;
    newPte &= ~PTE_NX;
    newPte |=  PTE_PRESENT;
    printf("  Swapping PTE: 0x%016llX → 0x%016llX\n", origPteVal, newPte);
    printf("  (about to swap — if BSOD occurs here, shadow PA mapping is bad)\n");
    fflush(stdout);

    WritePte(pageVA, newPte);
    FlushTlb(pageVA);

    // 6. Verify by reading back the PTE — check that the PA now equals shadow PA.
    //    We do NOT use Rd8(addr) here because:
    //      a) TLB on the IOCTL CPU may still cache the old mapping (no cross-CPU INVLPG).
    //      b) If target page is actively executed (e.g. mfehidk), reading shadow bytes
    //         risks AV on another CPU → BSOD.
    //    The PTE readback is authoritative: if the PA field matches our shadow PA,
    //    any future TLB miss (new access / context switch) will land on the shadow page.
    DWORD64 pteAfter = g_drv->Rd64(pte.pte_va);
    DWORD64 paAfter  = pteAfter & PTE_PA_MASK;
    printf("  PTE after swap: 0x%016llX  PA=0x%012llX (expect 0x%012llX)\n",
           pteAfter, paAfter, spte.page_pa);

    // 7. Immediate restore — do this before any other code path can run
    printf("  Restoring original PTE...\n");
    fflush(stdout);
    WritePte(pageVA, origPteVal);
    FlushTlb(pageVA);

    // Verify restore
    DWORD64 pteRestored = g_drv->Rd64(pte.pte_va);
    printf("  PTE restored:   0x%016llX  PA=0x%012llX (expect 0x%012llX)\n",
           pteRestored, pteRestored & PTE_PA_MASK, origPteVal & PTE_PA_MASK);

    DWORD old;
    VirtualProtect(shadow, 4096, PAGE_EXECUTE_READWRITE, &old);
    VirtualUnlock(shadow, 4096);
    VirtualFree(shadow, 0, MEM_RELEASE);

    bool swapOk    = (paAfter == spte.page_pa);
    bool restoreOk = ((pteRestored & PTE_PA_MASK) == (origPteVal & PTE_PA_MASK));

    if (swapOk && restoreOk) {
        printf("  %s[PASS]%s  PTE swap → shadow PA verified; restore → original PA verified\n",
               A_GREEN, A_RESET);
        printf("  Conclusion: safepatch PTE mechanism works (TLB coherency is a deploy-time concern)\n");
    } else {
        if (!swapOk)
            printf("  %s[FAIL]%s  PTE swap: PA after write (0x%012llX) != shadow PA (0x%012llX)\n",
                   A_RED, A_RESET, paAfter, spte.page_pa);
        if (!restoreOk)
            printf("  %s[FAIL]%s  PTE restore: PA after restore (0x%012llX) != original PA (0x%012llX)\n",
                   A_RED, A_RESET, pteRestored & PTE_PA_MASK, origPteVal & PTE_PA_MASK);
        printf("  Likely cause: HVCI silently blocked the PTE write\n");
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────
void CmdSpTest(DWORD64 addr) {
    printf("%s[sp-test]%s  Safepatch diagnostic — target 0x%016llX\n",
           A_CYAN, A_RESET, addr);

    // Reject PTE self-map region — sp-test Stage 3 does PTE swap,
    // which on a page table page would corrupt all mappings → instant BSOD.
    DWORD64 pteBase = GetMmPteBase();
    if (pteBase && addr >= pteBase && addr < pteBase + 0x8000000000ULL) {
        printf("\n  %s[!] ABORT: target 0x%016llX is inside the PTE self-map region%s\n"
               "      (MmPteBase=0x%016llX .. 0x%016llX)\n"
               "      This is a PAGE TABLE page — PTE swap would corrupt all mappings.\n"
               "      This would cause an immediate BSOD.\n",
               A_RED, (unsigned long long)addr, A_RESET,
               (unsigned long long)pteBase,
               (unsigned long long)(pteBase + 0x8000000000ULL - 1));
        return;
    }

    const wchar_t* drvName = nullptr; DWORD64 drvOff = 0;
    KUtil::BuildDriverCache();
    KUtil::FindDriverByAddr(addr, &drvName, &drvOff);
    printf("           Target resolves to: %ls +0x%llX\n\n", drvName, drvOff);

    StageVBS();

    bool pteOk = Stage1(addr);
    if (!pteOk) {
        printf("\n%s[sp-test]%s  Stage 1 failed — skipping stages 2 and 3\n",
               A_YELLOW, A_RESET);
        return;
    }

    bool writeOk = Stage2(addr);
    if (!writeOk) {
        printf("\n%s[sp-test]%s  Stage 2 failed — skipping stage 3\n",
               A_YELLOW, A_RESET);
        return;
    }

    Stage3(addr);

    printf("\n%s[sp-test]%s  Done\n", A_CYAN, A_RESET);
}

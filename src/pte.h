#pragma once
#include <Windows.h>

// x86-64 PTE bit masks
#define PTE_PRESENT  (1ULL << 0)
#define PTE_WRITE    (1ULL << 1)
#define PTE_USER     (1ULL << 2)
#define PTE_ACCESSED (1ULL << 5)
#define PTE_DIRTY    (1ULL << 6)
#define PTE_GLOBAL   (1ULL << 8)
#define PTE_NX       (1ULL << 63)
#define PTE_PA_MASK  (0x000FFFFFFFFFF000ULL)
#define PTE_FLAG_MASK (~PTE_PA_MASK)

// Result of a PTE read
struct PteInfo {
    bool    valid;       // MmPteBase found + kernel VA looks mapped
    DWORD64 pte_va;      // Kernel VA of the PTE entry itself
    DWORD64 pte_val;     // Raw 8-byte PTE value
    DWORD64 page_pa;     // Physical address of the mapped 4KB page
    bool    present;
    bool    writable;
    bool    user;        // U/S bit — should be 0 for kernel code
    bool    executable;  // true when NX bit is 0
};

// Cache-reset: call if you suspect MmPteBase changed (e.g. after reboot)
void PteResetCache();

// Get (cached) value of MmPteBase kernel variable
DWORD64 GetMmPteBase();

// Manually override MmPteBase (e.g. value obtained from WinDbg)
// Skips the scan entirely; persists until PteResetCache() is called.
void SetMmPteBase(DWORD64 val);

// Run the reference-count scan and print all top-N candidates + their runtime values.
// Does NOT update the cache — diagnostic only.
// If methodFilter >= 0, only run that specific method (1-12). -1 = run all.
void CmdPteBaseScan(int methodFilter = -1);

// Kernel VA of the PTE that describes 'va' (works for any VA: user or kernel)
// Returns 0 if MmPteBase unavailable
DWORD64 PteVaOf(DWORD64 va);

// Read and decode the PTE for 'va'
PteInfo ReadPte(DWORD64 va);

// Overwrite the PTE for 'va' with newPteVal (single Wr64 — atomicity on aligned addr)
bool WritePte(DWORD64 va, DWORD64 newPteVal);

// Flush TLB for 'va' via MapPhys + WRITE IOCTL + UnmapPhys.
// Replaces ~PTE_GLOBAL + SwitchToThread() approach.
// Falls back to SwitchToThread() if MapPhys is unavailable.
bool FlushTlb(DWORD64 va);

// Check if 'va' is present in the PTE self-map (P bit = 1).
// Returns false if MmPteBase is unknown, va is 0, or the page is not present.
// Only reads the PTE entry, never dereferences 'va' itself — safe to call on
// any kernel VA without risking BSOD from non-present pages.
bool IsVaMapped(DWORD64 va);

// Validate MmPteBase by reading PTE of ntoskrnl base (must be Present+Executable).
// Returns true if MmPteBase is correct; false if contaminated or wrong.
bool ValidateMmPteBase();

// Check if target VA is on a 2MB large page (PDE.PS=1 → no PTE layer).
// Returns true if large page — caller must NOT use ReadPte/WritePte on it.
bool IsLargePage(DWORD64 va);

// Pre-flight safety check before any PTE write operation.
// Returns true if safe to proceed; prints warnings and returns false if:
//   - MmPteBase validation fails (DKOM contamination)
//   - Target is on a 2MB large page
//   - Target address belongs to a DKOM-hidden driver
bool PteSafetyCheck(DWORD64 targetVA);

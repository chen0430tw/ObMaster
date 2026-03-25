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

// Kernel VA of the PTE that describes 'va' (works for any VA: user or kernel)
// Returns 0 if MmPteBase unavailable
DWORD64 PteVaOf(DWORD64 va);

// Read and decode the PTE for 'va'
PteInfo ReadPte(DWORD64 va);

// Overwrite the PTE for 'va' with newPteVal (single Wr64 — atomicity on aligned addr)
bool WritePte(DWORD64 va, DWORD64 newPteVal);

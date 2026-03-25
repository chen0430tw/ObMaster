#pragma once
#include <Windows.h>
#include <vector>

// Record of a single kernel patch (up to 16 bytes at one address)
struct PatchRecord {
    DWORD64 addr;              // Target kernel VA
    DWORD64 page_start;        // addr & ~0xFFF

    BYTE    orig[16];          // Bytes before patch
    BYTE    patched[16];       // Bytes after patch
    size_t  len;               // Number of bytes patched

    // Shadow page: a user-mode VirtualAlloc page whose physical frame
    // has been mapped over the kernel code page via PTE swap.
    bool    has_shadow;
    LPVOID  shadow_va;         // VirtualAlloc address (user VA)
    DWORD64 orig_pte_val;      // PTE value before we swapped it
    DWORD64 shadow_pa;         // PA of our shadow page

    // Guard watchdog state
    bool    guarded;
    bool    active;            // Patch is currently applied
};

// Global patch list (used by /safepatch, /guard, /restore)
extern std::vector<PatchRecord> g_patches;

// Find a record whose addr or page_start matches
PatchRecord* FindPatch(DWORD64 addr);

// Release the shadow page allocation for a record
void FreePatchShadow(PatchRecord& rec);

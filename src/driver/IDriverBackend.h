#pragma once
#include <Windows.h>

// ─── Abstract kernel memory access interface ──────────────────────────────────
// Implementations: RTCore64Backend (MSI Afterburner, default)
//                  GigabyteBackend (GIBT.sys, future)
//                  ENEBackend      (ENE.sys,   future)
//
// All reads/writes target kernel virtual addresses.
// Max atomic size: 4 bytes. 8-byte ops are split into two 4-byte ops.

class IDriverBackend {
public:
    virtual ~IDriverBackend() = default;

    virtual bool    Open()  = 0;
    virtual void    Close() = 0;
    virtual bool    IsOpen() const = 0;
    virtual const char* Name() const = 0;

    // Primitive R/W — size must be 1, 2, or 4
    virtual DWORD   ReadPrim (DWORD64 addr, DWORD size) = 0;
    virtual void    WritePrim(DWORD64 addr, DWORD size, DWORD value) = 0;

    // ── Convenience wrappers (implemented once here) ──────────────────────────
    BYTE    Rd8 (DWORD64 a)           { return (BYTE )(ReadPrim(a, 1) & 0xFF);   }
    WORD    Rd16(DWORD64 a)           { return (WORD )(ReadPrim(a, 2) & 0xFFFF); }
    DWORD   Rd32(DWORD64 a)           { return ReadPrim(a, 4);                   }
    DWORD64 Rd64(DWORD64 a)           {
        // Guard against a+4 wrapping to ~0 (e.g. a=0xFFFFFFFFFFFFFFFF → a+4=3 → BSOD)
        if (a + 4 < a) return 0;
        return ((DWORD64)Rd32(a+4) << 32) | Rd32(a);
    }

    void    Wr8 (DWORD64 a, BYTE    v) { WritePrim(a, 1, v);                    }
    void    Wr16(DWORD64 a, WORD    v) { WritePrim(a, 2, v);                    }
    void    Wr32(DWORD64 a, DWORD   v) { WritePrim(a, 4, v);                    }
    void    Wr64(DWORD64 a, DWORD64 v) { Wr32(a, (DWORD)(v & 0xFFFFFFFF));
                                         Wr32(a+4, (DWORD)(v >> 32));           }

    // Attempt a true 8-byte atomic write (single aligned QWORD store = CPU-atomic on x86-64).
    // Returns true  → backend issued a genuine 8-byte write (fully atomic).
    // Returns false → backend fell back to hi-then-lo pair (non-atomic but Present=1 throughout).
    // The write is ALWAYS completed by the time this returns; the bool is diagnostic only.
    virtual bool Wr64Atomic(DWORD64 a, DWORD64 v) {
        // Default fallback: write high DWORD first, then low DWORD with Present=1.
        // No Present=0 window, but a brief PA-inconsistency window remains.
        Wr32(a + 4, (DWORD)(v >> 32));
        Wr32(a,     (DWORD)(v & 0xFFFFFFFF));
        return false;
    }

    // Validate canonical kernel VA before reading (avoids driver crash on bad ptr).
    // Upper bound 0xFFFFFE0000000000: excludes PTE space / near-max addresses
    // that would cause RTCore64 to fault (e.g. 0xFFFFFFFFFFFFFFFC + offset wraps).
    bool IsKernelVA(DWORD64 a) {
        return (a >= 0xFFFF800000000000ULL) && (a <= 0xFFFFFE0000000000ULL);
    }

    bool SafeRd64(DWORD64 a, DWORD64& out) {
        if (!IsKernelVA(a)) return false;
        if (a & 7) return false;  // RTCore64 QWORD reads must be 8-byte aligned
        out = Rd64(a);
        return IsKernelVA(out) || out == 0;
    }

    // Physical memory mapping via MmMapIoSpace / MmUnmapIoSpace.
    // Returns a kernel VA that maps 'size' bytes starting at physical 'pa'.
    // Returns 0 on failure.  Call UnmapPhys when done.
    virtual DWORD64 MapPhys  (DWORD64 pa, DWORD size) { (void)pa; (void)size; return 0; }
    virtual void    UnmapPhys(DWORD64 va, DWORD size) { (void)va; (void)size; }

    // Physical memory mapping via \Device\PhysicalMemory (ZwMapViewOfSection).
    // Unlike MapPhys (MmMapIoSpace), this CAN map RAM pages at any PA.
    // Returns a kernel VA, or 0 on failure.  Call UnmapPhysSection when done.
    virtual DWORD64 MapPhysSection  (DWORD64 pa, DWORD size) { (void)pa; (void)size; return 0; }
    virtual void    UnmapPhysSection(DWORD64 va) { (void)va; }
};

// Global backend pointer — set in main before any operation
extern IDriverBackend* g_drv;

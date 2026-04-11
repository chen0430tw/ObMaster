#pragma once
#include <Windows.h>
#include <vector>
#include <string>

// ─── Kernel utility layer ─────────────────────────────────────────────────────
// All process/driver enumeration done via RTCore64 kernel reads.
// This avoids triggering ObRegisterCallbacks which would occur if we used
// user-mode APIs (OpenProcess, NtQuerySystemInformation object paths, etc.)
// against protected/System processes — preventing deadlocks.

namespace KUtil {

// Resolve kernel VA of an ntoskrnl export (variable or function)
DWORD64 KernelExport(const char* name);

// ─── Driver name cache ────────────────────────────────────────────────────────
struct DriverInfo {
    DWORD64 base;
    wchar_t name[64];
    wchar_t path[MAX_PATH];
};

void                        BuildDriverCache();
const std::vector<DriverInfo>& GetDrivers();
// Returns driver owning addr; fills name/offset
DWORD64 FindDriverByAddr(DWORD64 addr, const wchar_t** outName, DWORD64* outOffset = nullptr);

// ─── EPROCESS walker (reads kernel memory directly, no OpenProcess) ───────────
// Win10 22H2 (19045) x64 EPROCESS offsets
// Verified against: dt nt!_EPROCESS (WinDbg 10.0.26100)
// Cross-verified: ppm-engine v0.2.1 (2026-04-11) dkom.py + dataflow.py
//   ksafecenter64.sys uses 0x440/0x448/0x5a8 in IsProtectedPid (confirmed)
static const DWORD EP_UniqueProcessId            = 0x440;
static const DWORD EP_ActiveProcessLinks         = 0x448; // LIST_ENTRY
static const DWORD EP_InheritedFromUniqueProcessId = 0x540; // PPID
static const DWORD EP_Peb                        = 0x550; // PPEB
static const DWORD EP_HandleTable                = 0x570; // PHANDLE_TABLE
static const DWORD EP_ImageFileName              = 0x5a8; // UCHAR[15]
static const DWORD EP_ActiveThreads              = 0x5f0; // ULONG
static const DWORD EP_VadRoot                    = 0x7d8; // RTL_AVL_TREE
static const DWORD EP_Protection                 = 0x87a; // _PS_PROTECTION (1 byte)

struct ProcessEntry {
    DWORD64 eprocess;
    DWORD   pid;
    DWORD   ppid;
    char    name[16];       // ImageFileName (15 chars + null)
    BYTE    protection;     // _PS_PROTECTION byte (0 = none, see ProtectionStr)
    DWORD   activeThreads;
};

std::vector<ProcessEntry> EnumProcesses();

// Find EPROCESS for a given PID (returns 0 if not found)
DWORD64 FindEPROCESS(DWORD pid);

// Decode _PS_PROTECTION byte
const char* ProtectionStr(BYTE prot);

} // namespace KUtil

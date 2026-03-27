// cmd_unload.cpp — /drv-unload <driver_name> <drvobj_va>
//
// Force-unload a NOT_STOPPABLE kernel driver by:
//   1. Patching DriverUnload (DRIVER_OBJECT+0x68) to a safe ret stub
//      (found by scanning ntoskrnl .text for xor eax,eax+ret)
//   2. Calling ControlService(SERVICE_CONTROL_STOP) via SCM
//
// Get <drvobj_va> from WinDbg:  !object \Driver\<name>
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
#include <cstdio>
#include <cstring>
#include <vector>
#include <Psapi.h>

#include "kutil.h"
#include "driver/IDriverBackend.h"
#include "globals.h"

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

void CmdForceUnload(const char* drvName, DWORD64 drvObjVA) {
    printf("[*] /drv-unload  driver=%s  DRIVER_OBJECT=0x%016llX\n\n", drvName, drvObjVA);

    if (!g_drv->IsKernelVA(drvObjVA)) {
        printf("[!] DRIVER_OBJECT address is not a valid kernel VA\n");
        return;
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

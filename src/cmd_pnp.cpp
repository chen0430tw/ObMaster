// cmd_pnp.cpp — /pnp-remove <hwid_or_pattern>
//
// PnP device removal using SetupAPI — equivalent to "devcon remove <hwid>"
// or "pnputil /remove-device <instance_id>".
//
// Used to properly unload drivers with DeviceObjects that block NtUnloadDriver.
// PnP remove sends IRP_MN_REMOVE_DEVICE → driver's PnP handler calls
// IoDeleteDevice → DeviceObject released → MmUnloadSystemImage → file unlocked.
//
// The vendor's own uninstaller (uninst64.exe) uses this exact mechanism:
//   devcon64.exe remove kscsidiskadapter
//
// We replicate it with SetupAPI to avoid needing devcon or WDK.

#include <Windows.h>
#include <SetupAPI.h>
#include <cfgmgr32.h>
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#include <cstdio>
#include <cstring>
#include "ansi.h"

// ── /pnp-remove <hwid_or_pattern> ────────────────────────────────────────────
//
// Enumerates all devices matching <hwid_or_pattern> (case-insensitive substring)
// and calls SetupDiCallClassInstaller(DIF_REMOVE) on each match.
//
// Examples:
//   /pnp-remove kscsidiskadapter       — remove KScsiDisk virtual device
//   /pnp-remove "PCI\VEN_1234"         — remove by PCI vendor ID
//
void CmdPnpRemove(const char* pattern) {
    SetConsoleOutputCP(CP_UTF8);

    printf("[*] /pnp-remove  pattern=\"%s\"\n\n", pattern);

    // Convert pattern to wide string for comparison
    WCHAR wPattern[256]{};
    MultiByteToWideChar(CP_ACP, 0, pattern, -1, wPattern, 255);
    _wcslwr_s(wPattern, 256);

    // Enumerate all devices
    HDEVINFO devs = SetupDiGetClassDevsW(nullptr, nullptr, nullptr,
                                          DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (devs == INVALID_HANDLE_VALUE) {
        printf("%s[!]%s SetupDiGetClassDevs failed: %lu\n", A_RED, A_RESET, GetLastError());
        return;
    }

    SP_DEVINFO_DATA devInfo{};
    devInfo.cbSize = sizeof(devInfo);
    int found = 0, removed = 0;

    for (DWORD idx = 0; SetupDiEnumDeviceInfo(devs, idx, &devInfo); idx++) {
        // Get Hardware ID
        WCHAR hwid[1024]{};
        if (!SetupDiGetDeviceRegistryPropertyW(devs, &devInfo, SPDRP_HARDWAREID,
                                                nullptr, (BYTE*)hwid, sizeof(hwid), nullptr)) {
            continue;
        }

        // Get Instance ID
        WCHAR instanceId[512]{};
        CM_Get_Device_IDW(devInfo.DevInst, instanceId, 512, 0);

        // Get friendly name
        WCHAR friendlyName[256]{};
        SetupDiGetDeviceRegistryPropertyW(devs, &devInfo, SPDRP_FRIENDLYNAME,
                                           nullptr, (BYTE*)friendlyName, sizeof(friendlyName), nullptr);
        if (!friendlyName[0])
            SetupDiGetDeviceRegistryPropertyW(devs, &devInfo, SPDRP_DEVICEDESC,
                                               nullptr, (BYTE*)friendlyName, sizeof(friendlyName), nullptr);

        // Match: check if pattern appears in HWID or Instance ID (case-insensitive)
        WCHAR hwidLower[1024]{}; wcscpy_s(hwidLower, hwid); _wcslwr_s(hwidLower, 1024);
        WCHAR instLower[512]{}; wcscpy_s(instLower, instanceId); _wcslwr_s(instLower, 512);

        bool match = (wcsstr(hwidLower, wPattern) != nullptr) ||
                     (wcsstr(instLower, wPattern) != nullptr);
        if (!match) continue;

        found++;
        wprintf(L"  [%d] %ls\n", found, friendlyName[0] ? friendlyName : L"(no name)");
        wprintf(L"       HWID:     %ls\n", hwid);
        wprintf(L"       Instance: %ls\n", instanceId);

        // Remove the device
        SP_REMOVEDEVICE_PARAMS removeParams{};
        removeParams.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
        removeParams.ClassInstallHeader.InstallFunction = DIF_REMOVE;
        removeParams.Scope = DI_REMOVEDEVICE_GLOBAL;
        removeParams.HwProfile = 0;

        if (!SetupDiSetClassInstallParamsW(devs, &devInfo,
                                            &removeParams.ClassInstallHeader,
                                            sizeof(removeParams))) {
            printf("       %s[!] SetupDiSetClassInstallParams failed: %lu%s\n",
                   A_RED, GetLastError(), A_RESET);
            continue;
        }

        if (SetupDiCallClassInstaller(DIF_REMOVE, devs, &devInfo)) {
            printf("       %s[+] Device removed successfully%s\n", A_GREEN, A_RESET);

            // Check if reboot is needed
            SP_DEVINSTALL_PARAMS_W installParams{};
            installParams.cbSize = sizeof(installParams);
            if (SetupDiGetDeviceInstallParamsW(devs, &devInfo, &installParams)) {
                if (installParams.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART))
                    printf("       %s[*] Reboot required to complete removal%s\n",
                           A_YELLOW, A_RESET);
            }
            removed++;
        } else {
            DWORD err = GetLastError();
            printf("       %s[!] DIF_REMOVE failed: %lu%s\n", A_RED, err, A_RESET);
            if (err == ERROR_ACCESS_DENIED)
                printf("       Run as Administrator or SYSTEM.\n");
        }
    }

    SetupDiDestroyDeviceInfoList(devs);

    if (found == 0)
        printf("  (no devices matching \"%s\")\n", pattern);
    else
        printf("\n  Found: %d  Removed: %d\n", found, removed);

    printf("\n");
}

// ── /pnp-list [pattern] ─────────────────────────────────────────────────────
//
// List PnP devices, optionally filtered by HWID/instance ID substring.
//
void CmdPnpList(const char* pattern) {
    SetConsoleOutputCP(CP_UTF8);

    WCHAR wPattern[256]{};
    if (pattern && pattern[0]) {
        MultiByteToWideChar(CP_ACP, 0, pattern, -1, wPattern, 255);
        _wcslwr_s(wPattern, 256);
        printf("[*] /pnp-list  pattern=\"%s\"\n\n", pattern);
    } else {
        printf("[*] /pnp-list  (all devices)\n\n");
    }

    HDEVINFO devs = SetupDiGetClassDevsW(nullptr, nullptr, nullptr,
                                          DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (devs == INVALID_HANDLE_VALUE) {
        printf("%s[!]%s SetupDiGetClassDevs failed: %lu\n", A_RED, A_RESET, GetLastError());
        return;
    }

    SP_DEVINFO_DATA devInfo{};
    devInfo.cbSize = sizeof(devInfo);
    int count = 0;

    for (DWORD idx = 0; SetupDiEnumDeviceInfo(devs, idx, &devInfo); idx++) {
        WCHAR hwid[1024]{};
        SetupDiGetDeviceRegistryPropertyW(devs, &devInfo, SPDRP_HARDWAREID,
                                           nullptr, (BYTE*)hwid, sizeof(hwid), nullptr);

        WCHAR instanceId[512]{};
        CM_Get_Device_IDW(devInfo.DevInst, instanceId, 512, 0);

        WCHAR friendlyName[256]{};
        SetupDiGetDeviceRegistryPropertyW(devs, &devInfo, SPDRP_FRIENDLYNAME,
                                           nullptr, (BYTE*)friendlyName, sizeof(friendlyName), nullptr);
        if (!friendlyName[0])
            SetupDiGetDeviceRegistryPropertyW(devs, &devInfo, SPDRP_DEVICEDESC,
                                               nullptr, (BYTE*)friendlyName, sizeof(friendlyName), nullptr);

        if (wPattern[0]) {
            WCHAR hwidLower[1024]{}; wcscpy_s(hwidLower, hwid); _wcslwr_s(hwidLower, 1024);
            WCHAR instLower[512]{}; wcscpy_s(instLower, instanceId); _wcslwr_s(instLower, 512);
            if (!wcsstr(hwidLower, wPattern) && !wcsstr(instLower, wPattern))
                continue;
        }

        count++;
        wprintf(L"  [%d] %ls\n", count, friendlyName[0] ? friendlyName : L"(no name)");
        wprintf(L"       %ls\n", instanceId);
    }

    SetupDiDestroyDeviceInfoList(devs);
    printf("\n  Total: %d device(s)\n\n", count);
}

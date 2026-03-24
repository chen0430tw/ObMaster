#include <Windows.h>
#include <cstdio>
#include <string>
#include <vector>

// ─── /services ───────────────────────────────────────────────────────────────

static const char* SvcTypeStr(DWORD t) {
    if (t & SERVICE_KERNEL_DRIVER)       return "KernelDrv";
    if (t & SERVICE_FILE_SYSTEM_DRIVER)  return "FSDrv";
    if (t & SERVICE_WIN32_OWN_PROCESS)   return "Win32Own";
    if (t & SERVICE_WIN32_SHARE_PROCESS) return "Win32Shr";
    return "Other";
}

static const char* SvcStateStr(DWORD s) {
    switch (s) {
        case SERVICE_STOPPED:          return "Stopped";
        case SERVICE_START_PENDING:    return "Starting";
        case SERVICE_STOP_PENDING:     return "Stopping";
        case SERVICE_RUNNING:          return "Running";
        case SERVICE_CONTINUE_PENDING: return "Continuing";
        case SERVICE_PAUSE_PENDING:    return "Pausing";
        case SERVICE_PAUSED:           return "Paused";
        default:                       return "Unknown";
    }
}

static const char* StartTypeStr(DWORD s) {
    switch (s) {
        case SERVICE_BOOT_START:   return "Boot";
        case SERVICE_SYSTEM_START: return "System";
        case SERVICE_AUTO_START:   return "Auto";
        case SERVICE_DEMAND_START: return "Manual";
        case SERVICE_DISABLED:     return "Disabled";
        default:                   return "?";
    }
}

void CmdServices(bool allStates) {
    SetConsoleOutputCP(CP_UTF8);

    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr,
        SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!hScm) { printf("[!] OpenSCManager failed (%lu)\n", GetLastError()); return; }

    DWORD needed = 0, count = 0, resumeHandle = 0;
    // First call to get required buffer size
    EnumServicesStatusExW(hScm, SC_ENUM_PROCESS_INFO,
        SERVICE_DRIVER | SERVICE_WIN32, SERVICE_STATE_ALL,
        nullptr, 0, &needed, &count, &resumeHandle, nullptr);

    std::vector<BYTE> buf(needed);
    resumeHandle = 0;
    if (!EnumServicesStatusExW(hScm, SC_ENUM_PROCESS_INFO,
        SERVICE_DRIVER | SERVICE_WIN32, SERVICE_STATE_ALL,
        buf.data(), needed, &needed, &count, &resumeHandle, nullptr)) {
        printf("[!] EnumServicesStatusEx failed (%lu)\n", GetLastError());
        CloseServiceHandle(hScm);
        return;
    }

    auto* entries = (ENUM_SERVICE_STATUS_PROCESSW*)buf.data();

    printf("\n%-12s %-10s %-9s %-8s %s\n",
        "State", "Type", "Start", "PID", "Name (Display)");
    printf("%s\n", std::string(110, '-').c_str());

    DWORD shown = 0;
    for (DWORD i = 0; i < count; i++) {
        auto& e = entries[i];
        DWORD state = e.ServiceStatusProcess.dwCurrentState;
        if (!allStates && state != SERVICE_RUNNING) continue;

        // Get binary path via QueryServiceConfig
        SC_HANDLE hSvc = OpenServiceW(hScm, e.lpServiceName, SERVICE_QUERY_CONFIG);
        wchar_t binPath[MAX_PATH] = L"";
        if (hSvc) {
            DWORD cfgNeeded = 0;
            QueryServiceConfigW(hSvc, nullptr, 0, &cfgNeeded);
            std::vector<BYTE> cfgBuf(cfgNeeded);
            auto* cfg = (QUERY_SERVICE_CONFIGW*)cfgBuf.data();
            if (QueryServiceConfigW(hSvc, cfg, cfgNeeded, &cfgNeeded))
                wcsncpy_s(binPath, cfg->lpBinaryPathName, MAX_PATH-1);
            CloseServiceHandle(hSvc);
        }

        DWORD type    = e.ServiceStatusProcess.dwServiceType;
        DWORD pid     = e.ServiceStatusProcess.dwProcessId;
        DWORD startT  = 0; // filled above if hSvc succeeded

        wprintf(L"%-12hs %-10hs %-9hs %-8u %ls  [%ls]\n",
            SvcStateStr(state),
            SvcTypeStr(type),
            "",          // start type would need separate query
            pid,
            e.lpServiceName,
            e.lpDisplayName);

        if (binPath[0])
            wprintf(L"             Path: %ls\n", binPath);

        shown++;
    }

    printf("\n  Shown: %u / %u services%s\n\n",
        shown, count, allStates ? "" : " (running only; use /services all to show all)");

    CloseServiceHandle(hScm);
}

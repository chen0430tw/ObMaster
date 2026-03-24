// TestTarget.cpp
// Usage:
//   TestTarget.exe /zombie       - run as a sleeping process (zombie)
//   TestTarget.exe /install      - install as a Windows service
//   TestTarget.exe /uninstall    - remove the service
//   TestTarget.exe               - run as service dispatcher (called by SCM)

#include <Windows.h>
#include <cstdio>

static const wchar_t* SVC_NAME = L"ObMasterTest";
static const wchar_t* SVC_DESC = L"ObMaster Test Service (safe to delete)";

SERVICE_STATUS        g_status{};
SERVICE_STATUS_HANDLE g_hStatus = nullptr;

void SetStatus(DWORD state) {
    g_status.dwCurrentState = state;
    SetServiceStatus(g_hStatus, &g_status);
}

VOID WINAPI SvcCtrlHandler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP) {
        SetStatus(SERVICE_STOP_PENDING);
        SetStatus(SERVICE_STOPPED);
    }
}

VOID WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_hStatus = RegisterServiceCtrlHandlerW(SVC_NAME, SvcCtrlHandler);

    g_status.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwWaitHint                = 3000;
    g_status.dwControlsAccepted        = SERVICE_ACCEPT_STOP;
    SetStatus(SERVICE_RUNNING);

    // Just sleep until stopped
    while (g_status.dwCurrentState == SERVICE_RUNNING)
        Sleep(1000);
}

void Install(const wchar_t* exePath) {
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hScm) { printf("[!] OpenSCManager failed (%lu)\n", GetLastError()); return; }

    SC_HANDLE hSvc = CreateServiceW(hScm, SVC_NAME, SVC_DESC,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        exePath, nullptr, nullptr, nullptr, nullptr, nullptr);

    if (hSvc) {
        printf("[+] Service installed: ObMasterTest\n");
        StartServiceW(hSvc, 0, nullptr);
        printf("[+] Service started\n");
        CloseServiceHandle(hSvc);
    } else {
        printf("[!] CreateService failed (%lu)\n", GetLastError());
    }
    CloseServiceHandle(hScm);
}

void Uninstall() {
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    SC_HANDLE hSvc = OpenServiceW(hScm, SVC_NAME, SERVICE_STOP | DELETE);
    if (hSvc) {
        SERVICE_STATUS ss{};
        ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
        Sleep(500);
        DeleteService(hSvc);
        printf("[+] Service removed\n");
        CloseServiceHandle(hSvc);
    } else {
        printf("[!] Service not found (%lu)\n", GetLastError());
    }
    CloseServiceHandle(hScm);
}

int main(int argc, char* argv[]) {
    if (argc >= 2 && _stricmp(argv[1], "/zombie") == 0) {
        printf("[TestTarget] Running as zombie process (PID=%lu). Press Ctrl+C to exit.\n",
            GetCurrentProcessId());
        Sleep(INFINITE);
        return 0;
    }

    if (argc >= 2 && _stricmp(argv[1], "/install") == 0) {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        Install(path);
        return 0;
    }

    if (argc >= 2 && _stricmp(argv[1], "/uninstall") == 0) {
        Uninstall();
        return 0;
    }

    // Default: service dispatcher
    SERVICE_TABLE_ENTRYW table[] = {
        { (LPWSTR)SVC_NAME, ServiceMain },
        { nullptr, nullptr }
    };
    StartServiceCtrlDispatcherW(table);
    return 0;
}

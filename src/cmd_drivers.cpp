#include <Windows.h>
#include <Psapi.h>
#include <cstdio>
#include <string>
#include "kutil.h"
#include "globals.h"
#include "jutil.h"

// ─── /drivers ────────────────────────────────────────────────────────────────
// Lists all loaded kernel modules with base address and file path.
// Correlates with SCM to show service state where possible.

static SC_HANDLE s_scm = nullptr;

static const char* SvcState(const wchar_t* driverName) {
    if (!s_scm) s_scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!s_scm) return "";

    // Strip .sys extension for service name lookup
    wchar_t svcName[64] = {};
    wcsncpy_s(svcName, driverName, 63);
    wchar_t* dot = wcsrchr(svcName, L'.');
    if (dot) *dot = 0;

    SC_HANDLE hSvc = OpenServiceW(s_scm, svcName, SERVICE_QUERY_STATUS);
    if (!hSvc) return "";

    SERVICE_STATUS ss{};
    QueryServiceStatus(hSvc, &ss);
    CloseServiceHandle(hSvc);

    switch (ss.dwCurrentState) {
        case SERVICE_RUNNING:      return "Running";
        case SERVICE_STOPPED:      return "Stopped";
        case SERVICE_START_PENDING:return "Starting";
        case SERVICE_STOP_PENDING: return "Stopping";
        default:                   return "Unknown";
    }
}

void CmdDrivers() {
    SetConsoleOutputCP(CP_UTF8);
    KUtil::BuildDriverCache();
    const auto& drivers = KUtil::GetDrivers();

    if (g_jsonMode) {
        printf("{\"command\":\"drivers\",\"drivers\":[\n");
        bool first = true;
        for (auto& d : drivers) {
            const char* state = SvcState(d.name);
            if (!first) printf(",\n");
            first = false;
            printf(" {\"base\":%s,\"name\":%s,\"scm_state\":%s,\"path\":%s}",
                JAddr(d.base).c_str(),
                JEscape(d.name).c_str(),
                JEscape(state).c_str(),
                JEscape(d.path).c_str());
        }
        printf("\n]}\n");
        if (s_scm) { CloseServiceHandle(s_scm); s_scm = nullptr; }
        return;
    }

    printf("\n%-18s %-30s %-10s %s\n", "Base", "Name", "SCM State", "Path");
    printf("%s\n", std::string(120, '-').c_str());

    for (auto& d : drivers) {
        const char* state = SvcState(d.name);
        wprintf(L"%-18p %-30ls %-10hs %ls\n",
            (void*)d.base, d.name, state, d.path);
    }
    printf("\n  Total: %zu kernel modules\n\n", drivers.size());

    if (s_scm) { CloseServiceHandle(s_scm); s_scm = nullptr; }
}

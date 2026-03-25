#include <Windows.h>
#include <cstdio>
#include <cstring>
#include "driver/IDriverBackend.h"
#include "driver/RTCore64Backend.h"
#include "commands.h"
#include "globals.h"
#include "ansi.h"

// Global backend instance
IDriverBackend* g_drv = nullptr;

// Global flags (declared extern in globals.h)
bool g_jsonMode     = false;
bool g_quiet        = false;
bool g_ansiEnabled  = false;
bool g_debug        = false;

static void Banner() {
    printf(
        "\n"
        " ██████╗ ██████╗ ███╗   ███╗ █████╗ ███████╗████████╗███████╗██████╗\n"
        "██╔═══██╗██╔══██╗████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗\n"
        "██║   ██║██████╔╝██╔████╔██║███████║███████╗   ██║   █████╗  ██████╔╝\n"
        "██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║╚════██║   ██║   ██╔══╝  ██╔══██╗\n"
        "╚██████╔╝██████╔╝██║ ╚═╝ ██║██║  ██║███████║   ██║   ███████╗██║  ██║\n"
        " ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝\n"
        "  BYOVD-powered kernel toolkit -- see what System Informer can't\n\n"
    );
}

static void Usage(const char* prog) {
    printf(
        "Usage: %s [/json] [/quiet] <command> [args]\n\n"
        "  Global flags (can appear anywhere, /flag -flag --flag all accepted):\n"
        "    /json  --json         Machine-readable JSON output (for agents/scripts)\n"
        "    /quiet --quiet        Suppress banner\n"
        "    /debug --debug        Verbose diagnostics (export scan, slot reads)\n\n"
        "  Process:\n"
        "    /proc                 List all processes (kernel walk, no ObCallback)\n"
        "    /kill <pid>           Terminate process (PPL bypass via EPROCESS.Protection)\n\n"
        "  System:\n"
        "    /drivers              List loaded kernel modules\n"
        "    /services [all]       List services (default: running only)\n"
        "    /net                  TCP/UDP connections with process names\n\n"
        "  Privilege escalation:\n"
        "    /runas system <cmd>   Run <cmd> as SYSTEM (token duplication)\n"
        "    /runas ti     <cmd>   Run <cmd> as TrustedInstaller\n\n"
        "  ObCallbacks:\n"
        "    /obcb [process|thread] Enumerate ObRegisterCallbacks\n"
        "    /disable <PreOp_addr>  Disable callback (zero PreOp/PostOp, Enabled=0)\n"
        "    /enable  <PreOp_addr>  Set Enabled=1 on matching entry\n\n"
        "  NotifyRoutines:\n"
        "    /notify [image|process|thread]  Enumerate Ps*NotifyRoutine arrays\n"
        "    /ndisable <fn_addr>             Zero EX_CALLBACK slot for matching entry\n\n"
        "  File handles:\n"
        "    /handles [drive]               Enumerate open file handles system-wide (e.g. /handles E)\n\n"
        "  Minifilters:\n"
        "    /flt [drive]                   Enumerate minifilter instances via kernel walk\n"
        "    /flt-detach <filter> <drive>   Force-detach mandatory minifilter (zeros teardown callback)\n"
        "    /unmount <drive>               Force dismount + eject (like /kill for drives)\n\n"
        "  Deep scan:\n"
        "    /memscan <pid> [all]           Compare DLL sections vs on-disk (default: skip .rdata/.data noise)\n"
        "    /memrestore <pid> <dll> [sec]  Restore sections from disk (default: skip noisy sections)\n"
        "    /watchfix <proc> <dll> [sec]   Poll for new instances of <proc>, auto-restore on each launch\n\n"
        "  Per-command help:\n"
        "    %s /<command> ?\n\n"
        "Note: Requires RTCore64.sys running. Install via: sc create RTCore64 ...\n",
        prog, prog
    );
}

// Per-command help strings
static bool TryCommandHelp(const char* cmd) {
    if (_stricmp(cmd, "proc") == 0) {
        printf(
            "/proc — enumerate all processes via EPROCESS kernel walk\n\n"
            "  No OpenProcess calls are made, so ObRegisterCallbacks are never\n"
            "  triggered. Falls back to EPROCESS.ImageFileName (15 chars) when\n"
            "  OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) is denied.\n\n"
            "  Output columns: PID  PPID  Threads  Protection  Name  Integrity  Path\n\n"
            "  Flags: /json  -> JSON array of process objects\n"
        );
        return true;
    }
    if (_stricmp(cmd, "kill") == 0) {
        printf(
            "/kill <pid> — terminate a process, with optional PPL bypass\n\n"
            "  Strategy:\n"
            "    1. Try TerminateProcess normally.\n"
            "    2. On access denied: read EPROCESS, clear Protection byte (PPL\n"
            "       bypass via kernel write), retry, restore on failure.\n\n"
            "  Warning: /kill 4 and /kill 0 are refused (would BSOD).\n"
        );
        return true;
    }
    if (_stricmp(cmd, "drivers") == 0) {
        printf(
            "/drivers — list all loaded kernel modules\n\n"
            "  Reads the driver list via EnumDeviceDrivers (PSAPI).\n"
            "  Correlates with SCM to show running/stopped state.\n\n"
            "  Output columns: Base  Name  SCM_State  Path\n\n"
            "  Flags: /json  -> JSON array of driver objects\n"
        );
        return true;
    }
    if (_stricmp(cmd, "services") == 0) {
        printf(
            "/services [all] — list Windows services\n\n"
            "  Default: running services only.\n"
            "  'all': include stopped/disabled services.\n\n"
            "  Output columns: State  Type  Start  PID  Name  [DisplayName]\n"
            "                  Path: <binary path>\n\n"
            "  Flags: /json  -> JSON array of service objects\n"
        );
        return true;
    }
    if (_stricmp(cmd, "net") == 0) {
        printf(
            "/net — list TCP/UDP connections with owning process\n\n"
            "  Uses GetExtendedTcpTable / GetExtendedUdpTable (no kernel reads).\n"
            "  Covers: TCP4, TCP6, UDP4, UDP6.\n\n"
            "  Output columns: Proto  State  Local  Remote  PID / Process\n\n"
            "  Flags: /json  -> JSON array of connection objects\n"
        );
        return true;
    }
    if (_stricmp(cmd, "obcb") == 0) {
        printf(
            "/obcb [process|thread] — enumerate ObRegisterCallbacks\n\n"
            "  Scans PsProcessType and PsThreadType CallbackList chains in the\n"
            "  kernel, reading OB_CALLBACK_ENTRY structures directly.\n\n"
            "  Arguments:\n"
            "    (none)    both Process and Thread callbacks\n"
            "    process   Process callbacks only\n"
            "    thread    Thread callbacks only\n\n"
            "  To disable a callback: /disable <PreOp_hex_addr>\n"
            "  To re-enable:          /enable  <PreOp_hex_addr>\n\n"
            "  Flags: /json  -> JSON array of callback entries\n"
        );
        return true;
    }
    if (_stricmp(cmd, "disable") == 0) {
        printf(
            "/disable <PreOp_addr> — disable an ObCallback entry\n\n"
            "  Sets Enabled=0 and zeros PreOperation + PostOperation pointers.\n"
            "  Address is the PreOp value shown by /obcb (hex, e.g. fffff80012345678).\n"
        );
        return true;
    }
    if (_stricmp(cmd, "runas") == 0) {
        printf(
            "/runas <level> <cmdline> — run a program at elevated privilege\n\n"
            "  Levels:\n"
            "    system   SYSTEM account (via winlogon.exe token duplication)\n"
            "    ti       TrustedInstaller (higher than SYSTEM; can modify system files)\n\n"
            "  Technique: SeDebugPrivilege -> OpenProcess -> OpenProcessToken\n"
            "             -> DuplicateTokenEx -> CreateProcessWithTokenW\n\n"
            "  Examples:\n"
            "    /runas system cmd.exe\n"
            "    /runas ti \"C:\\Windows\\regedit.exe\"\n"
        );
        return true;
    }
    if (_stricmp(cmd, "enable") == 0) {
        printf(
            "/enable <PreOp_addr> — set Enabled=1 on an ObCallback entry\n\n"
            "  Finds the entry by its original PreOp address and sets Enabled=1.\n"
            "  Note: does not restore zeroed function pointers — use before disabling.\n"
        );
        return true;
    }
    if (_stricmp(cmd, "handles") == 0) {
        printf(
            "/handles [drive] — enumerate all open file handles system-wide\n\n"
            "  Technique:\n"
            "    1. NtQuerySystemInformation(SystemHandleInformation) — full handle table\n"
            "    2. Probe own process to identify File object type index\n"
            "    3. For each foreign File handle: DuplicateHandle + GetFinalPathNameByHandle\n"
            "    4. Filter by NT device path (QueryDosDevice resolves drive -> \\Device\\HarddiskVolumeN)\n\n"
            "  Arguments:\n"
            "    (none)   list all open file handles across all processes\n"
            "    drive    filter to a specific volume, e.g. /handles E or /handles E:\n\n"
            "  Output columns: PID  Process  Path\n\n"
            "  Flags: /json  -> JSON array of handle objects\n"
        );
        return true;
    }
    return false;
}

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, nullptr, _IONBF, 0);  // unbuffered stdout (needed for /watchfix piped output)

    // ── Pre-scan global flags (can appear anywhere in argv) ───────────────────
    // Accepts /flag  -flag  --flag  (--flag is not mangled by MSYS/Git Bash)
    auto stripDashes = [](const char* a) -> const char* {
        if (a[0]=='/' || a[0]=='-') { a++; if (a[0]=='-') a++; }
        // MSYS/Git Bash expands /notify -> /C:/Program Files/Git/notify
        // After stripping the leading slash we get a path; take the last component.
        const char* slash = strrchr(a, '/');
        if (!slash) slash = strrchr(a, '\\');
        if (slash) a = slash + 1;
        return a;
    };
    for (int i = 1; i < argc; i++) {
        const char* f = stripDashes(argv[i]);
        if (_stricmp(f, "json")  == 0) g_jsonMode = true;
        if (_stricmp(f, "quiet") == 0) g_quiet    = true;
        if (_stricmp(f, "debug") == 0) g_debug    = true;
    }

    if (!g_jsonMode) AnsiInit();
    if (!g_quiet) Banner();

    // ── Find command: first arg that isn't a global flag ─────────────────────
    const char* cmd = nullptr;
    int         cmdIdx = -1;  // argv index of cmd
    for (int i = 1; i < argc; i++) {
        const char* f = stripDashes(argv[i]);
        if (_stricmp(f, "json")  == 0) continue;
        if (_stricmp(f, "quiet") == 0) continue;
        if (_stricmp(f, "debug") == 0) continue;
        cmd    = f;
        cmdIdx = i;
        break;
    }

    if (!cmd) { Usage(argv[0]); return 1; }

    // ── Commands that don't need driver ───────────────────────────────────────
    if (_stricmp(cmd, "help") == 0 || _stricmp(cmd, "?") == 0 || _stricmp(cmd, "h") == 0) {
        Usage(argv[0]); return 0;
    }

    // ── Per-command help: ObMaster /proc ? ────────────────────────────────────
    for (int i = cmdIdx + 1; i < argc; i++) {
        if (strcmp(argv[i], "?") == 0) {
            if (!TryCommandHelp(cmd)) Usage(argv[0]);
            return 0;
        }
    }

    // ── Open driver ───────────────────────────────────────────────────────────
    RTCore64Backend rtcore;
    g_drv = &rtcore;

    if (!g_drv->Open()) {
        if (g_jsonMode)
            printf("{\"error\":\"Cannot open %s (err %lu)\"}\n", g_drv->Name(), GetLastError());
        else {
            printf("%s[!]%s Cannot open %s (error %lu)\n", A_RED, A_RESET, g_drv->Name(), GetLastError());
            printf("%s[!]%s Run: sc start RTCore64\n\n", A_RED, A_RESET);
        }
        return 1;
    }
    if (!g_jsonMode && !g_quiet)
        printf("%s[+]%s Backend: %s\n\n", A_GREEN, A_RESET, g_drv->Name());

    // Helper: get next non-flag arg after cmd
    auto nextArg = [&](int skip = 0) -> const char* {
        int found = 0;
        for (int i = cmdIdx + 1; i < argc; i++) {
            const char* a = argv[i];
            if (strcmp(a, "?") == 0) continue;
            const char* f = stripDashes(a);
            if (_stricmp(f,"json")==0 || _stricmp(f,"quiet")==0) continue;
            if (found++ == skip) return a;
        }
        return nullptr;
    };

    // ── Dispatch ──────────────────────────────────────────────────────────────
    if (_stricmp(cmd, "proc") == 0) {
        CmdProc();
    }
    else if (_stricmp(cmd, "kill") == 0) {
        const char* pidStr = nextArg();
        if (!pidStr) { printf("[!] /kill requires a PID\n"); g_drv->Close(); return 1; }
        DWORD pid = (DWORD)strtoul(pidStr, nullptr, 10);
        CmdKill(pid);
    }
    else if (_stricmp(cmd, "drivers") == 0) {
        CmdDrivers();
    }
    else if (_stricmp(cmd, "services") == 0) {
        const char* a = nextArg();
        bool all = (a && _stricmp(a, "all") == 0);
        CmdServices(all);
    }
    else if (_stricmp(cmd, "net") == 0) {
        CmdNet();
    }
    else if (_stricmp(cmd, "obcb") == 0) {
        bool proc = true, thr = true;
        const char* a = nextArg();
        if (a && _stricmp(a, "process") == 0) thr  = false;
        if (a && _stricmp(a, "thread")  == 0) proc = false;
        CmdObcb(proc, thr);
    }
    else if (_stricmp(cmd, "disable") == 0) {
        const char* addrStr = nextArg();
        if (!addrStr) { printf("[!] /disable requires an address\n"); g_drv->Close(); return 1; }
        unsigned long long addr = strtoull(addrStr, nullptr, 16);
        CmdDisable(addr);
    }
    else if (_stricmp(cmd, "runas") == 0) {
        const char* lvl = nextArg(0);
        const char* cli = nextArg(1);
        if (!lvl || !cli) {
            printf("%s[!]%s Usage: /runas <system|ti> <cmdline>\n", A_RED, A_RESET);
            g_drv->Close(); return 1;
        }
        CmdRunAs(lvl, cli);
    }
    else if (_stricmp(cmd, "epdump") == 0) {
        const char* pidStr = nextArg();
        if (!pidStr) { printf("[!] /epdump requires a PID\n"); g_drv->Close(); return 1; }
        DWORD pid = (DWORD)strtoul(pidStr, nullptr, 10);
        CmdEpDump(pid);
    }
    else if (_stricmp(cmd, "enable") == 0) {
        const char* addrStr = nextArg();
        if (!addrStr) { printf("[!] /enable requires an address\n"); g_drv->Close(); return 1; }
        unsigned long long addr = strtoull(addrStr, nullptr, 16);
        CmdEnable(addr);
    }
    else if (_stricmp(cmd, "notify") == 0) {
        const char* a = nextArg();
        bool img = true, proc = true, thr = true;
        if (a && _stricmp(a, "image")   == 0) { proc = false; thr = false; }
        if (a && _stricmp(a, "process") == 0) { img  = false; thr = false; }
        if (a && _stricmp(a, "thread")  == 0) { img  = false; proc = false; }
        CmdNotify(img, proc, thr);
    }
    else if (_stricmp(cmd, "ndisable") == 0) {
        const char* addrStr = nextArg();
        if (!addrStr) { printf("[!] /ndisable requires an address\n"); g_drv->Close(); return 1; }
        unsigned long long addr = strtoull(addrStr, nullptr, 16);
        CmdNotifyDisable(addr);
    }
    else if (_stricmp(cmd, "memscan") == 0) {
        const char* pidStr = nextArg(0);
        const char* a1     = nextArg(1);
        if (!pidStr) { printf("[!] /memscan requires a PID\n"); g_drv->Close(); return 1; }
        DWORD pid = (DWORD)strtoul(pidStr, nullptr, 10);
        bool all = (a1 && _stricmp(a1, "all") == 0);
        CmdMemScan(pid, all);
    }
    else if (_stricmp(cmd, "memrestore") == 0) {
        const char* pidStr  = nextArg(0);
        const char* dll     = nextArg(1);
        const char* section = nextArg(2);
        if (!pidStr || !dll) {
            printf("[!] /memrestore requires <pid> <dll> [section]\n"); g_drv->Close(); return 1;
        }
        DWORD pid = (DWORD)strtoul(pidStr, nullptr, 10);
        CmdMemRestore(pid, dll, section);
    }
    else if (_stricmp(cmd, "watchfix") == 0) {
        const char* proc = nextArg(0);
        if (!proc) {
            printf("[!] /watchfix requires <process.exe> <dll>[:<section>] ...\n");
            g_drv->Close(); return 1;
        }
        // Collect remaining args as dll[:section] targets
        std::vector<WatchTarget> targets;
        for (int skip = 1; ; skip++) {
            const char* a = nextArg(skip);
            if (!a) break;
            WatchTarget t;
            const char* colon = strchr(a, ':');
            if (colon) {
                t.dll     = std::string(a, colon);
                t.section = std::string(colon + 1);
            } else {
                t.dll     = a;
            }
            targets.push_back(std::move(t));
        }
        if (targets.empty()) {
            printf("[!] /watchfix requires at least one <dll>[:<section>] target\n");
            g_drv->Close(); return 1;
        }
        CmdWatchFix(proc, targets);
    }
    else if (_stricmp(cmd, "handles") == 0) {
        const char* filter = nextArg();
        CmdHandles(filter);
    }
    else if (_stricmp(cmd, "flt") == 0) {
        const char* vol = nextArg();
        CmdFlt(vol);
    }
    else if (_stricmp(cmd, "flt-detach") == 0) {
        const char* flt = nextArg(0);
        const char* vol = nextArg(1);
        CmdFltDetach(flt, vol);
    }
    else if (_stricmp(cmd, "unmount") == 0) {
        const char* vol = nextArg();
        if (!vol) { printf("[!] /unmount requires a drive letter\n"); g_drv->Close(); return 1; }
        CmdUnmount(vol[0]);
    }
    else {
        if (g_jsonMode)
            printf("{\"error\":\"Unknown command: %s\"}\n", cmd);
        else {
            printf("[!] Unknown command: /%s\n\n", cmd);
            Usage(argv[0]);
        }
        g_drv->Close();
        return 1;
    }

    g_drv->Close();
    return 0;
}

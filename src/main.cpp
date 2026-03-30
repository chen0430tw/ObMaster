#define NOMINMAX
#include <Windows.h>
#include <cstdio>
#include <cstring>
#include "kutil.h"
#include "driver/IDriverBackend.h"
#include "driver/RTCore64Backend.h"
#include "commands.h"
#include "globals.h"
#include "ansi.h"
#include "pte.h"

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
        "    /patch <addr> <hex>         Write raw bytes (legacy, unsafe — byte-by-byte)\n"
        "    /safepatch <addr> <hex>     Safe patch via shadow-page PTE swap\n"
        "    /restore <addr>             Undo a safepatch (restore original PTE)\n"
        "    /pte <addr> [--set-write] [--clear-nx] [--restore <val>]\n"
        "                               Walk all 4 page-table levels; modify leaf PTE flags\n"
        "    /rd64 <addr> [count]        Read 1-256 QWORDs from a kernel VA\n"
        "    /wr64 <addr> <value>        Write a QWORD to a kernel VA (atomic if driver supports)\n"
        "    /ptebase                    Diagnostic scan — find MmPteBase candidates in ntoskrnl\n"
        "    /ptebase-set <value>        Manually set MmPteBase (use WinDbg to obtain value)\n\n"
        "  Timing:\n"
        "    /timedelta <pid> [ms]       Measure transient System handles to <pid>\n\n"
        "  Guard watchdog:\n"
        "    /guard-add <addr>           Watch safepatch at <addr>, re-apply if reverted\n"
        "    /guard-start [interval_ms]  Start background watchdog (default 500ms)\n"
        "    /guard-stop                 Stop watchdog\n"
        "    /guard-list                 List guarded patches\n"
        "    /enable  <PreOp_addr>  Set Enabled=1 on matching entry\n\n"
        "  NotifyRoutines:\n"
        "    /notify [image|process|thread]  Enumerate Ps*NotifyRoutine arrays\n"
        "    /ndisable <fn_addr>             Zero EX_CALLBACK slot for matching entry\n\n"
        "  File handles:\n"
        "    /handles [drive]               Enumerate open file handles system-wide (e.g. /handles E)\n"
        "    /handle-close <pid> <handle>   Close a handle in any process\n"
        "                                   pid=4: kernel HANDLE_TABLE walk (WdFilter/ksafecenter64)\n"
        "                                   others: DuplicateHandle CLOSE_SOURCE\n"
        "    /handle-scan  <pid> [--access <mask>] [--target-pid <pid>] [--close]\n"
        "                                   Walk pid's kernel HANDLE_TABLE; list/close entries\n"
        "                                   matching access mask (default: 0x1fffff PROCESS_ALL_ACCESS)\n"
        "                                   --target-pid: only entries pointing to that PID's EPROCESS\n\n"
        "  Minifilters:\n"
        "    /flt [drive]                   Enumerate minifilter instances via kernel walk\n"
        "    /flt-detach <filter> <drive>   Force-detach mandatory minifilter (zeros teardown callback)\n"
        "    /unmount <drive>               Force dismount + eject (like /kill for drives)\n"
        "    /drv-unload <name> <va>        Force-unload NOT_STOPPABLE driver (patch DriverUnload + sc stop)\n"
        "                                   Get <va> from WinDbg: !object \\Driver\\<name>\n"
        "    /force-stop <name>             Stop driver via NtUnloadDriver, bypasses SCM error 1052\n"
        "                                   No VA needed; if DriverUnload is NULL use /drv-unload instead\n"
        "    /drv-zombie <drvobj_va>        Diagnose STOP_PENDING zombie: dump OBJECT_HEADER PointerCount,\n"
        "                                   DeviceObject chain, refcount breakdown, and unblock advice\n"
        "    /elevate-pid <pid>             Kernel token steal: write winlogon SYSTEM token into target pid\n"
        "                                   Bypasses UAC entirely — use when consent.exe is stuck\n"
        "    /elevate-self [cmd]            fodhelper UAC bypass: load RTCore64 elevated, no consent dialog\n"
        "                                   Works as standard user even with Explorer deadlocked\n\n"
        "  Deep scan:\n"
        "    /memscan <pid> [all]           Compare DLL sections vs on-disk (default: skip .rdata/.data noise)\n"
        "    /memrestore <pid> <dll> [sec]  Restore sections from disk (default: skip noisy sections)\n"
        "    /watchfix <proc> <dll> [sec]   Poll for new instances of <proc>, auto-restore on each launch\n\n"
        "  Object namespace:\n"
        "    /objdir [path]                 Enumerate object directory; show kernel addresses\n"
        "                                   Default path: \\  (root)\n\n"
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
    if (_stricmp(cmd, "pte") == 0) {
        printf(
            "/pte <addr> [--set-write] — walk all 4 page-table levels for a VA\n\n"
            "  Resolves MmPteBase, then uses the PTE self-map to compute the kernel VA\n"
            "  of each page-table entry (PML4E → PDPTE → PDE → PTE) and reads each one\n"
            "  via RTCore64.  Decodes P/W/U/NX/G/A/D/PS flags and prints physical address.\n\n"
            "  Handles large pages: PS=1 on PDPTE (1 GB) and PDE (2 MB).\n\n"
            "  Flags (applied to the leaf entry — PTE for 4KB, PDE/PDPTE for large pages):\n"
            "  --set-write          Set the W (writable) bit.\n"
            "                       Useful before /patch to make a read-only page writable.\n"
            "  --clear-nx           Clear the NX bit (make page executable).\n"
            "  --restore <val>      Write an exact raw value back (undo a previous change).\n"
            "                       <val> is the original raw PTE value shown by a prior walk.\n\n"
            "  Flags can be combined: --set-write --clear-nx applies both.\n"
            "  --restore overrides --set-write and --clear-nx if all three are given.\n\n"
            "  A verify read-back is always printed after any write.\n\n"
            "  Examples:\n"
            "    /pte FFFFF8086A4114DB\n"
            "    /pte FFFFF8086A4114DB --set-write\n"
            "    /pte FFFFF8086A4114DB --clear-nx\n"
            "    /pte FFFFF8086A4114DB --set-write --clear-nx\n"
            "    /pte FFFFF8086A4114DB --restore 8A0000019C601025\n\n"
            "  Requires MmPteBase.  If unavailable, run /ptebase or /ptebase-set first.\n"
        );
        return true;
    }
    if (_stricmp(cmd, "rd64") == 0) {
        printf(
            "/rd64 <addr> [count] — read 1-256 QWORDs from a kernel virtual address\n\n"
            "  Reads raw 64-bit values from arbitrary kernel VAs via RTCore64.\n"
            "  Useful for inspecting kernel variables, PTE entries, EPROCESS fields, etc.\n\n"
            "  Arguments:\n"
            "    addr    kernel VA in hex (e.g. fffff8086a000000)\n"
            "    count   number of consecutive QWORDs to read (default 1, max 256)\n\n"
            "  Output: one line per QWORD:  0x<addr>  =  0x<value>\n\n"
            "  See also: /wr64 (write), /pte (decode page-table entry)\n"
        );
        return true;
    }
    if (_stricmp(cmd, "wr64") == 0) {
        printf(
            "/wr64 <addr> <value> — write a QWORD to a kernel virtual address\n\n"
            "  Writes a 64-bit value to an arbitrary kernel VA via RTCore64.\n"
            "  Attempts a single atomic 8-byte write (Wr64Atomic); falls back to\n"
            "  hi-then-lo pair if the driver rejects Size=8.\n\n"
            "  Arguments:\n"
            "    addr    kernel VA in hex\n"
            "    value   64-bit value in hex\n\n"
            "  WARNING: Writing to arbitrary kernel addresses can cause an instant BSOD.\n"
            "           Use /safepatch for code patches (PTE shadow-page method).\n"
        );
        return true;
    }
    if (_stricmp(cmd, "ptebase") == 0) {
        printf(
            "/ptebase — diagnostic scan for MmPteBase in ntoskrnl\n\n"
            "  Scans ntoskrnl.exe .text for MOV r64,[RIP+imm32] instructions that\n"
            "  reference the .data section (including BSS), counts references per target,\n"
            "  and prints the top 32 candidates with their current runtime values.\n\n"
            "  Candidates are validated: must be a kernel VA (0xFFFF...) and page-aligned.\n"
            "  The winning candidate (first valid one) is automatically cached as MmPteBase.\n\n"
            "  Use this when /safepatch or /pte reports 'MmPteBase unavailable'.\n"
            "  If no candidate passes validation, use WinDbg + /ptebase-set to inject\n"
            "  the value manually.\n"
        );
        return true;
    }
    if (_stricmp(cmd, "ptebase-set") == 0) {
        printf(
            "/ptebase-set <value> — manually override the cached MmPteBase value\n\n"
            "  Skips the auto-scan entirely and sets MmPteBase to the given value.\n"
            "  Persists until the process exits or /ptebase-set is called again.\n\n"
            "  Arguments:\n"
            "    value   MmPteBase address in hex (obtain from WinDbg: dq MmPteBase)\n\n"
            "  Example:\n"
            "    ObMaster /ptebase-set FFFFCE8000000000\n"
            "    ObMaster /pte FFFFF8086A4114DB\n"
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

    // /runas uses pure Win32 token duplication — no driver needed
    if (_stricmp(cmd, "runas") == 0) {
        // find first two non-flag args after cmd
        int found = 0; const char* ra[2]{};
        for (int i = cmdIdx + 1; i < argc && found < 2; i++) {
            const char* f = stripDashes(argv[i]);
            if (_stricmp(f,"json")==0||_stricmp(f,"quiet")==0||_stricmp(f,"debug")==0) continue;
            ra[found++] = argv[i];
        }
        if (found < 2) {
            printf("[!] Usage: /runas system|ti <cmdline>\n");
            return 1;
        }
        CmdRunAs(ra[0], ra[1]);
        return 0;
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
        // /elevate-self does not need the driver — allow it through
        if (cmd && _stricmp(cmd, "elevate-self") == 0) {
            CmdElevateSelf("");
            return 0;
        }
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
    else if (_stricmp(cmd, "patch") == 0) {
        const char* addrStr  = nextArg(0);
        const char* hexBytes = nextArg(1);
        if (!addrStr || !hexBytes) {
            printf("[!] Usage: /patch <hex_addr> <hexbytes>  e.g. /patch FFFFF80127ED31B4 33C0C390\n");
            g_drv->Close(); return 1;
        }
        unsigned long long addr = strtoull(addrStr, nullptr, 16);
        CmdPatch(addr, hexBytes);
    }
    else if (_stricmp(cmd, "safepatch") == 0) {
        const char* addrStr  = nextArg(0);
        const char* hexBytes = nextArg(1);
        if (!addrStr || !hexBytes) {
            printf("[!] Usage: /safepatch <hex_addr> <hexbytes>\n");
            g_drv->Close(); return 1;
        }
        KUtil::BuildDriverCache();
        CmdSafePatch(strtoull(addrStr, nullptr, 16), hexBytes);
    }
    else if (_stricmp(cmd, "restore") == 0) {
        const char* addrStr = nextArg();
        if (!addrStr) { printf("[!] /restore requires an address\n"); g_drv->Close(); return 1; }
        CmdSafePatchRestore(strtoull(addrStr, nullptr, 16));
    }
    else if (_stricmp(cmd, "timedelta") == 0) {
        const char* pidStr  = nextArg(0);
        const char* durStr  = nextArg(1);
        if (!pidStr) { printf("[!] /timedelta requires a PID\n"); g_drv->Close(); return 1; }
        CmdTimeDelta((DWORD)strtoul(pidStr, nullptr, 10),
                     durStr ? (int)strtoul(durStr, nullptr, 10) : 3000);
    }
    else if (_stricmp(cmd, "guard-add") == 0) {
        const char* addrStr = nextArg();
        if (!addrStr) { printf("[!] /guard-add requires an address\n"); g_drv->Close(); return 1; }
        KUtil::BuildDriverCache();
        CmdGuardAdd(strtoull(addrStr, nullptr, 16));
    }
    else if (_stricmp(cmd, "guard-start") == 0) {
        const char* msStr = nextArg(0);
        CmdGuardStart(msStr ? (int)strtoul(msStr, nullptr, 10) : 500);
        // Keep process alive until user presses Enter
        printf("  Press Enter to stop guard and exit...\n");
        getchar();
        CmdGuardStop();
    }
    else if (_stricmp(cmd, "guard-stop") == 0) {
        CmdGuardStop();
    }
    else if (_stricmp(cmd, "guard-list") == 0) {
        KUtil::BuildDriverCache();
        CmdGuardList();
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
    else if (_stricmp(cmd, "pte") == 0) {
        const char* addrStr = nextArg(0);
        if (!addrStr) {
            printf("[!] Usage: /pte <hex_addr> [--set-write] [--clear-nx] [--restore <val>]\n");
            g_drv->Close(); return 1;
        }
        bool    setWrite   = false;
        bool    clearNx    = false;
        DWORD64 restoreVal = 0;
        for (int i = cmdIdx + 1; i < argc; i++) {
            const char* a = argv[i];
            if (_stricmp(a, "--set-write") == 0 || _stricmp(a, "set-write") == 0)
                setWrite = true;
            else if (_stricmp(a, "--clear-nx") == 0 || _stricmp(a, "clear-nx") == 0)
                clearNx = true;
            else if ((_stricmp(a, "--restore") == 0 || _stricmp(a, "restore") == 0) && i + 1 < argc)
                restoreVal = strtoull(argv[++i], nullptr, 16);
        }
        CmdPte(strtoull(addrStr, nullptr, 16), setWrite, clearNx, restoreVal);
    }
    else if (_stricmp(cmd, "rd64") == 0) {
        // Read one or more QWORDs from a kernel VA via RTCore64.
        // Usage: /rd64 <addr> [count]
        // count defaults to 1; each QWORD printed on its own line.
        const char* addrStr  = nextArg(0);
        const char* countStr = nextArg(1);
        if (!addrStr) { printf("[!] Usage: /rd64 <hex_addr> [count]\n"); g_drv->Close(); return 1; }
        DWORD64 addr  = strtoull(addrStr, nullptr, 16);
        DWORD   count = countStr ? (DWORD)strtoul(countStr, nullptr, 10) : 1;
        if (count == 0 || count > 256) count = 1;
        for (DWORD i = 0; i < count; i++) {
            DWORD64 va  = addr + (DWORD64)i * 8;
            DWORD64 val = g_drv->Rd64(va);
            printf("0x%016llX  =  0x%016llX\n", va, val);
        }
    }
    else if (_stricmp(cmd, "wr64") == 0) {
        const char* addrStr  = nextArg(0);
        const char* valStr   = nextArg(1);
        if (!addrStr || !valStr) {
            printf("[!] Usage: /wr64 <hex_addr> <hex_value>\n");
            g_drv->Close(); return 1;
        }
        DWORD64 addr = strtoull(addrStr, nullptr, 16);
        DWORD64 val  = strtoull(valStr,  nullptr, 16);
        bool atomic = g_drv->Wr64Atomic(addr, val);
        printf("[+] Wr64 0x%016llX <- 0x%016llX  (%s)\n",
               addr, val, atomic ? "ATOMIC 8B" : "hi-lo fallback");
    }
    else if (_stricmp(cmd, "ptebase") == 0) {
        KUtil::BuildDriverCache();
        CmdPteBaseScan();
    }
    else if (_stricmp(cmd, "ptebase-set") == 0) {
        const char* valStr = nextArg();
        if (!valStr) {
            printf("[!] Usage: /ptebase-set <hex_value>\n");
            g_drv->Close(); return 1;
        }
        DWORD64 val = strtoull(valStr, nullptr, 16);
        SetMmPteBase(val);
    }
    else if (_stricmp(cmd, "drv-unload") == 0) {
        const char* name  = nextArg(0);
        const char* vaStr = nextArg(1);
        if (!name || !vaStr) {
            printf("[!] Usage: /drv-unload <driver_name> <drvobj_va>\n");
            printf("    Get drvobj_va from WinDbg: !object \\Driver\\<name>\n");
            g_drv->Close(); return 1;
        }
        DWORD64 va = strtoull(vaStr, nullptr, 16);
        CmdForceUnload(name, va);
    }
    else if (_stricmp(cmd, "force-stop") == 0) {
        const char* name = nextArg(0);
        if (!name) {
            printf("[!] Usage: /force-stop <service_name>\n");
            printf("    Calls NtUnloadDriver directly, bypassing SCM error 1052\n");
            printf("    If driver has no DriverUnload, use /drv-unload <name> <va> instead\n");
            g_drv->Close(); return 1;
        }
        CmdForceStop(name);
    }
    else if (_stricmp(cmd, "elevate-pid") == 0) {
        const char* pidStr = nextArg(0);
        if (!pidStr) {
            printf("[!] Usage: /elevate-pid <pid>\n");
            printf("    Writes winlogon SYSTEM token into target pid via kernel R/W\n");
            g_drv->Close(); return 1;
        }
        DWORD pid = (DWORD)strtoul(pidStr, nullptr, 10);
        KUtil::BuildDriverCache();
        CmdElevatePid(pid);
    }
    else if (_stricmp(cmd, "enable-priv") == 0) {
        const char* priv = nextArg(0);
        if (!priv) { printf("[!] Usage: /enable-priv <privilege_name>\n"); g_drv->Close(); return 1; }
        KUtil::BuildDriverCache();
        CmdEnablePriv(priv);
    }
    else if (_stricmp(cmd, "drv-load") == 0) {
        const char* path = nextArg(0);
        if (!path) { printf("[!] Usage: /drv-load <path\\to\\driver.sys>\n"); g_drv->Close(); return 1; }
        KUtil::BuildDriverCache();
        CmdDrvLoad(path);
    }
    else if (_stricmp(cmd, "handle-close") == 0) {
        const char* pidStr = nextArg(0);
        const char* hStr   = nextArg(1);
        if (!pidStr || !hStr) {
            printf("[!] Usage: /handle-close <pid> <handle_hex>\n");
            printf("    pid=4 uses kernel HANDLE_TABLE walk; others use DuplicateHandle.\n");
            g_drv->Close(); return 1;
        }
        DWORD   pid = (DWORD)strtoul(pidStr, nullptr, 10);
        DWORD64 h   = strtoull(hStr, nullptr, 16);
        KUtil::BuildDriverCache();
        CmdHandleClose(pid, h);
    }
    else if (_stricmp(cmd, "handle-scan") == 0) {
        const char* pidStr = nextArg(0);
        if (!pidStr) {
            printf("[!] Usage: /handle-scan <pid> [--access <mask>] [--target-pid <pid>] [--close] [--spin <ms>]\n");
            printf("    Walk <pid>'s kernel HANDLE_TABLE; list entries matching access mask.\n");
            printf("    --access <mask>    : filter by GrantedAccess (default: 0x1fffff)\n");
            printf("    --target-pid <pid> : only show handles pointing to this PID's EPROCESS\n");
            printf("    --close            : zero each matching entry in-place\n");
            printf("    --spin <ms>        : loop continuously every <ms> ms (default 10); Ctrl+C to stop\n");
            g_drv->Close(); return 1;
        }
        DWORD   scanPid    = (DWORD)strtoul(pidStr, nullptr, 10);
        DWORD64 accessMask = 0;
        DWORD   targetPid  = 0;
        bool    doClose    = false;
        DWORD   spinMs     = 0;   // 0 = single shot; >0 = loop every N ms
        for (int i = cmdIdx + 1; i < argc; i++) {
            if (_stricmp(argv[i], "--close") == 0 || _stricmp(argv[i], "-close") == 0)
                doClose = true;
            else if ((_stricmp(argv[i], "--access") == 0 || _stricmp(argv[i], "-access") == 0) && i + 1 < argc)
                accessMask = strtoull(argv[++i], nullptr, 16);
            else if ((_stricmp(argv[i], "--target-pid") == 0 || _stricmp(argv[i], "-target-pid") == 0) && i + 1 < argc)
                targetPid = (DWORD)strtoul(argv[++i], nullptr, 10);
            else if ((_stricmp(argv[i], "--spin") == 0 || _stricmp(argv[i], "-spin") == 0) && i + 1 < argc) {
                int v = atoi(argv[++i]);
                spinMs = v > 0 ? (DWORD)v : 10;
            }
        }
        KUtil::BuildDriverCache();
        if (spinMs == 0) {
            CmdHandleScan(scanPid, accessMask, targetPid, doClose);
        } else {
            printf("[*] Spin mode: interval=%ums  Ctrl+C to stop.\n", spinMs);
            DWORD round = 0;
            while (true) {
                round++;
                CmdHandleScan(scanPid, accessMask, targetPid, doClose);
                Sleep(spinMs);
            }
        }
    }
    else if (_stricmp(cmd, "drv-zombie") == 0) {
        const char* vaStr = nextArg(0);
        if (!vaStr) {
            printf("[!] Usage: /drv-zombie <drvobj_va>\n");
            printf("    Diagnose why a driver is stuck in STOP_PENDING.\n");
            printf("    Get drvobj_va from: ObMaster /objdir \\Driver\n");
            g_drv->Close(); return 1;
        }
        DWORD64 va = strtoull(vaStr, nullptr, 16);
        KUtil::BuildDriverCache();
        CmdDrvZombie(va);
    }
    else if (_stricmp(cmd, "objdir") == 0) {
        const char* dirPath = nextArg(0);
        DWORD64 kva = 0;
        // Check for --kva <addr>
        for (int i = cmdIdx + 1; i < argc - 1; i++) {
            if (_stricmp(argv[i], "--kva") == 0 || _stricmp(argv[i], "-kva") == 0) {
                kva = strtoull(argv[i + 1], nullptr, 16);
                break;
            }
        }
        if (kva)
            CmdObjDir("", kva);
        else
            CmdObjDir(dirPath ? dirPath : "\\");
    }
    else if (_stricmp(cmd, "elevate-self") == 0) {
        // Does NOT need the driver — fodhelper bypass works as standard user
        g_drv->Close();
        const char* extra = nextArg(0);  // optional extra command to run after sc start
        CmdElevateSelf(extra ? extra : "");
        return 0;
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

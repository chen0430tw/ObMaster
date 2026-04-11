# ObMaster

> BYOVD-powered kernel toolkit — see what System Informer can't.

Process inspection, PPL bypass, two-stage UAC bypass (COM + kernel token steal), kernel code patching with TLB flush, privilege escalation, service/driver enumeration, network state, ObRegisterCallbacks management, Ps\*NotifyRoutine enumeration/disable, handle enumeration/suppression, minifilter inspection/detach, and force USB eject via RTCore64.sys (CVE-2019-16098).

## Commands

### Process
| Command | Description |
|---|---|
| `/proc` | List all processes via direct EPROCESS kernel walk — no `OpenProcess`, no ObCallback trigger |
| `/kill <pid>` | Terminate process; auto-escalates via `EPROCESS.Protection` clear if PPL blocks |
| `/epdump <pid>` | Dump raw EPROCESS fields for a given PID — verify offsets on non-19045 builds |
| `/proc-token <pid>` | Full security profile: token user, session, integrity level, UAC elevation type, PPL protection byte, and complete privilege list with enabled/disabled state |
| `/make-ppl <pid> [level]` | Set `EPROCESS.Protection` on any process to simulate PPL/PP for testing. Default `0x61` (PPL/Windows); `0x72` = PP/WinSys (highest). Confirms `OpenProcess(PROCESS_TERMINATE)` is denied after write |

### Privilege Escalation
| Command | Description |
|---|---|
| `/runas system <cmd>` | Run `<cmd>` as **SYSTEM** via SeDebugPrivilege + token duplication from winlogon.exe |
| `/runas ti <cmd>` | Run `<cmd>` as **TrustedInstaller** (above SYSTEM; can modify system files) |
| `/elevate-self [cmd]` | Two-stage UAC bypass: **Stage 1** ICMLuaUtil COM moniker (no driver) → **Stage 2** kernel token steal if COM is blocked by AV/EDR (requires RTCore64 loaded) |
| `/elevate-pid <pid>` | Kernel token steal — write winlogon SYSTEM token into target `EPROCESS.Token`; increments `OBJECT_HEADER.PointerCount` to prevent Bugcheck 0x18 |
| `/enable-priv <privilege>` | Patch `SEP_TOKEN_PRIVILEGES.Present/Enabled` bitmask directly in kernel — no token duplication, no `AdjustTokenPrivileges` |

### System
| Command | Description |
|---|---|
| `/drivers` | List loaded kernel modules with base address and SCM state |
| `/services [all]` | List services (default: running only) |
| `/net` | TCP/UDP connections (IPv4 + IPv6) with owning process name |

### ObCallbacks
| Command | Description |
|---|---|
| `/obcb [process\|thread]` | Enumerate ObRegisterCallbacks — color-coded by threat level |
| `/disable <addr>` | Disable callback (zero PreOp/PostOp, set Enabled=0) |
| `/enable <addr>` | Re-enable callback entry (set Enabled=1) |

### NotifyRoutines

| Command | Description |
|---|---|
| `/notify [image\|process\|thread]` | Enumerate `Ps*NotifyRoutine` arrays (LoadImage / CreateProcess / CreateThread) |
| `/ndisable <fn_addr>` | Zero the `EX_CALLBACK` slot for the matching entry — **⚠ BSOD risk, see below** |

> **⚠ BSOD warning — `/ndisable`:** Zeroing a notify slot while the kernel or another driver holds a rundown reference to that `EX_CALLBACK_ROUTINE_BLOCK` can cause an immediate bugcheck. Always enumerate first with `/notify`, identify the target, then disable during a quiet window (no active callbacks in flight). Never use on `ntoskrnl.exe` or `WdFilter.sys` entries.

### Handle Operations
| Command | Description |
|---|---|
| `/handles [filter] [--close]` | Show which processes hold open handles matching the filter; `--close` forcibly closes all matches |
| `/handle-close <pid> <handle>` | Close a handle held by any process — uses `DuplicateHandle(DUPLICATE_CLOSE_SOURCE)` for normal processes; kernel `HANDLE_TABLE` walk + zero for `pid=4` (System) |
| `/handle-scan <pid> [--access <mask>] [--target-pid <pid>] [--close] [--spin <ms>]` | Walk kernel `HANDLE_TABLE` for any PID; filter by access mask or target EPROCESS; `--close` zeroes entries in-place; `--spin` loops continuously for anti-cheat handle suppression |

### Minifilters
| Command | Description |
|---|---|
| `/flt [drive]` | Enumerate minifilter instances via two-level kernel walk (FrameList → FLTP_FRAME → FLT_FILTER → FLT_INSTANCE); optionally filter by volume |
| `/flt-detach <filter> <drive>` | Force-detach a mandatory minifilter by zeroing `InstanceQueryTeardown` then calling `FilterDetachW` |
| `/unmount <drive>` | Force dismount + physical USB eject — filesystem flush, volume offline, PnP safe removal |

### Object Namespace
| Command | Description |
|---|---|
| `/objdir [path]` | Enumerate NT object directory; shows kernel Object Addr + Header Addr for each entry. Default path: `\` |
| `/objdir --kva <addr>` | Walk directory hash buckets at a known kernel VA — bypasses DACL (use for `\Driver`, `\Device`, etc.) |

### Driver Operations
| Command | Description |
|---|---|
| `/drv-load <path.sys>` | Load driver via HKCU registry + `NtLoadDriver` (no SCM / no UAC prompt) |
| `/drv-unload <name> <drvobj_va>` | Force-unload a `NOT_STOPPABLE` or DKOM-hidden driver — patches `DriverUnload` to a `ret` stub then calls `sc stop` |
| `/force-stop <name>` | Auto-find `DRIVER_OBJECT` (PsLoadedModuleList → `.data` scan) + patch `DriverUnload` + `NtUnloadDriver` |
| `/drv-zombie <drvobj_va>` | Diagnose a driver stuck in STOP_PENDING — inspect `DriverUnload`, IRP queues, and reference counts |

> **DKOM-hidden driver note:** If the target driver has removed itself from `PsLoadedModuleList` **and** `EnumDeviceDrivers` (e.g. ksafecenter64), `/force-stop` auto-discovery will fail. The driver object still lives in the `\Driver` Object Directory hash bucket — use `/objdir` to find it:
>
> ```
> # Step 1 — get \Driver directory KVA from root namespace
> ObMaster /objdir \
>   → note Object Addr of "Driver" entry (e.g. ffffcd0dc901c060)
>
> # Step 2 — walk \Driver directly via kernel, bypassing DACL
> ObMaster /objdir --kva ffffcd0dc901c060
>   → note Object Addr of target driver (e.g. ffffa50e75f0b570)
>
> # Step 3 — patch DriverUnload + sc stop
> ObMaster /drv-unload <name> ffffa50e75f0b570
> ```
>
> `/objdir --kva` reads hash buckets directly via RTCore64 — DKOM cannot hide from this because the object must remain in the namespace as long as it exists.


### Deep Scan
| Command | Description |
|---|---|
| `/memscan <pid> [all]` | Compare all loaded DLL sections vs on-disk image; highlights patches/hooks (skips noisy sections by default) |
| `/memrestore <pid> <dll> [section]` | Restore modified sections from disk via `WriteProcessMemory` |
| `/watchfix <proc> <dll>[:<sec>] ...` | Watch for new instances of `<proc>` and auto-restore specified DLL sections on launch |

### PTE / Memory
| Command | Description |
|---|---|
| `/pte <addr> [--set-write] [--clear-nx] [--restore <val>]` | Walk 4-level page tables and display leaf PTE; optionally modify W/NX flags. **PteSafetyCheck** runs before any write: validates MmPteBase, rejects 2MB large pages, warns on DKOM drivers |
| `/safepatch <addr> <hex>` | Patch kernel read-only code pages via shadow-page PTE swap; TLB flushed with `FlushTlb()`. **PteSafetyCheck** blocks if MmPteBase is contaminated or target is on a large page |
| `/restore <addr>` | Undo a `/safepatch`, restore original PTE mapping |
| `/sp-test <addr>` | Four-stage safepatch diagnostic: Stage 0 HVCI check, Stage 1 PTE read, Stage 2 PTE write, Stage 3 shadow swap + verify |
| `/ptebase` | Run all `MmPteBase` discovery methods with full diagnostics |
| `/ptebase-set <val>` | Manually override the cached `MmPteBase` value |
| `/rd64 <addr> [count]` | Raw kernel QWORD read |
| `/wr64 <addr> <val>` | Raw kernel QWORD write |

### BSOD Diagnosis
| Command | Description |
|---|---|
| `/bsod` | Analyze latest dump file -- BugCheck code, parameters, faulting driver, diagnosis |
| `/bsod <path.dmp>` | Analyze a specific dump file |
| `/bsod --list` | One-line summary of all dumps with BugCheck code |
| `/bsod --all` | Analyze every dump inline |
| `/bsod --after 3d` | Filter: only dumps from last 3 days |
| `/bsod --before 2026-04-10` | Filter: only dumps before date |
| `/bsod --list --after td` | Today's dumps only |

Time filter shortcuts (same as doc_searcher.py): `td` (today), `yd` (yesterday), `Nd` (N days ago), `Nh` (N hours ago), `tw` (this week), `lw` (last week), `tm` (this month), `@timestamp`, `YYYY-MM-DD`

> `/bsod` does **not** require RTCore64 -- it reads dump files directly. No admin needed unless dumps are in a protected directory.

### Guard Watchdog
| Command | Description |
|---|---|
| `/guard-add <addr>` | Register a safepatch slot for watchdog monitoring |
| `/guard-start [ms]` | Start watchdog thread (default interval: 500 ms) — re-applies patches if reverted |
| `/guard-stop` | Stop watchdog thread |
| `/guard-list` | List all monitored slots and their current state |

### Timing
| Command | Description |
|---|---|
| `/timedelta <pid> [ms]` | Measure transient System handles to a process (detects race-window handle injection) |

### Winlogon / DLL Injection
| Command | Description |
|---|---|
| `/wlmon [ms]` | Monitor winlogon.exe kernel state + loaded module list; polls at `[ms]` interval (default 1000 ms) |
| `/wlinject <dll>` | Inject a DLL into winlogon.exe via user-mode APC queued to all winlogon threads |
| `/wluninject <dll>` | FreeLibrary a DLL from winlogon.exe — handles refcount (loops until module disappears), auto-dismisses blocking dialogs from all desktops if loader lock is stuck |
| `/wluninject-all <dll> [--force]` | Unload a DLL from **all** processes that have it loaded; `--force` terminates any process where FreeLibrary times out, with PPL bypass via `EPROCESS.Protection` clear if needed |
| `/wnd [--all] [--all-desktops]` | Enumerate windows; `--all` includes invisible/no-title; `--all-desktops` spans the Winlogon and Screen-saver desktops in addition to the default desktop |
| `/wnd-close <hwnd>` | Close/dismiss a window on any desktop (sends `WM_CLOSE` to the target HWND) |
| `/wl-sas` | Send Secure Attention Sequence (Ctrl+Alt+Del) via `sas.dll!SendSAS(FALSE)` — useful for unlocking the workstation programmatically |
| `/wl-persist <dll>` | Add DLL path to `AppInit_DLLs` registry key and set `LoadAppInit_DLLs=1` — DLL is injected into every process that loads user32.dll at startup |
| `/wl-unpersist <dll>` | Remove a DLL from `AppInit_DLLs`; automatically sets `LoadAppInit_DLLs=0` if the list becomes empty |
| `/dll-list <name>` | List every running process that currently has a DLL matching `<name>` loaded (case-insensitive substring match on filename) |
| `/inj-scan [pid]` | Scan all processes (or a single PID) for injection artifacts: **[MOD]** DLL loaded from outside System32/SysWOW64, **[REFL]** private RX/RWX memory with MZ header (reflective DLL), **[SHELL]** private RX/RWX memory without MZ header (shellcode), **[THD]** thread whose start address falls outside all known modules (orphan thread) |
| `/kill-ppl <pid>` | Kill a Protected Process Light — first attempts plain `TerminateProcess`; if denied, reads and zeroes `EPROCESS.Protection` byte via RTCore64, retries, and restores the original value if the kill still fails. If Protection is already 0 (non-PPL access denial), temporarily zeroes all Process ObCallback `PreOperation` pointers to bypass AV/EDR interception, then restores them |
| `/make-ppl <pid> [level]` | Set `EPROCESS.Protection` on any process to simulate PPL/PP — for testing `/kill-ppl` without a real protected process. Default level `0x61` (PPL/Windows); use `0x72` for full PP/WinSys. Confirms `OpenProcess(PROCESS_TERMINATE)` is denied after write |
| `/proc-token <pid>` | Full security profile for a process: token user, session ID, integrity level, UAC elevation type, PPL protection byte, and complete privilege list with enabled/disabled state |

> **⚠ AppInit_DLLs warning:** Any DLL registered with `/wl-persist` (or manually via `AppInit_DLLs`) **must not** call `MessageBox`, display any UI, or perform any blocking operation from `DllMain(DLL_PROCESS_ATTACH)`. Doing so will cause modal popups in every process loading user32.dll — including the session manager and desktop window manager — which can make the system unresponsive. Use `/wl-unpersist` or clear the registry key directly to recover:
> ```
> reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "" /f
> reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f
> ```

### Global flags
| Flag | Description |
|---|---|
| `/json` `--json` | Machine-readable JSON output — pipe to `jq`, agents, or scripts |
| `/quiet` `--quiet` | Suppress ASCII banner |
| `/debug` `--debug` | Verbose diagnostics: export scan progress, array VAs, per-slot raw values |

> `/flag`, `-flag`, and `--flag` are all accepted. Use `--flag` in bash/Cygwin/Git Bash to avoid MSYS path expansion.

### Per-command help
```
ObMaster /<command> ?
```

## Requirements

- Windows 10 x64 (tested on 22H2 build 19045)
- Administrator privileges
- RTCore64.sys loaded (see setup below)
- Windows Defender exclusion for the build directory (the binary contains kernel symbol names such as `PsLoadedModuleList` and `ObRegisterCallbacks` that trigger static heuristics — Sobocat.A):
  ```powershell
  # Run as Administrator
  Add-MpPreference -ExclusionPath "D:\ObMaster\build"
  Add-MpPreference -ExclusionPath "D:\ObMaster"
  ```

## Driver Setup

RTCore64.sys is **not included** in this repository. Obtain it from the MSI Afterburner installer (it is a legitimately signed driver bundled with the software).

```bat
:: 1. Place the driver (any path works; System32\drivers is conventional)
copy RTCore64.sys C:\Windows\System32\drivers\RTCore64.sys

:: 2. Register as kernel driver service
sc create RTCore64 type=kernel binPath=C:\Windows\System32\drivers\RTCore64.sys

:: 3. Start
sc start RTCore64

:: 4. Verify ObMaster can open it
ObMaster.exe /drivers
```

**Cleanup when done** (recommended — don't leave a vulnerable driver loaded):

```bat
sc stop RTCore64
sc delete RTCore64
del C:\Windows\System32\drivers\RTCore64.sys
```

## Build

```bat
cd build
build.bat
```

Requires Visual Studio 2022 BuildTools + Windows SDK 10.0.26100.0. `do_build2.bat` is an alternative that sets compiler paths directly without relying on `VsDevCmd.bat`.

**Note on output encoding:** `main.cpp` calls `SetConsoleOutputCP(CP_UTF8)` so the banner and all output is UTF-8. When invoking from PowerShell, set the encoding to match before running, otherwise box-drawing characters in the banner will appear garbled:

```powershell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
& .\build\ObMaster.exe obcb
```

This is not needed when running from `cmd.exe` or when using `--quiet` to suppress the banner.

When invoking via `sudo ObMaster.exe` from **Claude Code's built-in bash tool**, box-drawing characters will appear garbled regardless of encoding settings — this is a rendering issue in Claude Code's output pipeline, not an ObMaster or sudo bug. The same command displays correctly in PowerShell, Windows Terminal, Cygwin bash, and Git Bash.

## Tests

```bat
cd test
build_test.bat          :: builds TestTarget.exe (zombie process / service helper)
build_test_notify.bat   :: builds TestNotify.exe (pure user-mode, no driver required)
TestNotify.exe          :: validates DecodeRef, EX_CALLBACK_ROUTINE_BLOCK offsets,
                        ::   and LEA scan results against live ntoskrnl.exe
```

## Architecture

```
ObMaster
├── src/
│   ├── driver/
│   │   ├── IDriverBackend.h       Abstract R/W interface (plugin backend)
│   │   ├── RTCore64Backend.*      MSI Afterburner CVE-2019-16098 (default)
│   │   └── GigabyteBackend.h      GIBT.sys placeholder
│   ├── ansi.h                     ANSI color helpers (VT processing)
│   ├── globals.h                  Global flags (g_jsonMode, g_quiet, g_ansiEnabled, g_debug)
│   ├── jutil.h                    JSON string/address helpers
│   ├── kutil.*                    Kernel helpers, EPROCESS walker, driver cache
│   ├── cmd_proc.cpp               /proc + /kill + /proc-token
│   ├── cmd_drivers.cpp            /drivers
│   ├── cmd_services.cpp           /services
│   ├── cmd_net.cpp                /net
│   ├── cmd_obcb.cpp               /obcb + /disable + /enable
│   ├── cmd_notify.cpp             /notify + /ndisable
│   ├── cmd_runas.cpp              /runas system|ti
│   ├── cmd_memscan.cpp            /memscan + /memrestore + /watchfix
│   ├── cmd_handles.cpp            /handles + /handle-close
│   ├── cmd_flt.cpp                /flt + /flt-detach + /unmount
│   ├── cmd_unload.cpp             /drv-load + /drv-unload + /force-stop
│   ├── cmd_elevate.cpp            /elevate-self (2-stage) + /elevate-pid + /enable-priv + /drv-load
│   ├── cmd_handle_close.cpp       /handle-close + /handle-scan
│   ├── cmd_epdump.cpp             /epdump
│   ├── cmd_drvzombie.cpp          /drv-zombie
│   ├── pte.cpp                    MmPteBase discovery (10 methods) + PTE R/W + FlushTlb
│   ├── patch_store.cpp            safepatch slot store
│   ├── cmd_pte.cpp                /pte + /ptebase*
│   ├── cmd_safepatch.cpp          /safepatch + /restore
│   ├── cmd_sptest.cpp             /sp-test
│   ├── cmd_guard.cpp              /guard-*
│   ├── cmd_timedelta.cpp          /timedelta
│   ├── cmd_winlogon.cpp           /wlmon + /wlinject + /wluninject + /wluninject-all + /wnd + /wnd-close + /wl-sas + /wl-persist + /wl-unpersist + /dll-list + /inj-scan + /kill-ppl + /make-ppl
│   ├── cmd_bsod.cpp               /bsod (dump analysis + time filter)
│   └── main.cpp
├── build/
│   ├── build.bat                  Main build script
│   └── do_build2.bat              Alternative (explicit compiler paths)
└── test/
    ├── TestTarget.cpp             Zombie process / service install helper
    ├── TestNotify.cpp             User-mode unit tests for cmd_notify internals
    ├── build_test.bat
    └── build_test_notify.bat
```

## Technical notes

### Deadlock avoidance

Process enumeration (`/proc`) walks the `ActiveProcessLinks` chain in kernel memory via RTCore64 reads, never calling `OpenProcess` or `NtQuerySystemInformation` object paths. This prevents re-entrant deadlocks when querying protected processes whose ObCallbacks would block the very API used to enumerate them.

### EPROCESS offsets (Windows 10 22H2 x64 / build 19045)

| Field | Offset | Notes |
|---|---|---|
| `UniqueProcessId` | `0x440` | |
| `ActiveProcessLinks` | `0x448` | LIST_ENTRY |
| `InheritedFromUniqueProcessId` | `0x540` | PPID |
| `Peb` | `0x550` | |
| `HandleTable` | `0x570` | |
| `ImageFileName` | `0x5a8` | UCHAR[15] |
| `ActiveThreads` | `0x5f0` | |
| `VadRoot` | `0x7d8` | RTL_AVL_TREE |
| `Protection` | `0x87a` | _PS_PROTECTION (1 byte) |

Use `/epdump <pid>` to verify offsets on other builds.

### /runas technique

```
Admin process
  └─ EnablePrivilege(SeDebugPrivilege)
       └─ OpenProcess(PROCESS_QUERY_INFORMATION, winlogon/TrustedInstaller)
            └─ OpenProcessToken + DuplicateTokenEx -> primary token
                 └─ CreateProcessWithTokenW(token, cmd)
                      └─ New process running as SYSTEM / TrustedInstaller
```

TrustedInstaller holds `SeTakeOwnershipPrivilege` and `SeRelabelPrivilege` beyond what SYSTEM has — it can overwrite WRP-protected system files.

### /elevate-self two-stage technique

```
Stage 1 — ICMLuaUtil COM UAC bypass (no driver required)
  CoGetObject("Elevation:Administrator!new:{6EDD6D74...}")
    └─ ICMLuaUtil::ShellExec(cmd.exe, "sc start RTCore64 [& extra]")
       └─ Elevated cmd.exe starts RTCore64 service

Stage 2 — kernel token steal (fallback when Stage 1 is blocked)
  Requires RTCore64 already loaded (e.g. by another path)
  FindEPROCESS(winlogon) → Rd64(EPROCESS+0x4b8) → EX_FAST_REF
    → tokenPtr = value & ~0xF         (strip inline refcnt)
    → Wr64(tokenPtr - 0x30, count+1)  (OBJECT_HEADER.PointerCount +1)
    → Wr64(self EPROCESS+0x4b8, tokenPtr)  (clean pointer, no cached refs)
    → CreateProcess(extraCmd)          (child inherits SYSTEM token)
```

Skipping the `PointerCount` increment causes Bugcheck 0x18 (`REFERENCE_BY_POINTER` / `ObfDereferenceObjectWithTag`) when any syscall (e.g. `NtQueryInformationToken`) dereferences the token and the count underflows to -1.

### /safepatch TLB flush

After the PTE PA swap, stale TLB entries must be evicted before the patched mapping is visible. RTCore64 has no `INVLPG` or `WBINVD` opcode in any of its 18 IOCTLs (confirmed by full kd.exe disassembly). `FlushTlb(va)` uses the available IOCTLs instead:

```
MapPhys(PA, 0x1000)   → IOCTL 0x80002050 → MmMapIoSpace → fresh KVA, no TLB entry
Wr8(mapped+offset)    → IOCTL 0x8000204C → I/O serialization write barrier
UnmapPhys(mapped)     → IOCTL 0x80002054 → MmUnmapIoSpace → internal TLB broadcast
```

`MmUnmapIoSpace` broadcasts TLB invalidation across all CPUs as part of unmapping. No `~PTE_GLOBAL` bit manipulation or `SwitchToThread()` timing is required.

### /handles filter modes

`/handles` answers "what is holding this open?" for volumes, directories, and files:

| Filter | Example | Matches |
|---|---|---|
| Drive letter | `/handles E` or `/handles E:` | All handles on that volume |
| Directory prefix | `/handles "C:\path\to\dir"` | All handles whose NT path starts with that prefix |
| Exact file | `/handles "C:\path\to\file.txt"` | Handles to that exact file |
| (no filter) | `/handles` | All open file handles system-wide |

`--close` appended to any form forcibly closes every matching handle via `DuplicateHandle(DUPLICATE_CLOSE_SOURCE)` — useful for unlocking a file or ejecting a volume that something refuses to release.

```
# Who is holding D:\ open?
ObMaster /handles D --close

# What has a lock on this directory?
ObMaster /handles "D:\Projects\build"

# Force-close everything holding a specific log file
ObMaster /handles "C:\Windows\Logs\CBS\CBS.log" --close
```

Under the hood: `NtQuerySystemInformation(SystemHandleInformation)` → filter to File-type objects → `DuplicateHandle` + `GetFinalPathNameByHandle` for path resolution; volume-device handles (opened as `\\.\E:`) are caught via `IOCTL_STORAGE_GET_DEVICE_NUMBER`.

### OB_CALLBACK_ENTRY offsets

| Field | Offset |
|---|---|
| `Operations` | `+0x010` |
| `Enabled` | `+0x014` |
| `PreOperation` | `+0x028` |
| `PostOperation` | `+0x030` |

`_OBJECT_TYPE.CallbackList` (head) at `+0x0C8`.

### Ps\*NotifyRoutine internals

The three notify arrays (`PspLoadImageNotifyRoutine`, `PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`) are not exported by ntoskrnl. They are located at runtime by:

1. Loading `ntoskrnl.exe` as a user-mode DLL to access its export table and bytes.
2. Scanning the corresponding `PsRemove*` / `PsSet*` export for the first **RIP-relative LEA** (`REX.W 8D /r mod=00 rm=101`) whose target RVA falls inside the `.data` section.
3. Applying the RVA to the live kernel base.

`PsSetCreateProcessNotifyRoutineEx`'s first in-`.data` LEA hits `PspLoadImageNotifyRoutine`; the scanner skips it via `skipVA` and falls back to `PsSetCreateProcessNotifyRoutine`.

Each array entry is an `EX_CALLBACK` (`EX_FAST_REF`). Decoding: `block = value & ~0xF`. The actual callback is at `block + 0x08` (`EX_CALLBACK_ROUTINE_BLOCK.Function`). `/ndisable` zeroes the array slot; the kernel skips NULL entries on iteration.

### PTE safety checks

`/pte --set-write`, `/safepatch`, and related PTE operations run `PteSafetyCheck()` before any write:

1. **`ValidateMmPteBase()`** — reads PTE of ntoskrnl base, verifies Present + Executable. If flags don't match, MmPteBase is contaminated (DKOM interference).
2. **`IsLargePage()`** — checks PDE.PS bit. 2MB large pages have no PTE layer; `ReadPte`/`WritePte` would read garbage.
3. **DKOM driver warning** — if target VA belongs to ksafecenter64, kboot64, or kshutdown64, warns that PTE operations may be unreliable.

This prevents the BSOD scenarios (0x50, 0xBE) that occurred when `/safepatch` was used on DKOM-hidden drivers with contaminated MmPteBase or large page code.

### MmPteBase discovery (CR3 Walk)

`FindMmPteBaseByCR3Walk()` has two paths:

- **Path A (MapPhys):** Maps PML4 physical page via `MmMapIoSpace`, scans for self-reference entry. Fails on some low physical addresses.
- **Path B (known-VA probe):** Uses ntoskrnl base as a probe — computes `PteVaOf(ntoskrnl)` for each candidate MmPteBase, then walks 3 more self-map levels to verify PML4 self-reference against CR3. No `MapPhys` needed, no unmapped VA reads, no BSOD risk.

### ppm-engine cross-verification

All kernel structure offsets (EPROCESS, OB_CALLBACK_ENTRY, DRIVER_OBJECT, PTE bits, Token EX_FAST_REF) have been cross-verified by [ppm-engine](https://pypi.org/project/ppm-engine/) v0.2.1 static analysis against ksafecenter64.sys, kshutdown64.sys, kboot64.sys, RTCore64.sys, and 470 system drivers. See `docs/ksafe_architecture.md` for full verification results.

## Credits

- [Barakat/CVE-2019-16098](https://github.com/Barakat/CVE-2019-16098) — RTCore64 exploit
- [Mattiwatti/CheekyBlinder](https://github.com/Mattiwatti/CheekyBlinder) — BYOVD callback removal reference

---

## Disclaimer

This tool is provided **for educational and authorized security research purposes only**.

- The BYOVD technique (Bring Your Own Vulnerable Driver) exploits a known vulnerability (CVE-2019-16098) in a legitimately signed driver. Loading or using vulnerable drivers on systems you do not own or have explicit written authorization to test **is illegal** in most jurisdictions.
- ObMaster directly reads and writes kernel memory. Incorrect use can cause **immediate system crash (BSOD)** or data loss.
- The `/runas` privilege escalation feature demonstrates token duplication techniques documented in public security research. It requires and operates within **existing Administrator privileges** — it does not exploit a vulnerability to bypass UAC or gain unauthorized access.
- The author assumes **no liability** for any damage, data loss, or legal consequences arising from use of this software.
- Do not use this tool against production systems, third-party infrastructure, or any system without proper authorization.

**If you are unsure whether your use case is authorized, it is not.**

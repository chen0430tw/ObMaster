# ObMaster

> BYOVD-powered kernel toolkit — see what System Informer can't.

Process inspection, PPL bypass, privilege escalation, service/driver enumeration, network state, ObRegisterCallbacks management, Ps\*NotifyRoutine enumeration/disable, open file handle enumeration, minifilter inspection/detach, and force USB eject via RTCore64.sys (CVE-2019-16098).

## Commands

### Process
| Command | Description |
|---|---|
| `/proc` | List all processes via direct EPROCESS kernel walk — no `OpenProcess`, no ObCallback trigger |
| `/kill <pid>` | Terminate process; auto-escalates via `EPROCESS.Protection` clear if PPL blocks |

### Privilege Escalation
| Command | Description |
|---|---|
| `/runas system <cmd>` | Run `<cmd>` as **SYSTEM** via SeDebugPrivilege + token duplication from winlogon.exe |
| `/runas ti <cmd>` | Run `<cmd>` as **TrustedInstaller** (above SYSTEM; can modify system files) |

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
| `/handles [drive]` | Enumerate all open file handles system-wide; optionally filter by volume (e.g. `/handles E`) |
| `/handle-close <pid> <handle>` | Close a handle held by any process — uses `DuplicateHandle(DUPLICATE_CLOSE_SOURCE)` for normal processes; kernel `HANDLE_TABLE` walk + zero for `pid=4` (System) |

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

### Privilege / Token
| Command | Description |
|---|---|
| `/elevate-pid <pid>` | Kernel token steal — write winlogon SYSTEM token pointer into target `EPROCESS.Token` |
| `/enable-priv <privilege>` | Patch `SEP_TOKEN_PRIVILEGES.Present/Enabled` bitmask directly in kernel |

### Deep Scan
| Command | Description |
|---|---|
| `/memscan <pid> [all]` | Compare all loaded DLL sections vs on-disk image; highlights patches/hooks (skips noisy sections by default) |
| `/memrestore <pid> <dll> [section]` | Restore modified sections from disk via `WriteProcessMemory` |
| `/watchfix <proc> <dll>[:<sec>] ...` | Watch for new instances of `<proc>` and auto-restore specified DLL sections on launch |

### PTE / Memory
| Command | Description |
|---|---|
| `/pte <addr> [--set-write] [--clear-nx] [--restore <val>]` | Walk 4-level page tables and display leaf PTE; optionally modify W/NX flags |
| `/safepatch <addr> <hex>` | Patch kernel memory safely via shadow-page PTE swap (CoW-style, bypasses write-protect) |
| `/restore <addr>` | Undo a `/safepatch`, restore original PTE mapping |
| `/ptebase` | Run all `MmPteBase` discovery methods with full diagnostics |
| `/ptebase-set <val>` | Manually override the cached `MmPteBase` value |
| `/rd64 <addr> [count]` | Raw kernel QWORD read |
| `/wr64 <addr> <val>` | Raw kernel QWORD write |

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
│   ├── cmd_proc.cpp               /proc + /kill
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
│   ├── cmd_elevate.cpp            /elevate-pid + /enable-priv
│   ├── cmd_handle_close.cpp       /handle-close (kernel path for pid=4)
│   ├── pte.cpp                    MmPteBase discovery (10 methods) + PTE R/W
│   ├── patch_store.cpp            safepatch slot store
│   ├── cmd_pte.cpp                /pte + /safepatch + /restore + /ptebase*
│   ├── cmd_safepatch.cpp          /safepatch high-level handler
│   ├── cmd_guard.cpp              /guard-*
│   ├── cmd_timedelta.cpp          /timedelta
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

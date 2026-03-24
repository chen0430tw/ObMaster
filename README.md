# ObMaster

> BYOVD-powered kernel toolkit — see what System Informer can't.

Process inspection, PPL bypass, privilege escalation, service/driver enumeration, network state, and ObRegisterCallbacks management via RTCore64.sys (CVE-2019-16098).

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

### Global flags
| Flag | Description |
|---|---|
| `/json` `--json` | Machine-readable JSON output — pipe to `jq`, agents, or scripts |
| `/quiet` `--quiet` | Suppress ASCII banner |

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

```
cd build
build.bat
```

Requires Visual Studio 2022 BuildTools + Windows SDK 10.0.26100.0.

**Note on output encoding:** `main.cpp` calls `SetConsoleOutputCP(CP_UTF8)` so the banner and all output is UTF-8. When invoking from PowerShell, set the input encoding to match before running, otherwise box-drawing characters in the banner will appear garbled:

```powershell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
& .\build\ObMaster.exe obcb
```

This is not needed when running from `cmd.exe` or when using `--quiet` to suppress the banner.

## Architecture

```
ObMaster
├── src/
│   ├── driver/
│   │   ├── IDriverBackend.h       Abstract R/W interface (plugin backend)
│   │   ├── RTCore64Backend.*      MSI Afterburner CVE-2019-16098 (default)
│   │   └── GigabyteBackend.h      GIBT.sys placeholder
│   ├── ansi.h                     ANSI color helpers (VT processing)
│   ├── globals.h                  Global flags (g_jsonMode, g_quiet, g_ansiEnabled)
│   ├── jutil.h                    JSON string/address helpers
│   ├── kutil.*                    Kernel helpers, EPROCESS walker, driver cache
│   ├── cmd_proc.cpp               /proc + /kill
│   ├── cmd_drivers.cpp            /drivers
│   ├── cmd_services.cpp           /services
│   ├── cmd_net.cpp                /net
│   ├── cmd_obcb.cpp               /obcb + /disable + /enable
│   ├── cmd_runas.cpp              /runas system|ti
│   └── main.cpp
└── build/
    └── build.bat
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

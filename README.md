# ObMaster

Kernel System Toolkit — process inspection, service/driver enumeration, network state, and ObRegisterCallbacks management via BYOVD (RTCore64.sys).

## Features

| Command | Description |
|---|---|
| `/proc` | List all processes via kernel EPROCESS walk (no ObCallback trigger) |
| `/kill <pid>` | Terminate process; PPL bypass via `EPROCESS.Protection` clear |
| `/drivers` | List loaded kernel modules with base address and SCM state |
| `/services [all]` | List services (default: running only) |
| `/net` | TCP/UDP connections with owning process name |
| `/obcb [process\|thread]` | Enumerate ObRegisterCallbacks |
| `/disable <addr>` | Disable callback (zero PreOp, set Enabled=0) |
| `/enable <addr>` | Re-enable callback entry |

## Requirements

- Windows 10 x64 (tested on 22H2 build 19045)
- Administrator privileges
- RTCore64.sys loaded (`sc start RTCore64`)
  - Extract from MSI Afterburner installer or use CheekyBlinder `/installDriver`

## Build

```
cd build
build.bat
```

Requires Visual Studio 2022 BuildTools + Windows SDK 10.0.26100.0.

## Architecture

```
ObMaster
├── src/
│   ├── driver/
│   │   ├── IDriverBackend.h       Abstract R/W interface
│   │   ├── RTCore64Backend.*      MSI Afterburner (default)
│   │   └── GigabyteBackend.h      GIBT.sys placeholder
│   ├── kutil.*                    Kernel helpers, EPROCESS walker
│   ├── cmd_proc.cpp               /proc + /kill
│   ├── cmd_drivers.cpp            /drivers
│   ├── cmd_services.cpp           /services
│   ├── cmd_net.cpp                /net
│   ├── cmd_obcb.cpp               /obcb + /disable + /enable
│   └── main.cpp
└── build/
    └── build.bat
```

### Deadlock avoidance

Process enumeration uses direct EPROCESS kernel memory reads via RTCore64, bypassing all user-mode APIs (`OpenProcess`, `NtQuerySystemInformation` object paths) that would trigger ObRegisterCallbacks — preventing re-entrant deadlocks when querying the System process (pid=4).

### EPROCESS offsets (Windows 10 22H2 x64)

| Field | Offset |
|---|---|
| `UniqueProcessId` | `0x440` |
| `ActiveProcessLinks` | `0x448` |
| `Peb` | `0x550` |
| `HandleTable` | `0x570` |
| `ImageFileName` | `0x5a8` |
| `ActiveThreads` | `0x5f0` |
| `Protection` | `0x87a` |

## Credits

- [Barakat/CVE-2019-16098](https://github.com/Barakat/CVE-2019-16098) — RTCore64 exploit
- [Mattiwatti/CheekyBlinder](https://github.com/Mattiwatti/CheekyBlinder) — BYOVD callback removal reference

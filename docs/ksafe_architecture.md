# ksafe / lwclient 系统架构逆向分析

> 云更新（YunGengXin）网吧无盘管理系统驱动栈逆向研究
> 分析日期：2026-04-08
> 分析工具：dumpbin、7z 字符串提取、ObMaster /obcb /notify /drivers

---

## 系统概述

「云更新」（YunGengXin）是国内主流网吧无盘管理系统，客户端安装包：
`Standard_x64_2025.6.15.23946_sp39_Setup.zip`

核心功能：
- 磁盘影子还原（重启恢复）
- 进程保护与黑名单管控
- 远端策略下发（服务端 → 客户端）
- 游戏存档云同步

---

## 安装包结构

### 打包格式
- 外层：ZIP
- 内层 Setup：**NSIS-3 Unicode + LZMA**

### 客户端安装目录
注册表 `HKLM\SYSTEM\CurrentControlSet\Services\lwclient` 中 ImagePath：
```
B:\lwclient64\lwclient64.exe
```
安装在 **B 盘**（网咖无盘工作站的影子盘），不在 C 盘。

### 驱动文件位置（客户端）
```
B:\lwclient64\
├── kshut64.dll          — 进程终止用户态代理（注入到 winlogon.exe）
├── kshut.dll            — 32 位版本
├── kres64.dll           — 资源/还原模块
├── kpowershut64.dll     — 电源关机模块
├── config\
│   └── softwarecfg.dat  — 游戏存档同步配置（XML，非进程黑名单）
└── ...
```

驱动（.sys 文件）直接放在 `B:\lwclient64\` 或系统 drivers 目录。

### 关键发现：黑名单在安装后由服务端写入，安装时不存在

**`shut` 注册表值的生命周期（已通过反汇编 + 导入表分析确认）：**

| 阶段 | `HKLM\SYSTEM\CurrentControlSet\shut` 状态 |
|------|------------------------------------------|
| 安装前 | 不存在 |
| 安装后（未连接服务端） | **不存在**（安装包不写此值）|
| 客户端连接服务端后 | `lwclient64.exe` 写入（由管理员在服务端配置的黑名单）|
| 驱动/DLL 加载时 | 只读取，不写入 |

**证据：**
- `KSetup.exe` 安装包：只写 `SYSTEM\CurrentControlSet\services\`（服务注册），无 `shut` 值写操作
- `kshutdown64.sys`：只导入 `ZwOpenKey`/`ZwQueryValueKey`，无 `ZwSetValueKey`/`ZwCreateKey`
- `kshut64.dll`：只调用 `RegOpenKeyExW`/`RegQueryValueExW`，无写操作

**这解释了为什么本机测试 VirtualBox 不被杀**：lwclient64.exe 未连接服务端 → `shut` 值不存在 → 无动态黑名单。

---

## 驱动栈组成

> ppm-engine v0.2.2 静态分析验证，2026-04-11（PC44 网咖实机）

| 驱动 | ppm 类型 | 回调注册 | 自保护机制 | 威胁等级（对 VBox）|
|------|---------|---------|-----------|------------------|
| `ksafecenter64.sys` | `protection_minifilter` | ObCallback, CmCallback, ImageLoad notify, Minifilter | 无 DriverUnload; 注册表保护; handle 权限剥夺 | **高**（L1-L3）|
| `kshutdown64.sys` | `apc_injector` | Process notify, ImageLoad notify | 无 DriverUnload; MmGetSystemRoutineAddress 动态解析 | **高**（L4）|
| `kboot64.sys` | `apc_injector` | CmCallback, Process notify, ImageLoad notify | 无 DriverUnload; 注册表保护; MmGetSystemRoutineAddress; **EPROCESS DKOM** | **高**（APC 注入 + CmCallback + DKOM）|
| `vgk64.sys` | `apc_injector` (packed) | （packed 内部隐藏） | 无 DriverUnload; **EPROCESS DKOM** | **中**（反作弊，可能干扰 VBox）|
| `kcachec64.sys` | `process_monitor` | Process notify | 无 DriverUnload; MmGetSystemRoutineAddress | **中**（进程监控，可能上报）|
| `KScsiDisk64.sys` | `process_monitor` | Process notify, ImageLoad notify | 无 DriverUnload; MmGetSystemRoutineAddress | **低**（磁盘驱动但有进程监控）|
| `krestore64.sys` | `generic_driver` | 无 | 无 DriverUnload; MmGetSystemRoutineAddress; **EPROCESS DKOM** | **低**（磁盘还原，但有 DKOM 能力）|
| `kdisk64.sys` | `generic_driver` | 无 | 无 DriverUnload | 无 |
| `kantiarp64.sys` | `generic_driver` | 无 | 无 DriverUnload | 无（ARP 防火墙）|
| `kpowershutdown64.sys` | `generic_driver` | 无 | 无 DriverUnload | 无（电源控制）|

### ppm-engine 关键发现（2026-04-11）

1. **kboot64.sys 比预期危险得多**：确认为 `apc_injector`，具备 APC 注入 + CmCallback + EPROCESS DKOM。之前仅当作 PnP 硬件配置驱动，实际可注入并杀进程。
2. **kcachec64.sys**（此前未分析）：`process_monitor` 类型，注册 CreateProcess notify，可能是 kshutdown 的辅助监控组件。
3. **所有云更新驱动均无 DriverUnload**：全部"加载不走"设计，必须用 ObMaster `/drv-unload` patch ret stub 才能卸载。
4. **vgk64.sys (Valorant Vanguard)**：packed，静态分析无法看到完整逻辑，但确认有 DKOM 和 APC 注入能力。
5. **krestore64.sys**：虽是磁盘还原驱动，但有 EPROCESS DKOM 写入能力和 MmGetSystemRoutineAddress 动态解析，不排除辅助保护功能。

---

## kshutdown64.sys 详细分析

### PDB 路径
```
D:\kygx2019\trunk\bin\kshutdown64.pdb
```
确认为云更新自研驱动（kygx = KuaiYuanGuanXi / 快云管系）。

### 导入表
```
PsSetCreateProcessNotifyRoutine  — 监控所有新进程创建
PsSetLoadImageNotifyRoutine      — 监控模块/镜像加载
PsRemoveLoadImageNotifyRoutine   — 注销 notify（卸载时清理）
ZwQueryValueKey                  — 启动时从注册表读配置
ZwOpenKey                        — 打开注册表键
ZwAllocateVirtualMemory          — 在目标进程分配内存（APC payload）
ZwOpenProcess                    — 打开目标进程
KeInitializeApc + KeInsertQueueApc — 内核 APC 注入
KeInitializeMutex + KeReleaseMutex + KeWaitForSingleObject — 同步原语
IoCreateDevice                   — 创建设备对象（供 kshut64.dll 通信）
MmGetSystemRoutineAddress        — 动态解析内核函数
ProbeForWrite                    — 校验用户态指针
```

### 工作架构：双路径进程终止

```
路径一 — 内核 APC（主路径，绕过所有用户态保护）：
  PsSetCreateProcessNotifyRoutine 回调触发
    → 检查新进程名是否在黑名单
    → ZwOpenProcess 打开目标进程
    → ZwAllocateVirtualMemory 分配 shellcode/ExitProcess 桩
    → KeInsertQueueApc 注入内核 APC
    → 目标进程在下次 alertable wait 时执行 → 调用 ExitProcess

路径二 — 用户态 TerminateProcess（备用路径）：
  kshut64.dll 注入 winlogon.exe
    → DllMain 起线程，OpenEventW 等待命名 Event 信号
    → 驱动通过 IoCreateDevice 设备通知 dll
    → dll 调 OpenProcess + TerminateProcess 终止目标
```

### 进程名单（内嵌宽字符串）

**白名单（绝不终止）**：
```
csrss.exe  smss.exe  wininit.exe  winlogon.exe  lsass.exe  explorer.exe
```

**本地基础黑名单（硬编码，已知外挂进程）**：
```
checkudo.exe   udo.exe        ucheck.exe     clientprc.exe
jxclient.exe   knbclient.exe  pubwinclient.exe  yqsclient.exe
rsclient.exe   clsmn.exe      entry.exe      runme.exe
rwyncmc.exe    sdfox.exe      qsd.exe        JFUserClient.exe
```

**远端扩展黑名单（服务端下发，包含虚拟化工具）**：
- `VirtualBox.exe`、`VBoxSVC.exe`、`VBoxManage.exe`
- VMware Workstation 相关进程
- 调试器、抓包工具等（具体列表由网咖管理员配置）

### 设备/Event 接口

kshutdown64.sys 通过 `IoCreateDevice` 创建设备，但设备名未在字符串中明文出现（可能动态构造或加密）。

驱动与 kshut64.dll 的通信使用命名 Event：
```
Global\{00A8A8A1-D6D2-4896-A590-FFE0D3804C89}
```

---

## kshut64.dll 详细分析

### 核心导入

```
GetPrivateProfileStringW  — 读取 config\config.ini（进程黑名单来源）
GetModuleFileNameW        — 获取自身路径，拼接 config\config.ini 完整路径
OpenEventW               — 等待驱动通知 Event
CreateEventW + WaitForSingleObject — 同步等待
OpenProcess + TerminateProcess    — 用户态路径杀进程
GetProcessImageFileNameW          — 枚举进程名做匹配
SuspendThread + GetThreadContext + SetThreadContext
  + ResumeThread + FlushInstructionCache — 线程劫持注入（比 CreateRemoteThread 更隐蔽）
VirtualAlloc + VirtualProtect + VirtualFree + VirtualQuery — 内存操作
EnumWindowStationsW + EnumDesktopsW + OpenInputDesktop — 跨桌面枚举
AdjustTokenPrivileges + LookupPrivilegeValueW — 提权操作
RegOpenKeyExW + RegQueryValueExW — 补充配置读取
```

### config.ini 实际用途（已反汇编确认）

`kshut64.dll` 中 **只有一处** `GetPrivateProfileStringW` 调用，参数为：

```
lpAppName  = L"config"          ← section 名
lpKeyName  = L"serverip"        ← key 名
lpDefault  = L"127.0.0.1"       ← 默认值
```

**结论：config.ini 只存储服务端 IP，不存储进程黑名单。**

格式：
```ini
[config]
serverip=192.168.1.100
```

### 黑名单真实来源：注册表（完整路径已确认）

反汇编 `RegOpenKeyExW` + `RegQueryValueExW` 调用链，参数如下：

```
RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet", 0, KEY_READ, &hKey)
RegQueryValueExW(hKey, L"shut", NULL, &type, buf, &size)
```

**黑名单注册表路径（已确认）：**
```
HKLM\SYSTEM\CurrentControlSet
  └── 值名：shut        ← 服务端写入的进程黑名单
```

反汇编发现 `RegQueryValueExW` 在两处被调用：

| 调用地址 | 操作 |
|---------|------|
| `0x180001D5C` | 读 `SOFTWARE\{3798BE84-4E13-4b81-B8CF-5063730FF905}\kpandaclient\InstDir` — 获取安装目录 |
| `0x180005CEA` | 读 `HKLM\SYSTEM\CurrentControlSet` value `shut` — **读取进程黑名单** |

函数内无任何字符串拼接（wcscat/swprintf 等），路径为硬编码直连。
选择 `SYSTEM\CurrentControlSet` 而非服务专用键的原因：该键写权限限管理员，用户态进程无法篡改黑名单。

### 注入方式
kshut64.dll 通过 winlogon 注入后，对目标进程使用**线程劫持**（Thread Hijack）：
1. `SuspendThread` 暂停目标线程
2. `GetThreadContext` 读取寄存器状态
3. `VirtualAlloc` 在目标进程分配 payload
4. `SetThreadContext` 修改 RIP 指向 payload
5. `ResumeThread` 恢复执行
6. `FlushInstructionCache` 确保指令缓存一致

---

## 黑名单分发机制（已反汇编修正）

```
服务端管理控制台
    │
    │ 网络推送（私有协议）
    ├──► HKLM\SYSTEM\CurrentControlSet (value: shut)  ←  kshut64.dll RegQueryValueExW 读取
    │
    └──► HKLM\SOFTWARE\{GUID}\kpandaclient\serverip  ←  kshut64.dll config.ini GetPrivateProfileStringW
         （config.ini 仅存 serverip，不含黑名单）
    │
    ▼
进程黑名单（内存中）
    │
    ├── 路径一：kshutdown64.sys notify routine（内核 APC）
    └── 路径二：kshut64.dll TerminateProcess（用户态）
```

**关键结论（修正版）：**
- config.ini 只存服务端 IP，不含黑名单
- 黑名单通过注册表 `SYSTEM\CurrentControlSet\...\shut` 下发
- VirtualBox 被杀是服务端将其写入注册表黑名单，不是驱动硬编码

---

## VirtualBox vs 雷电模拟器

| | VirtualBox | 雷电模拟器 |
|---|---|---|
| 内核驱动 | `VBoxDrv.sys`、`VBoxSup.sys`（ring0）| 无内核驱动 |
| ksafe 处置 | 服务端下发黑名单，双路径终止 | 不在名单，完全放行 |
| 根本原因 | 内核级虚拟化可绕过反作弊监控 | 纯用户态 Android 模拟，无 ring0 访问 |

---

## 沙盒攻防模拟方案（ObMaster）

### 目标
在本机复现网咖 ksafe 完整攻击链，验证 ObMaster 的防御能力。

---

### 阶段一：用户态铁三角演习（2026-04-09 已完成）

**工具**：`test/sim_ksafe_blacklist/` 铁三角模拟器组

| 组件 | 文件 | 模拟对象 |
|------|------|---------|
| SimServer.exe | 交互式 CLI | 服务端策略推送 |
| SimKshutdown2.exe | 注册表黑名单 + snapshot poll + 杀进程 + SetEvent | kshutdown64.sys |
| SimKshut64.exe | WaitForSingleObject(GUID) → 扫描 → 杀进程 | kshut64.dll |
| SimKsafecenter2.exe | 持 PROCESS_ALL_ACCESS + 句柄被关立刻重开 | ksafecenter64.sys |
| SimTarget2.exe | 心跳 + 恶意句柄检测 + PPL 状态显示 | VirtualBox.exe |

**通信架构（完全匹配真实 ksafe）：**
```
SimServer  →  reg write HKLM\SYSTEM\CurrentControlSet\shut (REG_MULTI_SZ)
           →  Section Global\ksafe_policy (armed flag)
           →  Event Global\ksafe_policy_update

SimKshutdown2  →  RegNotifyChangeKeyValue 监听黑名单变化
               →  CreateToolhelp32Snapshot poll 每 200ms
               →  TerminateProcess(0xC0000409) + SetEvent(GUID)

SimKshut64     →  WaitForSingleObject(Global\{00A8A8A1-D6D2-4896-A590-FFE0D3804C89})
               →  读注册表 → 扫描 → TerminateProcess

SimKsafecenter2 →  OpenProcess(PROCESS_ALL_ACCESS) on SimKshutdown2 + SimKshut64
                →  poll 100ms：句柄被关 → 立刻重开
```

**演习实测结果（2026-04-09）：**

| 测试 | 结果 |
|------|------|
| 完整攻击链：push 黑名单 → SimKshutdown2 KILL → SetEvent → SimKshut64 wake | ✅ SimTarget2 被 `0xC0000409` 终止 |
| SimKshut64 Event 唤醒备用路径 | ✅ Wake #29 EVENT signaled，扫描执行 |
| SimKsafecenter2 句柄被 ObMaster `/handle-close` 关闭 | ✅ 100ms 内重开，句柄轮换（×5次压测）|
| PPL 防御：`/make-ppl 0x72` 后攻击重试 | ✅ `OpenProcess err 5`，SimTarget2 存活 |
| 杀掉攻击进程后 + `/make-ppl 0x72` 组合防御 | ✅ 攻击进程重启后仍全部 `OpenProcess failed` |

**演习的局限性（与真实 ksafe 的差距）：**

| 差距 | 演习行为 | 真实 ksafe 行为 |
|------|---------|----------------|
| ksafecenter64 保护机制 | 持句柄 + 轮询重开（100ms 窗口）| ObCallback PreOp 在 syscall 入口裁剪 access mask，零窗口 |
| kshutdown64 杀进程路径 | `TerminateProcess`（kshut64.dll 的备用路径）| 内核 APC：`ZwAllocateVirtualMemory` + `KeInsertQueueApc`，从 PID 4 注入 |
| 黑名单更新 | 手动 push | lwclient64 长连接，服务端随时推送 |
| 攻击进程可被 kill | `Stop-Process` 即可 | kshutdown64.sys 是内核驱动，不可直接终止 |

---

### 阶段二：真实驱动实战测试（待完成）

#### 攻击链搭建

**Step 1：加载驱动**
```
sc create kshutdown64 binPath= "C:\Users\asus\Downloads\ksafe_drivers\kshutdown64.sys" type= kernel start= demand
sc start kshutdown64
```
注：必须通过 SCM 启动，直接用 `NtLoadDriver` 会触发 DriverEntry 自检失败（0xC00000E5）。

**Step 2：写入注册表黑名单（激活真实内核 APC 路径）**
```
reg add "HKLM\SYSTEM\CurrentControlSet" /v shut /t REG_MULTI_SZ /d "SimTarget2.exe\0" /f
```
注：`shut` 值格式已通过反汇编确认为 REG_MULTI_SZ（ZwQueryValueKey at kshutdown64+offset）

**Step 3：启动 SimTarget2 观察内核 APC 行为**
```
SimTarget2.exe
```
此时 kshutdown64.sys 的 PsCreateProcessNotifyRoutine 会触发，
通过 `ZwOpenProcess` + `ZwAllocateVirtualMemory` + `KeInsertQueueApc` 注入 ExitProcess stub。

**Step 4（可选）：注入 kshut64.dll 到 winlogon（备用路径）**
```
ObMaster /wlinject C:\Users\asus\Downloads\ksafe_drivers\kshut64.dll
```

#### 防御方案（ObMaster）

**方案 A — 禁用 notify routine（推荐，盲化驱动）**
```
ObMaster /notify process        # 找 kshutdown64 的 CreateProcess 回调地址
ObMaster /ndisable <addr>       # 零掉回调 → 驱动对新进程完全失明
```

**方案 B — 卸载驱动**
```
ObMaster /force-stop kshutdown64
```
缺点：ksafecenter64 可能监控驱动状态并重新拉起。

**方案 C — 卸出 winlogon 里的 kshut64.dll**
```
ObMaster /wluninject kshut64.dll
```
仅断用户态备用路径，内核 APC 路径仍存在。

**方案 D — 给目标进程套 PPL**
```
ObMaster /make-ppl <pid> 0x72
```
kshutdown64 使用 `ZwOpenProcess`（Zw* 在内核也走完整安全检查），
PPL 理论上应挡住 `PROCESS_VM_OPERATION`（APC 注入需分配内存）。
**待实测确认：内核 APC 路径是否真的被 PPL 拦截。**

**最稳组合：方案 A + 方案 D**
- A：让驱动看不见新进程启动（notify 被零掉）
- D：已运行进程的 PPL 兜底（即使 A 失效，APC 注入仍被 ZwOpenProcess 安全检查拦截）

#### 待验证的核心问题

1. **PPL 能否挡住内核 APC 路径？**
   - kshutdown64 使用 `ZwOpenProcess(PROCESS_ALL_ACCESS)` 需要 `PROCESS_VM_OPERATION`
   - PPL 目标进程对外部 `ZwOpenProcess` 返回 `STATUS_ACCESS_DENIED`
   - 即使来自内核驱动，只要走 Zw* 路径就受 PPL 约束
   - **预期：PPL 有效；需实测确认**

2. **`/ndisable` 能否完全盲化 kshutdown64？**
   - 零掉 PsCreateProcessNotifyRoutine 回调数组中的函数指针
   - 驱动感知不到新进程 → APC 路径永远不触发
   - **预期：有效；需实测确认**

---

### 阶段三：真实 ObCallback PreOp 模拟（待完成）

在 ObMaster 加入 `/obcb-install` 命令，注册真实 `ObRegisterCallbacks` PreOp，
模拟 ksafecenter64 裁剪 `PROCESS_TERMINATE` 的行为，
然后用 ObMaster 自身的 PreOp bypass 测试能否突破自己注册的回调。

### ⚠️ 注意事项

- **禁止将 OBJECT_HEADER.SecurityDescriptor 写为 NULL** — 会触发 Bugcheck 0x189 (BAD_OBJECT_HEADER)，P1 = 对象头地址（已验证蓝屏）
- kshutdown64 的内核 APC 路径从 PID 4 发起，PPL 是否有效取决于 `ZwOpenProcess` 的安全检查（Zw* 路径受约束，但需实测）
- `sc.exe start` 需要管理员权限；驱动自检会验证调用上下文
- 加载真实驱动前确保注册表 `shut` 值只含测试进程名，避免误杀

---

## ParadexMonitor 自动化分析 (2026-04-10)

使用 `ppm-engine v0.2.0` 对云更新完整驱动栈做 8 阶段自动化分析。
分析时间: 全部 11 个组件合计 < 30 秒。

### 驱动栈威胁总览

| 驱动 | 大小 | 分类 | 回调 | Pattern | 威胁 |
|------|------|------|------|---------|------|
| **ksafecenter64.sys** | 61K | `protection_minifilter` | ObCallback + CmCallback + LoadImage + minifilter | ob_callback(0.85), cm_callback(0.75) | **高** |
| **kshutdown64.sys** | 27K | `apc_injector` | ProcessNotify + LoadImage | apc_inject(0.8) | **高** |
| **kboot64.sys** | 222K | `apc_injector` | CmCallback + ProcessNotify + LoadImage | cm_callback(0.85), apc_inject(0.8) | **高** |
| **kcachec64.sys** | 61K | `process_monitor` | ProcessNotify | - | **中** |
| **kscsidisk64.sys** | 131K | `process_monitor` | ProcessNotify + LoadImage | - | **中** |
| **krestore64.sys** | 53K | `generic_driver` | - | - | 低 |
| **kantiarp64.sys** | 27K | `generic_driver` | - | - | 低 |
| **kdisk64.sys** | 26K | `generic_driver` | - | - | 低 |
| **kpowershutdown64.sys** | 20K | `generic_driver` | - | - | 低 |

**全部 9 个驱动都没有 DriverUnload -- 加载后均无法通过正常手段卸载。**

### 用户态组件

| 组件 | 大小 | 分类 | 关键导入 |
|------|------|------|---------|
| **kshut64.dll** | PE64_DLL, 146 imports | 用户态杀手 | 线程劫持全套 (SuspendThread/GetThreadContext/SetThreadContext/ResumeThread/FlushInstructionCache), OpenProcess+TerminateProcess, RegOpenKeyExW+RegQueryValueExW (读黑名单), OpenEventW+WaitForSingleObject (等驱动信号), WS2_32 网络套件 (connect/send/recv), EnumWindowStationsW+EnumDesktopsW (跨桌面枚举) |
| **kssd.exe** | PE64, packed=True, 735 imports | 游戏磁盘管理器 | 17,164 函数, 32,627 depgraph 节点。标记为加壳。 |

### ksafecenter64.sys 深度分析

**回调注册:**
```
sub_74FC -> ObRegisterCallbacks (handler 入口未知, PreOp @ 0x78B8)
sub_7A08 -> CmRegisterCallbackEx (callback @ 0x7C20)
sub_69B4 -> PsSetLoadImageNotifyRoutine
FltRegisterFilter (minifilter)
```

**ObOpenObjectByPointer 数据流追踪:**
```
@ 0x4C10: DesiredAccess(rdx) = 0x200 [QUERY_INFO], r8=0, r9=0
@ 0x58AF: DesiredAccess(rdx) = 0x200 [QUERY_INFO], r8=0, r9=0
```
结论: 两个调用点都只用 0x200, 不产生 PROCESS_ALL_ACCESS (0x1FFFFF) 句柄。
Evil handle 是 ObOpenObjectByPointer -> ZwClose 之间的瞬态竞态产物。

**CmRegisterCallbackEx 数据流追踪:**
```
@ 0x7A47: callback(rcx) = 0x7C20 [rip_relative], context(r9) = 0
```
CmCallback @ 0x7C20 只拦截 RegNtPreSetValueKey, 保护 `\SOFTWARE\kSafeCenter`。

**ObOpenObjectByPointer 完整调用链:**
```
sub_78B8 (PreOp) -> sub_7600 (IsProtectedPid) -> sub_4BCC -> ObOpenObjectByPointer
sub_1724 -> sub_4BCC -> ObOpenObjectByPointer
sub_2764 -> sub_31B4 -> sub_4BCC -> ObOpenObjectByPointer
sub_27E8 -> sub_31B4 -> sub_4BCC -> ObOpenObjectByPointer
sub_5860 -> ObOpenObjectByPointer
```

**PreOp 伪代码 (0x78B8) -- 句柄权限剥夺:**
```c
void PreOp(OB_PRE_OPERATION_INFO* info) {
    if (info->KernelHandle) return;          // 跳过内核句柄
    if (KeGetCurrentIrql() >= DISPATCH) return; // 跳过高 IRQL
    pid = PsGetProcessId(info->Object);
    if (info->Operation != HANDLE_CREATE) return;
    if (IsProtectedPid(pid) == false) {
        // 剥夺权限位:
        DesiredAccess &= 0xFFFFFFFE;  // 去 PROCESS_TERMINATE (0x001)
        DesiredAccess &= 0xFFFFFFF7;  // 去 PROCESS_VM_OPERATION (0x008)
        DesiredAccess &= 0xFFFFFFEF;  // 去 PROCESS_VM_READ (0x010)
        DesiredAccess &= 0xFFFFFFDF;  // 去 PROCESS_VM_WRITE (0x020)
        BTR DesiredAccess, 11;        // 去 PROCESS_SUSPEND_RESUME (0x800)
    }
    return STATUS_SUCCESS;
}
```

**IsProtectedPid (0x7600) 逻辑:**
```
1. PsLookupProcessByProcessId(pid)
2. IoGetCurrentProcess() -- 排除自身
3. 检查进程存活时间 > 50 秒 (0x2FAF080 = 50,000,000 * 100ns)
4. 检查 PID > 4 (排除 System)
5. sub_4BCC -> ObOpenObjectByPointer(0x200) -> 读映像名
6. sub_5860 -> ObOpenObjectByPointer(0x200) -> 读 PEB
7. 字符串匹配检查
```

### kboot64.sys 关键发现

kboot64 是整个驱动栈中最危险的组件 (222K, 最大):
- **cm_callback(0.85)** @ 0x1853F -- 注册表保护
- **apc_inject(0.8)** -- APC 注入能力
- **EPROCESS offset 写入** -- DKOM 能力
- **MmGetSystemRoutineAddress** -- 动态 API 解析
- 540 函数, 1412 节点, 1840 边, 87 条链
- 之前文档怀疑 evil handle 可能来自 kboot64, 现在 ppm 确认它具备 CmCallback + APC + DKOM 全套能力

### kshutdown64.sys + kshut64.dll 双路径确认

**内核路径 (kshutdown64.sys):**
- `apc_inject(0.8)` -- PsSetCreateProcessNotifyRoutine + KeInitializeApc + KeInsertQueueApc + ZwAllocateVirtualMemory
- ProcessNotify 触发 -> ZwOpenProcess -> ZwAllocateVirtualMemory -> KeInsertQueueApc -> 目标进程执行 ExitProcess

**用户态路径 (kshut64.dll):**
- 注入 winlogon.exe, 等待 kshutdown64.sys 的 Event 信号
- 收到信号后: OpenProcess + TerminateProcess (主路径)
- 备用: SuspendThread -> VirtualAlloc -> SetThreadContext -> ResumeThread (线程劫持)
- 黑名单来源: RegOpenKeyExW + RegQueryValueExW 读 `HKLM\SYSTEM\CurrentControlSet\shut`
- 带 WS2_32 网络能力, 可能直接与服务端通信

### 防御优先级 (基于自动化分析)

```
1. ksafecenter64 -- /disable ObCallback + /ndisable ProcessNotify (盲化传感器)
2. kshutdown64   -- /ndisable ProcessNotify (断内核APC触发链)
3. kboot64       -- /force-stop (最危险但非核心攻击链)
4. kshut64.dll   -- /wluninject (断用户态备用路径)
5. kcachec64     -- /ndisable ProcessNotify (清除辅助监控)
```

### Evil Handle 根因与 VBox 修复方案 (ppm 确认)

**问题链条:**
```
VBoxSup 启动时扫描 System(PID 4) 句柄表
  → 发现 0x200 或 0x1FFFFF 的句柄指向 VBox 进程
  → 判定为 evil handle → VERR_SUP_VP_FOUND_EVIL_HANDLE (-3738)
  → VBox 拒绝启动
```

**ppm 确认的根因:**
```
ksafecenter64 PreOp (0x78B8)
  → 每次有进程 OpenProcess 时触发
  → 调用 IsProtectedPid (0x7600)
  → 内部 ObOpenObjectByPointer(DesiredAccess=0x200) 创建瞬态句柄
  → ZwQueryInformationProcess 读进程信息
  → ZwClose 关闭句柄
  → 句柄只存在微秒级窗口，但 VBoxSup 扫描恰好命中
```

**为什么 `/handle-close` 无效:**
句柄是瞬态竞态产物（微秒级生命周期），`/handle-close` 追不上。
即使关了一个，下一次 OpenProcess 触发 PreOp 又会产生新的。

**正确修复: 断源头（2 条命令）**
```bash
ObMaster /obcb                    # 找到 ksafecenter64 PreOp 地址
ObMaster /disable <PreOp_addr>    # 清零 PreOp → IsProtectedPid 永不调用 → 无瞬态句柄
```

### 僵尸驱动完整分析 (ppm v0.2.2 深度分析 + 2026-04-11 更新)

#### ppm-engine 分析结论

```
ksafecenter64.sys: PE64_DRIVER, x64, packed=False
  Imports: 94 from 2 libraries (ntoskrnl.exe + FLTMGR.SYS)
  Functions: 252, roots: 21
  Depgraph: 539 nodes, 528 edges
  Patterns: cm_callback (0.85), ob_callback (0.75)
  Chains: 18 (handle manipulation ×6, callback reg ×4, ob_callback ×4, cm_callback ×4)
  Type: protection_minifilter
  Self-protection:
    - No DriverUnload export — 不可正常卸载
    - Registry callback — 保护自己的注册表键
    - Object callbacks — 可剥夺 handle 访问权限
```

#### 四层防护架构 (ppm depgraph 确认)

DriverEntry (`sub_1458`) 注册四层防护，顺序为：

```
sub_1458 (DriverEntry)
  ├─ sub_15A8 → IoCreateDevice("\Device\SafeCenter", "\Device\SFFireWall")
  ├─ sub_69B4 → PsSetLoadImageNotifyRoutine    ← 层1: DLL 加载监控
  ├─ sub_7938 → sub_74FC → ObRegisterCallbacks  ← 层2: handle 访问拦截
  ├─ sub_7A08 → CmRegisterCallbackEx            ← 层3: 注册表保护
  └─ (FltRegisterFilter 在 sub_221C 子树)       ← 层4: 文件系统过滤
```

#### 死代码证据 — 清理函数存在但从未被调用

| 函数 | 功能 | 调用者 |
|------|------|--------|
| `sub_7894` → `ObUnRegisterCallbacks` | 注销 ObCallback | **无！死代码** |
| `FltUnregisterFilter` | 注销 minifilter | **无调用链到达** |
| `PsRemoveLoadImageNotifyRoutine` | 注销 notify | **无调用链到达** |

驱动导入了 `ObUnRegisterCallbacks`、`FltUnregisterFilter`、`PsRemoveLoadImageNotifyRoutine`
三个注销 API，但 ppm depgraph `who_calls` 确认：**所有注销函数都是死代码，没有任何执行路径会调用它们**。

这意味着即使有 DriverUnload，它也不会做任何清理 — 开发者写了注销代码但从未接线。

#### 为什么变僵尸 — 五层死锁

**第 1 层：无 DriverUnload**
```
DriverObject->DriverUnload = NULL
→ NtUnloadDriver 直接拒绝: STATUS_INVALID_DEVICE_REQUEST
→ sc stop / net stop 报 error 1052
```

**第 2 层：DeviceObject 残留**
```
/force-stop 写入 DriverUnload stub (xor eax,eax; ret)
→ NtUnloadDriver 调用 stub → return 0
→ IopUnloadDriver 检查 DriverObject->DeviceObject != NULL
→ 设备 \Device\SafeCenter + \Device\SFFireWall 还在
→ 拒绝释放 DRIVER_OBJECT → 僵尸
```

**第 3 层：CmCallback 注册表死锁**
```
/drv-unload 走 SCM 路径 (ControlService SERVICE_CONTROL_STOP)
→ SCM 需要修改 HKLM\...\Services\ksafecenter64
→ CmCallback (sub_7A08, cookie at RVA 0x15A58) 拦截
→ STATUS_ACCESS_DENIED (0xC0000022)
→ OpenService 失败: error 5
```

**第 4 层：ObCallback 句柄保护**
```
即使绕过注册表保护，尝试 OpenProcess 杀进程
→ ObCallback PreOp (sub_74FC) 拦截
→ 剥夺 PROCESS_TERMINATE 权限
→ TerminateProcess 失败
```

**第 5 层：ImageNotify 监控重生**
```
PsSetLoadImageNotifyRoutine (sub_69B4)
→ 监控所有 DLL/EXE 加载
→ 可在进程启动时立即注入保护
→ 杀了用户态组件也能重建
```

#### PointerCount 引用来源 (ppm 逐层确认)
```
+1  DRIVER_OBJECT body (始终存在)
+1  \Device\SafeCenter (IoCreateDevice, sub_15A8)
+1  \Device\SFFireWall (IoCreateDevice, sub_15A8)
+N  ObRegisterCallbacks (sub_74FC → sub_7938)
+1  CmRegisterCallbackEx (sub_7A08, cookie at RVA 0x15A58)
+1  FltRegisterFilter minifilter (sub_221C 子树)
+1  PsSetLoadImageNotifyRoutine (sub_69B4)
+1  Object Directory \Driver\ksafecenter64
```

#### 正确的完整卸载顺序（逆序拆引用 — "倒着拆弹"）

必须按注册的**逆序**拆除每层防护。正序拆会触发死锁或僵尸状态。

```bash
# 步骤 1. 杀 CmCallback — 解除注册表保护死锁 (最优先！)
# 不先杀这个，后面所有 SCM 操作都会被拦截
ObMaster /notify registry --kill ksafecenter64

# 步骤 2. 撤销 ObCallback — 解除句柄保护
ObMaster /obcb
ObMaster /disable <PreOp_addr>

# 步骤 3. 撤销 ImageNotify — 解除加载监控
ObMaster /notify image
ObMaster /ndisable <ksafe_image_notify_addr>

# 步骤 4. 卸 minifilter — 解除文件系统过滤
ObMaster /flt-detach ksafecenter64 C:

# 步骤 5. 删除 DeviceObject — 防止 IopUnloadDriver 僵尸检查
# (需要手动 Wr64 清零 DriverObject->DeviceObject 链)

# 步骤 6. force-stop — 此时所有引用已拆，可以安全卸载
ObMaster /force-stop ksafecenter64

# 步骤 7. 如果 auto-discovery 失败 (DKOM)，手动取地址
ObMaster /objdir \Driver
ObMaster /drv-unload ksafecenter64 <drvobj_va>
```

**关键: 不按顺序拆会变僵尸。必须先拆引用再卸载。**

**为什么必须倒序:**
```
注册顺序:  Device → ImageNotify → ObCallback → CmCallback → MiniFilter
拆除顺序:  CmCallback → ObCallback → ImageNotify → MiniFilter → Device → Unload
           ↑ 必须最先拆，否则后续 SCM 操作全部被拦截
```

#### 保护的进程 (ppm strings 确认)
```
explorer.exe     — 桌面进程（防篡改桌面快捷方式）
360chrome.exe    — 360 浏览器（网吧默认浏览器，防替换）
```

#### 保护的注册表路径
```
\Registry\Machine\SOFTWARE\kSafeCenter         — 配置
\Registry\Machine\System\CurrentControlSet      — 服务注册表
```

#### 文件系统过滤 (FsFilter1)
ppm 字符串确认驱动包含完整的目录枚举过滤：
```
CleanFileFullDirectoryInformation       — 隐藏文件（完整信息查询）
CleanFileBothDirectoryInformation       — 隐藏文件（双信息查询）
CleanFileDirectoryInformation           — 隐藏文件（基本查询）
CleanFileIdFullDirectoryInformation     — 隐藏文件（带 FileId）
CleanFileIdBothDirectoryInformation     — 隐藏文件（带 FileId 双查询）
CleanFileNamesInformation               — 隐藏文件名
```
这意味着 ksafecenter64 可以在 `FindFirstFile/FindNextFile` 层面隐藏任意文件。

---

## 多驱动拆除顺序（全栈卸载）

云更新驱动栈有**交叉保护**：ksafecenter64 保护注册表 → kboot64 也保护注册表 →
kshutdown64 依赖 ksafecenter64 的 ObCallback 保护 → 必须按正确顺序拆。

### 拆除优先级（由高到低）

```
Phase 1: 解除保护层（不卸载驱动，只拆回调）
─────────────────────────────────────────────
① ksafecenter64  CmCallback     /notify registry --kill ksafecenter64
② kboot64        CmCallback     /notify registry --kill kboot64
   ↑ 必须最先拆这两个，否则后续所有 SCM/注册表操作被拦截

③ ksafecenter64  ObCallback     /obcb → /disable <PreOp_addr>
   ↑ 拆完后 OpenProcess 不再被剥夺权限

④ ksafecenter64  ImageNotify    /notify image → /ndisable <addr>
⑤ kshutdown64    ProcessNotify  /notify process → /ndisable <addr>
⑥ kshutdown64    ImageNotify    /notify image → /ndisable <addr>
⑦ kboot64        ProcessNotify  /notify process → /ndisable <addr>
⑧ kboot64        ImageNotify    /notify image → /ndisable <addr>
⑨ kcachec64      ProcessNotify  /notify process → /ndisable <addr>

⑩ ksafecenter64  MiniFilter     /flt-detach ksafecenter64 C:
   ↑ 文件系统过滤最后拆（影响最小）

Phase 2: 卸载驱动（引用已清零，安全卸载）
─────────────────────────────────────────────
⑪ ksafecenter64   /force-stop ksafecenter64
⑫ kshutdown64     /force-stop kshutdown64
⑬ kboot64         /force-stop kboot64
⑭ kcachec64       /force-stop kcachec64

Phase 3: 非保护驱动（无回调，直接卸）
─────────────────────────────────────────────
⑮ krestore64      /force-stop krestore64
⑯ KScsiDisk64     /force-stop KScsiDisk64
⑰ kdisk64         /force-stop kdisk64
⑱ kantiarp64      /force-stop kantiarp64
⑲ kpowershutdown64  /force-stop kpowershutdown64
```

### 为什么这个顺序

| 规则 | 原因 |
|------|------|
| CmCallback 最先拆 | 它锁住注册表，不拆它后续 SCM 全部 ACCESS_DENIED |
| ObCallback 第二拆 | 它拦截 OpenProcess，不拆它杀不了用户态进程 |
| Notify 第三拆 | 它监控进程/DLL 加载，不拆它保护组件会重生 |
| MiniFilter 第四拆 | 文件隐藏，影响最小但阻碍取证 |
| ksafecenter64 先于 kshutdown64 | kshutdown 依赖 ksafe 的 ObCallback 保护 |
| kboot64 和 ksafe 并列 | 两者都有 CmCallback，互相掩护 |
| 非保护驱动最后 | 无回调，直接 force-stop 无风险 |

### 系统级 minifilter 干扰因素

fltmc 列表中还有非云更新的 filter 会影响拆除：

| Filter | Altitude | 来源 | 影响 |
|--------|----------|------|------|
| **WdFilter** | 328010 | Windows Defender | 可能拦截驱动卸载/可疑操作 |
| **mfehidk** | 321300 | McAfee | 可能拦截注册表/进程操作 |
| **gameflt** | 189850 | 游戏反作弊 | 可能与 vgk64 联动 |

**WdFilter 处理**：

首选 — 添加排除规则（不需要卸载）：
```bash
# 以 SYSTEM 权限写入 Defender 排除规则（普通 Admin 写入失败）
ObMaster /runas system reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes" /v VirtualBoxVM.exe /t REG_DWORD /d 0 /f
ObMaster /runas system reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "C:\Program Files\Oracle\VirtualBox" /t REG_DWORD /d 0 /f
```

备选 — 排除规则不够时的升级手段：
- 如果 WdFilter ObCallback 仍然拦截 VBox，用 `/disable` 清零 Pre 指针（参见 VBOX_DEBUG.md）
- 实战前 `sc stop WinDefend` 或组策略关闭 Defender 实时保护
- 如果 WdFilter 拦截了 ObMaster 操作，用 `/flt-detach WdFilter C:` 临时卸载
- WdFilter 有 8 个实例（所有卷），需要逐卷 detach

**ksafecenter64 minifilter 状态**：
- fltmc 中未出现（FltStartFiltering 可能未执行或注册失败）
- 驱动代码中有 `FltRegisterFilter` 但 ppm 显示 `FltUnregisterFilter` 无调用者
- 如果已激活，需要在 Phase 1 步骤 ⑩ 中 detach

### 注意事项
- WdFilter 不需要卸载，添加 Defender 排除规则即可（见上方命令）
- vgk64.sys（Valorant Vanguard）独立于云更新，有自己的保护体系，需要单独处理
- 如果任何 `/force-stop` 后驱动变僵尸，用 `/objdir \Driver` 取 DRIVER_OBJECT VA，
  再用 `/drv-unload <name> <va>` 走 patch DriverUnload 路径
- 拆除过程中不要重启 — 重启后所有驱动自动重新加载注册回调

---

## 待完成

### 逆向分析
- [x] 反汇编 kshut64.dll `GetPrivateProfileStringW` — config.ini 只存 serverip，不含黑名单
- [x] 确认黑名单来源 — 注册表 `HKLM\SYSTEM\CurrentControlSet` value `shut`（RegQueryValueExW 0x180005CEA，RegOpenKeyExW 0x180005CAA）
- [x] 分析 kcachec64.sys -- ppm 确认: process_monitor, ProcessNotify, MmGetSystemRoutineAddress, 无 DriverUnload
- [ ] 找到 kshutdown64 设备名（IoCreateDevice，名称未明文出现，可能动态构造）

### 沙盒演习（用户态）
- [x] 铁三角用户态模拟器（`test/sim_ksafe_blacklist/`）
- [x] 完整攻击链演习：SimServer push → SimKshutdown2 KILL → SetEvent → SimKshut64
- [x] SimKsafecenter2 句柄重开压测（×5）
- [x] PPL 防御演习：`/make-ppl 0x72` 挡住用户态 TerminateProcess 路径

### 真实驱动实战（路线一）
- [ ] 加载真实 kshutdown64.sys（SCM），触发内核 APC 路径
- [ ] 验证 PPL 是否挡住 `ZwOpenProcess(PROCESS_VM_OPERATION)` from kernel context
- [ ] 验证 `/ndisable` 能否盲化 kshutdown64 的 PsCreateProcessNotifyRoutine
- [ ] 加载真实 ksafecenter64.sys，验证 ObCallback PreOp 的零窗口拦截

### 真实 ObCallback PreOp 模拟（路线二）
- [ ] ObMaster 加 `/obcb-install` 注册真实 PreOp 回调（模拟 ksafecenter64）
- [ ] 用 ObMaster PreOp bypass 测试能否突破自己注册的回调

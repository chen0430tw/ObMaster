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

| 驱动 | 职能 | 威胁等级（对 VBox）|
|------|------|------------------|
| `ksafecenter64.sys` | ObCallback 进程保护 + LoadImage notify | 高（L1-L3）|
| `kshutdown64.sys` | 进程黑名单执行引擎（APC + notify） | 高（L4）|
| `kcachec64.sys` | CreateProcess notify + 线程监控 | 中（待分析）|
| `kpowershutdown64.sys` | 电源/关机控制 | 低 |
| `kantiarp64.sys` | ARP 防火墙 | 无直接威胁 |
| `kdisk64.sys` | 磁盘控制 | 无直接威胁 |
| `krestore64.sys` | 影子还原 | 无直接威胁 |
| `kscsidisk64.sys` | SCSI 磁盘过滤 | 无直接威胁 |
| `kboot64.sys` | 启动控制 | 无直接威胁 |

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

## 待完成

### 逆向分析
- [x] 反汇编 kshut64.dll `GetPrivateProfileStringW` — config.ini 只存 serverip，不含黑名单
- [x] 确认黑名单来源 — 注册表 `HKLM\SYSTEM\CurrentControlSet` value `shut`（RegQueryValueExW 0x180005CEA，RegOpenKeyExW 0x180005CAA）
- [ ] 分析 kcachec64.sys（已知有 CreateProcess notify，具体行为未知）
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

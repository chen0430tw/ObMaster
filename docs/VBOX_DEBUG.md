# VirtualBox + 云更新(YunGengXin)/WdFilter 冲突调试记录

**环境：** Windows 10 22H2 (build 19045), VirtualBox 7.2.6r172322, Ubuntu VM
**工具：** ObMaster.exe (RTCore64/CVE-2019-16098 BYOVD), VBoxHardening.log
**目标：** 让 Ubuntu VM 正常启动

> **⚠️ 更正（2026-03-26）：** 本文档早期将 `ksafecenter64.sys` 误判为金山安全（Kingsoft）产品的驱动。
> 经逆向分析确认，**ksafecenter64.sys 属于「云更新」（YunGengXin）网吧无盘管理系统**，
> 与金山安全毫无关系。文档中所有"金山"相关描述均指云更新产品。

---

## 问题概述

VBoxManage startvm 返回 exit code 1 (0x1) / 历史上出现过 0xc0000005。
VM 无法启动，VBoxHardening.log 记录失败原因。

---

## VirtualBox Hardening 机制

VBox 启动有三个 Respawn 阶段：

```
Respawn #0  → 初始启动
Respawn #1  → 自我净化 (self-purification)：扫描自身 DLL 段，
               修复与磁盘不符的内存字节，然后 spawn Respawn #2
Respawn #2  → 真正的 VM 初始进程；打开 VBoxSup 驱动，
               由 VBoxSup 做最终完整性检查
```

所有 Respawn 共享同一个 VBoxHardening.log 文件（不同 PID 写入）。

---

## 当前已加载的驱动

| 驱动 | 地址 | 备注 |
|------|------|------|
| ksafecenter64.sys | FFFFF8067C090000 | 云更新(YunGengXin) 网吧管理驱动，FSFilter Activity Monitor |
| kshutdown64.sys | FFFFF80661B30000 | 云更新关机控制驱动（当前 Stopped） |
| WdFilter.sys | FFFFF80649A10000 | Windows Defender minifilter |
| VBoxSup.sys | FFFFF80651480000 | VBox 支撑驱动 |
| vgk.sys | — | Valorant 游戏反作弊 |

---

## ObCallback 当前状态

```
[0] Process  Entry:FFFFC90D31C8EF40  Enabled:1  Ops:CREATE|DUPLICATE
     Pre : (none)   ← WdFilter.sys — 已用 /disable 清零 Pre 指针
[1] Process  Entry:FFFFC90D371738B0  Enabled:1  Ops:CREATE
     Pre : (none)   ← ksafecenter64.sys — 已用 /disable 清零
[2] Process  Entry:FFFFC90D49195C30  Enabled:1  Ops:CREATE|DUPLICATE
     Pre : FFFFF80651495A50  VBoxSup.sys +0x15a50  ← 正常
[3] Process  Entry:FFFFC90D33147280  Enabled:1  Ops:CREATE|DUPLICATE
     Pre : FFFFF8065BE3C42C  vgk.sys +0xc42c  ← 正常
```

**注：** WdFilter 原始 Pre 指针为 `FFFFF80649A1A2A0` (WdFilter.sys+0x3a2a0)，
已被 `/disable` 清零，**尚未恢复**。

---

## Notify Routines 状态（无云更新条目）

```
LoadImage:   [0] vgk.sys  [1] WdFilter.sys+0x3ce80  [2] ahcache.sys
Process:     [0] vgk.sys  [1] WdFilter.sys+0x3ce80  [2] ahcache.sys
Thread:      [0-1] WdFilter.sys  [2] vgk.sys  [3] nvlddmkm.sys  [4] mmcss.sys
```

**结论：** ksafecenter64（云更新驱动）不在任何 Notify Routine 中。

---

## Minifilter 状态

`fltmc filters` 中无 ksafecenter 条目（即使其服务注册在 FSFilter 组）。
`fltmc unload ksafecenter` → 0x801f0013 (FILTER_NOT_FOUND)。
ksafecenter 是 legacy 内核驱动，非真正 FltMgr minifilter。

---

## Windows Defender 排除规则（已添加）

```
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes
    VirtualBoxVM.exe = 0

HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
    C:\Program Files\Oracle\VirtualBox = 0
```

用 `/runas system` 以 SYSTEM 权限写入（普通 Admin 写入失败）。

---

## 调试进展时间线

### 阶段 1：初始状态（无任何干预）

- VBoxHardening.log: **325 行**
- Respawn#1 在 WinSxS 行附近死亡
- 云更新(ksafecenter64) ObCallback (Entry[1]) 阻止了 VBox 的关键调用

### 阶段 2：禁用云更新 ObCallback (`/disable ksafecenter_addr`)

- VBoxHardening.log: **441 行**
- Respawn#1 走得更远，但仍然死亡
- 发现 ntdll.text (RVA=0x1000, 10 bytes) 被异步 hook

### 阶段 3：禁用 WdFilter ObCallback Pre (`/disable FFFFF80649A1A2A0`)

- VBoxHardening.log: **601 行**
- Respawn#1 完成 self-purification：
  - 修复 VirtualBoxVM.exe `.00cfg` 段 (0x30 bytes at 0x00007ff7eed77000)
  - 修复 VirtualBoxVM.exe `.rsrc` 段 PADDINGXXPADDING (0x490 bytes at 0x00007ff7eeda8b70)
- **Respawn#2 仍然在写任何日志前就 crash (0xc0000005)**

**根因分析：** WdFilter 的 **LoadImage notify** (WdFilter.sys+0x3ce80) 仍然活跃，
在 Respawn#2 的 ntdll.dll 被映射时注入 inline hook。VBox purification
完成后，hook 被重新注入，Respawn#2 启动即 crash。

### 阶段 4：添加 Windows Defender 排除规则

- VBoxHardening.log: **1632 行** ← 大幅进步
- **Respawn#2 成功启动并写日志！**
- WdFilter 的 LoadImage notify 检查排除列表，跳过了 VirtualBoxVM.exe 的 ntdll hook
- **新错误 (error -3738)：**

```
Found evil handle to budding VM process:
  pid=0000000000000004  h=0000000000053004
  acc=0x1fffff  attr=0x0  type=process (7)  [System]
```

---

## 当前阻塞问题：Evil Handle from System Process

**VBoxSup.sys 在 Respawn#2 做最终完整性检查时，发现 System 进程 (PID 4)
持有对 VirtualBoxVM.exe 的 PROCESS_ALL_ACCESS (0x1fffff) 句柄。**

VBox 拒绝继续启动（VERR_SUP_VP_FOUND_EVIL_HANDLE, -3738）。

### 句柄来源分析

- PID 4 = System 进程 = 内核驱动的执行上下文
- 句柄由 **ksafecenter64.sys**（云更新驱动）从内核态打开（绕过用户态 API）
- VBoxSup 的 ObCallback PreOp 不 strip 内核态打开的句柄
- 句柄值每次 Respawn#2 创建时不同（0x50bb8, 0x53004, ...）
- **逆向分析确认**：属于竞态瞬态句柄，详见下方"ksafecenter64.sys 逆向分析"节

### 尝试过的解决方案

| 方法 | 结果 |
|------|------|
| `sc stop ksafecenter` | 失败，error 1052（服务不接受 Stop 命令） |
| `sc stop kshutdown` | 已经是 Stopped 状态 |
| `fltmc unload ksafecenter` | 失败，0x801f0013 (FILTER_NOT_FOUND) |
| PowerShell `OpenProcess(PID=4, PROCESS_DUP_HANDLE)` as SYSTEM | 失败，ERROR_ACCESS_DENIED (5) |
| 搜索云更新注册表白名单 | HKLM\SOFTWARE\Kingsoft 不存在；无安装目录（当时误以为金山产品） |

### 系统进程关键地址

```
System (PID 4) EPROCESS:  0xFFFF9501BE8BA040
EPROCESS+0x570 HandleTable ptr: 0xFFFFC90D30A35C80
```

---

## 下一步方案

### 方案 A：RTCore64 走核心句柄表，清零 evil handle 条目

1. 读取 System EPROCESS.HandleTable (0xFFFFC90D30A35C80)
2. 解析 HANDLE_TABLE 结构（可能是 3 级树）：
   - handle 0x53004 → index = 0x53004/4 = 85761
   - L0_idx = 85761 % 256 = 225
   - L1_idx = (85761/256) % 256 = 79
   - L2_idx = 85761 / 65536 = 1
3. 用 RTCore64 读取各级指针，定位 handle entry
4. 清零该 entry（16 bytes：Object指针 + AccessMask等）

**风险：** ksafecenter 可能立即重新打开句柄；每次 handle 值不同需动态计算

### 方案 B：修改 ksafecenter64 start type → DISABLED，重启

```
HKLM\SYSTEM\CurrentControlSet\Services\ksafecenter → Start = 4
```

需要重启机器，但彻底解决问题。

### 方案 C：内存 patch VBoxSup.sys 的 handle 检查

定位 VBoxSup.sys (base=FFFFF80651480000) 中检查 PID=4 句柄的代码，
用 RTCore64 patch 使其跳过来自 System 进程的 handle。

**风险：** 需要逆向 VBoxSup，修改内核代码有 BSOD 风险。

### 方案 D：内存 patch ksafecenter64.sys 中打开句柄的代码

定位 ksafecenter64.sys 中调用 `ObOpenObjectByPointer`/`PsLookupProcessByProcessId`
的位置，patch 使其不打开 VirtualBoxVM.exe 的句柄。

**风险：** 需要逆向 ksafecenter64.sys（闭源）。

---

## 关键技术细节

### EPROCESS 字段偏移（Windows 10 22H2 build 19045）

| 字段 | 偏移 |
|------|------|
| UniqueProcessId | +0x440 |
| ActiveProcessLinks | +0x448 |
| HandleTable | +0x570 |
| ImageFileName | +0x5a8 |
| Protection | +0x87a |

### OB_CALLBACK_ENTRY 偏移

| 字段 | 偏移 |
|------|------|
| Enabled | +0x014 |
| PreOperation | +0x028 |
| PostOperation | +0x030 |

### RTCore64 IOCTL

- Device: `\\.\RTCore64`
- IOCTL_READ: `0x80002048`
- IOCTL_WRITE: `0x8000204c`
- Struct (48 bytes): Pad0[8] + Address[8] + Pad1[8] + Size[4] + Value[4] + Pad2[16]
- 最大单次操作：4 bytes (DWORD)；64-bit 值需两次写入

### Windows HANDLE_TABLE 结构

句柄值到表项的计算（64位 Windows）：

```
index   = handle_value >> 2
L0_idx  = index % 256          # 第0级索引（叶节点）
L1_idx  = (index / 256) % 256  # 第1级索引
L2_idx  = index / 65536        # 第2级索引（根节点）

每个表项 (HANDLE_TABLE_ENTRY): 16 bytes
  [0..7]  ObjectPointer (低3位有标志位，清零后得对象地址)
  [8..15] GrantedAccessBits 等
```

---

## 模拟环境（sim_evil_handle）

为在非 VirtualBox 环境下复现和测试 evil handle 检测逻辑，编写了两个模拟程序：

**位置：** `D:\ObMaster\test\sim_evil_handle\`

### SimKsafe.exe — 模拟 ksafecenter64.sys 行为

```
SimKsafe.exe <pid|name>
```

对目标进程调用 `OpenProcess(PROCESS_ALL_ACCESS)`，持有句柄不关闭（按 Enter 释放）。
模拟 ksafecenter64.sys 从内核态对 VirtualBoxVM.exe 开句柄的效果。

### SimVBox.exe — 模拟 VBoxSup.sys 的 evil handle 检测

```
SimVBox.exe [--once]
```

---

## BSOD 分析报告（2026-03-26）

### 三次蓝屏事件

今日共发生 3 次 BSOD，WER 报告及 Minidump 已确认。

#### BSOD 1（05:56）— STOP 0xBE

```
故障模块: RTCore64!unknown_function
STOP code: 0xBE = ATTEMPTED_WRITE_TO_READONLY_MEMORY
P2 (写入地址): 0xFFFFF80127ED31B4 = ksafecenter64.sys + 0x31B4
```

**根因：** 上个会话的 `/patch` 命令用 `Wr8` 逐字节写入 ksafecenter64 代码页。
内核代码页的 PTE 没有 Write 位（W^X 执行保护），RTCore64 直接虚拟写入时
触发 CPU 写保护 → STOP 0xBE。

---

#### BSOD 2（11:45）+ BSOD 3（12:25）— 同一 bug

```
故障模块: RTCore64!unknown_function+0x14DB
STOP code: 0x3B = SYSTEM_SERVICE_EXCEPTION
P2: 0xC0000005 = STATUS_ACCESS_VIOLATION
P3 BSOD2: 0xFFFFF80644DC14DB = RTCore64_base_1 + 0x14DB
P3 BSOD3: 0xFFFFF80176B814DB = RTCore64_base_2 + 0x14DB  (KASLR重载，偏移一致)
```

**根因：** `/safepatch` 调用 `GetMmPteBase()` → `KernelExport("MmPteBase")` 返回 0
→ `g_drv->Rd64(0)` 让 RTCore64 读内核地址 0 → ACCESS_VIOLATION → STOP 0x3B。

调用链：

```
GetMmPteBase()
  -> KUtil::KernelExport("MmPteBase")
       -> LoadLibraryW("ntoskrnl.exe")   返回 NULL（OS 拦截，error 2）
       -> return 0;                      不做 null 检查直接返回 0
  -> g_drv->Rd64(0)                      RTCore64 读地址 0 -> AV -> BSOD
```

---

### 根因分析

#### 问题 1：LoadLibraryW 加载 ntoskrnl.exe 被拦截

Windows 10 故意对 ntoskrnl.exe 返回 ERROR_FILE_NOT_FOUND (error 2)，
即使文件位于 C:\Windows\System32\ 并且确实存在。
`LoadLibraryExW` 加任何 flag 同样失败（测试了 LOAD_LIBRARY_AS_IMAGE_RESOURCE / LOAD_LIBRARY_AS_DATAFILE）。

**修复（已提交）：** `kutil.cpp` 改用 `CreateFile` + 手动解析 PE 导出表（`ParseExport` 函数），
完全绕过 LoadLibrary。

#### 问题 2：MmPteBase 不在 ntoskrnl.exe 导出表

尽管文档记载 Windows 10 RS3 (build 16299) 起导出 `MmPteBase`，
但在 **build 19045 (22H2)** 上，ntoskrnl.exe 的 Export Directory（3070 个条目）
**不含 MmPteBase**，`GetProcAddress` 会返回 NULL。

#### 问题 3：MmPteBase 定位方案

扫描 ntoskrnl.exe `.text` 节所有 `MOV r64,[RIP+offset]` 指令，
统计指向 `.data` 节的引用次数：

```
.data RVA    引用次数   候选变量
0x00C124D0   1302      MmPteBase（高度疑似，比第二名高 65 倍）
0x00C01AA8   20        其他内核全局
0x00C04F48   20        其他内核全局
```

MmPteBase 全局变量 VA = ntoskrnl_base + 0xC124D0
当前系统值：0xFFFFF80639000000 + 0xC124D0 = 0xFFFFF80639C124D0（待 Rd64 验证）

---

#### BSOD 4（13:12）— STOP 0xBE（第二次只读写入）

```
故障模块: RTCore64!unknown_function
STOP code: 0xBE = ATTEMPTED_WRITE_TO_READONLY_MEMORY
P2 (写入地址): 0xFFFFF806F08C0010 = RTCore64_base + 0x10
```

**根因：** `/safepatch` 在影子页失败后回落到 `Wr32` 直接写 RTCore64 自身代码页。
代码页 PTE.Write=0 → STOP 0xBE。

**修复：** 移除 Wr32 回落路径，影子页失败时直接报错退出，不做任何内核写入。

---

#### BSOD 5（13:59）— STOP 0x50（页面错误）

```
故障模块: RTCore64!unknown_function
STOP code: 0x50 = PAGE_FAULT_IN_NONPAGED_AREA
P2 (错误地址): 0xFFFFF806F08C0010 = RTCore64_base + 0x10
P3: 0 = 读操作
P4 (崩溃 RIP): 0xFFFFF8082CCB14F6
```

**根因：** WritePte 的三步写产生了 Present=0 竞态窗口：

```
步骤1: Wr32(pteVA,   lo & ~1)  ← Present=0  ← 其他CPU执行RTCore64代码 → PAGE_FAULT
步骤2: Wr32(pteVA+4, hi_new)
步骤3: Wr32(pteVA,   lo)       ← Present=1 恢复（但已经太晚了）
```

另一个根本错误：**以 RTCore64 自身代码页为测试目标**。RTCore64 正在执行
（处理我们的 IOCTL），另一个 CPU 核必然在访问其代码 → 竞态不可避免。

**修复：**
1. WritePte 改为 hi→lo 两步写，避免 Present=0 窗口：
   - Step 1: `Wr32(pteVA+4, hi_new)` — 高位先写，PTE 仍 Present=1（旧低位）
   - Step 2: `Wr32(pteVA,   lo_new)` — 低位写入，PTE 完整更新
2. 禁止使用 RTCore64 自身地址作为 safepatch 测试目标

---

### 所有 BSOD 总结与修复状态

| # | 时间 | STOP | 地址 | 根因 | 修复状态 |
|---|------|------|------|------|----------|
| 1 | 05:56 | 0xBE | ksafecenter+0x31B4 | `/patch` Wr8 逐字节写只读页 | 已弃用 `/patch` |
| 2 | 11:45 | 0x3B | RTCore64+0x14DB | `Rd64(0)`（LoadLibrary 失败） | 已修复 ParseExport+null检查 |
| 3 | 12:25 | 0x3B | RTCore64+0x14DB | 同上 | 同上 |
| 4 | 13:12 | 0xBE | RTCore64+0x10 | safepatch Wr32 回落写只读页 | 已修复 移除Wr32回落 |
| 5 | 13:59 | 0x50 | RTCore64+0x10 | WritePte 3步写 Present=0 竞态 | 已修复 改hi→lo 2步写 |

---

### 修复进度

| 修复项 | 状态 |
|--------|------|
| kutil.cpp: LoadLibrary 改为 PE 磁盘手动解析 | 已完成 |
| pte.cpp: GetMmPteBase null 检查（防止 Rd64(0)）| 已有 |
| pte.cpp: MmPteBase 签名扫描 fallback（.text 引用计数）| 已完成 |
| cmd_safepatch.cpp: 移除 Wr32 回落路径 | 已完成 |
| pte.cpp: WritePte 改 hi→lo 2步写（消除 Present=0 窗口）| 已完成 |

---

### 下一步

1. 启动 RTCore64，验证 MmPteBase 扫描输出正确值（应落在 0xFFFF????00000000）
2. 用非 RTCore64 目标测试 /safepatch 机制（如 ksafecenter64 或其他驱动）
3. 加载 ksafecenter64，执行 `/safepatch <ksafe_base+0x31B4> 33C0C390`
4. 验证 VirtualBox 不再出现 evil handle

每隔 1 秒（或 `--once` 只扫一次）：

1. 对自身调用 `OpenProcess(PROCESS_ALL_ACCESS)` 获取已知句柄值
2. 用 `NtQuerySystemInformation` class 64（`SystemExtendedHandleInformation`）拿全系统句柄快照
3. 在快照中按 **64-bit 句柄值**（无 USHORT 截断）定位自身 EPROCESS 指针和 ObjectTypeIndex
4. 扫描快照，找来自非自身/非父进程、指向同一 EPROCESS 的句柄 → 报告为 evil handle

**检测输出示例：**
```
[pass 1] Scanning...
  [!] Evil handle:
      pid=4       (System)
      h=0x57EC  acc=0x102a  type=7
  VERR_SUP_VP_FOUND_EVIL_HANDLE (-3738) — 1 handle(s)
```

### 技术要点

- **必须用 class 64**（SystemExtendedHandleInformation），class 16 的 HandleValue 是 USHORT，在 Cygwin/bash 环境下句柄值超过 0xFFFF 时匹配失败
- **必须先 OpenProcess 再拍快照**：快照是静态的，hSelf 必须已存在才能被记录进去
- **用 Object 指针匹配**，而非 DuplicateHandle（DuplicateHandle 对全系统句柄做 O(N) 调用太慢）

### 构建

```
D:\ObMaster\test\sim_evil_handle\build_sim.bat
```

使用与主项目相同的 MSVC 工具链（do_build2.bat 同款路径）。

### 逆向工具安装（WSL）

Ubuntu 22.04 apt 源的 radare2 包损坏，需通过 snap 安装：

```bash
# 安装
wsl sudo snap install radare2 --classic

# 将 /snap/bin 加入 PATH 并设 r2 别名（持久化到 ~/.bashrc）
wsl bash -c "echo 'export PATH=\"/snap/bin:\$PATH\"' >> ~/.bashrc"
wsl bash -c "echo 'alias r2=\"snap run radare2\"' >> ~/.bashrc"

# 新开 WSL session 后直接用：
wsl r2 -v
# 当前 session 临时用：
wsl snap run radare2 -v
```

**snap vs apt：**
- apt：Ubuntu/Debian 官方仓库，包放 `/usr/bin/`，直接调用
- snap：Canonical 的独立包管理，沙盒运行，包放 `/snap/bin/`；Ubuntu 22.04 apt 源的 radare2 包损坏，只能走 snap
- snap 安装的程序默认不在 PATH，需手动加 `/snap/bin` 或用 `snap run <name>`
- radare2 作者 pancake 自己维护 snap 包（当前 6.1.0），比 apt 版本更新更稳定

---

## 未解决的问题

1. **WdFilter ObCallback Pre 指针未恢复**
   原值 `FFFFF80649A1A2A0` 应写入 `FFFFC90D31C8EF68`（Entry[0] +0x028）。
   Python 无法从 bash 上下文打开 `\\.\RTCore64` (err=2)。
   需要通过 ObMaster.exe 自身完成写入。

2. **Evil handle 根本解决方案**
   ksafecenter64.sys 无法通过 SC Manager 停止，无法通过 fltmc 卸载。
   需要内核级操作（方案 A/B/C/D 之一）。

3. **ksafecenter64.sys 打开句柄的具体代码路径**
   已通过逆向分析找到，见下方"ksafecenter64.sys 逆向分析"节。

---

## ksafecenter64.sys 逆向分析（2026-03-26）

**样本来源：** 云更新 v2025.6.15.23946 客户端包（Standard_x64_..._Setup.zip → Client_x64...Setup.exe）
**文件大小：** 61608 bytes，x64 PE，编译时间 2025-08-21 11:07:29 UTC
**签名：** WHQL（Microsoft Windows Hardware Compatibility Publisher，2025-10-09 到期）
**文件位置：** `D:\ObMaster\docs\ksafecenter64.sys`

### 运行时地址（本机测试，每次开机可能不同）

```
驱动基址:   FFFFF80127ED0000
PreOp CB:   FFFFF80127ED78B8  (+0x78B8)
Ob Entry:   FFFFD10E608DD930
```

### ObRegisterCallbacks 配置

- **ObjectType**: `PsProcessType`（仅监控进程对象）
- **Operations**: `OB_OPERATION_HANDLE_CREATE`（不处理 DUPLICATE）
- **OperationRegistrationCount**: 1
- **Altitude 冲突重试**: 最多 10 次（STATUS_FLT_INSTANCE_ALTITUDE_COLLISION 时递增）
- **注册函数**: `fcn.1400074fc` @ 静态 +0x4FC

### PreOperation Callback（静态 +0x78B8）

回调在以下条件下**直接跳过（不修改权限）**：

1. 句柄是内核句柄（`Flags & OBJ_KERNEL_HANDLE`）
2. 当前 IRQL ≥ DISPATCH_LEVEL（CR8 ≥ 2）
3. 操作不是 HANDLE_CREATE（是 DUPLICATE 则跳过）
4. `OriginalDesiredAccess` 不包含 `PROCESS_TERMINATE (0x1)`
5. 目标 PID 不在保护名单中（`IsProtectedPid()` 返回 false）

满足所有条件时，剥夺以下权限位：

| 权限位 | 值 | 说明 |
|--------|-----|------|
| PROCESS_TERMINATE | 0x001 | 终止进程 |
| PROCESS_VM_OPERATION | 0x008 | 修改内存 |
| PROCESS_VM_READ | 0x010 | 读取内存 |
| PROCESS_VM_WRITE | 0x020 | 写入内存 |
| PROCESS_SUSPEND_RESUME | 0x800 | 挂起/恢复 |

### Evil Handle 来源：IsProtectedPid 内部的瞬态 Kernel Handle

ObCallback 内部调用链：

```
PreOp callback (+0x78B8)
  └─ IsProtectedPid(targetPid)  [fcn.140007600, +0x7600]
       └─ fcn.140005860(EPROCESS_ptr, ...)
            ├─ ObOpenObjectByPointer(EPROCESS, OBJ_KERNEL_HANDLE=0x200,
            │                        NULL, DesiredAccess=0, NULL,
            │                        KernelMode, &hOut)
            │   → 在 System(PID 4) 句柄表中创建 ALL_ACCESS (0x1fffff) 句柄
            ├─ ZwQueryInformationProcess(hOut, 0, ...)   // 读基本信息
            ├─ KeStackAttachProcess(EPROCESS_ptr, ...)   // 附着目标进程
            ├─ ... 读 PEB / 进程镜像名 ...
            ├─ KeUnstackDetachProcess(...)
            └─ ZwClose(hOut)   ← 关闭，但窗口期内 VBoxSup 可能已扫描到
```

**关键结论**：
- evil handle 是**竞态瞬态句柄**，非持久句柄
- 句柄在 `ObOpenObjectByPointer` → `ZwClose` 之间存在于 System 句柄表
- VBoxSup 的 `NtQuerySystemInformation` 扫描恰好落在此窗口时触发 -3738
- 每次 Respawn#2 创建时，新进程触发新的 OpenProcess → 新的 IsProtectedPid 调用 → 新句柄值

### SimVBox 实测验证

在本机加载 ksafecenter64.sys 后运行 SimVBox.exe --once 结果：

```
[pass 1] Scanning...
  [!] Evil handle:  pid=4  h=0x3CE8  acc=0x102a  [瞬态，ZwQueryInfo中间产物]
  [!] Evil handle:  pid=4  h=0x6E64  acc=0x102a  [同上]
  [!] Evil handle:  pid=4  h=0x7A0C  acc=0x1fffff  [ObOpenObjectByPointer ALL_ACCESS]
  [!] Evil handle:  pid=1012 (csrss)  h=0x124C  acc=0x1fffff  [正常 Windows 句柄]
  [!] Evil handle:  pid=9332 (conhost) h=0x2AC  acc=0x1fffff  [正常 Windows 句柄]
  VERR_SUP_VP_FOUND_EVIL_HANDLE (-3738) — 5 handle(s)
```

### 对 /evilfix 实现的影响

由于 evil handle 是瞬态的，方案 A（走句柄表清零）需要在竞态窗口内完成，可靠性低。
更可行的方案：

- **方案 D'（推荐）**：在 ksafecenter PreOp 回调入口处 patch 一个 `ret` 指令
  - 地址：运行时 `FFFFF80127ED78B8`（需每次动态查询）
  - 效果：回调永不执行，IsProtectedPid 不调用，不产生瞬态句柄
  - 已有机制：`/disable` 清零 Pre 指针效果相同，但每次重启需重新执行


---

## BSOD 分析报告（2026-03-26）

### 三次蓝屏事件

今日共发生 3 次 BSOD，WER 报告已确认。

#### BSOD #1（05:56）— STOP 0xBE


**根因：** 上个会话的  命令用  逐字节写入 ksafecenter64 代码页。  
内核代码页的 PTE 没有 Write 位（W^X 执行保护），RTCore64 直接虚拟写入时触发 CPU 保护 → STOP 0xBE。

---

#### BSOD #2（11:45）+ BSOD #3（12:25）— 同一 bug，STOP 0x3B


**根因：** ObMaster  调用 ，最终执行  → RTCore64 在内核态读地址 0 → ACCESS_VIOLATION → STOP 0x3B。

**调用链：**


---

### 根因分析

#### 问题 1：LoadLibraryW 加载 ntoskrnl.exe 被拦截

Windows 10 故意返回 ERROR_FILE_NOT_FOUND (error 2) 阻止用户态加载内核 DLL，即使文件存在。
 加所有 flag（、）同样失败。

**修复：** 改为  直接读取磁盘上的 ntoskrnl.exe 并手动解析 PE 导出表（ 函数）。

#### 问题 2：MmPteBase 不在 ntoskrnl.exe 导出表

尽管文档记载 Windows 10 RS3 (1709) 起添加了  导出，  
但在 **build 19045 (22H2)** 上， **不在 ntoskrnl.exe 的 Export Directory 中**（3070 个导出条目均不含它）。

#### 问题 3：MmPteBase 定位方法

通过扫描 ntoskrnl.exe  节中所有  指令，  
统计指向  节的引用次数，得到：

| .data RVA      | 引用次数 | 候选变量         |
|----------------|----------|-----------------|
|    | **1302** | MmPteBase ← 高度疑似 |
|    | 20       | 其他内核全局变量  |
|    | 20       | 其他内核全局变量  |

 全局变量 VA = ntoskrnl_base +   
当前系统：

---

### 修复进度

| 修复项 | 状态 |
|--------|------|
| : LoadLibrary → ParseExport（PE 磁盘解析） | ✅ 已修复 |
| : GetMmPteBase 加 null 检查 | ✅ 已有（pte.cpp 已含 null 检查） |
| : MmPteBase 不在导出表时的扫描 fallback | 🔄 进行中 |
|  在 RTCore64+0x14DB 崩溃 | ✅ 根因已定位（null check 会阻止）|

---

### 下一步

1. 完成  的签名扫描 fallback（用 .text 引用计数法）
2. 测试  不再崩溃
3. 加载 ksafecenter64，执行 
4. 验证 SimVBox / VirtualBox 不再出现 evil handle

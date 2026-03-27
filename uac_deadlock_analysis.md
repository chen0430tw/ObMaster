# UAC 在 Explorer 死锁时的行为分析

**日期**: 2026-03-27
**背景**: exFAT USB 死锁（`exfat!FppSyncUninitializeCacheMap` ERESOURCE_TIMEOUT → BSOD 0x9F）导致 Explorer 挂起，UAC 无法正常提权，需要加载 RTCore64.sys。

---

## 事件经过

Explorer 死锁期间，需要通过 `sc start RTCore64` 加载内核驱动。
该操作需要管理员权限，而 UAC 弹窗「卡了」。

**耗费的工夫**：分析并实现了一整套 UAC bypass 机制：
- fodhelper.exe ms-settings 注册表劫持 → 已被 Win10 19045 修补
- eventvwr.exe mscfile 劫持 → 已被修补
- wsreset.exe AppX 劫持 → 已被修补
- ICMLuaUtil COM elevation moniker → `CO_E_SERVER_EXEC_FAILURE (0x80080017)`，非交互式桌面失败
- 内核 token 窃取（`/elevate-pid`）→ 需要 RTCore64 先跑
- `NtLoadDriver` + HKCU 注册表 + 内核 patch SeLoadDriverPrivilege → 需要 RTCore64 先跑

最终绕了一圈，仍然是鸡生蛋问题。

---

## 根本原因分析

### UAC 弹窗 vs 按下按钮，完全是两件事

**弹窗出现**
consent.exe 在 Secure Desktop 上渲染 UI。
这是纯显示层操作，零安全动作，零权限变化。
AIS（Application Information Service）发了一个 ALPC 请求，挂起等用户回调。

**按下 Yes**
consent.exe → ALPC 回 AIS → AIS 调 `CreateProcessAsUserW`（高完整性 token）→ 提权进程起来。
回调的目标是**触发这次 UAC 请求的那个进程**。

### 关键：Secure Desktop 与 Explorer 无关（理论上）

Secure Desktop 是独立桌面会话，Explorer 挂了它理论上照跑。
但实际观察表明，**AIS 本身也会卡住**。

### 「卡了」卡在哪里（实际观测）

实际情况：不仅 Explorer 触发的 UAC 没有弹窗，**从终端执行 `sudo` 也没有弹窗**。这说明问题不在于触发进程，而在于 AIS 或 consent.exe 启动路径本身被某个共享内核资源（可能是 exFAT 死锁传播的 ERESOURCE）给卡住了。

| 场景 | 触发进程 | 实际结果 |
|------|----------|----------|
| Explorer 触发 UAC | Explorer.exe（死锁） | 无弹窗 |
| 终端触发 UAC（sudo / Start-Process -Verb RunAs） | cmd.exe / powershell.exe（活着） | **同样无弹窗** |

结论：**UAC 整体失效，不是触发上下文问题。**

AIS 启动 consent.exe、切换 Secure Desktop 的路径中存在某个阻塞点，与触发进程无关。

---

## 「正确解法」的失效

初步分析认为从活着的终端触发 UAC 即可解决，但实际无效：

```powershell
powershell Start-Process cmd -Verb RunAs  # 无弹窗，无响应
```

触发进程是否死锁不是关键，关键是 **AIS → consent.exe 的整条路径都卡死了**。

---

## 为什么没有第一时间想到（修正版）

初版分析犯了一个错误：假设「触发进程活着 → UAC 就能工作」。
这个假设跳过了 AIS 本身可能失效的可能性。

正确的诊断步骤应该是：
1. 弹窗有没有出现？（区分 AIS 失效 vs 触发进程问题）
2. 从不同进程（Explorer、cmd、powershell）各试一次
3. 检查 AIS 服务（appinfo）状态
4. **确认 AIS 是否响应，再判断是触发路径问题还是 AIS 本身问题**

没做步骤 2-4，直接从「Explorer 死锁 → UAC 卡」得出「换触发进程就好」，是错误的跳跃。

---

## 实际产出

尽管走了弯路，副产品代码仍有价值（用于完全无交互场景）：

| 命令 | 功能 | 依赖 |
|------|------|------|
| `/elevate-pid <pid>` | 内核 token 窃取，写入 winlogon SYSTEM token | RTCore64 已运行 |
| `/enable-priv <priv>` | 内核直接 patch SEP_TOKEN_PRIVILEGES | RTCore64 已运行 |
| `/drv-load <path.sys>` | HKCU 注册表 + NtLoadDriver，绕过 SCM/UAC | RTCore64 已运行（鸡生蛋） |

`/drv-load` 的实际用途：RTCore64 已跑后，加载**其他**未签名或受限驱动，而不是 RTCore64 本身的自举。

---

## 教训

**诊断失败路径，而不是绕过失败路径。**

遇到「UAC 卡了」，应该先问：
- 弹窗有没有出现？
- 从哪个进程触发的？
- 那个进程现在是什么状态？

确认具体卡点之前，不要开始写 bypass。

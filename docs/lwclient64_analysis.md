# 云更新客户端（B:\lwclient64）完整分析

> 分析日期：2026-04-12
> 来源：网咖服务器 B:\lwclient64\ 目录完整拷贝
> 备份位置：C:\Users\Administrator\Desktop\lwclient64_backup\
> 工具：ppm-engine v0.2.2

---

## 目录结构

B 盘是云更新（YunGengXin）网吧��理系统的客户端安装盘。
**B 盘对普通用户和管理员不可见**，只有 SYSTEM 权限才能访问（krestore64.sys 驱动层过滤）。
Explorer 和普通命令行均报 "No such file or directory"，必须用 sudo 访问。

### B 盘容量

| 目录 | 大小 | 用途 |
|------|------|------|
| pnplib | **11GB** | kboot64 的 PnP 硬件驱动库（P2P 分发，给网咖机器自动适配硬件） |
| lwclient64 | 432MB | 云更新客户端主程序和 DLL |
| gameicon | 200MB | 游戏图标资源 |
| Cloud Wallpaper | 1.4MB | 云壁纸 |
| shortcut_icon | 197KB | 快捷方式图标 |
| **合计** | **~12GB / 100GB** | |

lwclient64 是核心目录，包含所有��执行文件、DLL、配置和资源。

```
B:\lwclient64\
├── lwclient64.exe           — 主客户端进程（服务模式，Session 0）
├── kssd.exe                 — 游戏存储管理（SSD Game Manager）
├── lwhardware64.exe         — 硬件信息采集
├── khardware64_v56.exe      — 硬件管理（32位，PE32）
├── lwPersonalSetting64.exe  — 个人设置
├── ReportBSGuard64.exe      — 蓝屏防护上报
├── DesktopIcoPlace64.exe    — 桌面图标管理（27MB，最大）
├── lwClientHelper64.exe     — 客户端辅助
├── lwdesk64.exe             — 桌面管理（27MB）
├── lwgamedl64.exe           — 游戏下载
├── lwgameview64.exe         — 游戏视图
├── lwlockscreen64.exe       — 锁屏
├── lwndfinder64.exe         — 窗口查找
├── lwwebhelper64.exe        — Web 辅助
├── lwDeleteNetcard64.exe    — 网卡删除工具
├── lwDisableIGraphics64.exe — 集显禁用工具
├── lwUserDisk64.exe         — 用户磁盘
├── lwdesktopIcoplace64.exe  — 桌面图标放置
│
├── kclient64.dll            — 客户端核心库（331 imports，6286 functions）
├── kcommon64.dll            — 公共库
├── kgamemgr64.dll           — 游戏管理库（13362 functions）
├── khwsdk64.dll             — 硬件 SDK
├── kicloud64.dll            — 云服务库
├── kmsdesk64.dll            — 桌面管理库（packed）
├── kmulmonitorctrl64.dll    — 多显示器控制
├── kpowershut64.dll         — 电源/关机模块
├── kscdrv64.dll             — 驱动通信库
├── kssdeploy64.dll          — SSD 部署库
├── foldersync64.dll         — 文件夹同步
├── ExtendSDK.dll            — 扩展 SDK
├── MulMonitorCtrl.dll       — 多显示器控制（另一版本）
│
├── config\                  — 配置文件
├── skin\                    — UI 皮肤
├── lang\                    — 语言包
├── log\                     — 日志
├── plugins\                 — 插件
├── tools\                   — 工具
├── arp\                     — ARP 相关
├── lanp2p64\                — P2P 局域网传输
├── lwfunctionbar64\         — 功能栏
│
├── libcef.dll               — Chromium Embedded Framework
├── chrome_elf.dll           — Chrome ELF
├── libcurl.dll              — cURL
├── 7z.dll                   — 7-Zip
├── avcodec-57.dll           — FFmpeg 音视频
├── avformat-57.dll
├── avutil-55.dll
├── swresample-2.dll
├── swscale-4.dll
└── ... (其他第三方库)
```

---

## ppm-engine 分析结果

### 可执行文件

| 文件 | 架构 | Packed | Imports | Functions | ppm 类型 | 备注 |
|------|------|--------|---------|-----------|---------|------|
| lwclient64.exe | PE64 | ✅ | 260/13 libs | 3990 | — | 主客户端，服务模式 |
| kssd.exe | PE64 | ✅ | 735/22 libs | 17164 | generic_executable | 游戏存储管理，最多 imports |
| lwhardware64.exe | PE64 | ❌ | 274/15 libs | 8874 | — | 硬件信息 |
| khardware64_v56.exe | **PE32** | ❌ | 204/15 libs | 2649 | generic_executable | 唯一 32 位程序 |
| lwPersonalSetting64.exe | PE64 | ✅ | 727/22 libs | 15960 | — | 个人设置 |
| ReportBSGuard64.exe | PE64 | ❌ | 192/10 libs | 1967 | — | 蓝屏上报 |
| DesktopIcoPlace64.exe | PE64 | ✅ | 483/18 libs | 36719 | — | 桌面图标，最多 functions |
| lwClientHelper64.exe | PE64 | ✅ | 224/7 libs | 1369 | — | 辅助进程 |
| lwdesk64.exe | PE64 | ❌ | 561/19 libs | 40500 | — | 27MB，最多 functions (40500) |
| lwgamedl64.exe | PE64 | ✅ | 250/12 libs | 3988 | — | 游戏下载 |
| lwgameview64.exe | PE64 | ✅ | 717/21 libs | 18604 | — | 游戏视图 |
| lwlockscreen64.exe | PE64 | ✅ | 701/18 libs | 7915 | — | 锁屏 |
| lwndfinder64.exe | PE64 | ❌ | 118/5 libs | 552 | — | 窗口查找，最小 |
| lwwebhelper64.exe | PE64 | ❌ | 180/9 libs | 1433 | — | Web 辅助 |
| lwDeleteNetcard64.exe | PE64 | ❌ | 152/9 libs | 6296 | — | 网卡删除 |
| lwDisableIGraphics64.exe | PE64 | ❌ | 152/9 libs | 5160 | generic_executable | 集显禁用 |
| lwUserDisk64.exe | PE64 | ❌ | 552/18 libs | 39109 | — | 用户磁盘，第二大 (39109 functions) |
| lwdesktopIcoplace64.exe | PE64 | ✅ | 483/18 libs | 37164 | — | 桌面图标放置 |

### DLL

| 文件 | Packed | Imports | Functions | ppm 类型 | 备注 |
|------|--------|---------|-----------|---------|------|
| kclient64.dll | ❌ | 331/18 libs | 6286 | — | 核心库，最多 imports |
| kcommon64.dll | ❌ | 220/15 libs | 944 | — | 公共库 |
| kgamemgr64.dll | ❌ | 323/12 libs | 13362 | generic_library | 游戏管理，最多 functions |
| khwsdk64.dll | ❌ | 168/9 libs | 5046 | — | 硬件 SDK |
| kicloud64.dll | ❌ | 299/16 libs | 10135 | — | 云服务 |
| kmsdesk64.dll | ✅ | 21/9 libs | 25 | generic_library | packed，极少 functions |
| kmulmonitorctrl64.dll | ❌ | 165/7 libs | 1817 | — | 多显示器 |
| kpowershut64.dll | ❌ | 124/6 libs | 594 | — | 电源关机 |
| kscdrv64.dll | ❌ | 160/8 libs | 939 | — | 驱动通信 |
| kssdeploy64.dll | ❌ | 227/12 libs | 9820 | — | SSD 部署 |
| foldersync64.dll | — | — | — | — | 文件夹同步 |
| ExtendSDK.dll | — | — | — | — | 扩展 SDK |
| MulMonitorCtrl.dll | — | — | — | — | 多显示器 |

**所有用户态组件均为 generic_executable / generic_library，无内核级威胁。**

### xor_payload 检测

多个文件检测到 `xor_payload` 模式（conf=0.5~0.9）。
高置信度（0.9）出现在：kgamemgr64.dll、kicloud64.dll、kssdeploy64.dll、lwclient64.exe、kssd.exe 等。
这些可能是加密配置/通信数据的 XOR 编码，也可能是 protobuf 序列化的误报。
需要进一步分析确认是否为恶意 payload。

---

## 关键发现：kscdrv64.dll — 驱动通信库

`kscdrv64.dll` 是用户态与内核驱动通信的桥梁（160 imports/8 libs）。
文件名 `kscdrv` = kSafeCenter Driver，可能是与 ksafecenter64.sys 通信的 IOCTL 库。

**待分析：**
- `ppm imports` 查看是否有 DeviceIoControl、CreateFile（打开驱动设备）
- `ppm dataflow` 追踪 IOCTL 参数

---

## 第六次实战诡异事件记录

### 时间线

1. Phase 1（拆回调）完成 — CmCallback、ObCallback、ImageNotify、ProcessNotify 全拆
2. Phase 2（卸载保护驱动）— ksafecenter/kshutdown/kboot 卸载成功，kcachec 拒绝
3. Phase 3（卸载非保护驱动）— kdisk 卸载成功，krestore/KScsiDisk 拒绝（DeviceObject）
4. WdFilter 处理 — ObCallback/ImageNotify/ThreadNotify 全禁用 + 服务停止
5. vgk.sys — ObCallback/ImageNotify 全禁用 + 驱动卸载
6. kshut64.dll — 文件重命名 + winlogon 卸载（/wluninject 确认成功）
7. 云更新用户态进程 — lwclient64/kssd/lwhardware64/lwPersonalSetting64/khardware64_v56 全杀 + 文件重命名
8. 云更新驱动 .sys 文件 — 全部重命名 .bak

### 诡异现象

**以上所有操作完成后，evil handle (pid=4, acc=0x1fffff) 仍在每次 VBox 启动时出现。**

每次测试的 evil handle 值都不同（动态分配），但模式完全一致：
```
pid=0000000000000004  acc=0x1fffff  type=process (7) [System]
ExitCode=0xc0000409  ~3100-3700ms
```

### 已排除的所有来源

| 来源 | 排除方法 | 状态 |
|------|---------|------|
| ksafecenter64 ObCallback | /disable | ✅ 已禁用 |
| ksafecenter64 CmCallback | /notify registry --kill | ✅ 已 unlink |
| ksafecenter64 ImageNotify (+0x6fac) | /ndisable | ✅ 已清零 |
| ksafecenter64 驱动 | /force-stop ksafecenter | ✅ 已卸载（\Driver 中消失） |
| kshutdown64 ImageNotify (+0x2ef8) | /ndisable | ✅ 已清零 |
| kshutdown64 驱动 | /force-stop kshutdown | ✅ 已卸载（\Driver 中消失） |
| kboot64 CmCallback | /notify registry --kill | ✅ 已 unlink |
| kboot64 驱动 | /force-stop kboot | ✅ 已卸载（\Driver 中消失） |
| kcachec64 驱动 | Stopped（DriverUnload 拒绝） | ⚠️ 代码仍驻留 |
| krestore64 驱动 | 活跃（15 DeviceObject） | ⚠️ 无法卸载 |
| KScsiDisk64 驱动 | 活跃（5 DeviceObject） | ⚠️ 无法卸载 |
| WdFilter ObCallback | /disable | ✅ 已禁用 |
| WdFilter ImageNotify (+0x3ce80) | /ndisable | ✅ 已清零 |
| WdFilter ThreadNotify ×2 | /ndisable | ✅ 已清零 |
| WdFilter 服务 | net stop WdFilter | ✅ STOPPED |
| vgk.sys ObCallback (Process+Thread) | /disable | ✅ 已禁用 |
| vgk.sys ImageNotify (+0xbee4) | /ndisable | ✅ 已清零 |
| vgk.sys 驱动 | /force-stop vgk | ✅ 已卸载 |
| kshut64.dll 文件 | 重命名 .bak（3 个位置） | ✅ 已中和 |
| kshut64.dll in winlogon | /wluninject | ✅ 已卸载 |
| lwclient64.exe | 杀进程 + 文件重命名 | ✅ 已中和 |
| kssd.exe | 杀进程 + 文件重命名 | ✅ 已中和 |
| lwhardware64.exe | 杀进程 + 文件重命名 | ✅ 已中和 |
| lwPersonalSetting64.exe | 杀进程 + 文件重命名 | ✅ 已中和 |
| khardware64_v56.exe | 杀进程 + 文件重命名 | ✅ 已中和 |
| ProcessNotify 数组 | /debug /notify process 全量扫描 | ✅ 无云更新条目 |
| ImageNotify 数组 | /notify image | ✅ 仅 ahcache.sys |
| ThreadNotify 数组 | /notify thread | ✅ 仅 nvlddmkm + mmcss |
| Defender 排除规则 | /runas system reg add | ✅ 已写入 |

### 仍活跃的内核驱动（ppm 深度分析）

| 驱动 | 基址 | 状态 | ppm 类型 | ppm 检测到的回调 | 特殊能力 |
|------|------|------|---------|-----------------|---------|
| **KScsiDisk64.sys** | 0xFFFFF80781E80000 | 活跃（5 DeviceObject） | `process_monitor` | Process notify + Image notify (2个) | MmGetSystemRoutineAddress 动态 API 解析 |
| **kcachec64.sys** | 0xFFFFF80782720000 | Stopped（代码驻留） | `process_monitor` | Process notify (1个) | MmGetSystemRoutineAddress 动态 API 解析 |
| **krestore64.sys** | 0xFFFFF80782700000 | 活跃（15 DeviceObject） | `generic_driver` | 无 | MmGetSystemRoutineAddress + **EPROCESS DKOM 写入** |

**关键矛盾：** ppm 静态分析确认 KScsiDisk64 和 kcachec64 有 Process/Image notify 注册能力，
但 `/notify process` 和 `/notify image` 运行时扫描数组中没有它们的条目。

**可能解释：**
1. 回调通过 MmGetSystemRoutineAddress 动态解析后注册，不走标准 IAT，注册时机不确定
2. 回调在特定条件下���注册（如检测到 VBox 进程时才延迟注册）
3. 回调注册后被 DKOM 隐藏（krestore64 有 EPROCESS DKOM 能力）
4. RTCore64 停止测试期间 evil handle 仍存在，说明 RTCore64 不是来源

### 诡异点分析

**诡异点 1：evil handle 来源不明**

所有已知的内核回调机制（ObCallback、CmCallback、ProcessNotify、ImageNotify、ThreadNotify）
均已拆除或确认无云更新条目，但 pid=4 仍能精准对 VBox 开 PROCESS_ALL_ACCESS。

**诡异点 2：0xc0000409 杀手不明**

0xc0000409 (STATUS_STACK_BUFFER_OVERRUN) 是 kshut64.dll 的签名杀法
（TerminateProcess(self, 0xc0000409) 伪装成 GS cookie 失败）。
但 kshut64.dll 已三重中和：文件重命名 + winlogon 卸载 + kshutdown64 驱动卸载。
**谁在用同样的手法杀 VBox？**

**诡异点 3：B 盘 49 个二进制全部无害**

ppm-engine 对 B:\lwclient64\ 下所有 EXE 和 DLL 跑完 8 阶段分析，
全部是 generic_executable / generic_library，无内核级威胁。

**调查结果：kshut64.dll 确实被注入到 explorer.exe**

```
powershell Get-Process | ForEach { $_.Modules | Where ModuleName -like '*kshut*' }
→ explorer (PID 6448): kshut64.dll
```

kshutdown64 的 APC 注入不只针对 winlogon，还注入了 explorer.exe。
使用 `/wluninject-all kshut64.dll` 从 explorer 成功卸载。

**但卸载后 evil handle 和 0xc0000409 仍然存在。**
kshut64.dll 在 winlogon 和 explorer 中都已清除，所有进程扫描确认无残留。
0xc0000409 的杀手仍然不明。

### 网咖工程师证词

网咖工程师确认：**VBox 无法运行是云更新系统公司（YunGengXin）在程序中设定的，
网咖工程师本人无法修改此行为。** 这从业务层面证实了 VBox 被杀确实是云更新的设计意图，
不是 bug 或副作用。

**云更新公司自称其系统为"模块化设计"。** 结合实战观察，这意味着：

1. **云更新对 VirtualBox 的封杀是故意的、多层冗余的**，不只是单一回调或单一驱动
2. 我们已经拆掉了所有已知的回调、驱动、DLL 注入、用户态进程，但仍有未发现的杀手机制
3. **"模块化"在安全对抗中意味着每个模块独立具备杀伤能力**：
   - 拆掉 A 模块，B 模块仍能独立执行封杀
   - 每个驱动（ksafecenter、kshutdown、kboot、kcachec、krestore、KScsiDisk）
     可能各自有独立的进程监控和终止路径
   - 不是传统的"中枢控制 + 执行器"架构，而是分布式冗余设计
4. 云更新的防护设计为"加载不走" + 多重冗余，即使大部分组件被中和，残余模块仍能独立执行
5. **可能存在我们尚未发现的第四层/第五层防护**：
   - krestore64.sys / KScsiDisk64.sys 内部线程（无法卸载，仍在内核运行）
   - 内核定时器（DPC/Timer）在驱动卸载后仍然存活
   - 驱动卸载前注册的内核工作项（WorkItem）仍在排队执行
   - ksafecenter64 虽然 Stopped 但代码仍驻留内存，可能被残余定时器调用
   - 各模块之间可能有心跳机制，发现同伴被杀后自动接管封杀职责

### 假设

1. **kshut64.dll 被注入到 winlogon 以外的其他进程**：
   kshutdown64 的 APC 注入可能不只注入 winlogon，还可能注入 explorer、svchost 等，
   这些进程中的 kshut64.dll 仍在内存中运行，监听 Event 信号杀 VBox

2. **krestore64/KScsiDisk64 通过非标准路径开 handle**：
   不通过 Notify/ObCallback 数组，而是通过内部线程、定时器或 IRP 派发例程，
   在检测到新进程时主动 ObOpenObjectByPointer

3. **Windows 内核自身行为**：
   进程创建时 System 默认持有 ALL_ACCESS handle，这是正常行为，
   但 VBoxSup hardening 将其视为 evil（第五次实战的逆向分析支持此假设）

4. **未知的第三方驱动**：
   cpuz160_x64.sys、OpenHardwareMonitorLib.sys 等可能对进程开 handle

---

### evil handle 出现时机（日志分析）

VBoxHardening.log 第 1552-1555 行：

```
a110.a0ac: supR3HardenedVmProcessInit: Opening vboxsup...
a110.a0ac: supR3HardenedWinReadErrorInfoDevice: 'Found evil handle to budding VM process:
  pid=0000000000000004 h=0000000000026aa8 acc=0x1fffff attr=0x0 type=process (7) [System]'
a110.a0ac: Error -3738 in suplibOsInit! (enmWhat=1)
```

**evil handle 是在 Respawn#2 打开 VBoxSup 驱动的瞬间被检测到的。**
VBoxSup 在 `suplibOsInit` 内扫描 System 进程的 handle table，发现 0x1fffff handle 后拒绝启动。

handle 值每次都不同（0x26aa8、0x1f0bc、0x215a0、0x1d410 等），值很大，
说明 System handle table 条目非常多。

### ObCallback 最终状态

```
[0] Process  Entry:FFFFAF0AE59BC430  Enabled:0  ← ksafecenter64（已禁用）
[1] Process  Entry:FFFFAF0B036F4890  Enabled:1  ← VBoxSup.sys（正常）
[2] Thread   Entry:FFFFAF0B036F48D0  Enabled:1  ← VBoxSup.sys（正常）
Total: 3 callback entries
```

只剩 VBoxSup 自己的 ObCallback，没有任何云更新驱动的回调。

### kshut64.dll 隐藏进程调查

```
powershell Get-Process | % { $_.Modules | ? ModuleName -like '*kshut*' }
→ explorer (PID 6448): kshut64.dll    ← 发现！
→ /wluninject-all kshut64.dll         ← 清除
→ 再次扫描：无残留
→ VBox 仍然失败                       ← kshut64.dll 不是最终杀手
```

### ppm 分析最终结果

lwdesk64.exe 分析完成：PE64，561 imports/19 libs，40500 functions，generic type。
**所有 49 个 B 盘二进制全部完成分析，全部为用户态 generic 类型，无内核级威胁。**

---

### KScsiDisk64.sys 深度分析 — ZwOpenProcess(0x1fffff) 确认

ppm dataflow 追踪结果：

```
PsSetCreateProcessNotifyRoutine @ 0xD803:
    arg0 (rcx): 0x137B0  ← ProcessNotify 回调函数 RVA

PsSetLoadImageNotifyRoutine @ 0x45E6:
    arg0 (rcx): 0x4DA4   ← ImageNotify 回调函数 RVA

ZwOpenProcess @ 0x1567A:
    arg1 (rdx): 0x1fffff ← PROCESS_ALL_ACCESS！evil handle 来源确认！
```

**KScsiDisk64.sys 在 RVA 0x1567A 调用 ZwOpenProcess 用 PROCESS_ALL_ACCESS 打开进程。**

#### safepatch 测试 1：patch ProcessNotify 回调

```
/safepatch 0xFFFFF80781E80000+0x137B0 C3   ← 把 ProcessNotify 入口 patch 成 RET
→ [+] Patch OK
→ VBox 测试：evil handle 仍存在
```

**ProcessNotify patch 无效。** ZwOpenProcess(0x1fffff) 在 RVA 0x1567A，
可能是从 ImageNotify 回调 (0x4DA4) 或内核线程 (PsCreateSystemThread) 调用的，
不经过 ProcessNotify 路径。

#### safepatch 测试 2：patch ZwOpenProcess 调用点 — 蓝屏（失败）

```
/safepatch 0xFFFFF80781E80000+0x1567A ...
→ BSOD
→ 系统被云更新还原
```

**蓝屏原因分析：**

RVA `0x1567A` 是函数**内部**的 `call ZwOpenProcess` 指令，不是函数入口。
在函数中间 patch 会导致以下问题：

1. **插 `C3` (RET) → 栈帧损坏**：函数已经 push 了参数、保存了非易失寄存器，
   此时 RET 弹出的不是正确的返回地址，跳转到垃圾地址 → BSOD
2. **NOP 掉 CALL → 后续代码依赖返回值**：`ZwOpenProcess` 的调用方检查 RAX (NTSTATUS)
   和输出参数（handle 指针），NOP 后这些值是垃圾，解引用无效 handle → BSOD
3. **多核竞态**：另一个 CPU 正在执行 `0x1567A` 附近代码，patch 写入瞬间指令被截断 → BSOD

**教训：safepatch 只能 patch 函数入口点（写 `C3` 直接返回），不能 patch 函数中间的调用点。**

#### 正确策略

ProcessNotify (RVA `0x137B0`) patch 成 RET 没蓝屏但无效——说明 ZwOpenProcess
不是从 ProcessNotify 路径调用的。下一个安全目标：

**patch ImageNotify 回调入口 (RVA `0x4DA4`) 为 `C3`**：
- `0x4DA4` 是函数入口，RET 直接返回，栈帧干净——与成功 patch ProcessNotify 同样的模式
- ImageNotify 回调被禁用后，KScsiDisk64 在 DLL 加载事件中不会被触发，
  ZwOpenProcess(0x1fffff) 调用链被切断

如果 ImageNotify patch 后 evil handle 仍存在，说明 ZwOpenProcess 是从
**内核线程** (PsCreateSystemThread) 或 **DPC/Timer** 调用的，需要进一步追踪。

---

## safepatch 验证结果（2026-04-12 确认）

**patch KScsiDisk64 的 ImageNotify 回调 (RVA 0x4DA4) 为 C3 → VBox 成功启动。**
但 safepatch 后约 1 分钟内触发 BSOD。

### safepatch BSOD 原因分析

safepatch 通过 PTE 交换实现：分配影子物理页 → 复制原页 → 修改目标字节 → PTE 指向影子页。
这对内核内存管理器（Mm）是**不可见的修改**：

1. **PFN 数据库不一致**：影子页的 PFN entry 记录属于用户态分配，但 PTE 把它映射到内核空间。
   Mm 做 working set trim / standby list / modified page writer 时遇到不一致就会崩溃
2. **PTE 会被覆写**：Mm 做页面状态转换（Active→Standby→Modified）时可能恢复原始 PTE
3. **多核 TLB flush**：其他 CPU 的 TLB 缓存旧映射

**结论：safepatch 设计上是临时的（测试→验证→还原），不适合长期驻留。**

### PPL 方案分析 — 无效

PPL (Protected Process Light) 对 KScsiDisk64 的 evil handle 攻击**无效**：

```
时序：
1. VBox Respawn#1 调 CreateProcess → 创建 Respawn#2 的 EPROCESS
2. 内核同步触发 ProcessNotify（包括 KScsiDisk64 的 0x137B0）
3. KScsiDisk64 回调内调 ZwOpenProcess(0x1fffff) → handle 已生成
4. CreateProcess 返回用户态 → Respawn#2 开始运行
5. ObMaster 此时才有机会设 PPL → 太晚了
6. VBoxSup 扫描 handle table → 发现 evil handle → 退出
```

PPL 只在 handle 创建时检查。步骤 3 发生在步骤 5 之前，handle 创建时 VBox 进程还没有
PPL 保护，ZwOpenProcess 拿到完整的 0x1fffff 权限。EPROCESS 在步骤 1 才被创建，
无法在此之前设置 PPL。

### 正确方案：safepatch + 延迟启动 + 立即还原

safepatch 只需要撑到 VBox 通过 VBoxSup 的 evil handle 检查（~10 秒）：

```
1. safepatch KScsiDisk64 ImageNotify (base+0x4DA4) → C3
2. 立刻启动 VBox
3. VBox Respawn#2 创建 → KScsiDisk64 回调直接 RET → 不开 handle
4. VBoxSup 检查通过 → VM 窗口弹出
5. 立即还原 safepatch（恢复原始 PTE）
6. KScsiDisk64 恢复正常 → 内核数据结构一致 → 不会蓝屏
7. VBox 已经跑起来了 — VBoxSup 只在启动时检查一次
```

整个窗口约 10-15 秒，远在 1 分钟 BSOD 触发之前。

### ppm 深度分析（2026-04-12 补充）

**KScsiDisk64.sys 完整分析：**

```
ppm analyze kscsidisk64.sys:
  PE64_DRIVER, x64, packed=False
  Imports: 128 from 4 libraries (ntoskrnl 122 + NDIS 2 + TDI 2 + HAL 2)
  Functions: 437, roots: 55
  Depgraph: 948 nodes, 1257 edges
  Type: process_monitor
  Self-prot: No DriverUnload + MmGetSystemRoutineAddress dynamic API
  PDB: E:\tools\yungengxin\bin\kscsidisk64.pdb
```

**回调注册（ppm depgraph who_registers）：**

| 注册函数 | 回调 RVA | 功能 |
|----------|---------|------|
| PsSetCreateProcessNotifyRoutine | 0x137B0 | 进程黑名单匹配，设置标志位 |
| PsSetLoadImageNotifyRoutine | 0x4DA4 | FsRtlIsNameInExpression 通配符匹配，记录信息 |
| IoRegisterShutdownNotification | 0xC940 | 关机通知 |

**关键 API 调用（ppm dataflow）：**

| API | RVA | 参数 |
|-----|-----|------|
| ZwOpenProcess | 0x1567A | arg1 (rdx) = **0x1fffff** (PROCESS_ALL_ACCESS) |
| MmGetSystemRoutineAddress | 0x3BFF, 0xCC08, 0xD6F3, 0x10EB0, 0x139E0, 0x15E18 | 动态解析 6 个 API |

**ProcessNotify 回调 (0x137B0) 伪代码要点：**
- 用 `sub_15634` 获取进程信息
- 用 `sub_13958` 处理后获取进程名
- 用 `sub_1618` 反复比较 6 个字符串常量（`data_19170`~`data_191C0`）— 黑名单匹配
- 匹配成功设置全局标志位 `byte ptr [rip + ...]`

**ImageNotify 回调 (0x4DA4) 伪代码要点：**
- `RtlInitUnicodeString` 初始化匹配模式字符串（`data_18020`）
- `FsRtlIsNameInExpression` 通配符匹配 DLL/镜像名
- 匹配成功后调 `sub_E6EC` → 分配 pool 记录信息 → 调 `sub_E8C4` 执行后续操作

**DriverEntry (0xD670) 注册顺序：**
1. 各种初始化（`sub_16038`, `sub_CE58`, `sub_16EA8`）
2. `MmGetSystemRoutineAddress` 动态解析 API
3. 设置 IRP dispatch table（`DriverObject+0x70`~`DriverObject+0x148`）
4. `sub_44DC` → `PsSetLoadImageNotifyRoutine(0x4DA4)` 注册 ImageNotify
5. `sub_C940` → `IoRegisterShutdownNotification` 注册关机通知
6. `PsSetCreateProcessNotifyRoutine(0x137B0, FALSE)` 注册 ProcessNotify

**关键字符串：**
- `EXPLORER.EXE` — 可能是白名单/特殊处理
- `%ws Virtual Disk %04d` — 虚拟磁盘名称模板
- `\DosDevices\B:`, `\Device\KDiskVol0` — B 盘和虚拟卷操作
- `\Device\KScsiDisk`, `\DosDevices\KScsiDisk` — 设备对象
- `kscsi_proto` — SCSI 协议相关
- `\Registry\Machine\...\services\KScsiDisk\param` — 驱动参数
- `ZwQueryInformationProcess` — 动态解析的进程查询 API

---

## KScsiDisk64 僵尸驱动研究（2026-04-12 实验机验证）

### 为什么 KScsiDisk64 无法卸载

ppm pseudo 分析 DriverUnload (RVA 0x3110)：

```c
void sub_3110() {
    return;  // 空函数，什么都不做
}
```

原始字节 `C2`（`RET imm16`），等价于直接返回。但 DriverEntry 注册了：

| 注册 | 清理 |
|------|------|
| `PsSetCreateProcessNotifyRoutine(0x137B0, FALSE)` | ❌ 没有 |
| `PsSetLoadImageNotifyRoutine(0x4DA4)` | ❌ 没有 |
| `IoRegisterShutdownNotification` | ❌ 没有 |
| `IoRegisterBootDriverReinitialization` | ❌ 没有 |
| `IoCreateDevice` + `IoAttachDeviceToDeviceStack` | ❌ 没有 |

**DriverUnload 是诱饵**——地址不为 NULL（骗过检查工具），但实际什么都不做。
内核调完 DriverUnload 后发现回调和设备还挂着，无法释放 → 僵尸。

这是云更新的**故意设计：加载不走**。

### 卸载尝试时间线

| 尝试 | 结果 |
|------|------|
| `sc stop KScsiDisk` | 1052 (SERVICE_CONTROL_INVALID) |
| `NtUnloadDriver` | 0xC0000010 (STATUS_INVALID_DEVICE_REQUEST) |
| `/force-stop KScsiDisk` | 自动发现失败（DKOM 隐藏） |
| `/drv-unload KScsiDisk <drvobj>` | DriverUnload 有值但 ControlService 1052 |
| `/drv-zombie <drvobj>` | PointerCount=2，完全正常，无明显阻塞原因 |
| safepatch DriverUnload → C3 | patch 成功但 sc stop 仍然 1052 |
| **`/nuke-driver <drvobj>`** | **✅ 成功——驱动功能性死亡** |

### /nuke-driver 验证结果

```
[*] /nuke-driver  DRIVER_OBJECT=0xFFFFDC81AAC19BB0
[*] Target: kscsidisk64.sys  range: 0xFFFFF800A03C0000 - 0xFFFFF800A03E4000 (144 KB)

[1] Scanning Ps*NotifyRoutine arrays...           (无条目——实验机未触发注册)
[2] Scanning CmCallback linked list...            (CallbackListHead 未找到)
[3] Clearing DeviceObject chain...                (无 DeviceObject)
[4] Zeroing MajorFunction[0..27]...               [+] 全部 → ret stub
[5] Zeroing DriverUnload...                       [+] → NULL
[6] Unlinking from PsLoadedModuleList...          [+] 已摘链
[*] nuke-driver complete — kscsidisk64.sys is functionally dead.

验证：/drivers 输出中 kscsidisk64 已消失 ✅
```

### safepatch 验证结果

| 目标 | RVA | 原始字节 | patch | sp-test | safepatch | 结果 |
|------|-----|---------|-------|---------|-----------|------|
| ImageNotify | 0x4DA4 | `4C` | `C3` | 三阶段 PASS | ✅ | 影子页验证 C3 |
| DriverUnload | 0x3110 | `C2` | `C3` | — | ✅ | ppm 确认是空壳 |

---

## IOCTL 控制通道发现（2026-04-12）

### 核心洞察：厂商自己的卸载通道

云更新是商业软件——有安装就有卸载，有试用版就有序列号验证。
厂商的卸载程序必须能干净卸载所有驱动，**它不可能手动减引用计数或摘 PsLoadedModuleList**。

**答案：驱动内部有 IOCTL 控制通道**，厂商的用户态程序通过 DeviceIoControl 通知驱动自清理，
驱动自己调 ObUnRegisterCallbacks、PsRemoveLoadImageNotifyRoutine、IoDeleteDevice，
然后 NtUnloadDriver 顺利执行 MmUnloadSystemImage。

### ksafecenter64.sys 设备与 IOCTL

**设备名（ppm strings）：**
```
\Device\SafeCenter       → 用户态: \\.\SafeCenter
\DosDevices\SafeCenter
\Device\SFFireWall        → 用户态: \\.\SFFireWall
\DosDevices\SFFireWall
```

**IRP_MJ_DEVICE_CONTROL handler: sub_1724**

IOCTL dispatch table（从伪代码提取）：

| IOCTL Code | 备注 |
|------------|------|
| `0x220004` | 基础控制 |
| `0x220008` | |
| `0x22000C` | |
| `0x220010` | |
| `0x220014` | |
| `0x220019` | 第一个检查（特殊处理） |
| `0x22001C` | |
| `0x220020` | |
| `0x220024` | 分界线（触发 sub_8200） |
| `0x220028` | 第二组开始 |
| `0x22002C` ~ `0x220040` | 扩展控制 |

**通信库：** `kscdrv64.dll`（B:\lwclient64\，160 imports/8 libs）是用户态到内核的 IOCTL 桥。
厂商的卸载程序和管理工具通过它发送控制命令。

### 正确的卸载策略

```
旧思路（Opus 硬干，炸了两次蓝屏）：
  手动减引用计数 → 手动摘 PsLoadedModuleList → BSOD 0x50
  手动清零 DeviceObject → 孤儿设备 → MmUnloadSystemImage 不执行
  手动写 ret stub → NtUnloadDriver SUCCESS 但文件仍锁着

新思路（Mythos 借力）：
  CreateFile("\\.\SafeCenter") → DeviceIoControl(卸载IOCTL) → 驱动自清理
  → NtUnloadDriver → MmUnloadSystemImage → 文件释放 → 可重新加载
```

**不要自己造轮子，找现有的路径当替死鬼。**

### 下一步

1. 到服务器上用 ppm 分析 `kscdrv64.dll` 的 DeviceIoControl 调用，提取 IOCTL codes
2. 或者直接对 `\\.\SafeCenter` 暴力尝试已知的 IOCTL（0x220004~0x220040）
3. 找到"清理并允许卸载"的 IOCTL 后，nuke-driver 只需一行 DeviceIoControl

### 思维蒸馏笔记

Mythos 的漏洞发现能力来自一个核心思维：**不要问"我怎么解决"，先问"谁已经解决过"。**

对于 ksafecenter64 的卸载问题：
- Opus 思维：逆向 DriverObject 结构 → 手动清理回调 → 手动减引用 → 手动摘链 → BSOD
- Mythos 思维：厂商自己要卸载 → 一定有 IOCTL → 找到它 → 一行代码解决

同样的原理适用于漏洞链接：不自己写 exploit 的每个环节，而是找到系统里
已有的代码路径（合法 API、错误处理、回退逻辑），串起来让系统自己做危险操作。

---

## 待完成

- [x] safepatch KScsiDisk64 的 ImageNotify 回调入口 (RVA 0x4DA4) 为 C3 → ✅ 有效，VBox 能开
- [x] PPL 方案分析 → ❌ 无效（时序问题，handle 在 PPL 设置前已创建）
- [x] KScsiDisk64 僵尸驱动研究 → DriverUnload 是空壳，/nuke-driver 解决
- [x] IOCTL 控制通道发现 → \\.\SafeCenter + IOCTL codes 0x220004~0x220040
- [ ] 分析 kscdrv64.dll 提取卸载 IOCTL code（需要服务器 B 盘访问）
- [ ] 暴力测试 IOCTL 找到"清理+卸载"命令
- [ ] 实施 safepatch + 延迟启动 + 立即还原方案（写自动化脚本）
- [ ] 确认 krestore64 是否也有独立的进程监控路径
- [ ] 在无云更新的干净系统上测试 VBox 是否有同样的 evil handle

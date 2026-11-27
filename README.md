# HOneClick

HOneClick 是一个面向荣耀设备的实验性临时 root 与安全研究工具。它通过 Shizuku 执行本地漏洞链，按实际 `uname -r` 自动选择，并允许在未锁定内核上手动切换后端，加载匹配的 SukiSU/KernelSU 模块，并初始化对应用户态环境。默认构建使用 SukiSU Ultra。

English summary: HOneClick is an unofficial Honor temporary-root research tool with kernel-driven exploit routing. It is not affiliated with Honor, SukiSU, KernelSU, or Shizuku.

> [!WARNING]
> 本项目会修改运行中的内核状态并加载内核模块。使用本应用可能存在风险，请自行评估并承担相应风险。请勿用于非法用途。仅在设备所有者明确同意的个人测试设备上使用。

## 当前状态

- 已验证内核 A（109）：`6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k` → 98260
- 已验证内核 B（115）：`6.18.21-android17-5-ge186062ea75f-abogki564062290-4k` → 98260
- 已验证内核 C（117）：`6.18.21-android17-5-gfee2325de189-abogki572422516-4k` → 99491 / 98260
- 默认路由：AUTO 在 117 上选择 CVE-2026-99491，在 109/115 上选择 CVE-2026-98260；可手动切换
- 98260 引擎按实际 `uname -r` 选择 109、115 或 117 内核配置
- 99491 仅支持 117 内核；默认使用固定目标 `selinux_state-7`（`--no-avc`），模块在 pwn 进程内用 SukiSU `ko_patch` 补丁；98260 保留为 117 的备选
- 对应内核的机器都可以尝试，目前在 Magic9 Pro Max 和 Win2 上验证。
- root 类型：当前启动有效的临时 root，重启后失效
- 不包含：bootloader 解锁、刷写分区、永久 root

## 功能

1. 安装并连接 Shizuku。
2. 安装 SukiSU Ultra 管理器（默认；KernelSU 风味可选）。
3. 读取设备与完整内核指纹，不再限制设备型号。
4. AUTO：117 选择 CVE-2026-99491，109/115 选择 CVE-2026-98260；可手动切换。
5. 98260 根据实际 `uname -r` 自动加载匹配的地址、KASLR 泄漏点与模块符号表；99491 在 117 上使用固定目标 `selinux_state-7` + pwn 进程内 SukiSU `ko_patch`。
6. 98260 正式运行采用与命令行一致的静默时序，跳过预检；需要诊断时单独执行 `--preflight`。
7. 加载与当前内核和所选管理器匹配的 SukiSU/KernelSU 模块。
8. 初始化 SukiSU/KernelSU 用户态组件并通过管理器授权应用和模块。

## 使用

1. 连接 Shizuku 后读取实际 `uname -r`；AUTO 在 117 上使用 `99491`，在 109/115 上使用 `98260`。
2. 打开无线调试和 Shizuku 服务。
3. 安装并打开 HOneClick。
4. 点击 `01 SHIZUKU` 步骤卡并在 Shizuku 中完成授权。
5. 点击 `02 SUKISU` 步骤卡安装 SukiSU 管理器（默认）；安装完成后无需操作，返回本应用即可自动识别。
6. 点击 `03 开始提权`（执行期间应用会自动保持屏幕常亮）。
7. root 完成后，在 SukiSU 管理器中按需授权应用。

运行大概需要 10-30 分钟，在某一个步骤如超过 5 分钟，重启手机再来一遍兴许是更好的选择。

设备型号不再作为硬拦截条件，但漏洞地址仍与内核版本绑定。手动在未知内核选择利用链可能导致失败、重启或数据损失；使用 `--preflight` 诊断失败时应立即停止，不要绕过。

## 构建

### 环境

- JDK 21
- Android SDK Platform 37
- Android Build Tools 37.0.0
- Android Gradle Plugin 9.4.1
- Kotlin Compose Plugin 2.4.20
- 自研 native helper 当前使用 NDK `28.2.13676358`

项目使用 Gradle Wrapper。首次构建前，在 `local.properties` 中配置本机 Android SDK，或通过 `ANDROID_HOME` 提供 SDK 路径。

```bash
./gradlew assembleSukisuRelease
```

### Release 签名

未提供签名环境变量时，Gradle 只生成 unsigned APK。

> **与 GitHub Releases 保持一致**：当前 GitHub 发布的 APK 使用 Android Debug 证书
> `CN=Android Debug`（SHA-256 `8a94093ac442383145a02d2eabc93fed48657ea166260716a2d73b4b8c3dd46f`）。
> 要覆盖升级 GitHub 发布版，必须使用同一个 debug keystore：
>
> ```bash
> export HONOR_KEYSTORE="$HOME/.android/debug.keystore"
> export HONOR_STORE_PASSWORD=android
> export HONOR_KEY_ALIAS=androiddebugkey
> export HONOR_KEY_PASSWORD=android
> ./gradlew assembleSukisuRelease
> ```
>
> 换用私有 release key 会导致 `INSTALL_FAILED_UPDATE_INCOMPATIBLE`；迁移签名必须先卸载旧包。

```bash
export HONOR_KEYSTORE=/absolute/path/to/release.keystore
export HONOR_STORE_PASSWORD='...'
export HONOR_KEY_ALIAS='...'
export HONOR_KEY_PASSWORD='...'
./gradlew assembleSukisuRelease
```

### 电脑端自动生成内核配置

从原始 AArch64 内核 `Image` 自动解析 kallsyms、BTF、结构偏移和漏洞调用顺序，并生成配置与符号表：

```bash
python3 scripts/generate-kernel-profile.py kernel.bin \\
  --symbols-out assets/syms-new.txt \\
  --module-asset ksu-template-new.ko \\
  --update-profiles assets/exploit-profiles.json
```

生成器会验证 `begin_new_exec` 中 POSIX timer 清理仍位于可失败 exec 步骤之后；不满足时拒绝生成可用配置。

### 资产校验

```bash
./scripts/verify-assets.sh
```

`ksu_grant` 可用固定 NDK 版本重新构建：

```bash
export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/28.2.13676358"
./scripts/build-ksu-grant.sh
./scripts/build-cve98260.sh
./scripts/build-cve99491.sh
./scripts/build-ksu-template-115.sh
./scripts/build-ksu-template-117.sh
```

### APK 产品风味

构建会生成两个可并存的 APK；默认使用 SukiSU：

```bash
./gradlew assembleSukisuDebug
./gradlew assembleKernelsuDebug
```

- `sukisu`（默认）：`com.aiden.honeclick`，内置 SukiSU Ultra 管理器、SukiSU `ksud` 和 109/115/117 对应的 SukiSU LKM 模板。
- `kernelsu`：`com.aiden.honeclick.kernelsu`，内置 KernelSU 管理器，作为可选风味保留。

### SukiSU Ultra 命令行版本

仓库提供独立的 SukiSU Ultra 命令行流程，不替换 APK 内置管理器。它会在全新启动后执行 98260、加载官方 SukiSU LKM、初始化用户态并安装管理器：

```bash
ANDROID_SERIAL=<DEVICE_SERIAL> ./scripts/root-98260-sukisu.sh --check
ANDROID_SERIAL=<DEVICE_SERIAL> ./scripts/root-98260-sukisu.sh --preflight
```

默认下载并校验 SukiSU Ultra `v4.3.0-r2` 官方资产。切换前必须重启，且不能已经加载 `kernelsu` 模块。详细说明见 [docs/SUKISU_CLI.md](docs/SUKISU_CLI.md)。

## 隐私

HOneClick 主应用清单未申请 `INTERNET` 权限，不包含遥测、广告或账号系统。应用会通过 Shizuku 在设备本地执行命令，并在 `/data/local/tmp` 创建临时文件。

随 APK 分发的 Shizuku 和 SukiSU/KernelSU 管理器属于独立应用，其联网权限和隐私行为以上游项目为准。

## 已知限制

- 98260 回收失败后不能立即重试；应用会保留已停放的 UAF 进程，必须重启设备。
- 99491 真机 WKL-AN20 已用 SukiSU + `selinux_state-7` 验证全链；caps 的 Wacom 写仍可能 miss，miss 后可能延迟 panic，不要连续重试。
- root 只在本次启动中有效，重启后需要重新执行。
- 不同系统版本、内核配置或分区布局可能使流程失效。
- 当前没有永久化、bootloader 解锁或自动开机提权能力。

## 贡献

欢迎提交设备兼容性、漏洞分析、稳定性修复、文档和界面改进。提交前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)，并遵守以下要求：

- 仅在自己的设备或明确获得授权的测试设备上进行验证。
- 提交日志前移除设备序列号、账号、IP 地址和个人路径。
- 不提交来源不明的第三方 APK、内核模块、厂商固件或提取二进制。
- 引入第三方代码或二进制时，必须同时提供来源、版本、许可证和对应源码要求。
- 修改设备地址、cred 布局或竞态参数时，应附上设备型号、完整内核版本、复现步骤和通过判据。

安全漏洞请按照 [SECURITY.md](SECURITY.md) 私下报告，不要先公开包含可用利用细节的 Issue。

## 致谢

HOneClick 的实现和验证离不开以下公开研究与开源项目：

- [woshigenm/CVE-2026-99491](https://github.com/woshigenm/CVE-2026-99491)：提供 99491 原始利用链，作为本项目 117 移植、`selinux_state-7`/AVC 路线的基础。
- [sganggs/CVE-2026-98260-BRM-AN00](https://github.com/sganggs/CVE-2026-98260-BRM-AN00)：提供 CVE-2026-98260 触发、timer slab 回收和临时 root 研究实现。
- [KernelSU](https://github.com/tiann/KernelSU) 作者 weishu 及贡献者：提供 KernelSU 内核模块、`ksud` 和用户态管理能力。
- [Shizuku](https://github.com/RikkaApps/Shizuku) 作者 Rikka 及贡献者：提供无需重复启动应用进程的特权 shell 通道。
- [AndroidLiquidGlass](https://github.com/Kyant0/AndroidLiquidGlass) 作者 Kyant0 及贡献者：提供液态玻璃视觉组件。
- Android Open Source Project、JetBrains 及 Kotlin/Compose 贡献者：提供 AndroidX、Jetpack Compose 和相关基础组件。
- OnePlus 一键提权与 HyperBreak 的相关研究作者：为流程比较、KernelSU 初始化和候选进程方案提供了研究参考。

## 许可证

本项目原创代码采用 MIT License，Copyright (c) 2026 superboyyy。

第三方组件不由本项目重新授权。KernelSU、Shizuku、AndroidLiquidGlass、AndroidX、Compose 和 Kotlin 分别遵循其上游许可证。

CVE-2026-99491 与 CVE-2026-98260 代码来自公开研究仓库；本项目只保留研究/个人测试用途，上游未提供明确许可证的部分不得重新表述为 MIT 或用于未经审查的公开二进制分发。

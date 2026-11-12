# HOneClick

HOneClick 是一个面向荣耀设备的实验性临时 root 与安全研究工具。它通过 Shizuku 执行本地漏洞链，按实际 `uname -r` 自动选择，并允许在未锁定内核上手动切换后端，加载匹配的 KernelSU 模块，并初始化 KernelSU 用户态环境。

English summary: HOneClick is an unofficial Honor temporary-root research tool with kernel-driven exploit routing. It is not affiliated with Honor, KernelSU, or Shizuku.

> [!WARNING]
> 本项目会修改运行中的内核状态并加载内核模块。使用本应用可能存在风险，请自行评估并承担相应风险。请勿用于非法用途。仅在设备所有者明确同意的个人测试设备上使用。

## 当前状态

- 已验证内核 A：`6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k`（64560 / 98260-109）
- 已验证内核 B：`6.18.21-android17-5-ge186062ea75f-abogki564062290-4k`（98260-115）
- 已验证内核 C：`6.18.21-android17-5-gfee2325de189-abogki572422516-4k`（98260-117）
- 默认路由：所有设备默认 CVE-2026-98260
- 98260 引擎按实际 `uname -r` 选择 109、115 或 117 内核配置
- 精确内核锁定：实际 `uname -r` 与内核 B/C 完全匹配时禁用 64560；其他内核可手动切换
- root 类型：当前启动有效的临时 root，重启后失效
- 不包含：bootloader 解锁、刷写分区、永久 root

## 功能

1. 安装并连接 Shizuku。
2. 安装 KernelSU 管理器。
3. 读取设备与完整内核指纹，不再限制设备型号。
4. 所有设备默认选择 CVE-2026-98260；实际 `uname -r` 精确匹配内核 B/C 时禁用 64560。
5. 98260 根据实际 `uname -r` 自动加载匹配的地址、KASLR 泄漏点与 KernelSU 符号表。
6. 手机端可直接导入 `boot.img`，自动解析 kallsyms/BTF、校验漏洞路径并生成本地内核配置。
7. 98260 正式运行采用与命令行一致的静默时序，跳过预检；需要诊断时单独执行 `--preflight`。
8. 加载与当前内核匹配的 KernelSU 模块。
9. 初始化 KernelSU 用户态组件并通过管理器授权应用和模块。

## 使用

1. 连接 Shizuku 后读取实际 `uname -r`；默认使用 `98260`，精确匹配时自动锁定。
2. 打开无线调试和 Shizuku 服务。
3. 安装并打开 HOneClick。
4. 点击 `01 连接 Shizuku` 并在其中完成授权。
5. 点击 `02 安装 KernelSU` ，安装完成后无需进行操作，返回本应用。
6. 保持屏幕开启，点击 `03 开始提权`。
7. root 完成后，在 KernelSU 管理器中按需授权应用。

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
./gradlew assembleRelease
```

### Release 签名

未提供签名环境变量时，Gradle 只生成 unsigned APK。

```bash
export HONOR_KEYSTORE=/absolute/path/to/release.keystore
export HONOR_STORE_PASSWORD='...'
export HONOR_KEY_ALIAS='...'
export HONOR_KEY_PASSWORD='...'
./gradlew assembleRelease
```

### 手机端导入 boot.img

在“设备信息 → 漏洞利用”区域点击“导入 boot.img 生成配置”，通过系统文件选择器选取完整 `boot.img`。应用会：

1. 解析 Android boot image 并提取 kernel
2. 解析 kallsyms、BTF 和完整版本字符串
3. 检查 `begin_new_exec` 中的漏洞调用顺序
4. 生成本地配置、符号表和 KernelSU vermagic

当前手机端生成器支持原始 AArch64 Image 和 gzip 压缩内核，并要求目标为 6.18 KMI。

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
./scripts/build-legacy-helpers.sh
./scripts/build-cve98260.sh
./scripts/build-ksu-template-115.sh
./scripts/build-ksu-template-117.sh
```

## 隐私

HOneClick 主应用清单未申请 `INTERNET` 权限，不包含遥测、广告或账号系统。应用会通过 Shizuku 在设备本地执行命令，并在 `/data/local/tmp` 创建临时文件。

随 APK 分发的 Shizuku 和 KernelSU 管理器属于独立应用，其联网权限和隐私行为以上游项目为准。

## 已知限制

- 98260 回收失败后不能立即重试；应用会保留已停放的 UAF 进程，必须重启设备。
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

- [Feng1586/CVE-2026-64560-public](https://github.com/Feng1586/CVE-2026-64560-public) 及 GhostLock/CVE-2026-64560 research contributors：公开的漏洞研究、零写原语和两阶段 cred 修改代码，是本项目 `t64560_v36` 与 Honor 适配版本的重要基础。
- [sganggs/CVE-2026-98260-BRM-AN00](https://github.com/sganggs/CVE-2026-98260-BRM-AN00)：提供 CVE-2026-98260 触发、timer slab 回收和临时 root 研究实现。
- [KernelSU](https://github.com/tiann/KernelSU) 作者 weishu 及贡献者：提供 KernelSU 内核模块、`ksud` 和用户态管理能力。
- [Shizuku](https://github.com/RikkaApps/Shizuku) 作者 Rikka 及贡献者：提供无需重复启动应用进程的特权 shell 通道。
- [AndroidLiquidGlass](https://github.com/Kyant0/AndroidLiquidGlass) 作者 Kyant0 及贡献者：提供液态玻璃视觉组件。
- Android Open Source Project、JetBrains 及 Kotlin/Compose 贡献者：提供 AndroidX、Jetpack Compose 和相关基础组件。
- OnePlus 一键提权与 HyperBreak 的相关研究作者：为流程比较、KernelSU 初始化和候选进程方案提供了研究参考。

## 许可证

本项目原创代码采用 MIT License，Copyright (c) 2026 superboyyy。

第三方组件不由本项目重新授权。KernelSU、Shizuku、AndroidLiquidGlass、AndroidX、Compose 和 Kotlin 分别遵循其上游许可证。

`t64560_v36.c` 和 `t64560_v42_honor.c` 基于 `CVE-2026-64560-public` 的 MIT 许可研究代码；上游版权和修改说明完整保留在 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 和 [LICENSES/MIT-CVE-2026-64560.txt](LICENSES/MIT-CVE-2026-64560.txt)。CVE-2026-98260 代码来自公开研究仓库，上游未提供明确的开源许可证；不得将这部分重新表述为 MIT 或用于未经审查的公开二进制分发。

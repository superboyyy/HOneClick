# HOneClick

HOneClick 是一个面向特定荣耀设备的实验性临时 root 与安全研究工具。它通过 Shizuku 执行本地漏洞验证流程，加载与当前内核匹配的 KernelSU 模块，并初始化 KernelSU 用户态环境。

English summary: HOneClick is an unofficial, device-specific temporary-root research tool for Honor Magic9 Pro Max. It is not affiliated with Honor, KernelSU, or Shizuku.

> [!WARNING]
> 本项目会修改运行中的内核状态并加载内核模块。使用本应用可能存在风险，请自行评估并承担相应风险。请勿用于非法用途。仅在设备所有者明确同意的个人测试设备上使用。

## 当前状态

- 设备：Honor Magic9 Pro Max
- 型号白名单：`WKL-AN20`、`WKL-AN80`
- 已验证内核：`6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k`
- root 类型：当前启动有效的临时 root，重启后失效
- 不包含：bootloader 解锁、刷写分区、永久 root

## 功能

1. 安装并连接 Shizuku。
2. 安装 KernelSU 管理器。
3. 验证设备型号和内核指纹。
4. 执行设备专用漏洞验证链。
5. 加载与当前内核匹配的 KernelSU 模块。
6. 初始化 KernelSU 用户态组件。
7. 通过 KernelSU 管理器管理应用授权和模块。

## 使用

1. 确认设备和内核版本符合支持范围。
2. 打开无线调试和 Shizuku 服务。
3. 安装并打开 HOneClick。
4. 点击 `01 连接 Shizuku` 并在其中完成授权。
5. 点击 `02 安装 KernelSU` ，安装完成后无需进行操作，返回本应用。
6. 保持屏幕开启，点击 `03 开始提权`。
7. root 完成后，在 KernelSU 管理器中按需授权应用。

运行大概需要 10-30 分钟，在某一个步骤如超过 5 分钟，重启手机再来一遍兴许是更好的选择。

不要在未知固件、未知内核或其他 Android 设备上直接运行。漏洞流程可能触发系统重启、服务异常或数据损失，请确保有风险承受能力。

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

### 资产校验

```bash
./scripts/verify-assets.sh
```

`ksu_grant` 可用固定 NDK 版本重新构建：

```bash
export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/28.2.13676358"
./scripts/build-ksu-grant.sh
```

## 隐私

HOneClick 主应用清单未申请 `INTERNET` 权限，不包含遥测、广告或账号系统。应用会通过 Shizuku 在设备本地执行命令，并在 `/data/local/tmp` 创建临时文件。

随 APK 分发的 Shizuku 和 KernelSU 管理器属于独立应用，其联网权限和隐私行为以上游项目为准。

## 已知限制

- 仅验证当前列出的设备型号和内核指纹。
- root 只在本次启动中有效，重启后需要重新执行。
- KernelSU 授权按应用分别管理，普通 ADB shell 不自动获得 root。
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
- [KernelSU](https://github.com/tiann/KernelSU) 作者 weishu 及贡献者：提供 KernelSU 内核模块、`ksud` 和用户态管理能力。
- [Shizuku](https://github.com/RikkaApps/Shizuku) 作者 Rikka 及贡献者：提供无需重复启动应用进程的特权 shell 通道。
- [AndroidLiquidGlass](https://github.com/Kyant0/AndroidLiquidGlass) 作者 Kyant0 及贡献者：提供液态玻璃视觉组件。
- Android Open Source Project、JetBrains 及 Kotlin/Compose 贡献者：提供 AndroidX、Jetpack Compose 和相关基础组件。
- OnePlus 一键提权与 HyperBreak 的相关研究作者：为流程比较、KernelSU 初始化和候选进程方案提供了研究参考。

## 许可证

本项目原创代码采用 MIT License，Copyright (c) 2026 superboyyy。

第三方组件不由本项目重新授权。KernelSU、Shizuku、AndroidLiquidGlass、AndroidX、Compose 和 Kotlin 分别遵循其上游许可证。

`t64560_v36.c` 和 `t64560_v42_honor.c` 基于 `CVE-2026-64560-public` 的 MIT 许可研究代码；上游版权和修改说明完整保留在 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 和 [LICENSES/MIT-CVE-2026-64560.txt](LICENSES/MIT-CVE-2026-64560.txt)。

# Third-Party Notices

HOneClick's MIT License applies only to original project code. Third-party components retain their own copyrights and licenses.

## KernelSU

- Component: KernelSU kernel module, `ksud`, KernelSU Manager
- Tested version: KernelSU `v3.3.1`, manager version code `32680`
- Upstream: <https://github.com/tiann/KernelSU>
- License: GNU General Public License v3.0
- License text: [LICENSES/GPL-3.0.txt](LICENSES/GPL-3.0.txt)

The bundled KernelSU module is modified for the documented Honor kernel. The module metadata declares `license=GPL`. Before publicly redistributing an APK containing KernelSU binaries, the distributor must provide the complete corresponding source and build information required by the applicable GPL terms.

This source repository does not yet include a complete, matching KernelSU source tree. Public binary redistribution is therefore blocked pending resolution in [OPEN_SOURCE_CHECKLIST.md](OPEN_SOURCE_CHECKLIST.md).

## Shizuku

- Components: Shizuku Manager, Shizuku API/AIDL/provider/shared JARs
- Tested version: `13.6.0.r1086.2650830c`
- Upstream: <https://github.com/RikkaApps/Shizuku>
- License: Apache License 2.0
- License text: [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt)

## CVE-2026-64560 research code

- Upstream: <https://github.com/Feng1586/CVE-2026-64560-public>
- Baseline commit: `63b4f2b7b497d835c7cb1a43ff8851cd0d7a9ac8`
- Upstream files: `src/posix64560/t64560_v36.c`, `src/posix64560/t64560_v42.c`
- Copyright: 2026 GhostLock/CVE-2026-64560 research contributors
- License: MIT
- License text: [LICENSES/MIT-CVE-2026-64560.txt](LICENSES/MIT-CVE-2026-64560.txt)

`t64560_v36.c` is retained from the upstream research code. `t64560_v42_honor.c` contains device-specific modifications by HOneClick, including retry tuning, phase completion markers, target-process module loading, `adb_root` feature forcing, and self-target test support.

## AndroidLiquidGlass / Backdrop

- Component: `io.github.kyant0:backdrop:2.0.1`
- Upstream: <https://github.com/Kyant0/AndroidLiquidGlass>
- License: Apache License 2.0
- License text: [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt)

## AndroidX, Jetpack Compose, Kotlin

- AndroidX and Jetpack Compose: Copyright The Android Open Source Project
- Kotlin: Copyright JetBrains s.r.o.
- License: Apache License 2.0
- License text: [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt)

## Honor firmware-derived data

`assets/syms.txt` is derived from kernel symbol information associated with the tested Honor firmware. No open-source license has been established for that vendor-derived data. It must not be represented as MIT-licensed project source.

See [ASSET_PROVENANCE.md](ASSET_PROVENANCE.md) for the per-file review status.

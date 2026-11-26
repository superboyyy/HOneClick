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

## CVE-2026-99491 research code

- Upstream: <https://github.com/woshigenm/CVE-2026-99491>
- HOneClick port: `native/kernel_117_analysis/new-cve-table-2026-11-23/cve99491-port-117/`
- Embedded binary: `assets/exp117`
- License: upstream research code; no explicit redistribution license was established for this port.

The 99491 port and AVC-only route are personal research artifacts. Do not
redistribute the binary or exploit source without reviewing upstream terms and
the corresponding kernel-module obligations.

## CVE-2026-98260 research code

- Upstream: <https://github.com/sganggs/CVE-2026-98260-BRM-AN00>
- Baseline: main at `8bb92a66a3d0`
- Upstream files: `plant/uaf_plant.c`, `plant/pc98260_rootd.c`, `plant/pc98260_su.c`, `plant/slide_probe.c`
- License: no explicit upstream license was found at the audited revision

HOneClick adds a preflight mode, a fixed socket path, HOneClick integration and a 115/117 KernelSU module loader. These files are not MIT-licensed HOneClick originals and must not be redistributed as such without permission from the upstream author.


## SukiSU Ultra

- Component: SukiSU Ultra manager, `ksud`, and Android17-6.18 LKM
- Tested version: `v4.3.0-r2`
- Upstream: <https://github.com/SukiSU-Ultra/SukiSU-Ultra>
- License: GPL-2.0-only for kernel files; GPL-3.0-or-later for other components
- License text: [LICENSES/GPL-3.0.txt](LICENSES/GPL-3.0.txt)

The SukiSU flavor embeds the official release artifacts after verifying their
upstream SHA-256 checksums. The LKM vermagic is adjusted to the documented
Honor kernels, and its undefined symbols are resolved at runtime by HOneClick.

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

`assets/syms.txt`, `assets/syms-115.txt`, and `assets/syms-117.txt` are derived from kernel symbol information associated with the tested Honor firmware. No open-source license has been established for that vendor-derived data. They must not be represented as MIT-licensed project source.

See [ASSET_PROVENANCE.md](ASSET_PROVENANCE.md) for the per-file review status.

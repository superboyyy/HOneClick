# SukiSU Ultra command-line root

`scripts/root-98260-sukisu.sh` is a standalone command-line variant of the
CVE-2026-98260 flow. It runs independently from the APK build and downloads the
official SukiSU Ultra manager, `ksud`, and LKM release directly.

## Requirements

- A fresh boot with no `kernelsu` module loaded
- An authorized WKL-AN20 device matching a profile in `assets/exploit-profiles.json`
- `adb`, `python3`, and `curl`
- USB debugging enabled with the device online

The default SukiSU Ultra release is `v4.3.0-r2`. The script downloads its
aarch64 `ksud` and Android17-6.18 LKM into the local cache and verifies fixed
SHA-256 checksums before use.

If `com.sukisu.ultra` is already installed with version code `41150` or newer,
the manager APK is neither downloaded nor reinstalled. Use
`--reinstall-manager` to force the pinned APK installation, or
`--no-manager-install` to skip manager handling entirely.

## Check the target

```sh
ANDROID_SERIAL=<DEVICE_SERIAL> \
./scripts/root-98260-sukisu.sh --check
```

The check does not modify the device. It reports the matched kernel profile and
whether a reboot is required.

## Run the root flow

Start from a fresh reboot before switching from vanilla KernelSU:

```sh
ANDROID_SERIAL=<DEVICE_SERIAL> \
./scripts/root-98260-sukisu.sh --preflight
```

The script performs this sequence:

1. Verifies the exact kernel and 98260 profile.
2. Reuses an installed SukiSU Ultra manager; installs the pinned APK only when
   it is missing or older than version code `41150`.
3. Stages the 98260 helpers and official SukiSU `ksud`.
4. Measures the KASLR slide.
5. Patches the official SukiSU LKM vermagic and undefined symbols.
6. Starts one 98260 plant instance in a quiet, single-instance flow.
7. Loads the patched SukiSU LKM through the temporary root channel.
8. Runs `ksu_grant`, installs `ksud`, and verifies `/system/bin/su`.
9. Launches `com.sukisu.ultra`.

`--preflight` is optional; normal execution follows the same quiet path used by
HOneClick. A failed preflight stops before the destructive stage.

## Local assets

Use explicitly verified local SukiSU files instead of downloading:

```sh
./scripts/root-98260-sukisu.sh \
  --apk /path/to/SukiSU.apk \
  --ksud /path/to/ksud-aarch64-linux-android \
  --lkm /path/to/lkm-aarch64-android17-6.18_kernelsu.ko
```

## Failure handling

- Do not rerun after a parked/failed 98260 state. Reboot first.
- If a `kernelsu` module is already loaded, reboot before switching to SukiSU.
- The existing vanilla KernelSU manager is not uninstalled automatically.
- Root and the late-loaded SukiSU module are valid only for the current boot.

## Implementation

- `scripts/root-98260-sukisu.sh`: device orchestration and verification
- `scripts/patch-kernel-module.py`: pure-Python ELF64 relocatable patcher for
  exact vermagic and runtime symbol addresses

The official SukiSU Ultra components are licensed under GPL-2.0/GPL-3.0. This
CLI downloads the pinned upstream release by default (the `sukisu` APK flavor
separately embeds verified upstream artifacts under `src/sukisu/assets/`).

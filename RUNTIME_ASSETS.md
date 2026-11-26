# Runtime Assets

This repository includes the runtime assets used by the tested build. Their presence does not override third-party licenses or confirm redistribution rights for vendor-derived data.

The shared runtime files are located under `assets/`:

| File | Status |
|---|---|
| `assets/ShizukuManager.apk` | Included; Apache-2.0 attribution required |
| `assets/ksud` | Included; KernelSU GPL-3.0 obligations apply (overridden in `sukisu` flavor) |
| `assets/exploit-profiles.json` | Included; default KernelSU 98260 profiles (overridden in `sukisu` flavor) |
| `assets/syms.txt` | Included; 109 firmware-derived symbols, redistribution rights unresolved |
| `assets/syms-115.txt` | Included; 115 firmware-derived symbols, redistribution rights unresolved |
| `assets/syms-117.txt` | Included; 117 firmware-derived symbols, redistribution rights unresolved |
| `assets/cve98260_plant` | Prebuilt helper; source included under `native/cve98260/` |
| `assets/cve98260_slide` | Prebuilt KASLR helper; source included under `native/cve98260/` |
| `assets/cve98260_su` | Prebuilt temporary-root client; source included under `native/cve98260/` |
| `assets/cve98260_module` | Prebuilt `finit_module` helper; source included under `native/cve98260/` |
| `assets/exp117` | 99491 117 aarch64 exploit binary; source included under `native/cve99491/` |
| `assets/ko_patch` | On-device ELF64 `.ko` vermagic/symbol patcher for 99491; source included under `native/cve99491/` |
| `assets/ksu_grant` | Prebuilt helper; reproducible source (`native/ksu_grant.c`) and build script included |

Flavor-specific manager and LKM assets are kept in separate Gradle source sets so each APK only bundles its own manager and kernel module templates:

- **`src/sukisu/assets/`** (default `sukisu` flavor):
  - `SukiSUManager.apk`, `ksud`, `exploit-profiles.json`
  - `sukisu-template-109.ko`, `sukisu-template-115.ko`, `sukisu-template-117.ko`
  - `ko_syms-sukisu117.txt` (99491 runtime symbol list for SukiSU 117 LKM)
- **`src/kernelsu/assets/`** (optional `kernelsu` flavor):
  - `KernelSUManager.apk`
  - `ksu-template.ko`, `ksu-template-115.ko`, `ksu-template-117.ko`
  - `ko_syms-117.txt` (99491 runtime symbol list for KernelSU 117 LKM)

Keep the existing shell scripts and license files in `assets/`.

`cve98260_*` can be rebuilt with `scripts/build-cve98260.sh`. The 115 and 117
KernelSU module metadata can be regenerated with `scripts/build-ksu-template-115.sh`
and `scripts/build-ksu-template-117.sh`. The 99491 `exp117` and `ko_patch`
binaries are built from `native/cve99491/` with the fixed NDK; see
`scripts/build-cve99491.sh`.

Runtime helpers honor `HONOR_WORK`, allowing each root attempt to use a fresh
`/data/local/tmp/honor-run-*` directory instead of a stale fixed directory.

Expected hashes for all bundled runtime assets are listed in `ASSET_SHA256SUMS`. Run:

```bash
./scripts/verify-assets.sh
```

Do not publish runtime assets unless their source, license, and redistribution rights have been reviewed.

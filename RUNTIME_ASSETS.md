# Runtime Assets

This repository includes the runtime assets used by the tested build. Their presence does not override third-party licenses or confirm redistribution rights for vendor-derived data.

The runtime files are located under `assets/`:

| File | Status |
|---|---|
| `KernelSUManager.apk` | Included; official artifact and corresponding-source review required |
| `ShizukuManager.apk` | Included; Apache-2.0 attribution required |
| `ksud` | Included; KernelSU GPL-3.0 obligations apply |
| `ksu-template.ko` | Included; modified KernelSU module, corresponding-source review required |
| `syms.txt` | Included; Honor firmware-derived redistribution rights unresolved |
| `forker` | Prebuilt helper; source included |
| `perf_cred_honor` | Prebuilt helper; source included |
| `t64560_v36` | Prebuilt helper; source included with upstream MIT attribution |
| `t64560_v42` | Prebuilt helper; source included with upstream MIT attribution |
| `kaslr_slide` | Prebuilt helper; source included |
| `ksu_grant` | Prebuilt helper; reproducible source and build script included |

Keep the existing shell scripts and license files in `assets/`.

Expected hashes for the currently tested private assets are listed in `ASSET_SHA256SUMS`. Run:

```bash
./scripts/verify-assets.sh
```

Do not publish runtime assets unless their source, license, and redistribution rights have been reviewed.

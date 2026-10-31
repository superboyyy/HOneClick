# Runtime Assets

This repository includes the runtime assets used by the tested build. Their presence does not override third-party licenses or confirm redistribution rights for vendor-derived data.

The runtime files are located under `assets/`:

| File | Status |
|---|---|
| `KernelSUManager.apk` | Included; official artifact and corresponding-source review required |
| `ShizukuManager.apk` | Included; Apache-2.0 attribution required |
| `ksud` | Included; KernelSU GPL-3.0 obligations apply |
| `ksu-template.ko` | Included; modified KernelSU module for the 64560 backend, corresponding-source review required |
| `ksu-template-115.ko` | Included; same KernelSU module with the 115 vermagic, corresponding-source review required |
| `syms.txt` | Included; 109 firmware-derived symbols, redistribution rights unresolved |
| `syms-115.txt` | Included; 115 firmware-derived symbols, redistribution rights unresolved |
| `cve98260_plant` | Prebuilt helper; source included under `native/cve98260/` |
| `cve98260_slide` | Prebuilt KASLR helper; source included |
| `cve98260_su` | Prebuilt temporary-root client; source included |
| `cve98260_module` | Prebuilt `finit_module` helper; source included |
| `forker` | Prebuilt helper; source included |
| `perf_cred_honor` | Prebuilt helper; source included |
| `t64560_v36` | Prebuilt helper; source included with upstream MIT attribution |
| `t64560_v42` | Prebuilt helper; source included with upstream MIT attribution |
| `kaslr_slide` | Prebuilt helper; source included |
| `ksu_grant` | Prebuilt helper; reproducible source and build script included |

Keep the existing shell scripts and license files in `assets/`.

`cve98260_*` can be rebuilt with `scripts/build-cve98260.sh`. The legacy
`t64560_*`, `perf_cred_honor`, `kaslr_slide`, and `forker` helpers can be rebuilt
with `scripts/build-legacy-helpers.sh`. The 115 module metadata can be regenerated
with `scripts/build-ksu-template-115.sh`.

Runtime helpers honor `HONOR_WORK`, allowing each root attempt to use a fresh
`/data/local/tmp/honor-run-*` directory instead of a stale fixed directory.

`speed.cfg` is intentionally not shipped: it is an optional, user-created file at
`/data/local/tmp/honor/speed.cfg` used to roll the spray timing back to the previous
behaviour. See the tuning section in `README.md`.

Expected hashes for the currently tested private assets are listed in `ASSET_SHA256SUMS`. Run:

```bash
./scripts/verify-assets.sh
```

Do not publish runtime assets unless their source, license, and redistribution rights have been reviewed.

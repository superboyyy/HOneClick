# Asset Provenance

This file records the known origin and redistribution status of embedded binaries and data. It does not grant any rights beyond the applicable upstream licenses.

| File | Version / source | License status | Release status |
|---|---|---|---|
| `assets/KernelSUManager.apk` | KernelSU `v3.3.1`, version code `32680` | Upstream GPL-3.0; exact artifact provenance still requires verification | Blocked pending corresponding-source and signature review |
| `assets/ShizukuManager.apk` | Shizuku `13.6.0.r1086.2650830c` | Apache-2.0 | Verify official artifact signature before public redistribution |
| `assets/ksud` | KernelSU `v3.3.1` userspace | GPL-3.0 | Provide corresponding source/build information |
| `assets/ksu-template.ko` | 109 Honor KernelSU LKM with the reproducible bootstrap-credential patch in `patches/patch_ksu_bootstrap_creds_v331.py`; input/output checksums and source equivalent are documented in `docs/SU_ACCESS_FIX.md` | Module metadata declares `GPL`; full matching module source is still not in this tree | Existing release blocker remains |
| `assets/ksu-template-115.ko` | `ksu-template.ko` with 115 vermagic | Module metadata declares `GPL`; matching source not in this tree | Release blocker |
| `assets/ksu-template-117.ko` | `ksu-template.ko` with 117 vermagic | Module metadata declares `GPL`; matching source not in this tree | Release blocker |
| `libs/shizuku-*.jar` | Shizuku client libraries | Apache-2.0 | Include notice and license |
| `assets/syms.txt` | Derived from 109 Honor firmware kernel symbol data | No redistribution license established | Release blocker |
| `assets/syms-115.txt` | Derived from 115 Honor firmware kernel symbol data | No redistribution license established | Release blocker |
| `assets/syms-117.txt` | Derived from 117 Honor firmware kernel symbol data | No redistribution license established | Release blocker |
| `src/sukisu/assets/SukiSUManager.apk` | SukiSU Ultra `v4.3.0-r2`, version code `41150`, official release SHA-256 verified | GPL-3.0; upstream source available | SukiSU flavor only |
| `src/sukisu/assets/ksud` | SukiSU Ultra `v4.3.0-r2` aarch64 userspace, official release SHA-256 verified | GPL-3.0 | SukiSU flavor only |
| `src/sukisu/assets/sukisu-template-*.ko` | Official SukiSU Android17-6.18 LKM with flavor-specific vermagic; undefined symbols patched at runtime | GPL-2.0 kernel component | SukiSU flavor only |
| `native/ksu_grant.c`, `assets/ksu_grant` | Project implementation of the KernelSU root-fd bootstrap | Project MIT | Rebuild with `scripts/build-ksu-grant.sh`; output hash verified |
| `assets/exp117` | 99491 117 port (`native/kernel_117_analysis/new-cve-table-2026-11-23/cve99491-port-117/`); source included | Upstream research/port; public redistribution requires review | Personal research only |
| `native/cve98260/*`, `assets/cve98260_*` | Port of `sganggs/CVE-2026-98260-BRM-AN00` main at `8bb92a66a3d0` | Upstream provides no explicit license | Personal research only; public redistribution blocked |
| `assets/root_stage.sh` | Project script | Project MIT | Include checksum |

## Checksums

Run:

```bash
./scripts/verify-assets.sh
```

The expected hashes are stored in `ASSET_SHA256SUMS`.

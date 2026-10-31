# Asset Provenance

This file records the known origin and redistribution status of embedded binaries and data. It does not grant any rights beyond the applicable upstream licenses.

| File | Version / source | License status | Release status |
|---|---|---|---|
| `assets/KernelSUManager.apk` | KernelSU `v3.3.1`, version code `32680` | Upstream GPL-3.0; exact artifact provenance still requires verification | Blocked pending corresponding-source and signature review |
| `assets/ShizukuManager.apk` | Shizuku `13.6.0.r1086.2650830c` | Apache-2.0 | Verify official artifact signature before public redistribution |
| `assets/ksud` | KernelSU `v3.3.1` userspace | GPL-3.0 | Provide corresponding source/build information |
| `assets/ksu-template.ko` | KernelSU LKM modified for the 109 Honor kernel | Module metadata declares `GPL`; matching source not in this tree | Release blocker |
| `assets/ksu-template-115.ko` | `ksu-template.ko` with 115 vermagic | Module metadata declares `GPL`; matching source not in this tree | Release blocker |
| `libs/shizuku-*.jar` | Shizuku client libraries | Apache-2.0 | Include notice and license |
| `assets/syms.txt` | Derived from 109 Honor firmware kernel symbol data | No redistribution license established | Release blocker |
| `assets/syms-115.txt` | Derived from 115 Honor firmware kernel symbol data | No redistribution license established | Release blocker |
| `native/ksu_grant.c`, `assets/ksu_grant` | Project implementation of the KernelSU root-fd bootstrap | Project MIT | Rebuild with `scripts/build-ksu-grant.sh`; output hash verified |
| `native/forker.c`, `assets/forker` | Project research helper; source present | Project MIT, provenance review recommended | Document build command |
| `native/perf_cred_honor.c`, `assets/perf_cred_honor` | Project device-specific helper; source present | Project MIT, provenance review recommended | Document build command |
| `native/t64560_v36.c`, `assets/t64560_v36` | Upstream `CVE-2026-64560-public` at commit `63b4f2b`; source retained with an added attribution header | MIT, copyright retained in source and `LICENSES/MIT-CVE-2026-64560.txt` | Provenance resolved |
| `native/t64560_v42_honor.c`, `assets/t64560_v42` | Derived from upstream `t64560_v42.c` at commit `63b4f2b`; Honor changes documented | Upstream MIT plus HOneClick modifications | Provenance resolved; native rebuild still pending |
| `native/kaslr_slide.c`, `assets/kaslr_slide` | Project KASLR helper | Project MIT | Document build command |
| `native/cve98260/*`, `assets/cve98260_*` | Port of `sganggs/CVE-2026-98260-BRM-AN00` main at `8bb92a66a3d0` | Upstream provides no explicit license | Personal research only; public redistribution blocked |
| `assets/grab.sh`, `assets/root_stage.sh` | Project scripts | Project MIT | Include checksum |

## Checksums

Run:

```bash
./scripts/verify-assets.sh
```

The expected hashes are stored in `ASSET_SHA256SUMS`.

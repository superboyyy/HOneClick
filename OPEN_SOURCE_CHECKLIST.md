# Open-Source Release Checklist

## Completed

- [x] Project code has an explicit MIT copyright holder.
- [x] KernelSU GPL-3.0 and Apache-2.0 license texts are included.
- [x] Shizuku, AndroidLiquidGlass, AndroidX, Compose, and Kotlin are listed in third-party notices.
- [x] Build directories, local SDK configuration, caches, and signing material are excluded by `.gitignore`.
- [x] README, security policy, contribution rules, asset provenance, and checksum verification are present.
- [x] In-app safety notice describes the temporary-root and personal-research scope.
- [x] `ksu_grant` has a reproducible NDK build script and verified output hash.
- [x] `t64560_v36` and `t64560_v42_honor` are traced to the public upstream MIT source, with copyright and modifications retained.

## Release blockers

- [ ] Confirm that the KernelSU Manager APK and `ksud` came from official upstream releases and record their signatures.
- [ ] Provide complete corresponding source and reproducible build information for the modified KernelSU LKM and other GPL components distributed in the APK.
- [ ] Confirm whether Honor firmware-derived `syms.txt` may be redistributed, or replace it with a user-side generation process.
- [ ] Add reproducible build scripts and verify every remaining generated native helper.

## Before a public binary release

- [ ] Build and sign with a dedicated release key.
- [ ] Publish the APK SHA-256 and a signed source tag.
- [ ] Test a clean reboot, successful root, rollback, and failure paths.
- [ ] Confirm the README still matches the exact supported firmware and kernel.
- [ ] Re-read all third-party notices after any dependency upgrade.

# Late-load SU access fix

The legacy 109-kernel flow can load KernelSU successfully while a normal ADB
shell still gets `Permission denied` from `su`. Executing the same virtual SU
path through `env` or `timeout` succeeds, because those commands skip mksh's
`access()` preflight.

## Cause and change

The bootstrap helper changes its filesystem IDs and capabilities before loading
the module, without first normalizing its complete identity. KernelSU initially
copies the caller using `ksu_cred = prepare_creds()`. Its later root transition
does not repair that cached copy. The SU compatibility `faccessat` path uses
`ksu_cred`; Linux access checks restore the real IDs and lose access to the
root-only `/data/adb` directory.

The bootstrap allocation is changed to
`ksu_cred = prepare_kernel_cred(&init_task)`. This makes an independent copy of
the initial task's complete root credentials. The existing `setup_ksu_cred()`
still applies the KernelSU SELinux domain. Application authorization and root
profiles are not changed.

The complete corresponding Honor module source/build tree is absent from this
repository. Consequently, this change supplies a guarded ELF patch and the source
equivalent in `patches/kernelsu-v3.3.1-bootstrap-creds.patch`; it does not claim a
full module source rebuild or resolve the pre-existing source/provenance blocker.

The ELF patch rejects an unknown input hash, instruction sequence or relocation
layout. It reuses the optional bootstrap `allow_shell` diagnostic sequence to
load `&init_task` and calls `prepare_kernel_cred` instead of `prepare_creds`.
It removes that one diagnostic call, updates the relevant relocations, and keeps
the other module sections and runtime code unchanged.

Input SHA-256:
`e33b7c5dbbef2206571c99b13eadf1bc99a11d3182f6e5f3e2540c6ca9568003`

Output SHA-256:
`86ed32a0946490736850d0c5d7a703c6e5bfde541e82864ed892b31e2b590563`

The source asset in the initial release (`87dfc2e`) and in the 2.0 Beta base
(`9c6769f`) has the same input hash. To reproduce, retrieve that original asset
from Git into a separate file and run:

```sh
python patches/patch_ksu_bootstrap_creds_v331.py original.ko fixed.ko
```

`initializeKernelSU()` also verifies `/system/bin/su -c id` directly from a fresh
Shizuku shell, without an `env` or `timeout` wrapper. The log marker is
`direct su identity:`. Success requires both `uid=0(root)` and
`context=u:r:ksu:s0`; otherwise initialization fails and asks for a reboot before
retrying, rather than reporting Root ready with a reused faulty module.

## Validation

Device regression was performed on an owned WKL-AN20, Android 17, kernel
`6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k`.
The baseline was HOneClick 1.0 (40); the test APK was
`1.0.1-su-fix-test` (41), based on `87dfc2e`. After rebooting and running the
patched legacy flow:

- Plain `su -c id` and absolute `/system/bin/su -c id` succeed.
- Interactive `adb shell` followed by `su` enters the root shell.
- `command -v su` and `which su` return `/system/bin/su`.
- `faccessat` checks for existence, read and execute permission return success;
  all three returned `EACCES` before the fix.
- SELinux remains Enforcing and KernelSU remains in late-load mode.

Offline checks require Python 3, `pyelftools`, Git and a JDK:

```sh
python -m unittest discover -s tests -v
python tests/check_java_module_relocation.py --java-home "$JAVA_HOME"
```

The tests check deterministic output, the bundled module hash, refusal of
unknown inputs, the exact bootstrap relocations and unchanged unrelated module
sections. The Java check runs the application's actual `patchModule` method and
verifies that `init_task` and `prepare_kernel_cred` are resolved correctly.
For a shallow/source-only checkout, `KSU_ORIGINAL_MODULE` may point to a copy of
the original input module for the Python tests.

This PR targets the existing 109 template. It does not modify
`ksu-template-115.ko` or claim hardware validation of the 115 profile or the new
2.0 Beta flow. No exploit helpers, compatibility profiles, application ID,
version number, package providers, or APK files are changed by this PR.

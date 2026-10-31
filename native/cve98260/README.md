# CVE-2026-98260 backend

These files are adapted from
`sganggs/CVE-2026-98260-BRM-AN00` at main commit
`8bb92a66a3d0`.

HOneClick changes:

- `uaf_plant.c` accepts `--preflight` for a non-destructive tracefs,
  timer, AIO and Unix-socket gate check.
- A slide value is mandatory for the destructive path.
- The temporary-root socket defaults to
  `/data/local/tmp/cve98260-root.sock`, outside the replaceable staging
  directory. `PC98260_SOCK` overrides it so HOneClick can use a unique socket
  path for each run and bypass stale sockets.
- `module_loader.c` is an HOneClick addition that calls `finit_module()`
  after the 115 KernelSU module has been symbol- and vermagic-patched.

The upstream repository did not contain an explicit license at the audited
revision. See `THIRD_PARTY_NOTICES.md` and `ASSET_PROVENANCE.md`.

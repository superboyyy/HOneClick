# CVE-2026-98260: AVC flags route status

Date: 2026-11-27

## Short answer

The 99491 AVC clean-flags route is **not a drop-in** for the current 98260
timer-UAF chain.

## Why

99491 AVC write (from `cve99491-port-117`) targets:

```text
avc_node+0x18  avd.seqno = 0x000e0005
avc_node+0x1c  avd.flags = 1          (AVD_FLAGS_PERMISSIVE)
node+0x20      xp_node untouched
```

It needs a **controlled value write of 1** into `avd.flags`.

The 98260 `uaf_plant.c` POSIX-timer UAF plants fake rb nodes as:

```text
node[0] = 0
node[1] = 0
node[2] = target
```

and is used as a **zero write**:

- `selinux_state-7` -> clears `enforcing` (0);
- `cred+8` / `cred+...` -> zeros uid/euid/gid fields.

A zero write to `avc_node+0x18` would produce:

```text
seqno = 0
flags = 0   (not AVD_FLAGS_PERMISSIVE)
```

So it cannot set the permissive bit; it may also corrupt the AVC seqno.

## Options

1. **Keep `selinux_state-7` for 98260** (current behavior). This is a zero
   write and fits the existing primitive.
2. **Controlled-value 4/8-byte write**: needs a new 98260 primitive or a
   different fake-timer layout; not currently proven.
3. **Two-stage**: 98260 fake-cred root (`--skip-selinux`) -> run the 99491
   AVC writer (`exp117 --avc-only --avc-test`) as root -> load 98260 SukiSU.
   This is not a one-line change: it depends on the 99491 Wacom/uhid/tracefs
   path, per-boot slide, and needs its own QEMU/real validation.

## Current decision

- 99491: HOneClick currently invokes `--no-avc` (`selinux_state-7`) on 117;
  AVC-only (`--avc-only`) remains available for research testing.
- 98260: **not changed**; it remains on `selinux_state-7` until option 2 or 3
  is implemented and validated. Directly changing it to the AVC target would
  break the permissive step.

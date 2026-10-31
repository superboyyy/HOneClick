# CVE-2026-98260 on BRM-AN00

Reference port: `references/CVE-2026-98260-nezha-android` (Xiaomi 17 Ultra `nezha`, kernel `6.12.69-android16-6`). That tree is unchanged. This directory is the BRM retarget.

## Vulnerability is in this boot image

Upstream fix `acb03d388181` ("exec: Cleanup POSIX timers right after de_thread") is in 6.18.54. This kernel is `6.18.21-android17-5-ge186062ea75f-abogki564062290-4k`, built 2026-09-20.

In `begin_new_exec` (`0xffffffc08033fe80`) the non-leader path is the branch at `+0x28c` (`b.ne` to `0xffffffc0803402f8`): `zap_other_threads`, then `exchange_tids` at `+0x844`, then `release_task` at `+0x918`. That path branches back to `+0x33c`, which falls into `unshare_files`, `set_mm_exe_file`, `exec_mmap` (`down_read_killable` at `+0x170`), and `exec_task_namespaces`. Only after those succeed does the straight-line code call `posix_cpu_timers_exit` (`+0x2f8`), `exit_itimers` (`+0x308`) and `flush_itimer_signals` (`+0x30c`).

`down_read_killable` failure jumps to `+0x574` and returns. `bprm+0x28` bit 3 is set at `+0x74`, before `de_thread`. A SIGKILL during `exec_mmap` is the published trigger: the task dies in `do_exit` -> `exit_itimers` while the per-thread CPU-timer node is still queued, and the parent's reap calls `timerqueue_del` on the freed node.

`posix_cpu_timers_exit` has only two callers: `release_task+0xd0` and `begin_new_exec+0x2f8`. The second one is the late call above, not a call immediately after `de_thread`.

## Constants re-derived from this image

| Item | nezha | BRM |
| --- | --- | --- |
| `k_itimer` | 0x100 | 0x180 |
| `cpu_timer.node` | +0x78 | +0xe0 (`it` at 0xe0, `node` at 0) |
| slab | 32 x 256, order-1 | 21 x 384, order-1 |
| `rcu` member | +0xf0 | +0x158 |
| timer leak | `do_timer_create+0xb0` `%x19` | `do_timer_create+0xbc` `%x20` (the `mov x20, x0` after `kmem_cache_alloc` has retired; `x19` is a counter) |
| free observation | `k_itimer_rcu_free` (rcu head) | `__kasan_slab_free` `%x1`. There is no `k_itimer_rcu_free`. Bulk frees go through `kmem_cache_free_bulk` and still call `__kasan_slab_free(cache, object)`. The list path's `kvfree` does too. The probe is created disabled and armed only after a slab-range filter is installed, and only once the exec zombie exists |
| `selinux_state` | `0xffffffc0827f9ba0` | `0xffffffc08299a6f0` |
| `__arm64_sys_getpid` | `0xffffffc080102e10` | `0xffffffc08034b368` |
| notif lock | symbol present | `avc_latest_notif_update.notif_lock` at `selinux_state-8`; the `-7` zero-write still lands on `enforcing` |
| `task->cred` / `real_cred` / `comm` | 0x900 / 0x8f8 / 0x910 | 0x908 / 0x900 / 0x918 |
| `cred.uid` / `cap_bset` | +8 / +0x48 | same (+8 and +72) |
| `perf_buffer.user_page` | +0x120 | +0x118 (`perf_mmap_to_page` loads `[rb,#0x118]` for pgoff 0; data pages start at +0x120) |
| vmemmap | `0xfffffffec0000000` | same immediate in `virt_to_page` (`movn`/`movk #0xc000,lsl #16`) |
| page offset | `0xffffff8000000000` | same |

`0x180` is not a power of two, so `addr & (size-1)` is not a slot test. Slot checks use `(addr - slab) % 0x180 == 0`. The AIO spray also writes the victim's exact page offset, because `slot * 0x180` does not cover every node offset inside a 4 KiB half-page. Key payload length is 224 so the forged node at `0xe0 - 0x18` still fits in `kmalloc-256`.

## Device gate measured 2026-10-24

Same boot as the earlier capture (`6d317882-e071-4d08-b7e9-e9ac8e6b1a66`). `uname` matches this image. `posix_timers_cache` is `384  21  2`. Page size is 4096. Shell is uid 2000, enforcing.

The port's probes are not installable from this shell:

| Interface | Result |
| --- | --- |
| `/sys/kernel/tracing/kprobe_events` | mode `0640` root:readtracefs, write returns EACCES. No events are installed |
| `perf_event_open` | EACCES even for a software event. `perf_event_paranoid` is `-1`; SELinux still denies it |
| `kmem/*` tracepoints | SELinux denies `enable` and `format` |
| `/proc/self/pagemap` | readable, present bit set, PFN forced to 0 |
| `/proc/timer_list`, `/proc/kallsyms` | not readable |
| `adb root` | refused on this production build |

`timer_create(CLOCK_THREAD_CPUTIME_ID)` succeeds. `rss_stat`, `sched_blocked_reason`, `signal_generate`, and `mm_filemap_add_to_page_cache` are shell-writable and the trace file is readable. The filemap event prints a real PFN (`pfn=0x98bb62`). Raw `sched_blocked_reason` still contains `worker_thread+0x2d4` at runtime `0xffffffe42f57f228`, so the slide on boot `6d317882-e071-4d08-b7e9-e9ac8e6b1a66` is still `0x23af400000`. `task_rename` and `sched_process_free` text records have no kernel object pointer. `simpleperf` cannot open `kprobe_events`. `perfetto` can record `sched/sched_switch` but a `kmem/kmem_cache_alloc` session contains no allocation records. `atrace memory` does not emit slab events.

Shell can still leak the timer object. `rss_stat`'s trigger file is mode `0666`. Writing `enable_event:kmem:kmem_cache_alloc` there, then faulting one anonymous page, turns the alloc trace on even though shell cannot open that event's own `enable` file. In the raw per-CPU record the `do_timer_create+0xb8` call site is followed by the real object pointer at `+8` and `bytes_req=0x180` at `+24`. The text form of `ptr=` is hashed. The same trigger enables `kmem:mm_page_free`, whose text prints a real PFN. Anonymous faults are movable: eight rounds of 2048 faults produced 2052 `mm_page_alloc` events each, four of them page-table pages, and none was a leaked timer PFN. New files on this f2fs `/data` do not emit `mm_filemap_add_to_page_cache`.

`io_uring_setup` and `add_key` return `EACCES` while `Seccomp` is 0. `msgget` returns `ENOSYS`. AIO does run, and `mm_filemap_add_to_page_cache` prints one real PFN per `io_setup`. A 320-delete returns no leaked slab page within 2 seconds. A 2048-delete does. Holding 66 MiB of pipe pages, then deleting 2048 timers and spraying 3072 AIO rings, put leaked timer `pfn=0xb51c04` in ring 181 at `ctx=0x75dfe6a000` with ring magic `0xa10a10a1`. A normal `_exit` of 2048 thread-CPU timers returns their slabs: 84 of 99 order-1 bases showed up in `mm_page_free`. The same volume inside the SIGKILL exec also returns a middle timer's page.

The UAF page comes back as order-1 and is not split for an order-0 AIO ring or pipe buffer. Runs with the spray on every CPU, a 66 MiB pipe drain, 4 GiB of unix-socket buffers, and 65536 held AIO rings (four processes at the 16384 per-process cap) still showed `victim_order0=0`. Under the 4 GiB socket hold, `io_setup` itself allocated the armed timer PFN as `order=1 migratetype=0` with `__GFP_COMP|__GFP_NORETRY`. That allocation is a kernel slab page. The filemap ring is a separate order-0 page (`GFP_USER|__GFP_ZERO|__GFP_COMP|__GFP_ACCOUNT`, migratetype 0), so the slab bytes are not writable from the ring. Binder data pages are the same order-0 unmovable allocation (`gfp 0xdc2`) inserted with `vm_insert_page`; the mapping is readable, and `mprotect` to writable returns EACCES. `AF_NETLINK` returns EACCES. `setxattr` accepts 4096 bytes and rejects 8192 with E2BIG.

A 16000-byte `AF_UNIX` `SOCK_DGRAM` allocates one unmovable order-2 page (`GFP_USER|__GFP_NOWARN|__GFP_COMP|__GFP_NOMEMALLOC|__GFP_ACCOUNT`) and copies the payload at skb offset 0. `unix_dgram_sendmsg` passes header length 0 and the message length to `sock_alloc_send_pskb`, then `skb_copy_datagram_from_iter` at offset 0. That order-2 request cannot use a lone order-1 page. On a run that sent 512 of those datagrams across the free, `victim_frees=1`, `buddy_frees=0`, `order2=512`, `hit=0`. The armed page's buddy stayed allocated, so the freed page never became an order-2 block. `mq_open` and `msgget` return ENOSYS. `add_key("user")` and `add_key("big_key")` return EACCES before `user_preparse` copies the payload; the failure path can still allocate an order-1 `key_jar` slab page (240-byte objects) with the same GFP as the earlier `io_setup` slab steal. Four hundred 6000-byte datagrams produced only a handful of those order-1 slab pages, not one data page per message. A unix `SOCK_STREAM` write is different: `alloc_skb_with_frags` asks for an unmovable compound page and falls from order 3 down to order 1. Writing an 8KB pattern while the UAF page is free takes that exact pfn (`order=1`, `GFP_NOWAIT|__GFP_IO|__GFP_FS|__GFP_COMP|__GFP_HARDWALL|__GFP_ACCOUNT`). The frag descriptor stores offset 0. `release_task` is the caller of `posix_cpu_timers_exit`, so the reap is the delete. Reaping after the hit does not panic, including when `{0,0,selinux-7}` is tiled across the buffer at the node's 24-byte alignment. A second run tiled a non-canonical parent at that same alignment. Filling the whole 8KB buffer with `0x41` also does not fault. `exit_itimers` calls `posix_timer_delete` and `posix_timer_unhash_and_free`, which unlink the hash, not the cpu-timer rbtree. `posix_cpu_timer_del` is only reached from `do_cpu_nanosleep`. The queue walk is `release_task`. `exchange_tids` swaps the pid at `task+0x718` and the pid pointer at `task+0x780`, so the parent reaps the exec thread's `task_struct`. The node address is still not the bytes copied into the matched stream page. Holding 2.5GB of stream data still gets fresh order-3 pages, so the 8KB write is not forced to be the sole contents of that order-1 page. SELinux is still enforcing and the shell is still uid 2000. `--target` has not been run. Parked UAF parents were left alive so their zombies are not reaped.

Those plants used `SIGEV_NONE`. On this image `posix_cpu_timer_set` skips `timerqueue_add` when `it_sigev_notify` is 1, so the node was never queued. `k_clock.timer_del` at `posix_cpu_clock+0x40` is `posix_cpu_timer_del` (`0xffffffc080581ee8`); a direct-call scan misses it. If pid lookup fails while `cpu_timer.head` is set, that function hits `WARN_ON_ONCE` (`brk #0x800`, bug-table flags `0x903`, warning plus once) and returns without `timerqueue_del`. The armed timer has to be `SIGEV_SIGNAL`. The phone then rebooted. New boot `14605d19-7b1b-4b79-8570-9a2a3da39a91`, same fingerprint. Raw `do_timer_create+0xb8` is `0xffffffd239de1fd0`, so the slide is `0x11b9a00000`. On that boot the armed timer was created with `SIGEV_SIGNAL` / `SIGRTMIN`. The stream write took `pfn=0xbaf8c6` order-1 at node offset `0x1ee0`, and the reap wrote the safe node. A fresh adb shell reads `getenforce` as Permissive and `/sys/fs/selinux/enforce` as 0. The same boot then installed a fake credential: fork leaked the child `task_struct`, the reclaimed order-1 page held the cred at the timer node, and the reap stored that address at `task+0x908`. Two following zero-writes repaired uid/gid and suid/sgid. `pc98260_run_rootd` is listening. A fresh `adb shell /data/local/tmp/pc98260-su -c id` prints `uid=0(root) gid=0(root)` and `CapEff: 000001ffffffffff`. `getenforce` inside that command is Permissive. The shell context string is null because the fake cred's SELinux sid is 0.

## Shown on this boot

uid 0, gid 0, and `CapEff 000001ffffffffff` were confirmed from a fresh adb shell on boot `14605d19-7b1b-4b79-8570-9a2a3da39a91`. ReSukiSU (BakaSU v4.2.0-rc3) was then late-loaded, which sets SELinux back to Enforcing by design. `/system/bin/su -c id` is `uid=0(root)` in `u:r:ksu:s0` with the same full `CapEff`. The manager is `com.resukisu.resukisu`. Nothing was flashed.

Boot `7edf256a-7842-48cd-b715-4d6e8ea9d009` has slide `0xfbd800000` (`do_timer_create+0xb8` at `0xffffffd03dbe1fd0`). Polling `/data/local/tmp/cred_ask` stopped after the cred write: musl `access()` clones a helper once uid and euid differ, and that helper could not see the file. The cred child stayed alive. `/proc/pid/status` kept showing uid 2000 because it reads `real_cred` at `task+0x900`, while `getuid` reads `cred` at `task+0x908`. The rebuilt plant asks over a pipe created before the write, and first plants a zero at `selinux_state-7`. On this boot that zero landed on the first try (`enforce=0`). The first cred plant answered `uid=0 euid=0 gid=0 egid=0`, and `capget` reported `000001ffffffffff`. `ksud late-load` then came up: `late_load: true`, `/system/bin/su -c id` is `uid=0(root)` in `u:r:ksu:s0`, and `getenforce` is Enforcing again. Nothing was flashed.

## Replay after reboot

`replay.ps1` measures the new KASLR slide, runs `uaf_plant_replay --slide`, then `ksud late-load --kmi android17-6.18`. The manager APK stays installed. The kernel module and `/system/bin/su` do not. Bootloader stays locked. A miss parks the UAF parent instead of letting init reap it.

Before any reap:

1. `--preflight` only. It must print a timer pointer, a full 21-slot slab, and an RCU match for that object.
2. `kprobe_events` must be writable by the shell. An earlier session saw mode `0640`.
3. The slab filter on the RCU event is attempted and is non-fatal if tracing denies it. Without it, `kvfree_rcu_list` is too busy and the snapshot in `/sys/kernel/tracing/trace` can drop the match.
4. Object free is observed at `__kasan_slab_free` (`x1` is the object on both the single-free and bulk-free calls). The probe stays disabled until the owned slab address is known, a `head >= slab && head < slab+0x2000` filter is installed, and the fillers are about to be deleted. If that filter file is not writable, the run stops instead of leaving the probe armed on every slab free.

`memstart_addr` in the image is the relocatable `-1`. `MEMSTART_PFN` stays `0x80000` until `/proc/iomem` on this boot confirms the RAM base.

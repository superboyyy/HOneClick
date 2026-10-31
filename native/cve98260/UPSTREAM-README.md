# CVE-2026-98260 on HONOR Win2 (BRM-AN00)

在自己的 HONOR Win2 上，把 CVE-2026-98260 重放到 Magic OS 11 / Android 17，拿到本次开机的 root，再交给 BakaSU（ReSukiSU）管理。不解锁、不刷分区、不装系统更新。重启后模块和 `/system/bin/su` 都会消失，需要再跑一次。

只适用于这一版内核：

`6.18.21-android17-5-ge186062ea75f-abogki564062290-4k`

对应系统 `BRM-AN00 11.0.0.115(SP7C00E115R101P3)`。同型号、同一固件的另一台手机可以用，因为每次开机都会重新测量 KASLR。系统版本或安全补丁不同就不适用，结构体偏移是按这颗内核重算的。

上游修复是 `acb03d388181`（`exec: Cleanup POSIX timers right after de_thread`），进了 6.18.54。这颗内核是 2026-09-20 编的 6.18.21，里面没有这个修复。

另一台机器上的公开移植在 [CVE-2026-98260-nezha-android](https://github.com/quyicheng03-boop/CVE-2026-98260-nezha-android)。那边的 `k_itimer` 大小和节点偏移不能直接拿来用。本仓库的测量记在 [plant/ADAPTATION-BRM.md](plant/ADAPTATION-BRM.md)。

## 这条链在做什么

`CLOCK_THREAD_CPUTIME` 的 POSIX CPU 定时器在 `de_thread` 之后、`exec_mmap` 之前不会被清掉。非 leader 线程执行期间如果在 `mmap_read_lock_killable` 上被 `SIGKILL`，`exit_itimers` 先释放 `k_itimer`，父进程回收时 `timerqueue_del` 还拿着已经释放的节点。

这颗内核上，武装用的那个定时器必须是 `SIGEV_SIGNAL`。`SIGEV_NONE` 不会进 timerqueue。释放出来的是单独一张 order-1 页，8KB 的 unix `SOCK_STREAM` 写入可以把它占住。占住之后，回收路径把伪造的 `cred` 地址写进被泄露的 `task + 0x908`。接着两次写零，把擦除时弄脏的 uid/gid 和 suid/sgid 清掉。`getuid` 读的是 `cred`，`/proc/pid/status` 读的是 `real_cred`（`task + 0x900`），所以 proc 里仍可能显示原来的 uid。

SELinux 仍是 Enforcing 时，新 cred 打不开新文件。问询走的是提权前就建好的管道。写 `selinux_state - 7` 可以把 enforcing 字节清掉。BakaSU late-load 成功之后会按它自己的设计把 SELinux 设回 Enforcing。

错过页面时，父进程停在原地，不退出。init 去回收仍挂在队列上的节点有可能把机器打崩。

## 目录

- `plant/`：测量 slide、占页、写 cred、临时 root 套接字。`uaf_plant.c` 是主程序。
- `app/`：手机上的 `BRM ReSuki`。用 Shizuku（和 adb shell 同一个身份）跑上面的程序，再 late-load BakaSU。
- `third_party/`：不附带 `ksud` 和管理器 APK，自己放进去。

## 编译

安装 [zig](https://ziglang.org/)，然后：

```powershell
powershell -File plant/build.ps1
```

产物是 `plant/uaf_plant_replay`、`slide_probe`、`pc98260-su`、`cap_check`，目标为 `aarch64-linux-musl`。

电脑上重放：

```powershell
$env:ADB = 'adb.exe'
powershell -File plant/replay.ps1
```

只接一台手机时不用设 `ANDROID_SERIAL`。`third_party/ksud` 和 `third_party/manager.apk` 要先放好。late-load 参数是 `ksud late-load --kmi android17-6.18 --allow-shell --package-name com.resukisu.resukisu`。

手机应用的构建依赖 JDK 17、`android.jar`、build-tools 里的 aapt2/d8/zipalign/apksigner，以及 Shizuku 的 jar。见 `app/build.ps1`。

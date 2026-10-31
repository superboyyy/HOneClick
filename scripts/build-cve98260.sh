#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ndk=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}

if [ -z "$ndk" ]; then
    echo "Set ANDROID_NDK_HOME to an Android NDK installation." >&2
    exit 1
fi

case "$(uname -s)" in
    Darwin) host=darwin-x86_64 ;;
    Linux) host=linux-x86_64 ;;
    *)
        echo "Unsupported build host: $(uname -s)" >&2
        exit 1
        ;;
esac

bindir="$ndk/toolchains/llvm/prebuilt/$host/bin"
cc="$bindir/aarch64-linux-android29-clang"
if [ ! -x "$cc" ]; then
    echo "Android NDK clang not found: $cc" >&2
    exit 1
fi

out=${1:-"$root/assets"}
mkdir -p "$out"

"$cc" -O2 -static -s -Wno-macro-redefined \
    -o "$out/cve98260_plant" \
    "$root/native/cve98260/uaf_plant.c" \
    "$root/native/cve98260/pc98260_rootd.c"
"$cc" -O2 -static -s \
    -o "$out/cve98260_slide" \
    "$root/native/cve98260/slide_probe.c"
"$cc" -O2 -static -s \
    -o "$out/cve98260_su" \
    "$root/native/cve98260/pc98260_su.c"
"$cc" -O2 -static -s \
    -o "$out/cve98260_module" \
    "$root/native/cve98260/module_loader.c"

echo "Built CVE-2026-98260 runtime helpers in $out"
shasum -a 256 \
    "$out/cve98260_plant" \
    "$out/cve98260_slide" \
    "$out/cve98260_su" \
    "$out/cve98260_module"

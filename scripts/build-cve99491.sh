#!/bin/sh
# Rebuild the CVE-2026-99491 helpers (exp117 and ko_patch) used by HOneClick.
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

cc="$ndk/toolchains/llvm/prebuilt/$host/bin/aarch64-linux-android30-clang"
if [ ! -x "$cc" ]; then
    echo "Android NDK clang not found: $cc" >&2
    exit 1
fi

srcdir="$root/native/cve99491"
out=${1:-"$root/assets"}
mkdir -p "$out"

[ -f "$srcdir/exp117.c" ] || { echo "missing $srcdir/exp117.c" >&2; exit 1; }
[ -f "$srcdir/ko_patch.c" ] || { echo "missing $srcdir/ko_patch.c" >&2; exit 1; }
[ -f "$srcdir/ko_patch_main.c" ] || { echo "missing $srcdir/ko_patch_main.c" >&2; exit 1; }

"$cc" -O2 -static -s -pthread -I"$srcdir" \
    -o "$out/exp117" \
    "$srcdir/exp117.c"
"$cc" -O2 -static -s -I"$srcdir" \
    -o "$out/ko_patch" \
    "$srcdir/ko_patch.c" \
    "$srcdir/ko_patch_main.c"

chmod 755 "$out/exp117" "$out/ko_patch"
echo "Built CVE-2026-99491 runtime helpers in $out"
shasum -a 256 "$out/exp117" "$out/ko_patch"

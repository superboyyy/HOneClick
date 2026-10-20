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

cc="$ndk/toolchains/llvm/prebuilt/$host/bin/aarch64-linux-android35-clang"
if [ ! -x "$cc" ]; then
    echo "Android NDK clang not found: $cc" >&2
    exit 1
fi

output=${1:-"$root/build/native/ksu_grant"}
mkdir -p "$(dirname -- "$output")"

"$cc" -O2 -static -s \
    -o "$output" \
    "$root/native/ksu_grant.c"

echo "Built: $output"
shasum -a 256 "$output"

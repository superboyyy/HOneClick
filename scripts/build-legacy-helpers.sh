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

cc="$ndk/toolchains/llvm/prebuilt/$host/bin/aarch64-linux-android29-clang"
if [ ! -x "$cc" ]; then
    echo "Android NDK clang not found: $cc" >&2
    exit 1
fi

out=${1:-"$root/assets"}
mkdir -p "$out"

"$cc" -O2 -static -s -pthread -o "$out/t64560_v36" "$root/native/t64560_v36.c"
"$cc" -O2 -static -s -pthread -o "$out/t64560_v42" "$root/native/t64560_v42_honor.c"
"$cc" -O2 -static -s -pthread -o "$out/perf_cred_honor" "$root/native/perf_cred_honor.c"
"$cc" -O2 -static -s -o "$out/kaslr_slide" "$root/native/kaslr_slide.c"
"$cc" -O2 -static -s -o "$out/forker" "$root/native/forker.c"

echo "Built legacy runtime helpers in $out"
shasum -a 256 \
    "$out/t64560_v36" \
    "$out/t64560_v42" \
    "$out/perf_cred_honor" \
    "$out/kaslr_slide" \
    "$out/forker"

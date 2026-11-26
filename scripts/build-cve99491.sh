#!/bin/sh
# Rebuild the CVE-2026-99491 117 exp117 helper used by HOneClick/99491.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ndk=${ANDROID_NDK_HOME:-"$HOME/Library/Android/sdk/ndk/28.2.13676358"}
cc="$ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android30-clang"
src="$root/native/kernel_117_analysis/new-cve-table-2026-11-23/cve99491-port-117/src/exp117.c"
out="$root/assets/exp117"
[ -f "$src" ] || { echo "missing $src" >&2; exit 1; }
"$cc" -O2 -static -s -pthread -o "$out" "$src"
chmod 755 "$out"
shasum -a 256 "$out"

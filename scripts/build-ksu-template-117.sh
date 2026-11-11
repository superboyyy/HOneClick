#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ndk=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}
source="$root/assets/ksu-template.ko"
destination="$root/assets/ksu-template-117.ko"

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

objcopy="$ndk/toolchains/llvm/prebuilt/$host/bin/llvm-objcopy"
if [ ! -x "$objcopy" ]; then
    echo "llvm-objcopy not found: $objcopy" >&2
    exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

cp "$source" "$tmp/ksu-template.ko"
"$objcopy" --dump-section .modinfo="$tmp/modinfo.bin" "$tmp/ksu-template.ko"
python3 - "$tmp/modinfo.bin" "$tmp/modinfo-new.bin" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_bytes()
vermagic = (
    b"6.18.21-android17-5-gfee2325de189-abogki572422516-4k "
    b"SMP preempt mod_unload modversions aarch64"
)
Path(sys.argv[2]).write_bytes(
    source.replace(b"vermagic=", b"zermagic=")
    + b"vermagic=" + vermagic + b"\0"
)
PY
"$objcopy" --update-section ".modinfo=$tmp/modinfo-new.bin" "$tmp/ksu-template.ko"
cp "$tmp/ksu-template.ko" "$destination"

echo "Built: $destination"
shasum -a 256 "$destination"

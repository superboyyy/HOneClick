#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

if ! command -v shasum >/dev/null 2>&1; then
    echo "shasum is required" >&2
    exit 1
fi

shasum -a 256 -c ASSET_SHA256SUMS

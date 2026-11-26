#!/system/bin/sh
set -eu
D="${1:-${HONOR_WORK:-/data/local/tmp/honor}}"
mkdir -p /data/adb/ksu/bin /data/adb/modules
cp "$D/ksud" /data/adb/ksud
chmod 755 /data/adb/ksud
/data/adb/ksud install
ln -sf /data/adb/ksud /data/adb/ksu/bin/su
ln -sf /data/adb/ksud /data/adb/ksu/bin/ksud
/data/adb/ksud feature set su_compat 1
/data/adb/ksud debug mark refresh
R="${HONOR_WORK:-$D}"
id > "$R/root_id" 2>/dev/null || true
chmod 644 "$R/root_id" 2>/dev/null || true
echo ROOT_STAGE_OK

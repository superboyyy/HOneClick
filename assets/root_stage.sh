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
id > "$D/root_id" 2>&1 || true
chmod 644 "$D/root_id" 2>/dev/null || true
echo ROOT_STAGE_OK

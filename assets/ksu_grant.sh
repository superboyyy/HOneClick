#!/system/bin/sh
D="${HONOR_WORK:-/data/local/tmp/honor}"
exec /system/bin/su -c "/system/bin/sh '$D/root_stage.sh'"

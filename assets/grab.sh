#!/system/bin/sh
D=/data/local/tmp/honor
cd "$D" || exit 1
rm -f bl_*.bin bl_text.txt
echo 0 > /sys/kernel/tracing/trace 2>/dev/null
echo 1 > /sys/kernel/tracing/events/sched/sched_blocked_reason/enable 2>/dev/null
echo 1 > /sys/kernel/tracing/tracing_on 2>/dev/null
for c in 0 1 2 3 4 5 6 7; do
    cat "/sys/kernel/tracing/per_cpu/cpu$c/trace_pipe_raw" > "bl_$c.bin" 2>/dev/null &
done
sleep 1
i=0
while [ "$i" -lt 120 ]; do
    ./forker 2 20 >/dev/null 2>&1
    i=$((i + 1))
done
sleep 1
pkill -f trace_pipe_raw 2>/dev/null
sleep 0.3
grep sched_blocked_reason /sys/kernel/tracing/trace > bl_text.txt 2>/dev/null
echo 0 > /sys/kernel/tracing/events/sched/sched_blocked_reason/enable 2>/dev/null
echo 0 > /sys/kernel/tracing/tracing_on 2>/dev/null
chmod 644 bl_*.bin bl_text.txt 2>/dev/null
echo GRAB_DONE

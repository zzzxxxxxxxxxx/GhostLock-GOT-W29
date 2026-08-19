#!/system/bin/sh
# run_rtmdbg_test.sh - run GhostLock once with rtmutex-dbg KPM watching.
# REAL attack path: run as shell (uid 2000), NO RT boost (GOT_SLIDE_NO_RT=1):
# the pselect-overlay RT fix needs root and is NOT part of the real chain.
# Launch via: adb shell 'sh /data/local/tmp/ghostlock-test/run_rtmdbg_test.sh'
#
# Watches: dmesg [RTMDBG] (module must be loaded first via sc_kpm_load)
set -u

DST=/data/local/tmp/ghostlock-test
cd "$DST" || exit 1

# Pre-test sync loop: keep page cache flushed so a panic/reboot cannot
# lose the experiment logs or corrupt files (2026-08-15 / 2026-08-19 lesson).
su -c 'sh /sdcard/ghostlock-test/sync_loop.sh >/dev/null 2>&1' &
SYNC_PID=$!
sleep 1

rm -f "$DST/rtmdbg_exe.log" "$DST/rtmdbg_poc.log" "$DST/rtmdbg_dmesg.log"

# dmesg watcher: capture [RTMDBG] lines to a sync-protected file so a panic
# cannot lose them even if the ring buffer is wiped on reboot.
su -c "dmesg -w > '$DST/rtmdbg_dmesg.log' 2>&1" &
DMESG_PID=$!
sleep 1

(
  cd "$DST" || exit 1
  POC_LOG_FILE="$DST/rtmdbg_poc.log" \
  GOT_FULL_RUN=1 \
  GOT_VERIFY_WRITE=1 \
  GOT_SLIDE_ATTEMPTS=5 \
  GOT_SLIDE_NO_RT=1 \
  GOT_FAKELOCK_BSS=1 \
  ./ghostlock_exe > "$DST/rtmdbg_exe.log" 2>&1
) &
EXE_PID=$!

echo "started ghostlock_exe pid=$EXE_PID $(date +%T)"
sleep 90
killall ghostlock_exe 2>/dev/null
kill $SYNC_PID 2>/dev/null
kill $DMESG_PID 2>/dev/null
su -c 'pkill -f sync_loop.sh 2>/dev/null'
su -c 'pkill -f "dmesg -w" 2>/dev/null'
sync
echo "reaped $(date +%T)"

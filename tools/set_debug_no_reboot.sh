#!/system/bin/sh
#
# GhostLock-GOT-W29 on-device debugging helper.
#
# Disables kernel-side panic/reboot paths so an oops (or a hung-task
# khungtaskd panic) does not reset the device mid-experiment.
#
# NOTE: these are runtime knobs only; every boot resets them to the
# device defaults (panic_on_oops=1, hung_task_panic=1).  Run this
# manually BEFORE each test session after a reboot:
#
#   su -c 'sh /sdcard/ghostlock-test/set_debug_no_reboot.sh'
#   # or, from the repo:
#   su -c 'sh GhostLock/GhostLock-GOT-W29/tools/set_debug_no_reboot.sh'
#
# Deliberately NOT made persistent: permanently disabling panic paths
# hides real kernel faults and can mask a wedged device.

[ "$(id -u)" = 0 ] || {
  echo "need root: run via  su -c 'sh $0'"
  exit 1
}

set_knob() {
  f="$1"
  v="$2"
  if echo "$v" > "$f" 2>/dev/null; then
    echo "ok   $f = $v"
  else
    echo "FAIL $f = $v"
  fi
}

# --- kernel panic switches -------------------------------------------
set_knob /proc/sys/kernel/panic_on_oops 0    # oops -> kill thread, no panic
set_knob /proc/sys/kernel/panic 0            # even if panic() runs: no auto reboot
set_knob /proc/sys/kernel/hung_task_panic 0  # khungtaskd warns, does not panic
set_knob /proc/sys/kernel/panic_on_rcu_stall 0
set_knob /proc/sys/kernel/panic_on_warn 0

# --- Huawei DFX hungtask (htbase) --------------------------------------
# The stock hung_task_panic sysctl does NOT gate this one: Huawei's htbase
# has its own panic counter (whitelist_panic_cnt) and calls panic() on its
# own ("hungtask_base already in doing panic" in dmesg), rebooting the
# device even with hung_task_panic=0.  Disable it explicitly.
set_knob /sys/kernel/hungtask/enable off

# --- watchdog (best effort) -------------------------------------------
# msm_watchdog disable=1 also asks TZ to deactivate the secure watchdog
# (SCM_SVC_SEC_WDOG_DIS).  On GOT-W29 firmware TZ rejects the SCM call
# ("Failed to deactivate secure wdog"), so this is expected to fail;
# kept here in case a different firmware/build allows it.
set_knob /sys/devices/platform/soc/17c10000.qcom,wdt/disable 1

echo "---"
for f in \
  /proc/sys/kernel/panic_on_oops \
  /proc/sys/kernel/panic \
  /proc/sys/kernel/hung_task_panic \
  /proc/sys/kernel/hung_task_timeout_secs \
  /proc/sys/kernel/hung_task_warnings \
  /proc/sys/kernel/panic_on_rcu_stall \
  /proc/sys/kernel/panic_on_warn; do
  printf '%s = %s\n' "$f" "$(cat "$f" 2>/dev/null)"
done

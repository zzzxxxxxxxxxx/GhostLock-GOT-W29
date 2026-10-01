#!/bin/bash
# Build the exploit with a cross gcc and run it as /init under QEMU
# (kernel.patched, nokaslr).  Usage: ./build_and_run.sh
# Default mode: --escalate; override with GLMODE, e.g.
#   GLMODE="--verify-all" ./build_and_run.sh
#   GLMODE="--root; --bench 8" ./build_and_run.sh
#
# Requires: aarch64-linux-gnu-gcc, qemu-system-aarch64, cpio, and
# firmware/unpacked_boot/kernel.patched.  Read the result with read_log.py
# (about 90s after start) or attach GDB to :1234.
set -e
cd "$(dirname "$0")/../.."          # repo root
SRC=exploit/ghostlock-source/src
OUT=${OUT:-/tmp/ghostlock-qemu}
mkdir -p "$OUT/build" "$OUT/root"

for f in main util slide su perf main_exe; do
  aarch64-linux-gnu-gcc -O2 -g0 -Wall -Wextra -Wno-unused-parameter \
    -Wno-sign-compare -I"$SRC" -DTARGET_CONFIG_H='"target.h"' \
    -c "$SRC/$f.c" -o "$OUT/build/$f.o"
done
aarch64-linux-gnu-gcc -static -pthread -o "$OUT/root/ghostlock_exe" "$OUT"/build/*.o
aarch64-linux-gnu-gcc -static -O2 -o "$OUT/root/init" tools/qemu-test/init_wrapper.c
# glsh stands in for /system/bin/sh, which the initramfs does not have (only
# needed to exercise --su-server's generic command path; see glsh.c).
aarch64-linux-gnu-gcc -static -O2 -o "$OUT/root/glsh" tools/qemu-test/glsh.c
chmod 755 "$OUT/root/init" "$OUT/root/glsh" "$OUT/root/ghostlock_exe"
# Optional extra argv for the wrapper (e.g. GLMODE="--bench 20")
rm -f "$OUT/root/glmode"
if [ -n "$GLMODE" ]; then
  printf '%s\n' "$GLMODE" > "$OUT/root/glmode"
fi
(cd "$OUT/root" && find . | cpio -o -H newc 2>/dev/null | gzip -9) > "$OUT/initramfs.cpio.gz"

GDB_ARGS=()
if [ "${GDB:-1}" != 0 ]; then
  # NOTE: any TCP client that touches the gdb port halts all vCPUs; use
  # GDB=0 for unattended runs, or bind to a port you control.
  GDB_ARGS=(-gdb "tcp::${GDB_PORT:-1234}")
fi

# KASLR=1 boots with KASLR on (no "nokaslr"): the wrapper then leaves
# --kaslr-base off and the exploit has to perf-leak the slide itself, which is
# what the device does.  Default stays nokaslr + a pinned base.
APPEND_ARGS="rdinit=/init console=ttyAMA0 panic=0 loglevel=6 initcall_blacklist=proc_app_info_init printk.devkmsg=on"
if [ "${KASLR:-0}" = 0 ]; then
  APPEND_ARGS="nokaslr $APPEND_ARGS"
fi

exec qemu-system-aarch64 -machine virt -no-reboot -cpu cortex-a76 -smp "${SMP:-8}" -m 2048 \
  -kernel firmware/unpacked_boot/kernel.patched \
  -initrd "$OUT/initramfs.cpio.gz" \
  -append "$APPEND_ARGS" \
  -qmp unix:"$OUT/qmp.sock",server,nowait "${GDB_ARGS[@]}" -display none -no-shutdown

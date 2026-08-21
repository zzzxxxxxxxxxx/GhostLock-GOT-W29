#!/bin/bash
# Boot the real device kernel (binary-patched) in QEMU -M virt with an
# initramfs containing the GhostLock exploit.
#
# Usage: qemu_run.sh [initramfs.cpio.gz] [extra_qemu_args...]
#
# The kernel has no PL011 serial driver (CONFIG_SERIAL_AMBA_PL011 is not set
# in the device config), so console output goes to a shared-memory backing
# file instead.  Read /tmp/guest_ram.bin to find __log_buf contents:
#   python3 -c "d=open('/tmp/guest_ram.bin','rb').read(); \
#     print(d.find(b'Booting Linux on physical CPU 0x00000000'))"
#
# Required kernel cmdline (in addition to normal):
#   initcall_blacklist=proc_app_info_init,scm_mem_protection_init,\
# storage_rochk_misc_init,qseecom_init,pil_tz_init,qcom_smem_probe

set -e

KERNEL="${KERNEL:-/tmp/real_boot4.bin}"
INITRD="${1:-/tmp/v9_initramfs.cpio.gz}"
RAMFILE="/tmp/guest_ram.bin"

pkill -f qemu-system-aarch64 2>/dev/null || true
sleep 1
rm -f "$RAMFILE"

setsid qemu-system-aarch64 \
  -machine virt,memory-backend=pcram,highmem=off \
  -cpu max \
  -smp 2 \
  -accel tcg \
  -object memory-backend-file,id=pcram,mem-path="$RAMFILE",size=1024M,share=on \
  -nographic -no-reboot \
  -kernel "$KERNEL" \
  -initrd "$INITRD" \
  -append 'console=ttyAMA0 loglevel=8 initcall_blacklist=proc_app_info_init,scm_mem_protection_init,storage_rochk_misc_init,qseecom_init,pil_tz_init,qcom_smem_probe' \
  </dev/null > /tmp/qemu_console.log 2>&1 &

echo "QEMU started (PID $!)"
echo "guest RAM: $RAMFILE"
echo "console log: /tmp/qemu_console.log"

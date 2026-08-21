#!/bin/bash
# Binary-patch the real device kernel (kernel_image.bin) to boot in QEMU -M virt.
#
# Usage: patch_kernel.sh <kernel_image.bin> <output.bin>
#
# Four patches applied:
#   1. 0x1c2f23c: NOP __no_granule_support branch
#      QEMU CPU models report a different ID_AA64MMFR0.TGRAN4 field than kona;
#      the kernel's granule check fails and parks the CPU in wfe/wfi.
#   2. 0x415b0: NOP bl qcom_minidump_add_task_stack
#   3. 0x19764: NOP bl qcom_minidump_add_task_stack (second call site)
#      QEMU has no SMEM; current->stack vmap walk hits NULL -> fake
#      "kernel stack overflow" panic via handle_bad_stack.
#   4. 0x6daec0: ldr w8,[x18,#3268] -> mov w8,#1
#      Short-circuits is_scm_armv8() to always return false.  QEMU has no
#      EL3/ATF firmware; the SMC instruction triggers an undefined-instruction
#      exception that kills the idle task.  With this patch all SCM calls
#      gracefully degrade (init_random_pool, qcom_scm, etc).
#
# Also required on the kernel command line:
#   initcall_blacklist=proc_app_info_init,scm_mem_protection_init,\
# storage_rochk_misc_init,qseecom_init,pil_tz_init,qcom_smem_probe

set -e

IN="$1"
OUT="$2"
[ -f "$IN" ] || { echo "usage: $0 <kernel_image.bin> <output.bin>"; exit 1; }
SIZE=$(stat -c %s "$IN")
[ "$SIZE" -eq 57470992 ] || { echo "unexpected size $SIZE (expected 57470992)"; exit 1; }

cp "$IN" "$OUT"

python3 - <<'PY'
import struct, sys

with open(sys.argv[1] if len(sys.argv)>1 else 'patch_out.bin', 'r+b') as f:
    patches = [
        # (offset, expected_original_hex, replacement_hex, description)
        (0x1c2f23c, 'A1020054', '1F2003D5', 'NOP __no_granule_support branch'),
        (0x0415b0,  '97F76B18', '1F2003D5', 'NOP minidump call site 1'),
        (0x019764,  '97F8B6E2', '1F2003D5', 'NOP minidump call site 2'),
        (0x6daec0,  '48C64CB9', '20008052', 'is_scm_armv8 short-circuit'),
    ]
    for off, orig_hex, new_hex, desc in patches:
        f.seek(off)
        orig = bytes.fromhex(orig_hex)
        new  = bytes.fromhex(new_hex)
        cur = f.read(len(orig))
        if cur == new:
            print(f'  [skip] 0x{off:x} already patched ({desc})')
            continue
        if cur != orig:
            print(f'  [WARN] 0x{off:x} unexpected content {cur.hex()} (expected {orig_hex}): {desc}')
        f.seek(off)
        f.write(new)
        print(f'  [ok]   0x{off:x}: {orig_hex} -> {new_hex}  ({desc})')
PY
echo "done: $OUT"

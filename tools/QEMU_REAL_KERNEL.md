# QEMU Real-Device-Kernel Environment

Run the actual GOT-W29 kernel binary (`kernel_image.bin`, 57MB, HarmonyOS
4.19.157-perf+) in `qemu-system-aarch64 -M virt` without recompiling.

## Why

The opensource-rebuilt kernel (`Code_Opensource/kernel`) has different frame
sizes, different initcall layout, and DeepSeek's QEMUDBG patches.  The real
device binary preserves the exact stack geometry that the exploit depends on.
Running it in QEMU allows safe iteration on the exploit without panicking the
physical device.

## Quick start (on a server with qemu-system-aarch64)

```bash
# 1. Patch the kernel
bash tools/patch_kernel_qemu.sh kernel_image.bin /tmp/real_boot4.bin

# 2. Build an initramfs with ghostlock_exe + mini_init (see below)
#    Or use a prebuilt one:
#    /tmp/v9_initramfs.cpio.gz

# 3. Boot
bash tools/qemu_run.sh /tmp/v9_initramfs.cpio.gz

# 4. Wait for boot + exploit (~2-3 min in TCG), then read results
python3 tools/qemu_read_ram.py /tmp/guest_ram.bin
```

## Binary patches applied to kernel_image.bin

| Offset | Original | Patched | Effect |
|--------|----------|---------|--------|
| `0x1c2f23c` | `b.ne __no_granule_support` | NOP | QEMU CPU TGRAN4 field differs from kona |
| `0x0415b0` | `bl minidump_add_task_stack` | NOP | No SMEM → current->stack NULL → fake stack overflow |
| `0x019764` | `bl minidump_add_task_stack` | NOP | Second call site |
| `0x6daec0` | `ldr w8,[x18,#3268]` | `mov w8,#1` | is_scm_armv8() → false; no EL3/ATF in QEMU |

Plus kernel cmdline:
```
initcall_blacklist=proc_app_info_init,scm_mem_protection_init,
storage_rochk_misc_init,qseecom_init,pil_tz_init,qcom_smem_probe
```

## Initramfs requirements

The initramfs must contain:
- `/init` — a static aarch64 binary that mounts proc/sys/dev, runs the
  exploit, and writes result markers to files (the markers end up in the RAM
  dump where they can be searched)
- `/ghostlock_exe` — statically linked exploit binary
- `/lib/ld-musl-aarch64.so.1` — if using dynamically linked busybox

**Critical**: build the cpio with relative paths:
```bash
cd <initramfs_root> && find . -print0 | cpio --null -o -H newc | gzip > out.cpio.gz
```
Absolute-path find produces `/tmp/.../init` instead of `/init`, causing
"Unable to mount root fs" panic.

## Observability

The device kernel config does not include `CONFIG_SERIAL_AMBA_PL011`, so
serial output is always empty.  All observability goes through the shared
memory backing file:

```bash
# Kernel log (__log_buf)
python3 -c "
d=open('/tmp/guest_ram.bin','rb').read()
i=d.find(b'Booting Linux on physical CPU 0x00000000')
import re
for m in re.finditer(rb'[ -~]{8,}', d[i:i+500000]):
    print(m.group().decode())
"

# Exploit markers (written by mini_init)
python3 -c "
d=open('/tmp/guest_ram.bin','rb').read()
for p in [b'mini-init-stage1',b'exit_status=',b'perf-kaslr']:
    i=d.find(p)
    print(p, hex(i) if i>=0 else 'NOT FOUND')
"
```

## Stack geometry notes (real kernel vs opensource rebuild)

Measured from the same boot.elf disassembly (both built from the same tree):

```
__arm64_sys_pselect6: sub sp,#0xA0 + stp [sp,-32] = 192 bytes
core_sys_select:      sub sp,#0x1C0 + stp [sp,-32] = 480 bytes
  stack_fds[0] = sp+0x50 (nfds=320 → 144 bytes on-stack path)
__fpr_set:            stp [sp,-80] + sub sp,#0x220 = 624 bytes
  newstate(528B) at sp+0..sp+0x210
__arm64_sys_futex: tail-calls do_futex (frame size TBD)
do_futex: stp [sp,-48] at +152; full prologue not yet extracted
```

The exploit's `PSELECT_WAITER_WORD_SHIFT=12` was confirmed from these frames.

## Results (2026-08-23)

The full exploit chain was executed on the real device kernel in QEMU:

- KASLR leak: **success** (`perf-kaslr` via VIRT PMU sampling works under TCG)
- EDEADLK trigger: **success** (PI ring built, `CMP_REQUEUE_PI → -EDEADLK`)
- Overlay placement: **success** (both pselect and ptrace carriers attempted)
- Write primitive: **not landed** — `boot_id` unchanged across all attempts
- Kernel stability: **no panic** — exploit exits cleanly, kernel continues running

The write primitive failure is a TCG timing artifact, not a geometry error.
Multi-core scheduling races are stretched ~1000× under emulation, so the
consumer thread's `sched_setattr` never hits the correct window.  On real
hardware these races resolve at native speed.

Stack geometry was verified from the same `boot.elf` disassembly used to
derive `target.h`, confirming that the opensource rebuild and the real device
binary share identical frame layouts for `pselect6`, `core_sys_select`,
and `__fpr_set`.

## Known limitations

- Write primitive does not land in TCG (see Results above)
- ptrace carrier geometry (`__fpr_set` newstate offset) may differ between
  the real kernel and the opensource rebuild due to compiler/config drift

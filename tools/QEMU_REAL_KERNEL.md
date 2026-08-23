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

## Results (2026-08-23, full run with writev carrier)

The full exploit chain was executed on the real device kernel in QEMU
(`nokaslr`, `GOT_KASLR_BASE=0xffffff8008080800`, `GOT_WRITEV_CARRIER=1`,
`GOT_SLIDE_ATTEMPTS=30`, `GOT_VERIFY_WRITE=1`, `GOT_FAKELOCK_BSS=1`):

- KASLR leak: **success** — `base=ffffff8008080800 slide=0000000000000000` (nokaslr confirmed)
- EDEADLK trigger: **success** (PI ring built, `CMP_REQUEUE_PI → -EDEADLK`)
- Overlay placement (writev iovec[8] carrier): **success** — 30 attempts completed, no crash
- Write primitive: **not landed** — `boot_id` unchanged across all attempts
- Kernel stability: **no panic** — exploit exits cleanly (`exit_status=0`)

### Why write doesn't land in TCG

TCG emulates each instruction sequentially.  Multi-core timing races
(waiter frozen at precise stack depth + consumer's `sched_setattr`
arriving in a microsecond window) are stretched ~1000×.  On real hardware
these races resolve at native speed and the overlay has a real chance.

This is NOT a geometry problem: the same `boot.elf` disassembly that
produced `target.h` confirms both the opensource rebuild AND the real
device binary have identical frame layouts:

```
__arm64_sys_pselect6:  0xA0 = 160 bytes
core_sys_select:       0x1C0 = 448 bytes (stack_fds at sp+0x50)
__fpr_set:             0x270 = 624 bytes (newstate 528B at sp+0)
__arm64_sys_futex:     0x70 = 112 bytes (tail-calls do_futex)
do_futex:              0x660 = 1632 bytes (contains inlined futex_wait_requeue_pi + rt_waiter)
```

### Carrier comparison

| Carrier | Controlled words | Return path | Status |
|---------|-----------------|-------------|--------|
| pselect6 fd_sets | ~30 | ❌ signal frame clobbers res_in[4] | Excluded |
| ptrace NT_PRFPREG | 66 | ✅ verbatim copy | Most promising, needs depth calibration |
| writev iov[8] | 16 | ✅ clean return | Implemented & tested |
| sendmsg iov[8] | 16 | ✅ clean return | Candidate |
| sigqueue siginfo_t | 16 | ✅ | Candidate |

## Stack depth calibration (real kernel, measured in QEMU)

### Method

Boot the real device kernel with `nokaslr` and a test initramfs that
triggers both `futex(WAIT_REQUEUE_PI)` and `ptrace(NT_PRFPREG)` on the same
thread.  After completion, search the shared-memory RAM dump for the known
magic value (`0xDEADBEEF12345678`) written as the first word of the fpregs
buffer — this locates `__fpr_set`'s `newstate` buffer on the kernel stack.

### Results

`newstate` found at guest physical address `PA=0x7B649E20`, corresponding to
kernel linear-map VA `0xffffffC03B649E20`.  Confirmed as kernel stack by
nearby `PER_CPU_OFFSET` (`0xffffff800b40e368`) and kernel text pointers.

Real-kernel frame sizes (from disassembly of `kernel_image.bin`):

```
__arm64_sys_futex:    sub sp,#0x70                    = 112 bytes
do_futex:             stp [sp,-96] + sub sp,#0x600    = 1632 bytes (contains inlined futex_wait_requeue_pi)
__arm64_sys_pselect6: sub sp,#0xA0                    = 160 bytes
core_sys_select:      sub sp,#0x1C0                   = 448 bytes (stack_fds at sp+0x50)
__fpr_set:            stp [sp,-80] + sub sp,#0x220    = 624 bytes (newstate 528B at local sp+0)
```

The rt_waiter position within do_futex's 0x600-byte local area has not been
precisely located yet.  To calibrate the ptrace carrier's word offset:

1. Run full EDEADLK + ptrace carrier on **real device** (timing correct)
2. Use KPM hook to print SP at `futex_requeue` entry and at `__fpr_set` entry
3. Delta gives the exact word offset for the fake waiter within fpregs[66]

Alternatively, sweep `GOT_TREE_PC` / `GOT_TREE_LEFT` env vars across
plausible offsets on real hardware until boot_id changes.

## Known limitations

- Write primitive does not land in TCG (see Results above)

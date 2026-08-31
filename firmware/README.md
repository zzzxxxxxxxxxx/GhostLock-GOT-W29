# Firmware — GOT-W29 HarmonyOS 内核的 QEMU 适配与启动

本目录是 CVE-2026-43499（GhostLock，rtmutex/futex-PI UAF）研究用的 boot 镜像解包产物与 QEMU 适配。
目标内核：**HarmonyOS 4.0 / Qualcomm kona (SM8250) / `4.19.157-perf+`**（VA 39-bit、4K 页、KASLR）。

## 目录结构

- `boot.img` — 原始 boot 镜像
- `unpacked_boot/`
  - `kernel` / `kernel.raw` — 内核（gzip 压缩 / 解压后的 ARM64 Image）
  - `kernel.elf` — vmlinux-to-elf 生成的带符号 ELF（逆向/断点用）
  - `kernel.patched` — 经 SCM + PAN patch 的可用内核
  - `kernel.config` — 从内核提取的 .config
  - `ramdisk` / `ramdisk.cpio` / `ramdisk_root/` — ramdisk（gzip / cpio / 展开后）
  - `dtb` / `dtb.dts` / `dtbs/` — 设备树（拼接的多 DTB，含 kona v1/v2/v2.1 变体）

## 解包

```bash
unpack_bootimg --boot_img boot.img --out unpacked_boot
gzip -dc unpacked_boot/kernel > kernel.raw      # ARM64 boot Image
dtc -I dtb -O dts -o dtb.dts unpacked_boot/dtb  # 反编译设备树
```

## QEMU 适配（必需的内核 patch）

该内核为真机 kona 编译，在 QEMU `virt` 上会崩，需在 `kernel.raw` 上做四处 patch：

1. `init_random_pool` @ `0xae42e3c` → `mov w0,#0; ret`
2. `is_scm_armv8`  @ `0x875aeb8` → `mov w0,#0; ret`
3. `__scm_call2`   @ `0x875afb0` → `mov w0,#0; ret`
4. 全部 `msr pan,#1`（`9f 41 00 d5`，共 2056 处）→ `nop`（`1f 20 03 d5`）

原因：SCM/SMC 调用在 QEMU 上没有安全世界，`smc` 变未定义指令；PAN
（`CONFIG_ARM64_PAN` + `CONFIG_ARM64_SW_TTBR0_PAN`）使内核 uaccess 访问用户内存时报
`ESR EC=0x25` 数据中止（futex / clear_user 都受影响）。

## 启动

```bash
qemu-system-aarch64 \
  -machine virt -no-reboot -cpu cortex-a76 -smp 1 -m 2048 \
  -kernel unpacked_boot/kernel.patched \
  -initrd /tmp/initramfs.cpio.gz \
  -append "nokaslr rdinit=/init console=ttyAMA0 panic=0 loglevel=6 \
           initcall_blacklist=scm_mem_protection_init,proc_app_info_init,storage_rochk_misc_init,socinfo_init" \
  -S -qmp unix:/tmp/qmp.sock,server,nowait -display none -no-shutdown
```

黑名单为 QEMU 上必崩的高通初始化。`futex_init` 已移出黑名单（PAN 修好后可用，便于 futex-PI 调试）。

## 调试要点

- **无串口控制台**：内核只有高通 GENI 串口，QEMU 无可用于它的驱动，故只见
  `Warning: unable to open an initial console`。
- **读内核日志（log_buf）**：QMP `pmemsave` 导出内存 → 定位 `__log_buf`
  （VA `0xffffff800b7599dc`）→ 解码 printk 记录。
- **GDB 断点**：`do_futex` @ `0xffffff80081a5248`、`cmpxchg_futex_value_locked` @
  `0xffffff80081a9720`。
- 当前状态：内核可启动到用户态（`Run /init as init process`）。

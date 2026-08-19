# rtmutex-dbg KPM 调试工具（GOT-W29 / FolkPatch）

自写 KernelPatch 模块，用于实机观测/验证 GhostLock（CVE-2026-43499）的
fake rt_mutex_waiter 与写原语。编译基于 **LyraVoid/KernelPatch 0.13.5**
（FolkPatch 同源）头文件。

## 编译 KPM

```sh
cd <KernelPatch>/kpms/rtmutex-dbg
make TARGET_COMPILE=aarch64-linux-android- \
  CC=$PREFIX/bin/aarch64-linux-android-clang \
  LD=$PREFIX/bin/aarch64-linux-android-ld
```

产出 `rtmutex_dbg.kpm`。**编译 flag 必须含**
`-fno-pic -fno-pie -fno-asynchronous-unwind-tables -fno-unwind-tables`
（Makefile 已内置）：clang 默认 PIC 产生 GOT 重定位、默认生成 `.eh_frame`
（`R_AARCH64_PREL32`），KernelPatch KPM 加载器都不支持 → 加载失败 -1。

## 加载（supercall，热加载无需重启）

FolkPatch 的 superkey 是 `su`（不是 APatch 默认的 `KernelPatch`）。用
`sc_kpm_load` 工具：

```sh
adb shell /data/local/tmp/sc_kpm_load su /sdcard/Download/rtmutex_dbg.kpm  # 加载
adb shell /data/local/tmp/sc_kpm_load unload rtmutex-dbg su               # 卸载
```

源码 `sc_kpm_load.c`，设备上编译：
`aarch64-linux-android-clang -O2 -o sc_kpm_load sc_kpm_load.c`。

## 一键测试

`run_rtmdbg_test.sh`（设备端 `/data/local/tmp/ghostlock-test/`）：
shell 身份（真实攻击路径，`GOT_SLIDE_NO_RT=1`）跑 GhostLock，0.5s sync
循环防日志丢失，dmesg -w 落盘，90s 自动收网。测试前需：

```sh
adb shell 'su -c "sh /sdcard/ghostlock-test/set_debug_no_reboot.sh"'  # 防重启
```

## 观测点（dmesg `[RTMDBG]`）

- `REPAIR3`：fake walk 时重建 overlay（tree/task/lock）并改写 next_lock 参数
- `prio_chain[N]`：adjust_prio_chain 调用与 waiter dump
- `prio_chain_ret`：walk 返回值（0=走完；4294967261=-EDEADLK）
- `do_select n=320`：内核侧 res_in[3]/[4]（overlay 编码验证）
- `futex op=13/14`：CMP_REQUEUE_PI / WAIT_REQUEUE_PI 调用与返回

华为 oops/panic 完整栈记录在 `/data/log/bbox/history.log`。

## 关键结论

写原语已验证：REPAIR3 让 `rt_mutex_adjust_prio_chain` [3] 检查通过
（next_lock 参数改写为 empty_zero_page）+ 完整 overlay 构造，step[7]
`rt_mutex_dequeue`（rb_erase 单左子）把 `sysctl_bootid` 改写为
`&loggers[0][1]`，`slide-kaslr-ok`。详见
`../../docs/kpm-write-validation.md`。

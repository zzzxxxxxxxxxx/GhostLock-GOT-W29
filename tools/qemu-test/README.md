# QEMU 验证器具（kernel.patched）

把 exploit 作为 QEMU guest 的 `/init` 跑：默认现在是
`--escalate`（端到端提权：perf 泄露自己 task → comm 校验 → cred 写 →
`getuid()==0`），以**uid 2000** 起跑模拟设备 shell。三种原语的自检
（指针写 / leaf 零写 / boot_id 读 + restore）用 `--verify-all` 单独跑，
wrapper 里改 argv 即可。

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

期望输出（`--escalate` 节选）：

```text
... [*] perf task leak: tid=236 samples=1292 abi=1292 in_sched=27 in_window=12 cands=1 best=ffffffc07a373240 (n=12)
... [*] escalate: candidate 1/1 task=ffffffc07a373240 (n=12)
... [+] slide read8 boot_id raw=67686f73746c6f6330d74c0b80ffffff lo=636f6c74736f6867 ... ok=1   # "ghostloc"
... [+] slide escalate-cred test PASSED
... [+] slide child pid=246 uid=0 ...                       # 子进程已是 root
...     init: ghostlock_exe exited status=0x0 (SUCCESS)     # wrapper 退出码标记
```

（`--verify-all` 的期望输出仍是 write/leaf/read/restore 四段 PASSED。）

说明：

- `init_wrapper.c` 会挂载 `/proc` 和 `devtmpfs`、给 fd 0/1/2 补 `/dev/null`
  （QEMU 无控制台，否则 `pipe()` 会占用 fd 0/1）、关掉内核 printk 限流
  （`printk_ratelimit=0`，否则最终结果行被 `output lines suppressed` 吞掉），
  然后以 uid 2000 + 补充组 3003（`CONFIG_ANDROID_PARANOID_NETWORK` 要求
  inet 组才能建 AF_INET socket，真机 shell 同款）fork 出 exploit，并自己保持
  PID 1 存活；exploit 退出后 wrapper 会把退出码写进 `/dev/kmsg`
  （`init: ghostlock_exe exited status=... (SUCCESS)`），作为一个不受 exploit
  日志影响的独立判据。
- exploit 以 `--no-rt --attempts 4` 跑（设备 shell 拿不到 RT；walk 偶发卡在
  `rt_mutex_adjust_prio_chain` 的 `raw_spin_trylock` 重试循环，靠 attempt 重试）。
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

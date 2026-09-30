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
   `write_ok=1`（boot_id 高 8 字节 = `0xffffff800b412320`）。
3. **早期“投递死结”结论已撤销**：旧扫描把 `sock_setsockopt` 的 0x80 帧算进了
   setsockopt 链。反汇编 + QEMU 实测确认 `__arm64_sys_setsockopt` 对
   `level != SOL_SOCKET` **直接 `blr ops->setsockopt`**，不经过 `sock_setsockopt`；
   修正后 `do_ip_setsockopt` 拷贝深度 = 0x210（旧判 0x290），几何合身。
   已排除的机制：pselect/select、ptrace、import_iovec、ppoll、SCTP（实测 0x158）。
4. **设备端剩余工作**：MCAST setsockopt 的 SELinux 放行验证（mrx 在 EMUI 下以
   shell 身份使用同款载体提权成功，预期可行）、真机返回路径/park 行为复核
   （可用 KPM 直接观测 W）、以及 HKIP/后利用链（原课题，未变）。

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
- [3] `next_lock == waiter->lock`（`lock = empty_zero_page`，固定 .bss，ownerless）
- [5] `raw_spin_trylock(&lock->wait_lock)` 零锁成功
- [7] `rt_mutex_dequeue` → `rb_erase` 单左子路径：`*(rb_left) = rb_parent_color`
  → 写值 `0xffffff800b412320`（&loggers[0][1]）写入 `sysctl_bootid + 8`
- [9] ownerless 干净返回

**不需要 owner-ful 页 / `prepare_skb_payload` / `kernelsnitch`**——`empty_zero_page`
（固定 .bss 地址 0xffffff800b750000）即可作 `lock`。

QEMU（`kernel.patched`，nokaslr，`--probe-cycle`）工具自验证输出：

```text
slide boot_id raw=00000000000000002023410b80ffffff lo=0 hi=ffffff800b412320 expected_hi=ffffff800b412320 write_ok=1
slide attempt 1 ok=1 value=ffffff800b412320 target=ffffff800b7f8b6c requeue=-1/35 trigger=0/0 wait=-1/110 carrier=-1/22
slide write test PASSED
```

注意验证目标写 `boot_id + 8`：`proc_do_uuid()` 在 `bootid[8] == 0` 时会重新生成
整个 UUID，写低 8 字节会被验证读本身覆盖（QEMU 实测确认）。

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
| 单值 `get_user` 深栈写 | `scan_carriers3.py` 84 个命中全是 printf varargs，无用户数据 |

其余事实：

- **k40 对照**：同为 `4.19.157-perf` 的 Redmi K40 用 shift=1 全落输入位图可提权；
  GOT-W29 的 futex 帧大（do_futex 0x1a0+），rt_waiter 沉到 `stack_fds[12]`；
  现在有 MCAST 路径，不再需要 select 编码。
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

# 示例组合
./ghostlock_exe --verify-write --attempts 5 --no-rt --hold
./ghostlock_exe --verify-write --probe-cycle \
                --kaslr-base 0xffffff8008080800 \
                --log-file /data/local/tmp/gl.log      # QEMU/nokaslr
```

参数：`--kaslr-base ADDR`、`--log-file PATH`、`--attempts N`、
`--wait-seconds N`、`--requeue-ms N`、`--no-rt`、`--rt-prio N`、
`--probe-cycle`（kernel.patched/QEMU 必需）、`--noconsume`、`--hold`、
`--detach`、`--fsync`。**环境变量已全部移除**（含旧 `GOT_*` 实验开关）。

QEMU 以本程序做 /init 时注意：内核没有控制台，fd 0/1/2 可能未打开，
需在 wrapper 里先补上可用 fd（否则 `pipe()` 会占用 fd 0/1，子进程的
printf 会写进结果管道）。

## 调试工具链

自写 KPM（`tools/kpm-debug/rtmutex-dbg.c`，KernelPatch 0.13.5 inline-hook）
用于实机观测，hook 集：`rt_mutex_adjust_pi`（记录/重建 overlay）、
`rt_mutex_adjust_prio_chain`（dump waiter）、`__arm64_sys_pselect6`/`do_select`
（fd_set 观测）、`__arm64_sys_futex`（wait/requeue 追踪）、`rt_mutex_dequeue`
（step[7] 确认）。加载方式见 `tools/kpm-debug`。

QEMU 启动 / kernel.patched（SCM+PAN 补丁）见 `firmware/README.md`；
GDB 断点与内存读取工具：`tools/qemu_read_ram.py`、`tools/patch_kernel_qemu.sh`。

## 目录

```
firmware/                     boot.img 解包产物 + QEMU 启动（kernel.patched）
exploit/ghostlock-source/     MCAST 载体写原语（main/util/slide/perf，命令行参数）
tools/                        KASLR/EDEADLK 探针、载体扫描器、KPM 工具链、
                              QEMU 验证器具（qemu-test/）
android_kernel_huawei_sm8250/ 设备内核源码树（外部参考，自带 git，不入库）
ghostlock-cve-2026-43499-4.19-k40/ 同族 4.19 参考实现（外部参考，不入库）
```

## 致谢

- 上游 PoC: [x-spy/CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle),
  [soralis0912/CVE-2026-43499-aristotle](https://github.com/soralis0912/CVE-2026-43499-aristotle),
  [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus),
  [Wtrwx/smt878u-ionstack-poc](https://github.com/Wtrwx/smt878u-ionstack-poc) (GPL-3.0)
- CVE: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-43499),
  [Red Hat RHSB-2026-010](https://access.redhat.com/security/vulnerabilities/RHSB-2026-010)

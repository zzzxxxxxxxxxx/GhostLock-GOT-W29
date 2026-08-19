# CVE-2026-43499 (GhostLock) — HUAWEI MatePad Pro 11 GOT-W29 研究

针对 **HUAWEI MatePad Pro 11 GOT-W29**（Qualcomm kona / Snapdragon 870, HarmonyOS 4.x, kernel
`4.19.157-perf+`）上 **CVE-2026-43499**（Linux rtmutex/futex-PI UAF, "GhostLock"）
的提权研究记录。

## 设备

| 项 | 值 |
|---|---|
| 型号 | HUAWEI MatePad Pro 11 GOT-W29 (tablet) |
| SoC | Qualcomm kona (SM8250, Snapdragon 870) |
| 系统 | HarmonyOS 4.2 (104.2.0.237C00), 出厂 4.0 (104.0.0.136) |
| 内核 | `4.19.157-perf+` (2025-10-13 build) |
| VA | 39-bit, 4K pages, KASLR on |

## 漏洞

CVE-2026-43499: `kernel/locking/rtmutex.c` 的 `remove_waiter()` 在
`rt_mutex_start_proxy_lock()` 回滚路径用 `current` 而非 `waiter->task` 清理，
导致悬空 `pi_blocked_on`（栈 UAF）。影响 `2.6.39 ~ 7.1`（本内核在范围内）。
上游修复: commit `3bfdc63936dd`。

本设备确认：源码 `rtmutex.c:1110-1112`、反编译 `boot.elf`、真机触发全部验证。

## 已验证的成果（设备实测）

### 1. KASLR 泄露 — 通过 perf_event_open ✅

shell (uid 2000) 下 `perf_event_paranoid=-1`，`perf_event_open(PERF_SAMPLE_IP,
exclude_user=1)` 采样内核文本地址簇，对齐已知符号偏移得 slide。

```text
samples=27651 kernel_ips=1685 lo=0xffffff948728176c hi=0xffffff9488ebfc7c
KASLR slide=0x147f200000    (40/40 IP 映射进内核文本区验证)
runtime _stext=0xffffff9487280800
```

工具: `tools/perf_kaslr.c`。运行前提：shell（Shizuku `rish`），无 seccomp 拦截。

### 2. EDEADLK 触发器 ✅

制造 PI 环让 `FUTEX_CMP_REQUEUE_PI` 返回 `-EDEADLK`，回滚触发 remove_waiter bug。

**关键排列**：requeue 目标 futex 由**被 requeue 的 waiter 持有**（`futex2 =
waiter_tid`）→ `task_blocks_on_rt_mutex` 中 `owner == task` → `-EDEADLK`。

```text
[M] CMP_REQUEUE_PI ret=-1 errno=35 (EDEADLK!)
[W] WAIT_REQUEUE_PI ret=-1 errno=110 (ETIMEDOUT)  ← waiter 返回
[M] waiter_returned=1                              ← 留下悬空 pi_blocked_on
```

工具: `tools/edeadlk_probe.c`（variant 8+2+1 = 11，或 27）。

### 3. 写原语机制（已理解）

`rt_mutex_adjust_prio_chain` step[7] 对 fake waiter 做 rb_erase（单左子路径）：
`*(tree_left) = tree_pc`（value→target）+ `__rb_change_child` 增量写。target.h 中
全部偏移为 boot.elf 反汇编实测。

### 4. 完整偏移（target/）

见 `target/got_w29_target.h`。要点：
- task_struct: cred=0x988, prio=0x184, pi_blocked_on=0xa90, usage=0x68, mm=0x728
- rt_mutex_waiter (HW_FUTEX_PI): tree@0x0, pi_tree@0x18, task@0x30, lock@0x38,
  major@0x40, prio@0x48, deadline@0x50
- PAGE_OFFSET=0xffffffc000000000, PHYS_OFFSET=0x80000000 (kona),
  KIMAGE_TEXT_BASE=0xffffff8008080000

### 5. 写原语实机验证（2026-08-19，KPM 辅助）✅

自写 KPM（`tools/kpm-debug/rtmutex-dbg.c`，KernelPatch 0.13.5 inline-hook）
在 fake walk 时重建 overlay（tree/task/lock）并**改写 `next_lock` 参数**为
`empty_zero_page`（KernelPatch `_transit8` 用修改后的 fargs 调原函数），使
`rt_mutex_adjust_prio_chain` [3] `next_lock==waiter->lock` 通过、[5] trylock
零锁成功、[6] ownerless、[7] `rt_mutex_dequeue`（rb_erase 单左子）执行——
**`sysctl_bootid` 被改写为 `&loggers[0][1]`，`slide-kaslr-ok`，KASLR
泄露/验证通过**。关键日志：

```text
REPAIR3 waiter=0xffffff801ecdbc00 lock=0xffffffa7c4950000
slide boot_id_leaked_nfulnl_logger value=ffffffa7c4612320
slide-kaslr-ok base=ffffffa7c1280000 slide=00000027b9200000
```

详见 `docs/kpm-write-validation.md`。真实攻击（shell 无 KPM 无 RT）仍需
解决 pselect 返回路径帧覆盖 overlay 的问题（待办）。

## 阻塞与修复（2026-08-10 更新）

### 真正根因：EDEADLK 触发走错子路径（先于 overlay）

boot.elf 反汇编 `task_blocks_on_rt_mutex` 实锤：本设备内核在 0x3808-0x3868 处
有**提前 `owner==task` 检查**（`cmp owner,task; b.eq -> -EDEADLK`），它在
`task->pi_blocked_on` 写入（0x38d4 `str x21,[x20,#0xa90]`）**之前**返回。
GOT-W29 旧触发让 waiter 自持 `futex2=waiter_tid`（self-own）→ 恰好命中该提前
检查 → **从不设置 pi_blocked_on → 无悬空指针**。设备观察（无崩溃 + boot_id 不变）
完全符合"无悬空"——overlay 放置是误诊。

**正确触发（smt878u 参考，已实施）**：PI 环——owner `FUTEX_LOCK_PI(target)` 持有
requeue 目标；waiter 持 chain futex；owner 再阻塞在 chain（环：waiter→target→
owner→chain→waiter）。requeue 时链走检测 `rt_mutex_owner(chain)==top_task`
（rtmutex step[6]）→ `-EDEADLK` → 回滚 `remove_waiter` 用 requeuer 的 `current`
清错人 → **waiter 的 pi_blocked_on 悬空**。owner 需降优先级（nice=10）使 boost 后
prio 与 owner_waiter->prio 不同，否则 `rt_mutex_waiter_equal` 早退。

### Overlay 修复（已实施，2026-08-15 复核）

栈几何由 boot.elf 帧尺寸实锤：`__arm64_sys_futex(0x70) + do_futex(0x60+0x1a0)`
里 rt_waiter 在 `sp+0xc0` → 深度 `0x1b0`；pselect 路径 `stack_fds[0]` 深度
`0x210`，差 `0x60` = **12 words**（旧值 24 漏算 do_futex 开头 `stp
x29,x30,[sp,#-0x60]!` 的 0x60）。因此 `word_i` 落在 `stack_fds[12+i]`：
words 0-2 在 ex[2..4] 输入区（直接可控），words 6-7（task/lock）在
res_in[3..4]（用 in[3..4] + POLLIN-ready fd 编码），words 3-5/8-10 留 0
（pi_tree 不用，prio/deadline 由 step[7] 覆写）。pselect 因 ready fd 立即返回
→ waiter **用户态忙等**（禁信号、零 syscall）直到 consumer 触发完成。

### 遗留次要问题

- KASLR slide 一律以 `_stext`（`KIMAGE_STEXT_LINK`）为锚：perf 返回 runtime
  `_stext`，`kaslr_slide = stext - KIMAGE_STEXT_LINK`，kimage 目标 =
  `image + slide`（此前 `stext - KIMAGE_TEXT_BASE` 会残留 +0x800）。
- 写形状：smt878u 走 pi_tree（dequeue_pi），GOT-W29 ownerless 路径只用 tree
  （rt_mutex_dequeue）——本次修复用 tree 形状（tree_pc=LOGGERS, tree_left=BOOT_ID）。
- tgsig overlay 实验（rt_tgsigqueueinfo siginfo 栈拷贝）已删除：siginfo 深度
  `0xb8`，与悬空 rt_waiter 的 `0x1b0` 差 0xf8，路径不成立。
- 写形状：smt878u 走 pi_tree（dequeue_pi），GOT-W29 ownerless 路径只用 tree
  （rt_mutex_dequeue）——本次修复用 tree 形状（tree_pc=LOGGERS, tree_left=BOOT_ID）。

### 实机验证（需 rish）

1. `tools/cycle_probe`（已编译）：廉价验证 cycle EDEADLK 触发；EDEADLK 后对 waiter
   sched_setattr 若触发 consumer oops = 悬空存在 + overlay 落地。
2. 完整 exploit：`build_tools/deploy_test.sh` 部署，看 slide-kaslr-ok 或 consumer oops。
3. overlay 编码校验：`GOT_SLIDE_NOCONSUME=1` 跳过 walk，先核对 pselect 返回后
   用户态 res words；再 `GOT_SLIDE_LOCK0` / `GOT_SLIDE_TASK0` 分步确认 walk 走到
   step[5]/step[9]。

### 普通 app（untrusted_app / Termux）可行性探测

```sh
cc -O2 -Wall tools/app_env_probe.c -o tools/app_env_probe
./app_env_probe            # 安全模式: 不触发悬空 walk
./app_env_probe walk       # 触发后对 waiter 做 sched_setattr（可能 oops 本线程）
```

输出决定 app 化路线：kallsyms 是否可读（KASLR 是否白送）、pagemap PFN 是否可见
（能否反推 PAGE_OFFSET 走 DM 别名）、`sched_setattr` 同进程线程是否可用（consumer
触发 walk 的前提）、`/proc/<child>/mem` 是否可开（direct stage 前提）、以及
`trigger0`（纯 PI 环 EDEADLK，rish/root cpuset 特征）与 `trigger1`（提前 unlock +
ownerless target 的绕 cpuset 悬空变体）在 app 域的实际行为。

### app 域实测结论（2026-08-15，Termux = untrusted_app）

- 原语可用：`sched_setattr`/`getattr`（同进程其他线程）、`/proc/<child>/mem`、
  `timerfd_create`、futex-PI、boot_id 读取、8 核 affinity 全部 OK。
- KASLR 无现成通道：`perf_event_open` EPERM、`/proc/kallsyms` EPERM、
  pagemap PFN 隐藏、dmesg 拒绝。
- 触发：app 域 `CMP_REQUEUE_PI` 返回 1（requeue 成功），不走 EDEADLK 回滚；
  "成功 requeue + owner 提前解锁 target" 的变体实测把锁直接转给 waiter
  （WAIT 返回 0），不产生悬空；独立 unlocker 线程解锁 chain 因非 owner 必然
  EPERM。
- QOS 路线（源码级发现）：链走 step[3] 的 hw `waiter_equal` 用
  `major_prio`(=get_preempt_qos，仅 CRITICAL 非零) + `can_all_pi` 决定是否早退；
  app 在 /top-app → `major_only=1` → can_all_pi=false，但若 owner 阻塞期间 QOS
  发生变化（CRITICAL→NORMAL），`major_prio` 不等仍可让链走继续到 step[6]
  EDEADLK。唯一用户态改 QOS 的入口是 `/dev/iaware_qos_ctrl` ioctl，实测
  untrusted_app 打开被 SELinux 拒（EACCES）。
- **结论（源码 + 真机双重确认）**：本内核 `CONFIG_DEBUG_RT_MUTEXES=n`，
  buggy `remove_waiter` 只由 `rt_mutex_start_proxy_lock()` 的 EDEADLK 回滚调用，
  而 EDEADLK 依赖链走走到 step[6]，被非 root cpuset 的 major_only 硬性短路；
  信号竞态不经过该调用。因此**普通 app 权限（非 root cpuset）在本设备上无法
  触发此 CVE 的悬空**。触发恢复只可能来自：进程进入 root cpuset，或获得
  iaware_qos_ctrl 的 SELinux 访问权（均非"普通 app"能力）。

### 设备级事实（bugreport 佐证，2026-08-15）

- 历史 rish 日志（/sdcard/ghostlock-test/preload_rish*.log）显示 EDEADLK 每次
  都成立（`CMP_REQUEUE_PI ret=-1 errno=35`），但 boot_id 从未被写入、zero-page
  探针从未污染——即 24-word 错位 overlay 时代写原语从未落地。
- 所有 perf 行 slide 都带 `+0x800`（`slide=...0800`）——`_stext` 锚点 bug 实锤。
- **oops 会整机重启**：bugreport cmdline 显示 `sreason=null_pointer`（4 次）、
  `page_request`（6 次+）、`SP_PC_AE`；被截断的 preload 日志与重启时间一一对应。
  代码注释中"PANIC_ON_OOPS 关、oops 只死线程"的假设不成立，真机测试必须
  单次尝试并先跑 `sync_loop.sh` / `watch_bootid.sh` 保日志。

## 目录

```
tools/      验证工具（perf KASLR, EDEADLK 探针, overlay 测试, kaslr.json）
target/     全部实测偏移
exploit/    移植的 slide.c（含 EDEADLK 触发改动）
```

## 致谢

- 上游 PoC: [x-spy/CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle),
  [soralis0912/CVE-2026-43499-aristotle](https://github.com/soralis0912/CVE-2026-43499-aristotle),
  [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus),
  [Wtrwx/smt878u-ionstack-poc](https://github.com/Wtrwx/smt878u-ionstack-poc) (GPL-3.0)
- CVE: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-43499),
  [Red Hat RHSB-2026-010](https://access.redhat.com/security/vulnerabilities/RHSB-2026-010)

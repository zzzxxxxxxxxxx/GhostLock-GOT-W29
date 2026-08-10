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

### Overlay 修复（已实施）

shift=12 下 fake waiter 的 words 6-7（task/lock）落在 res_in[3..4]（内核清零区）。
利用 do_select 语义：`res_in[i] = in[i] & POLLIN-ready`。将 SLIDE_INIT_TASK /
fake_lock 写入 in[3]/in[4]，并把对应 fd 全部 dup2 到"有数据的 pipe 读端"（永远
EPOLLIN-ready）→ res_in[3]=init_task、res_in[4]=fake_lock 精确编码。words 3-5
(pi_tree) 与 8-10 可为零（ownerless-lock 路径不用 pi_tree；prio/deadline 由内核在
step[7] 覆写）。pselect 因 ready fd 立即返回 → waiter **用户态忙等**（禁信号、零
syscall，防内核栈复用清掉 fake waiter）直到 consumer 触发完成。11-word HW_FUTEX_PI
表、双 fd 类、父进程等待超时均已实现（git diff）。

### 遗留次要问题（设计 agent 标注，未阻塞 overlay）

- boot_id 泄漏值是**常数 direct-map 别名**（`*(boot_id)=DM(loggers[0][1])`），
  `stext=leaked-p0_alias_image_offset(NFULNL_LOGGER)` 与 DM(_stext) 有 off-by；
  root 阶段若全程走 physmap（DM 空间）则自洽，否则需改用 perf_event_open 的运行时
  slide（rish 下可用）。
- 写形状：smt878u 走 pi_tree（dequeue_pi），GOT-W29 ownerless 路径只用 tree
  （rt_mutex_dequeue）——本次修复用 tree 形状（tree_pc=LOGGERS, tree_left=BOOT_ID）。

### 实机验证（需 rish）

1. `tools/cycle_probe`（已编译）：廉价验证 cycle EDEADLK 触发；EDEADLK 后对 waiter
   sched_setattr 若触发 consumer oops = 悬空存在 + overlay 落地。
2. 完整 exploit：`build_tools/deploy_test.sh` 部署，看 slide-kaslr-ok 或 consumer oops。
3. 次要阻塞：泄漏算术用 perf slide 校准。

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

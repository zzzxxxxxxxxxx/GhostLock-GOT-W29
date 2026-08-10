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

## 未解决的阻塞

**Overlay：无法在内核栈放置有效的内核 lock 指针**（fake waiter 需
`lock@0x38` 为有效内核 rt_mutex）：

| 方案 | 阻塞 |
|---|---|
| pselect | 本设备布局 shift=12，waiter words 3-10 落 res_* 清零区 |
| sendmsg iovstack | iovec 校验拒绝内核地址（iov_len 巨大值→EFAULT, iov_base 必须用户指针, PAN 阻止） |
| prctl(35) | 需 CAP_SYS_RESOURCE（shell 无） |

参考实现（smt878u, 4.19.113）能工作因其 pselect 布局有利 + host 注入内核
fake_lock。本设备需新 overlay gadget 或 IonStack 堆整理。

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

# CVE-2026-43499 (GhostLock) — HUAWEI MatePad Pro 11 GOT-W29

针对 GOT-W29（HarmonyOS 4.0, kernel `4.19.157-perf+`）上
**CVE-2026-43499**（rtmutex/futex-PI 栈 UAF，"GhostLock"）的提权研究。

## 最终结论

1. **漏洞真实且可触发**：值持有 PI 环使 `FUTEX_CMP_REQUEUE_PI` 返回 `-EDEADLK`，
   回滚路径激活 `remove_waiter()` 的 `current != waiter->task` 清理 bug（本内核
   `kernel/locking/rtmutex.c:1110-1112`，上游修复 `3bfdc63936dd`），waiter 的
   `pi_blocked_on` 悬空（指向其内核栈 `E-0x1b0` 处的 rt_waiter）。
2. **写原语从未在无作弊条件下验证成功**：`rt_mutex_adjust_prio_chain` step[7]
   的 `rb_erase`（单左子路径 `[tree_left] = tree_pc`）写入 boot_id（值为
   0xffffff800b412320、`empty_zero_page` ownerless 假锁即可，无需 owner/
   groom/ kernelsnitch）**仅在前述写原语机制的正确性层面成立，且两次验证都是
   注入方式**：QEMU 真机内核上 GDB 直接把 fake waiter 写入悬空 blk；实机上次
   成功则靠自写 KPM 重建 overlay 并改写 `next_lock` 参数。**两者都不是纯用户态
   触发，因此不能算“写原语在实机验证成功”。**
3. **根本限制（投递层死结）**：shell→写原语卡在 fake waiter 的投递——必须放在
   `E-0x1b0`（11 个 64 位词），而该深度不存在任何用户可控缓冲区——四大投递
   机制（块拷贝 / import_iovec / 单值 get_user / 用户结构体镜像）已全量穷举。
   **这是该内核 futex 帧几何决定的死结，不是实现缺陷。**（同 CVE 在 k40
   (shift=1)、Pixel 7/smt878u（rt_waiter=0x470）等几何不同的设备上可完整提权。）

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

### 写原语机制（仅注入下验证，非干净利用）

[注] 此为 `rb_erase` 写原语的**机制验证**，两次验证都依赖注入：
一次在 QEMU 真机内核 `kernel.patched` 上用 **GDB** 把 fake waiter 直接写入
悬空 blk；另一次在实机用自写 **KPM**（下文工具链）重建 overlay。两者都不是
纯用户态触发，不代表“实机验证成功”，仅证明 walk 的写路径与编码正确。

`rt_mutex_adjust_prio_chain` 的 walk 读悬空 `pi_blocked_on` 处的 fake rt_waiter：
- [3] `next_lock == waiter->lock`（`lock = empty_zero_page`，{wait_lock=0,
  waiters 由 GDB 设为 blk}）
- [5] `raw_spin_trylock(&lock->wait_lock)` 零锁成功
- [7] `rt_mutex_dequeue` → `rb_erase` 单左子路径：`[tree_left] = tree_pc`
  → 把 `w0=0xffffff800b412320`（写值）写入 `w2=0xffffff800b7f8b64`（boot_id）
- [9] ownerless 干净返回（`rt_mutex_adjust_pi` 无 `if(!owner)` 拦截——该检查只在
  `requeue=false` 分支，fake waiter prio=130 ≠ task->prio 使 `requeue` 保持 true）

实测（GDB 直接向悬空 blk 写 ownerless fake）回读：

```text
boot_id[0..7] @0xffffff800b7f8b64 = 0xffffff800b412320   (== SLIDE_LOGGERS_0_1，写入成功!)
empty_zero_page owner=0x0  waiters.root=blk              (ownerless!)
```

**不需要 owner-ful 页 / `prepare_skb_payload` / `kernelsnitch`**——`empty_zero_page`
（固定 .bss 地址 0xffffff800b750000）即可作 `lock`。整条链仅剩“用户态把 fake
waiter 放到悬空 blk”一步，而这一步已被载体穷举判定为不可行（见下节）。

### 关键偏移（boot.elf 反汇编实测，`exploit/ghostlock-source/src/target.h`）

- task_struct：cred=0x988, prio=0x184, pi_blocked_on=0xa90, usage=0x68, mm=0x728
- rt_mutex_waiter (CONFIG_HW_FUTEX_PI)：tree@0x0, pi_tree@0x18, task@0x30,
  lock@0x38, major_prio@0x40(=w8)，major_only@0x44, prio@0x48(=w9), deadline@0x50
- rt_mutex：wait_lock@0x0, waiters.root@0x8, leftmost@0x10, owner@0x18
- PAGE_OFFSET=0xffffffc000000000, PHYS_OFFSET=0x80000000 (kona),
  KIMAGE_TEXT_BASE=0xffffff8008080000

## 为什么写原语无法从 shell 落地（载体死结）

悬空 blk = waiter 的 `__arm64_sys_futex` 入口 SP(E) − `0x1b0`（GDB 实测
`E=…be70, blk=…bcc0`），即 `core_sys_select` 的 `stack_fds[12]`。载体必须把
11 个任意 64 位词放到 `[E-0x1b0, E-0x158)`。四类机制全量穷举（`kernel.elf`
反汇编 + `tools/scan_carriers2.py` + `tools/scan_carriers3.py`）结果：

| 机制 | 最深可达 | 排除原因 |
|---|---|---|
| `copy_from_user` 块拷贝 | 见右 | 唯一覆盖 `E-0x1b0` 的 `core_sys_select`：nfds=320（栈路径上限，`FDS_BYTES(320)=40B`，**nfds≥321 → 48B 必走 kvmalloc**）下 fake waiter w0..w6 落 `out[3..4]/ex[0..4]` 输入位图，但 **w7 lock 恰好落 `res_in[0]`**——`zero_fd_set` 清零；阻塞需无就绪 fd→lock=0→[5] `raw_spin_trylock(&0)` 崩；编码则 select 立即返回→`do_notify_resume` 0x1b0 帧覆盖。**差一格，无解** |
| ptrace `NT_PRFPREG`（`__fpr_set` newstate 528B） | `[E-0x4e0, E-0x2d0)` | 链 `sys_ptrace 0x30 + arch_ptrace 0x10 + ptrace_request 0xf0 + ptrace_regset 0x30 + fpr_set 0x20 + __fpr_set 0x270 = 0x4e0`，比目标**深 0x120**，覆盖不到 |
| `import_iovec` 族（readv/writev/vmsplice/process_vm_*/keyctl） | `E-0x160` | 浅 0x50 |
| ppoll `stack_pps` | `E-0x3f0`（do_sys_poll 帧 0x400, nfds≤30） | 深 0x240 且超数组容限 |
| 单值 `get_user` 写深栈（新扫） | — | `scan_carriers3.py` 对全部 syscall 可达函数过滤“参数指针源 load → 写 [sp+0x100..0x280]”：仅 84 个命中，全是 printf 家族 varargs 转存，无用户数据 |
| 其他 | — | `kernel_quotactl`（getname 路径串约束）、`___sys_sendmsg`（msghdr 48B@E-0x210）、`btf_get_info_by_fd`/`do_seccomp`/`get_compat_msghdr`/`restore_altstack`（尺寸/特权不够）、setxattr（value 为 kvmalloc） |

补充事实：

- **do_notify_resume 返回路径覆盖**：`ret_to_user → do_notify_resume` 的 0x1b0
  字节帧恰好压在 `[E-0x1b0, E)`，任何“就绪 fd 编码”的 select 载体返回时
  task/lock 都被覆盖；阻塞载体虽绕开覆盖，但几何上无法同时满足
  “lock 非零”与“无就绪 fd”。
- **k40 对照**：同为 `4.19.157-perf` 的 Redmi K40 用 shift=1（rt_waiter 在
  `stack_fds[1]`，全部落在输入位图）可完整提权；GOT-W29 的 futex 帧大
  （do_futex 0x1a0+），rt_waiter 沉到 `stack_fds[12]`，属**内核构建差异**，
  不可通过参数/排列“对齐”。
- **普通 app 域**：KASLR（perf/kallsyms/pagemap/dmesg）、`CMP_REQUEUE_PI`
  触发、major_only 链走在权限层面均被拒；`/dev/iaware_qos_ctrl` 被 SELinux 拦。
- KPM/APatch root 属“鸡生蛋”，仅作研究观测工具（见调试工具链），不是提权路径。

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
exploit/ghostlock-source/     slide.c 移植（EDEADLK 触发、载体、GOT_SLIDE_* 实验开关）
tools/                        KASLR/EDEADLK 探针、载体扫描器、KPM 工具链
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

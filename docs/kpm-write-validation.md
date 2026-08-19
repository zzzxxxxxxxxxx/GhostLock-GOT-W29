# GhostLock 写原语实机验证（KPM 辅助）

## 结论

**CVE-2026-43499（rtmutex/futex-PI UAF）的写原语已在 GOT-W29 实机验证**：
通过 pselect-overlay 布置 fake rt_mutex_waiter，驱动
`rt_mutex_adjust_prio_chain` step[7] 的 `rt_mutex_dequeue()`（rb_erase
单左子路径）把内核 `sysctl_bootid` 改写为 `&loggers[0][1]` 的地址，
KASLR 泄露/验证（`slide-kaslr-ok`）通过。

验证环境：FolkPatch root + 自写 KPM `rtmutex-dbg`（KernelPatch 0.13.5，
inline-hook rt_mutex 路径）。真实攻击（shell 无 KPM 无 RT）仍需解决
overlay 在 consumer walk 前被 pselect 返回路径破坏的问题，但**漏洞利用的
核心写原语机制已实锤**。

## 调试链路（KPM rtmutex-dbg 的 hook 集）

| hook | 作用 |
|---|---|
| `rt_mutex_adjust_pi` | 记录 PI 调整；normal walk 的 waiter dump |
| `rt_mutex_adjust_prio_chain` | 完整 dump fake waiter（含从 `task->pi_blocked_on` 读悬空 waiter）；**REPAIR3 overlay 重建**；after 打印返回值 |
| `__arm64_sys_pselect6` / `__arm64_sys_ppoll` | 返回路径清 `_TIF_WORK_MASK`（仅 nfds==320）；pselect 前后 fd_set 观测 |
| `do_select` | 内核侧读 `res_in[3]/[4]`（fd_set_bits 结构） |
| `__arm64_sys_futex` | 追踪 WAIT_REQUEUE_PI / CMP_REQUEUE_PI 调用与返回值 |

## 关键发现链

1. **overlay 编码成功**：`res_in[3]=in3（init_task）`、`res_in[4]=in4（fake_lock）`
   （内核侧 do_select hook 实测，非用户侧拷贝的 0）。shift=12 与栈几何推算
   （rt_waiter@E-0x1b0、stack_fds@E-0x210）一致，`waiter = bits+0x60`。
2. **overlay 被返回路径破坏**：pselect 返回路径的 `do_notify_resume`（LR
   `do_notify_resume+0x88`，symtab 确认）帧落在 bits 区域，覆盖 words 6-7。
   触发条件不限于 `TIF_NEED_RESCHED`（`_TIF_WORK_MASK` 任一位置位即调用），
   因此 RT 优先级、清 NEED_RESCHED 均无法完全阻止。
3. **写原语进入条件**（`rt_mutex_adjust_prio_chain`）：
   - [3] `next_lock == waiter->lock`（否则退出）
   - [5] `raw_spin_trylock(&lock->wait_lock)`（lock 必须可写）
   - [6] `rt_mutex_owner(lock) != top_task`（ownerless）
   - [7] `rt_mutex_dequeue(lock, waiter)` → rb_erase 单左子 → 写原语
4. **fake walk 的 next_lock 是垃圾**（从被破坏的 owner 推出），原始
   GOT_FAKELOCK_BSS 模式（lock=empty_zero_page）会在 [3] 退出（next_lock
   垃圾 != empty_zero_page），写原语不执行。

## REPAIR3（KPM overlay 重建）

在 `rt_mutex_adjust_prio_chain` before 回调（fake walk：`orig_waiter==NULL`
且 waiter->task 字段为 0）：

1. `waiter = task->pi_blocked_on`（+0xa90）
2. 写 overlay：`tree_pc=&loggers[0][1]`、`tree_right=0`、
   `tree_left=sysctl_bootid`、`task=init_task`、`lock=empty_zero_page`
3. **修改 `args->arg3`（next_lock）= empty_zero_page**——KernelPatch
   `_transit8` 用修改后的 fargs 调原函数，[3] 检查 `next_lock == waiter->lock`
   通过。empty_zero_page 是 `.bss`（可写、全零）：[5] trylock 成功、
   [6] owner=NULL、[7] rb_erase 执行。

## 验证数据

```
REPAIR3 waiter=0xffffff801ecdbc00 tree_pc=0xffffffa7c4612320
        tree_left=0xffffffa7c49f8b64 task=0xffffffa7c461e100 lock=0xffffffa7c4950000
prio_chain_ret=0

slide boot_id_leaked_nfulnl_logger value=ffffffa7c4612320   ← boot_id 改写成功
slide boot_id-derived_stext value=ffffffa7c1280000
slide-kaslr-ok base=ffffffa7c1280000 slide=00000027b9200000
```

`leaked` 从原始 boot_id（小端非 0xffff 前缀）变为 `0xffffffa7c4612320`
（= `&loggers[0][1]` runtime），`(leaked>>48)==0xffff` 检查通过——
**写原语把 boot_id 改写为 loggers 地址**。

## 工具

- `tools/kpm-debug/rtmutex-dbg.c` + `Makefile`：KPM 模块（编译见 README）
- `tools/kpm-debug/sc_kpm_load.c`：supercall 热加载/卸载/查询（key=`su`）
- `tools/kpm-debug/run_rtmdbg_test.sh`：一键测试（shell 无 RT 真实路径、
  sync 落盘、90s 收网）
- 华为 panic 记录：`/data/log/bbox/history.log`（每次 oops 的完整栈）

## 待办

- 真实攻击（shell 无 KPM 无 RT）的 overlay 保护（返回路径帧覆盖）
- 写原语 → 完整提权链（cred 改写等）

## 2026-08-19 后续：owner-ful 尝试与 4.19 确定性覆盖

### 新发现

1. **ownerless 路径在 4.19 被挡死**：`rt_mutex_adjust_pi()` 有
   `if (!owner) return 0;`——fake_lock 无 owner（empty_zero_page/零页）时
   根本不调 `rt_mutex_adjust_prio_chain()`。popsicle（6.12）没有该检查，
   因此它的 ownerless slide 验证在 4.19 无法复现。
2. **owner-ful payload 已移植**（util.c SLIDE 模式）：fake_lock 的 owner=
   fake_task|1、fake_task->pi_blocked_on=fake_w0、fake_w0->lock=lockB
   （第二个 payload 零锁，绕开 walk [6] `lock==orig_lock` 死结）。
3. **4.19 返回路径确定性覆盖 res_in[4]**（lock word，bits+152）：实测每次
   fake walk 的 lock 都是内核地址残留（如 `stext+0xe0a0` = rt_sigreturn 内部、
   payload 页基址），**从未等于 payload fake_lock**。FP+sched_yield 只把
   do_notify_resume 触发率降到 ~21%，但 lock 覆盖几乎必然（res_in[3] task
   偶尔完好=init_task，res_in[4] 必坏）。这是 GOT-W29 真实攻击的机制死结。
4. **empty_zero_page 不可作为强制写目标**：REPAIR3/REPAIR5 用它当 fake_lock
   写 wait_lock 会破坏全系统共享零页 → 测试后 oops 风暴。
5. **收网 killall 触发 soft-lock 重启**：SIGKILL child 跑 futex_exit_release
   走悬空 pi_blocked_on → soft-lock → wdog/PS_HOLD（slide.c 注释早有警告）。
   收网改用 SIGSTOP 后设备不再每次重启。

### 当前 KPM 兜底（统一 skip）

`rt_mutex_adjust_prio_chain` before 对 fake walk（orig_waiter==NULL）无条件
`skip_origin=1` + 清 `task->pi_blocked_on`：不写不崩，系统稳定，可重复测试。
代价是无法验证 owner-ful 写（被跳过）。

### 下一方向：ppoll 载体

pselect 的 res_in[4] 被确定性覆盖；ppoll 的 pollfd 数组在栈的深度可能不同，
若避开返回路径帧则 words 可用 pollfd.events（用户可控）承载。`do_poll`
符号在 GOT-W29 kallsyms 缺失（验证工具受限），需直接实现 ppoll overlay
并实测 pollfd 数组 vs rt_waiter 的栈几何是否重叠。

### 结论（2026-08-19 最终）：ppoll 载体编码层面不可行

boot.elf 反汇编 `__arm64_sys_ppoll` / `do_sys_poll`（0xffffff80083070c0 /
0xffffff8008307c18，栈帧 0x90+0x3a0）后确认：**pollfd 是 16 字节结构**
（fd 4B + events 4B + revents 4B + pad 4B），无法承载 fake waiter 的
64 位 task/lock words：

- task/lock 需要**连续 8 字节用户可控**；pollfd 的 fd 值受限（必须真实
  fd），events 只有 4 字节且每 16 字节一个（不连续），revents 由内核写
  （不可控，类似 res_in）。

**GOT-W29（4.19）真实攻击确认不可行**（两个确定性死结）：

1. pselect 载体的 `res_in[4]`（lock）被返回路径（rt_sigreturn 帧）确定性
   覆盖，用户态无法防（FP+sched_yield 只降触发率）。
2. ppoll 载体的 pollfd 结构在编码层面无法承载 64 位 words。

smt878u / popsicle 可行是因为它们的栈几何允许 words 落在用户可控的
in/out/ex（pselect 3 个 fd_set），GOT-W29 的 waiter 位置（bits+0x60 →
task/lock 在 res_in[3]/[4]）没有该窗口。

**研究价值已完整**：CVE-2026-43499 写原语机制在 GOT-W29 实机验证（KPM
辅助：boot_id 改写、slide-kaslr-ok），根因链（EDEADLK → 悬空 pi_blocked_on
→ fake waiter → step[7] rb_erase 写原语）与"为什么 GOT-W29 卡住 / 为什么
其他设备可以"的对比分析完整，调试工具链（rtmutex-dbg KPM + supercall 工具
+ 测试脚本）可复用。

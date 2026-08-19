# CVE-2026-43499 (GhostLock) — HUAWEI MatePad Pro 11 GOT-W29

针对 GOT-W29（HarmonyOS 4.0, kernel `4.19.157-perf+`）上
**CVE-2026-43499**（rtmutex/futex-PI UAF，"GhostLock"）的提权研究。

**核心结论**：

- 漏洞的**写原语在实机上验证成功**（KPM 辅助下改写内核 `sysctl_bootid`、
  推导 KASLR slide）。
- **但真实提权（shell 无 KPM 无 RT）不可行**：4.19 内核的 pselect 返回路径
  会确定性覆盖 overlay 的 lock 字，且无替代载体。这是内核栈几何决定的
  死结，不是实现缺陷（对比设备 smt878u/popsicle 可完整提权，因栈几何不同）。

## 设备

| 项 | 值 |
|---|---|
| 型号 | HUAWEI MatePad Pro 11 GOT-W29 |
| SoC | Qualcomm kona (SM8250, Snapdragon 870) |
| 系统 | HarmonyOS 4.0 (104.0.0.136) |
| 内核 | `4.19.157-perf+` |
| VA | 39-bit, 4K pages, KASLR on |

## 漏洞

`kernel/locking/rtmutex.c` 的 `remove_waiter()` 在
`rt_mutex_start_proxy_lock()` 回滚路径用 `current` 而非 `waiter->task` 清理，
导致悬空 `pi_blocked_on`（栈 UAF）。影响 `2.6.39 ~ 7.1`（本内核在范围内）。
上游修复 commit `3bfdc63936dd`。

本设备确认：源码 `rtmutex.c:1110-1112`、boot.elf 反编译、真机触发全部验证。

## 触发

### 漏洞触发机制

制造 PI 环让 `FUTEX_CMP_REQUEUE_PI` 返回 `-EDEADLK`，回滚触发 remove_waiter
bug，留下悬空的 `pi_blocked_on`（指向 waiter 线程内核栈上的 rt_waiter）。

### 旧触发为何失败

旧触发让 waiter 自持 requeue 目标 futex（self-own），恰好命中本内核
`task_blocks_on_rt_mutex` 的提前 `owner==task` 检查（boot.elf 0x3808-0x3868），
在写入 `pi_blocked_on` **之前**返回 → **从不产生悬空指针** → overlay 放置
是误诊（无崩溃 + boot_id 不变）。

### 正确触发（PI 环，已实施）

PI 环：owner `FUTEX_LOCK_PI(target)` 持有 requeue 目标；waiter 持 chain futex；
owner 再阻塞在 chain（环：waiter→target→owner→chain→waiter）。requeue 时
链走检测 `rt_mutex_owner(chain)==top_task` → `-EDEADLK` → 回滚清错人的
`pi_blocked_on` → **waiter 的 pi_blocked_on 悬空**。owner 需降优先级
（nice=10）使 boost 后 prio 与 owner_waiter->prio 不同，否则
`rt_mutex_waiter_equal` 早退。

## 成果

### KASLR 泄露（perf_event_open）

shell (uid 2000) 下 `perf_event_paranoid=-1`，`perf_event_open(PERF_SAMPLE_IP,
exclude_user=1)` 采样内核文本地址簇，对齐已知符号偏移得 slide。

```text
samples=27651 kernel_ips=1685 lo=0xffffff948728176c hi=0xffffff9488ebfc7c
KASLR slide=0x147f200000    (40/40 IP 映射进内核文本区验证)
runtime _stext=0xffffff9487280800
```

工具: `tools/perf_kaslr.c`。运行前提：shell（Shizuku `rish`），无 seccomp 拦截。

### EDEADLK 触发

```text
[M] CMP_REQUEUE_PI ret=-1 errno=35 (EDEADLK!)
[W] WAIT_REQUEUE_PI ret=-1 errno=110 (ETIMEDOUT)  ← waiter 返回
[M] waiter_returned=1                              ← 留下悬空 pi_blocked_on
```

工具: `tools/edeadlk_probe.c`（variant 8+2+1 = 11，或 27）。

### 写原语机制

`rt_mutex_adjust_prio_chain` step[7] 对 fake waiter 做 rb_erase（单左子路径）：
`*(tree_left) = tree_pc` + `__rb_change_child` 增量写。target.h 中全部偏移为
boot.elf 反汇编实测。

### 完整偏移

见 `target/got_w29_target.h`。要点：

- task_struct: cred=0x988, prio=0x184, pi_blocked_on=0xa90, usage=0x68, mm=0x728
- rt_mutex_waiter (HW_FUTEX_PI): tree@0x0, pi_tree@0x18, task@0x30, lock@0x38,
  major@0x40, prio@0x48, deadline@0x50
- PAGE_OFFSET=0xffffffc000000000, PHYS_OFFSET=0x80000000 (kona),
  KIMAGE_TEXT_BASE=0xffffff8008080000

### 写原语实机验证

自写 KPM（`tools/kpm-debug/rtmutex-dbg.c`，KernelPatch 0.13.5 inline-hook）
在 fake walk 时重建 overlay（tree/task/lock）并改写 `next_lock` 参数为
`empty_zero_page`（KernelPatch `_transit8` 用修改后的 fargs 调原函数），使
`rt_mutex_adjust_prio_chain` [3] `next_lock==waiter->lock` 通过、[5] trylock
零锁成功、[6] ownerless、[7] `rt_mutex_dequeue`（rb_erase 单左子）执行——
**`sysctl_bootid` 被改写为 `&loggers[0][1]`，`slide-kaslr-ok`**。

```text
REPAIR3 waiter=0xffffff801ecdbc00 lock=0xffffffa7c4950000
slide boot_id_leaked_nfulnl_logger value=ffffffa7c4612320
slide-kaslr-ok base=ffffffa7c1280000 slide=00000027b9200000
```

## Overlay 设计

栈几何由 boot.elf 帧尺寸实锤：`__arm64_sys_futex(0x70) + do_futex(0x60+0x1a0)`
里 rt_waiter 在 `sp+0xc0` → 深度 `0x1b0`；pselect 路径 `stack_fds[0]` 深度
`0x210`，差 `0x60` = 12 words。因此 `word_i` 落在 `stack_fds[12+i]`：
words 0-2 在 ex[2..4] 输入区（直接可控），words 6-7（task/lock）在
res_in[3..4]（用 in[3..4] + POLLIN-ready fd 编码），words 3-5/8-10 留 0。
pselect 因 ready fd 立即返回 → waiter 用户态忙等（禁信号、零 syscall）直到
consumer 触发完成。

## 为什么真实提权不可行

### 1. pselect 载体的 lock 字被返回路径覆盖

overlay 的 task/lock words 落在 `res_in[3]/[4]`（由 fd ready 编码）。实测
`res_in[4]`（lock）在 pselect 返回路径被确定性覆盖（rt_sigreturn 帧残留），
从未等于 payload 的 fake_lock；`res_in[3]`（task）偶尔完好。用户态规避
（FP 操作 + sched_yield）只能把 do_notify_resume 触发率降到 ~21%，但 lock
覆盖几乎必然。

另外两条相关事实：

- **ownerless 路径被 4.19 挡死**：`rt_mutex_adjust_pi()` 有 `if (!owner)
  return 0;`，fake_lock 无 owner 时不调 adjust_prio_chain。popsicle（6.12）
  无此检查。owner-ful payload 已移植（fake_lock owner=fake_task|1），但因
  lock 字必被覆盖而无法可靠触发。
- **empty_zero_page 不能当强制写目标**：写它会破坏全系统共享零页 → 测试后
  oops 风暴。

### 2. 替代载体（ppoll）编码层面不行

boot.elf 反汇编 `__arm64_sys_ppoll` / `do_sys_poll` 后确认：pollfd 是
16 字节结构（fd 4B + events 4B + revents 4B + pad 4B），无法承载 fake
waiter 的 64 位 task/lock words——fd 值受限（必须真实 fd）、events 只有
4 字节且不连续、revents 由内核写（不可控）。

### 3. 与其他设备的差异

smt878u / popsicle 可完整提权：它们的栈几何允许 words 落在用户可控的
in/out/ex（pselect 3 个 fd_set）。GOT-W29 的 waiter 位置（bits+0x60 →
task/lock 在 res_in[3]/[4]）没有该窗口。**这是内核栈几何差异，不是实现
缺陷**。

### 4. 普通 app 域的限制

app 域（untrusted_app）无现成 KASLR 通道（perf/kallsyms/pagemap/dmesg 全
被拒）；`CMP_REQUEUE_PI` 返回 1（requeue 成功）不走 EDEADLK 回滚；非 root
cpuset 的 major_only 硬性短路链走的 step[6]。改 QOS 的唯一入口
`/dev/iaware_qos_ctrl` 被 SELinux 拒。因此普通 app 权限无法触发此 CVE。

## 调试工具链

自写 KernelPatch 模块（rtmutex-dbg）用于实机观测 fake waiter 与写原语，
编译基于 LyraVoid/KernelPatch 0.13.5（FolkPatch 同源）头文件。

### hook 集

| hook | 作用 |
|---|---|
| `rt_mutex_adjust_pi` | 记录 PI 调整；覆盖 overlay 时 skip（清 pi_blocked_on） |
| `rt_mutex_adjust_prio_chain` | fake walk 无条件 skip；完整 dump waiter |
| `__arm64_sys_pselect6` / `__arm64_sys_ppoll` | 返回路径清 `_TIF_WORK_MASK`；fd_set 观测 |
| `do_select` | 内核侧读 `res_in[3]/[4]` |
| `__arm64_sys_futex` | 追踪 WAIT_REQUEUE_PI / CMP_REQUEUE_PI |
| `rt_mutex_dequeue` | 确认 step[7] 写原语执行与 tree 形状 |

### 编译

```sh
cd <KernelPatch>/kpms/rtmutex-dbg
make TARGET_COMPILE=aarch64-linux-android- \
  CC=$PREFIX/bin/aarch64-linux-android-clang \
  LD=$PREFIX/bin/aarch64-linux-android-ld
```

产出 `rtmutex_dbg.kpm`。编译 flag 必须含
`-fno-pic -fno-pie -fno-asynchronous-unwind-tables -fno-unwind-tables`
（Makefile 已内置）：clang 默认 PIC 产生 GOT 重定位、默认生成 `.eh_frame`
（`R_AARCH64_PREL32`），KPM 加载器都不支持 → 加载失败 -1。

### 加载

FolkPatch 的 superkey 是 `su`（不是 APatch 默认的 `KernelPatch`）。用
`sc_kpm_load` 工具（源码 `sc_kpm_load.c`）：

```sh
adb shell /data/local/tmp/sc_kpm_load su /sdcard/Download/rtmutex_dbg.kpm  # 加载
adb shell /data/local/tmp/sc_kpm_load unload rtmutex-dbg su               # 卸载
adb shell /data/local/tmp/sc_kpm_load ctl rtmutex-dbg counts su           # 计数器
```

### 一键测试

`run_rtmdbg_test.sh`（设备端 `/data/local/tmp/ghostlock-test/`）：shell 身份
（`GOT_SLIDE_NO_RT=1` 真实路径）跑 GhostLock，0.5s sync 循环防日志丢失，
dmesg -w 落盘，90s 自动收网（SIGSTOP 防 soft-lock 重启）。测试前：

```sh
adb shell 'su -c "sh /sdcard/ghostlock-test/set_debug_no_reboot.sh"'  # 防重启
```

### 观测点（dmesg `[RTMDBG]`）

- `REPAIR3`：写原语验证时重建 overlay 并改写 next_lock 参数
- `FAKEWALK skip`：覆盖的 fake walk 被跳过（不写不崩）
- `prio_chain[N]` / `prio_chain_ret`：walk 调用与返回值（0=走完；
  4294967261=-EDEADLK）
- `do_select n=320`：内核侧 res_in[3]/[4]
- `futex op=13/14`：CMP_REQUEUE_PI / WAIT_REQUEUE_PI

华为 oops/panic 完整栈记录在 `/data/log/bbox/history.log`。

## 目录

```
tools/      验证工具（perf KASLR, EDEADLK 探针, overlay 测试, KPM 工具链）
target/     全部实测偏移
exploit/    移植的 slide.c（含 EDEADLK 触发改动）
docs/       其他攻击面复核（FastRPC, KGSL timeline）
```

## 致谢

- 上游 PoC: [x-spy/CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle),
  [soralis0912/CVE-2026-43499-aristotle](https://github.com/soralis0912/CVE-2026-43499-aristotle),
  [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus),
  [Wtrwx/smt878u-ionstack-poc](https://github.com/Wtrwx/smt878u-ionstack-poc) (GPL-3.0)
- CVE: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-43499),
  [Red Hat RHSB-2026-010](https://access.redhat.com/security/vulnerabilities/RHSB-2026-010)

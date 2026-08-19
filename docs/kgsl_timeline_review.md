# KGSL timeline destroy UAF — GOT-W29 复核结论：已修复，路线废弃

> 2026-08-15 复核。初版文档（`kgsl_timeline_plan.md`）基于“老版竞态未修复”
> 的前提，本轮对照 drop 源码与 boot.elf 反汇编后**推翻**该前提。
> 本文保留有用的事实与常数，供后续其他 KGSL 攻击面参考。

## 1. 结论

`kgsl_ioctl_timeline_destroy` 在本设备（boot.elf，2024-04-25 构建）中
**已经带 CVE-2022-22057 / GHSL-2022-037 的修复**，即使用
`kref_get_unless_zero(&fence->base.refcount)`（反汇编为
`refcount_inc_not_zero_checked`）而不是无条件 `dma_fence_get`。

- drop 源码 `drivers/gpu/msm/kgsl_timeline.c:513`：
  `if (!kref_get_unless_zero(&fence->base.refcount)) list_del_init(&fence->node);`
- boot.elf `kgsl_ioctl_timeline_destroy` @ `0xffffff80088bc240`：
  `bl refcount_inc_not_zero_checked`（`0xffffff80086573b8`），随后仅对
  refcount 非零的 fence 走 signal+put。
- 因此“destroy 拉取已进入释放路径的 fence”这条 UAF 不成立；
  文档原计划中的竞态骨架（阶段 C/D/E）**不再建议投入**。
- CVE-2024-33028 描述涉及 isync/syncsource，本 4.19 源码
  `drivers/gpu/msm` 无 `isync`/`syncsource` 文件，判定不适用。

## 2. 仍有效的事实（供后续使用）

### 2.1 普通 app 可达的 KGSL 面

- `/dev/kgsl-3d0` 666，TIMELINE_CREATE/FENCE_GET/QUERY/SIGNAL/WAIT/DESTROY
  全部 ioctl 可用（探针 `tools/kgsl_timeline_probe.py`）。
- KGSL sparse（VBO）ioctl 返回错误（`SPARSE_PHYS_ALLOC` errno 524），
  稀疏路线不可用。
- KGSL 版本：GETPROPERTY 返回 3.14 / dev 3.1。

### 2.2 常数（boot.elf 反汇编实测）

- `kgsl_timeline_fence` 尺寸 0x78（kmalloc-128），`node`@0x68。
- `dma_fence` 布局：refcount@0、ops@8、rcu@0x10、cb_list@0x20、lock@0x30、
  context@0x38、seqno@0x40、flags@0x48、timestamp@0x50、error@0x58。
- 本内核 `dma_fence_signal_locked` 直接遍历 cb_list 并 blr `cb->func`，
  无 5.x 的 list_replace/栈拷贝。

### 2.3 内核加固（与堆利用相关）

- `CONFIG_SLAB_FREELIST_HARDENED=y` + `RANDOM=y`、`REFCOUNT_FULL` +
  `PANIC_ON_REFCOUNT_ERROR`、`STATIC_USERMODEHELPER_PATH=""`。
- 无 kCFI、无 RKP、`INIT_STACK_NONE`、KASLR on。

## 3. 参考

- GHSL advisory：GHSL-2022-037 (msm kernel)，漏洞函数正是本函数，checked inc
  即修复。
- 中文利用文章：`/data/data/com.termux/files/usr/tmp/kgsl_timeline_cn.txt`。
- 反汇编：`/data/data/com.termux/files/usr/tmp/timeline_destroy.dis`、
  `timeline_fence_release.dis`。

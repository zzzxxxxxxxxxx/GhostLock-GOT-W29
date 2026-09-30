#!/usr/bin/env python3
"""Print the exploit's log lines from the QEMU guest.

Default (`--kmsg`): dump the kernel log buffer over GDB -- the qemu-test
harness runs the exploit with `--log-file /dev/kmsg`, so its lines land in
__log_buf (128KB, cheap to read; the vCPU is paused only for a moment).

`--ram`: dump 2GB guest RAM over QMP and grep the log file's page cache
(works without GDB, but pauses the VM for a long time).

Both modes poll every 15s until something matches or --wait elapses.

Usage: read_log.py [--kmsg|--ram] [--wait SECONDS] [QMP_SOCK]
"""
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time

KLOG_BUF_VA = 0xFFFFFF800B7599DC  # __log_buf (nokaslr kernel.patched)
KLOG_BUF_SIZE = 0x20000           # CONFIG_LOG_BUF_SHIFT=17
PRINT = re.compile(r"slide |escalate|perf task|PASSED|FAILED")

mode = "kmsg"
sock_path = "/tmp/ghostlock-qemu/qmp.sock"
wait = 300.0
until = PRINT
args = sys.argv[1:]
i = 0
while i < len(args):
    if args[i] == "--ram":
        mode = "ram"
        i += 1
    elif args[i] == "--kmsg":
        mode = "kmsg"
        i += 1
    elif args[i] == "--wait" and i + 1 < len(args):
        wait = float(args[i + 1])
        i += 2
    elif args[i] == "--until" and i + 1 < len(args):
        until = re.compile(args[i + 1])
        i += 2
    else:
        sock_path = args[i]
        i += 1


def grep_lines(text):
    return "\n".join(l for l in text.splitlines() if PRINT.search(l))


def dump_kmsg():
    path = tempfile.mktemp()
    try:
        subprocess.run(
            ["gdb", "-batch", "-q",
             "-ex", "target remote :1234",
             "-ex", "dump binary memory %s 0x%x 0x%x"
                    % (path, KLOG_BUF_VA, KLOG_BUF_VA + KLOG_BUF_SIZE),
             "-ex", "detach"],
            capture_output=True, text=True, timeout=120)
        out = subprocess.run(["strings", "-a", path],
                             capture_output=True, text=True).stdout
        return grep_lines(out)
    finally:
        if os.path.exists(path):
            os.unlink(path)


def dump_ram():
    ram = tempfile.NamedTemporaryFile(delete=False)
    path = ram.name
    ram.close()
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock_path)
        f = s.makefile("rw")
        f.readline()
        f.write(json.dumps({"execute": "qmp_capabilities"}) + "\n")
        f.flush()
        f.readline()
        f.write(json.dumps({"execute": "pmemsave", "arguments": {
            "val": 0x40000000, "size": 0x80000000, "filename": path}}) + "\n")
        f.flush()
        while True:
            line = f.readline()
            if '"return"' in line or '"error"' in line:
                break
        s.close()
        out = subprocess.run(
            "strings -a -n 6 %s | sort -u" % path,
            shell=True, capture_output=True, text=True).stdout
        return grep_lines(out)
    finally:
        os.unlink(path)


deadline = time.time() + wait
text = ""
while True:
    try:
        raw = dump_kmsg() if mode == "kmsg" else dump_ram()
    except Exception as exc:  # keep polling; the guest may not be up yet
        raw = ""
        sys.stderr.write("read_log: %s\n" % exc)
    if raw.strip():
        text = raw
    if until.search(text) or time.time() >= deadline:
        break
    sys.stderr.write("read_log.py: nothing yet (%ds left), retrying...\n"
                     % int(deadline - time.time()))
    time.sleep(15)
sys.stdout.write(text + ("\n" if text else ""))
sys.exit(0 if text.strip() else 1)

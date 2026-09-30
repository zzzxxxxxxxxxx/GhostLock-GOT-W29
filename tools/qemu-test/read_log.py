#!/usr/bin/env python3
"""Print the exploit's log lines from the QEMU guest.

Reads the kernel log buffer over QMP `pmemsave` (physical memory, so it works
no matter what EL the vCPUs are in -- GDB virtual reads fail while a vCPU is in
EL0).  The buffer may be the static __log_buf or (with several vCPUs, where the
per-CPU log buffers are negotiated) a dynamically allocated one; chase the
`log_buf` pointer like the kernel does.

Polls every 15s until something matches or --wait elapses.

Usage: read_log.py [--wait SECONDS] [--until REGEX] [QMP_SOCK]
"""
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time

# nokaslr kernel.patched (linker addresses)
VA_TEXT = 0xFFFFFF8008080000
PHYS_TEXT = 0x40080000
PAGE_OFFSET = 0xFFFFFFC000000000
MEMSTART = 0x40000000
LOG_BUF_VAR = 0xFFFFFF800B43BC78      # char *log_buf
LOG_BUF_LEN_VAR = 0xFFFFFF800B43BC80  # u32 log_buf_len
STATIC_LOG_BUF = 0xFFFFFF800B7599DC   # __log_buf (pre-negotiation)
MAX_LOG = 4 * 1024 * 1024

PRINT = re.compile(r"slide |escalate|perf task|root:|bench:|glsh-proof|PASSED"
                   r"|FAILED|SUCCESS")

sock_path = "/tmp/ghostlock-qemu/qmp.sock"
wait = 300.0
until = PRINT
args = sys.argv[1:]
i = 0
while i < len(args):
    if args[i] == "--wait" and i + 1 < len(args):
        wait = float(args[i + 1])
        i += 2
    elif args[i] == "--until" and i + 1 < len(args):
        until = re.compile(args[i + 1])
        i += 2
    else:
        sock_path = args[i]
        i += 1


def image_phys(va):
    return PHYS_TEXT + (va - VA_TEXT)


def dm_phys(va):
    return MEMSTART + (va - PAGE_OFFSET)


def qmp_call(cmds):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    f = s.makefile("rw")
    f.readline()
    f.write(json.dumps({"execute": "qmp_capabilities"}) + "\n")
    f.flush()
    f.readline()
    outs = []
    for cmd in cmds:
        path = tempfile.mktemp()
        f.write(json.dumps({"execute": "pmemsave", "arguments": {
            "val": cmd[0], "size": cmd[1], "filename": path}}) + "\n")
        f.flush()
        while True:
            line = f.readline()
            if '"return"' in line or '"error"' in line:
                break
        outs.append(path)
    s.close()
    return outs


def read_phys(addr, size):
    path = qmp_call([(addr, size)])[0]
    try:
        with open(path, "rb") as fh:
            return fh.read()
    finally:
        os.unlink(path)


def dump_lines():
    ptr_raw = read_phys(image_phys(LOG_BUF_VAR), 8)
    ptr = int.from_bytes(ptr_raw, "little") if len(ptr_raw) == 8 else 0
    if PAGE_OFFSET <= ptr < PAGE_OFFSET + 0x100000000:
        phys, size = dm_phys(ptr), 0x20000
        ln_raw = read_phys(image_phys(LOG_BUF_LEN_VAR), 4)
        ln = int.from_bytes(ln_raw, "little") if len(ln_raw) == 4 else 0
        if 0 < ln <= MAX_LOG:
            size = ln
    else:
        # static buffer (single vCPU: no per-CPU negotiation happened)
        phys, size = image_phys(STATIC_LOG_BUF), 0x20000
    path = tempfile.mktemp()
    try:
        with open(path, "wb") as fh:
            fh.write(read_phys(phys, size))
        out = subprocess.run(
            "strings -a -n 6 %s | grep -aE '%s' | sort -u" % (path, PRINT.pattern),
            shell=True, capture_output=True, text=True).stdout
        return out
    finally:
        os.unlink(path)


deadline = time.time() + wait
text = ""
while True:
    try:
        raw = dump_lines()
    except Exception as exc:  # keep polling; the guest may not be up yet
        raw = ""
        sys.stderr.write("read_log: %s\n" % exc)
    if raw.strip():
        text = raw
    if until.search(text):
        break
    if time.time() >= deadline:
        sys.stderr.write("read_log.py: --wait elapsed\n")
        break
    sys.stderr.write("read_log.py: nothing yet (%ds left), retrying...\n"
                     % int(deadline - time.time()))
    time.sleep(15)
sys.stdout.write(text + ("\n" if text else ""))
sys.exit(0 if text.strip() else 1)

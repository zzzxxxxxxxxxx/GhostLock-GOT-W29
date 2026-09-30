#!/usr/bin/env python3
"""Dump guest RAM over QMP and print the exploit's rendered log lines.

Usage: read_log.py [/tmp/ghostlock-qemu/qmp.sock] [--wait SECONDS]

Under TCG the guest takes a few minutes to boot and run the exploit, so this
script re-dumps RAM every 15s until matching lines appear (or --wait elapses,
default 300s).
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

sock_path = "/tmp/ghostlock-qemu/qmp.sock"
wait = 300.0
args = sys.argv[1:]
i = 0
while i < len(args):
    if args[i] == "--wait" and i + 1 < len(args):
        wait = float(args[i + 1])
        i += 2
    else:
        sock_path = args[i]
        i += 1

GREP = r"^[0-9]+\.[0-9]{3} [0-9]+ \[[!*+-]\]"


def dump_lines():
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
            "strings -a -n 10 %s | grep -aE '%s' | sort -u" % (path, GREP),
            shell=True, capture_output=True, text=True)
        return out.stdout
    finally:
        os.unlink(path)


deadline = time.time() + wait
while True:
    text = dump_lines()
    if text.strip() or time.time() >= deadline:
        break
    sys.stderr.write("read_log.py: no log lines yet "
                     "(%ds left), retrying...\n" % int(deadline - time.time()))
    time.sleep(15)
sys.stdout.write(text)
sys.exit(0 if text.strip() else 1)

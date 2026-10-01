#!/usr/bin/env python3
"""Print the exploit's log lines from the QEMU guest.

Reads the kernel log buffer over QMP `pmemsave` (physical memory, so it works
no matter what EL the vCPUs are in -- GDB virtual reads fail while a vCPU is in
EL0).  The buffer may be the static __log_buf or (with several vCPUs, where the
per-CPU log buffers are negotiated) a dynamically allocated one; glqemu.Guest
chases the `log_buf` pointer like the kernel does.

Polls every 15s until something matches or --wait elapses.

Usage: read_log.py [--wait SECONDS] [--until REGEX] [QMP_SOCK]
"""
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import glqemu  # noqa: E402  (path set up above)

PRINT = glqemu.PRINT

sock_path = glqemu.DEFAULT_SOCK
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


guest = glqemu.Guest(sock_path)
deadline = time.time() + wait
text = ""
while True:
    try:
        raw = guest.log_text()
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

#!/usr/bin/env python3
"""Talk to the GhostLock QEMU guest over QMP.

Shared by read_log.py (dump the exploit log) and run_rounds.py (the campaign
driver).  The exploit logs into /dev/kmsg, so the log is read straight out of
guest physical memory: that works no matter which EL the vCPUs are in, unlike
GDB virtual reads.  kernel.patched runs nokaslr, so the linker addresses below
are also the runtime addresses (and the physical load offset is fixed by
PAGE_OFFSET/PHYS_TEXT).
"""
import json
import os
import re
import socket
import subprocess
import tempfile

VA_TEXT = 0xFFFFFF8008080000
PHYS_TEXT = 0x40080000
PAGE_OFFSET = 0xFFFFFFC000000000
MEMSTART = 0x40000000
LOG_BUF_VAR = 0xFFFFFF800B43BC78      # char *log_buf
LOG_BUF_LEN_VAR = 0xFFFFFF800B43BC80  # u32 log_buf_len
STATIC_LOG_BUF = 0xFFFFFF800B7599DC   # __log_buf (pre-negotiation)
MEMSTART_VAR = 0xFFFFFF800AC57910     # memstart_addr (linear-map base)
KIMAGE_VOFFSET_VAR = 0xFFFFFF800AC57920  # kimage_voffset
RAM_SIZE = 0x80000000                 # QEMU -m 2048
MAX_LOG = 4 * 1024 * 1024
MASK64 = (1 << 64) - 1

# Where every vCPU ends up when the walk oopsed and left a spinlock held:
# queued_spin_lock_slowpath's __cmpwait loop (README "第二种失败模式").
WEDGE_PCS = (0xFFFFFF8008162B58, 0xFFFFFF8008162B68)

DEFAULT_SOCK = "/tmp/ghostlock-qemu/qmp.sock"

PRINT = re.compile(r"slide |escalate|perf task|root:|bench:|glsh-proof|PASSED"
                   r"|FAILED|SUCCESS|su selftest|selinux|harden|GLMOUNT"
                   r"|GLUMOUNT|Unable to handle|Internal error|preempt_count")


def image_phys(va):
    """Physical address of a kernel *image* symbol from its link-time VA.

    QEMU loads Image at a fixed physical address, and KASLR only randomizes the
    virtual mapping, so the image-relative offset is all we need -- this stays
    valid with KASLR on.
    """
    return PHYS_TEXT + (va - VA_TEXT)


def dm_phys(va):
    """Linear-map VA -> phys under nokaslr (memstart_addr == MEMSTART)."""
    return MEMSTART + (va - PAGE_OFFSET)


def temp_path():
    """Private temp file path (QEMU writes it; mktemp() would race)."""
    fd, path = tempfile.mkstemp(prefix="glqemu-")
    os.close(fd)
    return path


class Guest:
    """One QEMU guest, addressed through its QMP unix socket."""

    def __init__(self, sock_path=DEFAULT_SOCK):
        self.sock_path = sock_path

    def cmd(self, request, timeout=10.0):
        """Send one QMP command; return its "return" value (None on error)."""
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(self.sock_path)
        try:
            f = s.makefile("rw")
            f.readline()          # QMP greeting
            f.write(json.dumps({"execute": "qmp_capabilities"}) + "\n")
            f.flush()
            f.readline()
            f.write(json.dumps(request) + "\n")
            f.flush()
            while True:
                line = f.readline()
                if not line:
                    return None
                if '"return"' in line:
                    return json.loads(line)["return"]
                if '"error"' in line:
                    return None
        finally:
            s.close()

    def hmp(self, command):
        return self.cmd({"execute": "human-monitor-command",
                         "arguments": {"command-line": command}}) or ""

    def pmem(self, addr, size):
        path = temp_path()
        try:
            self.cmd({"execute": "pmemsave",
                      "arguments": {"val": addr, "size": size,
                                    "filename": path}})
            with open(path, "rb") as fh:
                return fh.read()
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def memstart_addr(self):
        """Physical base of the linear map (randomized by KASLR)."""
        raw = self.pmem(image_phys(MEMSTART_VAR), 8)
        return int.from_bytes(raw, "little") if len(raw) == 8 else MEMSTART

    def kimage_voffset(self):
        """offset between an image VA and its physical address (KASLR)."""
        raw = self.pmem(image_phys(KIMAGE_VOFFSET_VAR), 8)
        return int.from_bytes(raw, "little") if len(raw) == 8 else 0

    def slide(self):
        """Runtime - link address offset of the image (0 under nokaslr)."""
        return (self.kimage_voffset() + PHYS_TEXT - VA_TEXT) & MASK64

    def linear_phys(self, va):
        """Physical address of a linear-map (__va) address, KASLR included."""
        return (va - PAGE_OFFSET + self.memstart_addr()) & MASK64

    def log_buffer(self):
        """Return (guest phys addr, bytes) of the live kernel log buffer."""
        ptr = int.from_bytes(self.pmem(image_phys(LOG_BUF_VAR), 8), "little")
        # A linear-map address is one whose translation lands in RAM; the
        # window test PAGE_OFFSET..+4G only holds under nokaslr, because KASLR
        # shifts the whole linear map (memstart_addr).
        phys = self.linear_phys(ptr)
        if phys >> 48 == 0 and MEMSTART <= phys < MEMSTART + RAM_SIZE:
            raw = self.pmem(image_phys(LOG_BUF_LEN_VAR), 4)
            ln = int.from_bytes(raw, "little") if len(raw) == 4 else 0
            size = ln if 0 < ln <= MAX_LOG else 0x20000
            return phys, self.pmem(phys, size)
        # static buffer (single vCPU: no per-CPU negotiation happened)
        return (image_phys(STATIC_LOG_BUF),
                self.pmem(image_phys(STATIC_LOG_BUF), 0x20000))

    def log_text(self):
        """Log lines the harness cares about (PRINT), sorted and de-duplicated."""
        _, data = self.log_buffer()
        path = temp_path()
        try:
            with open(path, "wb") as fh:
                fh.write(data)
            out = subprocess.run(
                "strings -a -n 6 %s | grep -aE '%s' | sort -u"
                % (path, PRINT.pattern),
                shell=True, capture_output=True, text=True).stdout
            return out
        finally:
            os.unlink(path)

    def cpus(self):
        """Per-vCPU registers as QEMU sees them (no GDB stub needed)."""
        out = []
        for i in range(8):
            self.hmp("cpu %d" % i)
            regs = self.hmp("info registers")
            d = {}
            for line in regs.splitlines():
                line = line.strip()
                if line.startswith(("PC=", "X00=", "X01=")):
                    for kv in line.split():
                        if "=" in kv:
                            k, v = kv.split("=", 1)
                            d[k] = int(v, 16)
            out.append(d)
        return out

    def wedge(self):
        """(True, detail) iff every vCPU parks in __cmpwait on one lock word.

        Note this only says "no progress possible": jiffies keeps ticking at HZ
        while wedged, and a healthy idle guest also parks every vCPU on a single
        PC, so the caller must combine this with "the log stopped growing".
        """
        try:
            cpus = self.cpus()
        except (OSError, ValueError) as exc:
            return False, "register read failed: %s" % exc
        if len(cpus) < 8 or any("PC" not in c for c in cpus):
            return False, "registers unavailable"
        # PCs are runtime addresses; WEDGE_PCS are link-time, so undo the slide.
        try:
            slide = self.slide()
        except OSError:
            slide = 0
        pcs = {(c["PC"] - slide) & MASK64 for c in cpus}
        if not pcs <= set(WEDGE_PCS):
            return False, "PCs %s" % ", ".join("%#x" % p for p in sorted(pcs))
        locks = {c.get("X01") for c in cpus}
        if len(locks) != 1:
            return False, "all vCPUs in __cmpwait but on different lock words"
        return True, "all 8 vCPUs spinning in __cmpwait on %#x" % locks.pop()

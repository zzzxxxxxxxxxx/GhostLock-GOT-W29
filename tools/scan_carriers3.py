#!/usr/bin/env python3
"""scan_carriers3: refine scan_getuser to syscall-reachable functions only.

For every __arm64_sys_* we BFS the direct call graph (same loader as
scan_carriers2), then for each reachable function containing str/stp to
[sp+0x100..0x280], check whether the stored register's value can be traced
back to an LDR from a register that was an ARGUMENT (x0-x5) of the function
(aka 'user pointer -> loaded value -> deep stack slot').  Reports (fn, site,
imm, loaded-from-arg-reg) so a human can verify.
"""
import struct, sys, bisect
from collections import deque, defaultdict

ELF = sys.argv[1] if len(sys.argv) > 1 else "firmware/unpacked_boot/kernel.elf"
SYMTAB = sys.argv[2] if len(sys.argv) > 2 else "firmware/symtab.txt"

SECTIONS = [
    (".kernel",  0xffffff8008080000, 0x240,    0x2eda198),
    (".kernel2", 0xffffff800b3047a8, 0x2eda3d8, 0x44a868),
]
data = open(ELF, "rb").read()
def u32_at(o): return struct.unpack("<I", data[o:o+4])[0]
def sext(v, bits):
    if v & (1 << (bits-1)): v -= (1 << bits)
    return v

funcs = {}; by_name = {}
for line in open(SYMTAB):
    p = line.split()
    if len(p) >= 7 and ":" in p[0]:
        try: a = int(p[1], 16)
        except ValueError: continue
        funcs[a] = p[-1]; by_name.setdefault(p[-1], a)
func_addrs = sorted(funcs.keys())
def func_containing(a):
    i = bisect.bisect_right(func_addrs, a) - 1
    return func_addrs[i] if i >= 0 else None
def off_of(a):
    for (_n, v, f, s) in SECTIONS:
        if v <= a < v+s: return f + (a - v)
    return None

# ---- all bl edges ------------------------------------------------
bl_edges = {}
for (_n, vbase, foff, fsize) in SECTIONS:
    o, v, end = foff, vbase, foff + fsize
    while o + 4 <= end:
        x = u32_at(o)
        if (x & 0xFC000000) == 0x94000000:
            src = func_containing(v + (o - foff))
            tgt = v + (o - foff) + (sext(x & 0x03FFFFFF, 26) << 2)
            if src is not None and func_containing(tgt) is not None:
                bl_edges.setdefault(src, set()).add(func_containing(tgt))
        o += 4

syscall_addrs = [a for a in funcs if funcs[a].startswith("__arm64_sys_")]
entry_depth = {}
for ea in syscall_addrs:
    dq = deque(); dq.append((ea, 0)); seen = {}
    while dq:
        f, d = dq.popleft()
        if f in seen: continue
        seen[f] = d
        dmin, dmax = entry_depth.get(f, (10**9, -1))
        entry_depth[f] = (min(dmin, d), max(dmax, d))
        for c in bl_edges.get(f, ()):
            dq.append((c, d))
print(f"syscall-reachable functions: {len(entry_depth)}")

# ---- frame size ---------------------------------------------------
frame_cache = {}
def frame_size(fa):
    if fa in frame_cache: return frame_cache[fa]
    o = off_of(fa)
    if o is None: frame_cache[fa] = 0; return 0
    sp = 0; a = fa
    for _ in range(64):
        x = u32_at(o)
        if (x & 0xFFC00000) in (0xA9800000, 0xA9C00000):
            sp += abs(sext((x >> 15) & 0x3F, 6) * 8)
        elif (x & 0xFF000000) == 0xD1000000 and (x & 0x1F) == 0x1F and ((x >> 5) & 0x1F) == 0x1F:
            imm = (x >> 10) & 0xFFF
            if (x >> 22) & 1: imm <<= 12
            sp += imm
        elif (x & 0xFF000000) == 0x91000000 and (x & 0x1F) == 0x1F and ((x >> 5) & 0x1F) == 0x1F:
            break
        elif (x & 0xFFFFFC00) == 0xD65F0000:
            break
        a += 4; o += 4
        if (x & 0xFFFFFC00) == 0xD65F0000: break
    frame_cache[fa] = sp
    return sp

# ---- per reachable function: track reg->sp store provenance -------
# tiny interpreter: for each instruction, update roff[reg] = (srcbase, offset)
# where srcbase is an ARG reg tag ('A0'..'A7') if value comes from an arg,
# None otherwise.  Record sites where a STORE to [sp+imm] uses a value with
# A-tag provenance... then also record where an LDR from an A-tag'ed register
# happened (i.e., '*user_ptr' read).  Two independent facts:
#   1) store to sp+0x100..0x280 of value loaded from arg-reg (user pointer follow)
sites = []
for fa in (f for f in entry_depth if (e := frame_size(f)) >= 0x100):
    o = off_of(fa)
    if o is None: continue
    roff = [None]*32
    for i in range(32): roff[i] = ('A', i) if i < 7 else None   # arg regs
    a = fa
    for _ in range(6000):
        x = u32_at(o)
        # ldr xN,[xM,#imm]  (64/32/16/8, incl. ldrb ldrh)
        if (x & 0x3F000000) == 0x20000000 or True:
            pass
        ins_ldr = ((x & 0xFF000000) in (0xF9400000, 0xF9000000) or
                   (x & 0xFF000000) in (0xB9400000, 0xB9000000) or
                   (x & 0xFF000000) in (0x79400000, 0x79000000) or
                   (x & 0xFF000000) in (0x39400000, 0x39000000))
        if ins_ldr:
            rd = x & 0x1F; rn = (x >> 5) & 0x1F
            if rn != 0x1F:
                roff[rd] = roff[rn]    # keep tag of source pointer expr
            else:
                roff[rd] = None
            a += 4; o += 4; continue
        # str xN,[sp,#imm]
        if (x & 0xFBC00000) == 0xF9000000 and ((x >> 5) & 0x1F) == 0x1F:
            imm = ((x >> 10) & 0xFFF) * 8
            rt = x & 0x1F
            if roff[rt] is not None and 0x100 <= imm <= 0x280:
                sites.append((fa, a, rt, imm, roff[rt]))
            a += 4; o += 4; continue
        if (x & 0xFBC00000) == 0xA9000000 and ((x >> 5) & 0x3F) == 0x1F:
            imm = ((x >> 10) & 0x3F) * 8
            rt = x & 0x1F
            if roff[rt] is not None and 0x100 <= imm <= 0x280:
                sites.append((fa, a, rt, imm, roff[rt]))
            a += 4; o += 4; continue
        # mov/add copies and non-live regs
        if (x & 0xFF000000) == 0xAA000000:  # mov xN,xM
            rm = (x >> 16) & 0x1F; rd = x & 0x1F
            roff[rd] = roff[rm]
        elif (x & 0xFF000000) == 0x91000000:
            rd = x & 0x1F; rn = (x >> 5) & 0x1F
            roff[rd] = roff[rn]
        else:
            # bl/b.ret clobber caller regs (x0-x18); stay conservative
            if (x & 0xFC000000) == 0x94000000 or (x & 0xFFFFFC00) == 0xD65F0000:
                for r in range(19):
                    if r >= 7: roff[r] = None
                if (x & 0xFFFFFC00) == 0xD65F0000:
                    break
        a += 4; o += 4
        if (x & 0xFFFFFC00) == 0xD65F0000: break

print(f"arg-provenance stores to [sp+0x100..0x280]: {len(sites)}")
grouped = defaultdict(list)
for (fa, a, rt, imm, prov) in sites:
    grouped[fa].append((a, rt, imm, prov))
for fa in sorted(grouped, key=lambda f: len(grouped[f]), reverse=True)[:25]:
    nm = funcs.get(fa, fa)
    ed = entry_depth.get(fa, (0, 0))
    print(f"{nm:36s} {fa:#x} depth={ed} sites={len(grouped[fa])}")
    for (a, rt, imm, prov) in grouped[fa][:6]:
        print(f"    0x{a:x} x{rt} -> sp+0x{imm:x} src={prov}")

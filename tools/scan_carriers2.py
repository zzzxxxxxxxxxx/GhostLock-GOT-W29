#!/usr/bin/env python3
"""Fast whole-kernel scan for copy-to-stack carriers that can reach E-0x1b0.

For every __arm64_sys_* entry we follow the static call graph (direct bl) and
compute the stack depth (below the syscall-entry SP E) of every user-copy
destination buffer.  A usable carrier must have a user-controlled buffer whose
range covers E-0x1b0 (the futex rt_waiter, sizeof 0x58):

    dest_start <= E-0x1b0 <= dest_start + len

Depth model (ARM64 -O2, frame fully allocated at prologue):
    entry_depth(f) = sum of frame(g) for every g on the path from the syscall
                     entry down to f's CALLER
    a local at 'add xN, sp, #imm' inside f is at depth
        entry_depth(f) + frame(f) - imm
"""
import struct, sys, bisect
from array import array
from collections import deque

ELF = sys.argv[1] if len(sys.argv) > 1 else "firmware/unpacked_boot/kernel.elf"
SYMTAB = sys.argv[2] if len(sys.argv) > 2 else "firmware/symtab.txt"
RT_WAITER = 0x1b0
WAITER_SZ = 0x58

SECTIONS = [
    (".kernel",  0xffffff8008080000, 0x240,   0x2eda198),
    (".kernel2", 0xffffff800b3047a8, 0x2eda3d8, 0x44a868),
]

def u32_at(o): return struct.unpack("<I", data[o:o+4])[0]
def sext(v, bits):
    if v & (1 << (bits-1)): v -= (1 << bits)
    return v

data = open(ELF, "rb").read()

# ---- symbols -----------------------------------------------------------
funcs = {}; syms = {}; by_name = {}
for line in open(SYMTAB):
    p = line.split()
    if len(p) >= 7 and ":" in p[0]:
        try: a = int(p[1], 16)
        except ValueError: continue
        name = p[-1]; syms[a] = name; by_name.setdefault(name, a)
        if p[3] == "FUNC": funcs[a] = name

TEXT_LO = SECTIONS[0][1]; TEXT_HI = SECTIONS[0][1] + SECTIONS[0][3]
TEXT2_LO = SECTIONS[1][1]; TEXT2_HI = SECTIONS[1][1] + SECTIONS[1][3]
func_addrs = sorted(funcs.keys())
def func_containing(a):
    i = bisect.bisect_right(func_addrs, a) - 1
    return func_addrs[i] if i >= 0 else None

# ---- load text sections as uint32 arrays ------------------------------
def load_words():
    va = array("Q"); ins = array("I")
    for (_n, vaddr, foff, size) in SECTIONS:
        raw = data[foff:foff+size]
        w = array("I"); w.frombytes(raw)
        addr = array("Q", [vaddr + i*4 for i in range(len(w))])
        va.extend(addr); ins.extend(w)
    return va, ins

va, ins = load_words()
N = len(va)
print(f"[*] text words: {N}")

# ---- copy helper addresses ---------------------------------------------
copy_helpers = {}
for n in ["__arch_copy_from_user","_copy_from_user","__copy_from_user","copy_from_user"]:
    if n in by_name: copy_helpers[by_name[n]] = "copy"
iov_helpers = {}
for n, reg in [("import_iovec",4),("import_single_range",2)]:
    if n in by_name: iov_helpers[by_name[n]] = reg
all_helpers = set(copy_helpers) | set(iov_helpers)

# ---- one pass: find copy sites + bl edges -----------------------------
# forward[func] = set of callees; copysite[func] appended (site, helper)
forward = {}
copysite = {}
bl_count = 0
for i in range(N):
    v = va[i]; x = ins[i]
    if (x & 0xFC000000) != 0x94000000:
        continue
    bl_count += 1
    t = v + (sext(x & 0x03FFFFFF, 26) << 2)
    fa = func_containing(v)
    if fa is None:
        continue
    if t in all_helpers:
        copysite.setdefault(fa, []).append((v, t))
    # only record edges into functions (in text) to bound graph size
    if func_containing(t) is not None:
        forward.setdefault(fa, set()).add(t)

print(f"[*] bl instructions: {bl_count}, functions with edges: {len(forward)}, "
      f"copy-caller functions: {len(copysite)}")
del va, ins

# ---- frame size (prologue decode, memoized) ---------------------------
def off_of(a):
    for (_n, v, f, s) in SECTIONS:
        if v <= a < v+s: return f + (a - v)
    return None

frame_cache = {}
def frame_size(fa):
    if fa in frame_cache: return frame_cache[fa]
    o = off_of(fa)
    if o is None: frame_cache[fa]=0; return 0
    sp = 0; a = fa
    for _ in range(64):
        x = u32_at(o)
        if (x & 0xFFC00000) in (0xA9800000, 0xA9C00000):
            sp += abs(sext((x>>15)&0x3F,6)*8)
        elif (x & 0xFF000000)==0xD1000000 and (x&0x1F)==0x1F and ((x>>5)&0x1F)==0x1F:
            imm=(x>>10)&0xFFF
            if (x>>22)&1: imm<<=12
            sp+=imm
        elif (x & 0xFF000000)==0x91000000 and (x&0x1F)==0x1F and ((x>>5)&0x1F)==0x1F:
            break
        elif (x & 0xFFFFFC00)==0xD65F0000:
            break
        a+=4; o+=4
        if (x & 0xFFFFFC00)==0xD65F0000: break
    frame_cache[fa]=sp
    return sp

# ---- BFS entry_depth from syscall entries -----------------------------
syscall_addrs = [a for a in funcs if funcs[a].startswith("__arm64_sys_")]
entry_depth = {}   # func -> (min_depth, max_depth)
for ea in syscall_addrs:
    dq = deque(); dq.append((ea, 0))
    seen = {}
    while dq:
        f, d = dq.popleft()
        if f in seen: continue
        seen[f] = d
        dmin, dmax = entry_depth.get(f, (10**9, -1))
        entry_depth[f] = (min(dmin, d), max(dmax, d))
        nd = d + frame_size(f)
        for c in forward.get(f, ()):
            dq.append((c, nd))

print(f"[*] syscall-reachable functions: {len(entry_depth)}")

# ---- track dest sp-offset in a copy caller up to the bl ---------------
def track_dest_off(fa, site_vaddr):
    o = off_of(fa)
    if o is None: return None
    roff = {}
    a = fa
    for _ in range(3000):
        if a == site_vaddr:
            x = u32_at(o)
            t = a + (sext(x & 0x03FFFFFF,26)<<2)
            reg = 0 if t in copy_helpers else iov_helpers.get(t)
            if reg is None: return None
            return roff.get(reg)
        x = u32_at(o)
        # Detect a bl BEFORE treating the instruction as normal.  We must not
        # let caller-saved regs (x0-x18) keep stale sp provenance across a
        # non-copy call (they are clobbered).  x19-x28 are callee-saved.
        if (x & 0xFC000000) == 0x94000000:
            t = a + (sext(x & 0x03FFFFFF,26)<<2)
            if t not in (set(copy_helpers) | set(iov_helpers)):
                for r in range(19):
                    roff[r] = None
            a += 4; o += 4
            continue
        if (x & 0x1F000000) == 0x10000000:
            roff[x & 0x1F] = None            # adrp breaks sp provenance
        elif (x & 0xFF000000)==0x91000000:    # add xd, xn, #imm
            rd=x&0x1F; rn=(x>>5)&0x1F
            imm=(x>>10)&0xFFF
            if (x>>22)&1: imm<<=12
            base = 0 if rn==0x1F else roff.get(rn)
            roff[rd] = (base+imm) if base is not None else None
        elif (x & 0xFF000000)==0x8B000000 and ((x>>22)&0x3)==0:   # add xd, xn, xm
            rd=x&0x1F; rn=(x>>5)&0x1F
            base = 0 if rn==0x1F else roff.get(rn)
            roff[rd]=base
        elif (x & 0xFF000000)==0xAA000000:    # ORR/ADD(variable) logical -> mov if rn==31
            rd=x&0x1F; rn=(x>>5)&0x1F; rm=(x>>16)&0x1F
            if rn==0x1F:                       # ORR rd, xzr, rm  == mov rd, rm
                roff[rd]=roff.get(rm)
            elif (x>>21)&0x1 == 0:             # ORR rd, rn, rm -> rn break (unknown)
                roff[rd]=roff.get(rn)
            else:
                roff[rd]=None
        a+=4; o+=4
        if (x & 0xFFFFFC00)==0xD65F0000: break
    return None

rows = []
for fa, sitelist in copysite.items():
    if fa not in entry_depth: continue
    fr = frame_size(fa)
    for (site, t) in sitelist:
        doff = track_dest_off(fa, site)
        if doff is None: continue
        dmin, dmax = entry_depth[fa]
        for ed in sorted({dmin, dmax}):
            depth = ed + fr - doff
            kind = "copy" if t in copy_helpers else ("iov4" if t == by_name.get("import_iovec") else "iov2")
            rows.append((depth, site, funcs.get(fa, "?"), kind, doff, fr, ed))

rows.sort(key=lambda r: abs(r[0]-RT_WAITER))
print(f"\n== syscall-reachable copy-to-stack sites (target E-{RT_WAITER:#x}) ==")
for (depth, site, fn, kind, doff, fr, ed) in rows:
    flag = ""
    if depth <= RT_WAITER <= depth + 0x200:
        flag = "   <== may cover target"
    print(f"depth={depth:#07x} site={site:#x} into={fn:30s} kind={kind:4s} "
          f"dest_off={doff:#x} frame={fr:#x} entry_depth={ed:#x}{flag}")

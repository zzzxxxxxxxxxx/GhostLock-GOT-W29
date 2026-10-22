#!/usr/bin/env python3
"""scan_carriers -- copy-to-stack carrier scan.

Replaces the earlier scan_carriers2/3 attempts.  Fixes / additions:

  * coverage predicate: scan2 tested `depth <= 0x1b0 <= depth + 0x200` and
    threw away the copy length.  For a buffer that starts at depth D (below
    the syscall-entry SP E) and is L bytes long, it covers the futex
    rt_waiter [E-0x1b0, E-0x158) iff
        0x1b0 <= D <= 0x158 + L
  * records L from the x2 constant at the copy call and reports how many
    target bytes are covered
  * roots: __arm64_sys_* AND __arm64_compat_sys_* (compat was never scanned)
  * indirect dispatch edges (sock->ops->setsockopt and friends) are added as
    explicit edges; more can be added with --edge FROM TO
  * frame decoder: proper 7-bit imm7, LDP/STP pre/post writeback, SUB sp imm,
    STR xN,[sp,#-imm]! ; unknown SP update -> frame unknown (skipped)
  * dest/len tracker: clears caller-saved provenance on every call (bl and
    blr), clears provenance on any unrecognised write to x0/x1/x2

Depth model (same as scan2):
    entry_depth(f) = sum of frame sizes on the path from a syscall entry
                     down to f's entry point
    a local at `add xN, sp, #imm` inside f sits at depth
        entry_depth(f) + frame(f) - imm

Usage:
    scan_carriers.py [ELF] [SYMTAB] [--edge FROM TO]...
"""
import struct, sys, bisect
from array import array
from collections import deque, defaultdict

_argv = sys.argv[1:]
_extra = []
_dump = []
_pos = []
i = 0
while i < len(_argv):
    if _argv[i] == "--edge" and i + 2 < len(_argv):
        _extra.append((_argv[i + 1], _argv[i + 2])); i += 3
    elif _argv[i] == "--dump" and i + 1 < len(_argv):
        _dump.append(_argv[i + 1]); i += 2
    else:
        _pos.append(_argv[i]); i += 1

ELF = _pos[0] if len(_pos) > 0 else "firmware/unpacked_boot/kernel.elf"
SYMTAB = _pos[1] if len(_pos) > 1 else "firmware/symtab.txt"

RT_BOT = 0x1b0          # rt_waiter base (deepest byte)
RT_TOP = 0x158          # rt_waiter end (exclusive)
WAITER_SZ = 0x58

SECTIONS = [
    (".kernel",  0xffffff8008080000, 0x240,   0x2eda198),
    (".kernel2", 0xffffff800b3047a8, 0x2eda3d8, 0x44a868),
]

data = open(ELF, "rb").read()


def u32_at(o):
    return struct.unpack("<I", data[o:o + 4])[0]


def sext(v, bits):
    if v & (1 << (bits - 1)):
        v -= (1 << bits)
    return v


# ---- symbols ----------------------------------------------------------
funcs = {}
by_name = {}
for line in open(SYMTAB):
    p = line.split()
    if len(p) >= 7 and ":" in p[0]:
        try:
            a = int(p[1], 16)
        except ValueError:
            continue
        by_name.setdefault(p[-1], a)
        if p[3] == "FUNC":
            funcs[a] = p[-1]

func_addrs = sorted(funcs)


def func_containing(a):
    k = bisect.bisect_right(func_addrs, a) - 1
    return func_addrs[k] if k >= 0 else None


def off_of(a):
    for (_n, v, f, s) in SECTIONS:
        if v <= a < v + s:
            return f + (a - v)
    return None


# ---- text as words ----------------------------------------------------
def load_words():
    va = array("Q"); ins = array("I")
    for (_n, vaddr, foff, size) in SECTIONS:
        w = array("I"); w.frombytes(data[foff:foff + size])
        va.extend(array("Q", [vaddr + k * 4 for k in range(len(w))]))
        ins.extend(w)
    return va, ins


va, ins = load_words()
N = len(va)

copy_helpers = {}
for n in ["__arch_copy_from_user", "_copy_from_user", "__copy_from_user", "copy_from_user"]:
    if n in by_name:
        copy_helpers[by_name[n]] = n
all_helpers = set(copy_helpers)

forward = defaultdict(set)
copysite = defaultdict(list)
bl_count = 0
for k in range(N):
    v = va[k]; x = ins[k]
    if (x & 0xFC000000) != 0x94000000:
        continue
    bl_count += 1
    t = v + (sext(x & 0x03FFFFFF, 26) << 2)
    fa = func_containing(v)
    if fa is None:
        continue
    if t in all_helpers:
        copysite[fa].append((v, t))
    if func_containing(t) is not None:
        forward[fa].add(t)

print(f"[*] text words={N} bl={bl_count} copy-callers={len(copysite)}")

# ---- indirect dispatch edges -----------------------------------------
# QEMU-verified two-hop model: the syscall wrapper calls the proto_ops entry
# (sock_common_setsockopt, frame 0x10), which calls sk_prot->setsockopt
# (udp/tcp/raw/ping).  Mapping the syscall straight to udp_setsockopt skips a
# 0x10 frame and shifts the computed destination depth (was D=0x200, real
# D=0x210 for MCAST_BLOCK_SOURCE).
INDIRECT = {
    "__arm64_sys_setsockopt": [
        "sock_common_setsockopt",
    ],
    "sock_common_setsockopt": [
        "udp_setsockopt", "tcp_setsockopt", "raw_setsockopt",
        "ping_setsockopt",
    ],
    "__arm64_compat_sys_setsockopt": [
        "compat_sock_common_setsockopt",
    ],
    "compat_sock_common_setsockopt": [
        "compat_udp_setsockopt", "compat_tcp_setsockopt",
        "compat_raw_setsockopt",
    ],
}
added = []
for frm, tos in INDIRECT.items():
    if frm not in by_name:
        continue
    for to in tos:
        if to in by_name:
            forward[by_name[frm]].add(by_name[to])
            added.append(f"{frm} -~> {to}")
for frm, to in _extra:
    if frm in by_name and to in by_name:
        forward[by_name[frm]].add(by_name[to])
        added.append(f"{frm} -~> {to}")
print(f"[*] indirect edges added: {len(added)}")
for e in added:
    print(f"      {e}")

# ---- frame size -------------------------------------------------------
frame_cache = {}


def frame_size(fa):
    if fa in frame_cache:
        return frame_cache[fa]
    o = off_of(fa)
    if o is None:
        frame_cache[fa] = 0
        return 0
    # Track the MAXIMUM stack depth reached, not the value at the end of the
    # function: epilogues restore SP (ldp/stp post-index or add sp,sp,#imm)
    # and a naive running value nets back to 0 for many leaf-ish functions.
    sp = 0
    mx = 0
    for _ in range(80):
        x = u32_at(o)
        m = x & 0xFFC00000
        delta = None
        if m in (0xA9800000, 0xA9C00000, 0x29800000, 0x29C00000):     # ldp/stp pre
            delta = -sext((x >> 15) & 0x7F, 7) * 8
        elif m in (0xA8800000, 0xA8C00000, 0x28800000, 0x28C00000):   # ldp/stp post
            delta = -sext((x >> 15) & 0x7F, 7) * 8
        elif (x & 0xFF800000) == 0xD1000000 and (x & 0x1F) == 31 and ((x >> 5) & 0x1F) == 31:
            delta = (x >> 10) & 0xFFF
            if (x >> 22) & 1:
                delta <<= 12
        elif (x & 0xFFE00C00) == 0xF8000C00 and ((x >> 5) & 0x1F) == 31:  # str xt,[sp,#-imm]!
            delta = -sext((x >> 12) & 0x1FF, 9)
        elif (x & 0xFF800000) == 0x91000000 and (x & 0x1F) == 31 and ((x >> 5) & 0x1F) == 31:
            break                                                     # add sp,sp,#imm (restore)
        elif (x & 0xFFFFFC00) == 0xD65F0000:                          # ret
            break
        elif (x & 0x7C000000) == 0x14000000:                          # b (tail path)
            break
        if delta is not None:
            sp += delta
            if sp > mx:
                mx = sp
        o += 4
    frame_cache[fa] = mx
    return frame_cache[fa]


# ---- min/max entry depth ---------------------------------------------
roots = [a for a in funcs
         if (funcs[a].startswith("__arm64_sys_")
             or funcs[a].startswith("__arm64_compat_sys_"))]
depth = {}
visits = defaultdict(int)
q = deque((ea, 0) for ea in roots)
while q:
    f, d = q.popleft()
    if d > 0x8000 or visits[f] > 24:
        continue
    cur = depth.get(f)
    if cur and cur[0] <= d <= cur[1]:
        continue
    depth[f] = (min(cur[0], d), max(cur[1], d)) if cur else (d, d)
    visits[f] += 1
    fr = frame_size(f)
    if fr is None:
        continue
    nd = d + fr
    for c in forward.get(f, ()):
        q.append((c, nd))

print(f"[*] roots={len(roots)} syscall-reachable funcs={len(depth)}")

for _name in _dump:
    _a = by_name.get(_name)
    if _a is None:
        print(f"[dump] {_name}: not found")
        continue
    _fr = frame_size(_a)
    print(f"[dump] {_name} @ {_a:#x} frame="
          + ("?" if _fr is None else f"{_fr:#x}") + f" depth={depth.get(_a)}")
    for _c in sorted(forward.get(_a, ())):
        _cfr = frame_size(_c)
        print(f"        -> {funcs.get(_c, hex(_c)):34s} @ {_c:#x} "
              f"frame=" + ("?" if _cfr is None else f"{_cfr:#x}")
              + f" depth={depth.get(_c)}")


# ---- dest / length tracker -------------------------------------------
def _is_load(x):
    # LDR/LDRB/LDRH/LDRSW (unsigned offset class); L bit = 22
    return (x & 0x3B000000) == 0x39000000 and ((x >> 22) & 1) == 1


def _is_call(x):
    return (x & 0xFC000000) == 0x94000000 or (x & 0xFFFFFC1F) == 0xD63F0000


def _no_gpr_write(x):
    if (x & 0x7C000000) in (0x14000000, 0x10000000, 0x90000000):
        return True                                    # b/bl/adr/adrp (+ lr only)
    if (x & 0x7E000000) == 0x34000000:
        return True                                    # cbz/cbnz
    if (x & 0x7E000000) == 0x36000000:
        return True                                    # tbz/tbnz
    if (x & 0x7C000000) == 0x54000000:
        return True                                    # b.cond
    if (x & 0x3B000000) == 0x28000000:
        return True                                    # stp/str pairs (stores)
    if (x & 0x3B000000) == 0x39000000 and ((x >> 22) & 1) == 0:
        return True                                    # str (stores)
    if (x & 0xFFFFF01F) == 0xD503201F:
        return True                                    # nop/hint/csdb
    if (x & 0xFFFFFC00) == 0xD65F0000:
        return True                                    # ret
    return False


def track(fa, site):
    o = off_of(fa)
    if o is None:
        return None
    soff = [None] * 32          # sp-relative byte offset (address = sp + soff)
    klen = [None] * 32          # constant value
    a = fa
    for _ in range(5000):
        if a == site:
            x = u32_at(o)
            t = a + (sext(x & 0x03FFFFFF, 26) << 2)
            if t in copy_helpers:
                return soff[0], klen[2]
            return None
        x = u32_at(o)

        if _is_call(x):
            for r in range(19):
                soff[r] = None
                klen[r] = None
        elif _is_load(x):
            rd = x & 0x1F
            soff[rd] = None
            klen[rd] = None
        elif (x & 0xFF800000) == 0x91000000:           # add xd, xn, #imm
            rd = x & 0x1F; rn = (x >> 5) & 0x1F
            imm = (x >> 10) & 0xFFF
            if (x >> 22) & 1:
                imm <<= 12
            base = 0 if rn == 31 else soff[rn]
            soff[rd] = (base + imm) if base is not None else None
            klen[rd] = None
        elif (x & 0x7F800000) in (0x52800000, 0xD2800000):   # movz
            rd = x & 0x1F
            klen[rd] = ((x >> 5) & 0xFFFF) << (((x >> 21) & 3) * 16)
            soff[rd] = None
        elif (x & 0x7F800000) in (0x12800000, 0x92800000):   # movn
            rd = x & 0x1F
            klen[rd] = (~(((x >> 5) & 0xFFFF) << (((x >> 21) & 3) * 16))) & 0xFFFFFFFFFFFFFFFF
            soff[rd] = None
        elif (x & 0x7F800000) in (0x72800000, 0xF2800000):   # movk
            rd = x & 0x1F
            if klen[rd] is not None:
                sh = ((x >> 21) & 3) * 16
                klen[rd] = (klen[rd] & ~(0xFFFF << sh)) | (((x >> 5) & 0xFFFF) << sh)
            soff[rd] = None
        elif (x & 0xFF000000) == 0xAA000000:           # orr rd, rn, rm == mov
            rn = (x >> 5) & 0x1F; rm = (x >> 16) & 0x1F; rd = x & 0x1F
            if rn == 31:
                soff[rd] = soff[rm]; klen[rd] = klen[rm]
            else:
                soff[rd] = soff[rn] if rn <= 2 else None
                klen[rd] = None
        elif not _no_gpr_write(x):
            rd = x & 0x1F
            if rd <= 2:
                soff[rd] = None
                klen[rd] = None
        a += 4; o += 4
        if (x & 0xFFFFFC00) == 0xD65F0000:
            break
    return None


# ---- evaluate ---------------------------------------------------------
rows = []
for fa, sites in copysite.items():
    if fa not in depth:
        continue
    fr = frame_size(fa)
    if fr is None:
        continue
    for (site, t) in sites:
        r = track(fa, site)
        if r is None or r[0] is None:
            continue
        doff, ln = r
        for ed in sorted(set(depth[fa])):
            D = ed + fr - doff
            cover = 0
            if ln is not None:
                cover = max(0, min(D, RT_BOT) - max(D - ln, RT_TOP))
            rows.append({
                "depth": D, "len": ln, "cover": cover, "func": funcs.get(fa, "?"),
                "site": site, "off": doff, "frame": fr, "ed": ed,
                "kind": copy_helpers[t],
            })

rows.sort(key=lambda r: (0 if r["cover"] >= WAITER_SZ else (1 if r["cover"] else 2),
                         abs(r["depth"] - RT_BOT)))
print(f"\n== copy-to-stack sites (buffer must cover [E-{RT_BOT:#x}, E-{RT_TOP:#x})) ==")
print(f"{'depth':>7} {'len':>6} {'cover':>6}  {'function':34s} helper")
shown = 0
for r in rows:
    if shown >= 80:
        break
    shown += 1
    ln = "-" if r["len"] is None else f"{r['len']:#x}"
    if r["cover"] >= WAITER_SZ:
        flag = " FULL"
    elif r["cover"]:
        flag = " part"
    else:
        flag = ""
    print(f"{r['depth']:#07x} {ln:>6} {r['cover']:#06x}  {r['func']:34s} "
          f"{r['kind']} site={r['site']:#x} off={r['off']:#x} "
          f"frame={r['frame']:#x} ed={r['ed']:#x}{flag}")

full = [r for r in rows if r["cover"] >= WAITER_SZ]
part = [r for r in rows if 0 < r["cover"] < WAITER_SZ]
print(f"\n[*] total rows={len(rows)}  full-cover rows={len(full)}  partial={len(part)}")

import struct
import sys

# usage: scan_branches.py <boot.elf>
if len(sys.argv) < 2:
    print(f"usage: {sys.argv[0]} <boot.elf>", file=sys.stderr)
    sys.exit(1)
path = sys.argv[1]

# sections: (name, vaddr, fileoff, size)
secs = [
    (".kernel", 0xffffff8008080000, 0x240, 0x2eda198),
    (".kernel2", 0xffffff800b3047a8, 0x2eda3d8, 0x44a868),
]

data = open(path, "rb").read()

targets = {
    0xffffff80080bdeb0: "__put_task_struct",
    0xffffff800810c890: "sched_move_task",
    0xffffff80080c60c0: "delayed_put_task_struct",
}

def pc_to_inst(pc):
    for name, vaddr, foff, size in secs:
        if vaddr <= pc < vaddr + size:
            off = foff + (pc - vaddr)
            if off + 4 <= len(data):
                return struct.unpack("<I", data[off:off+4])[0], name
    return None, None

found = {}
for name, vaddr, foff, size in secs:
    for i in range(0, size, 4):
        pc = vaddr + i
        inst = struct.unpack("<I", data[foff+i:foff+i+4])[0]
        op = (inst >> 26) & 0x3F
        if op == 0x25:  # BL
            imm = inst & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            target = pc + (imm << 2)
            if target in targets:
                found.setdefault(targets[target], []).append(pc)
        elif op == 0x05:  # B
            imm = inst & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            target = pc + (imm << 2)
            if target in targets:
                found.setdefault(targets[target], []).append(pc)

for tname, pcs in found.items():
    print(f"=== references to {tname} ===")
    for pc in pcs:
        print(f"  {pc:#x}")

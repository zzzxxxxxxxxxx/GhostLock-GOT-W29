#!/usr/bin/env python3
"""Search a QEMU guest RAM dump (QMP pmemsave) offline for the kernel boot log
and exploit markers.

Usage: qemu_read_ram.py [ram_file]

Prefer tools/qemu-test/read_log.py for live reads (it chases the `log_buf`
pointer and reads physical memory directly).  This script is for offline dumps
of the whole 2GB image, e.g. captured with:
  qmp-shell -c 'pmemsave val=0x40000000 size=0x80000000 filename=/tmp/guest_ram.bin'
"""
import re
import sys

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else '/tmp/guest_ram.bin'
    data = open(path, 'rb').read()

    # --- locate log_buf ---
    i = data.find(b'Booting Linux on physical CPU 0x00000000')
    if i >= 0:
        seg = data[i:i + 500000]
        lines = [m.group().decode(errors='replace')
                 for m in re.finditer(rb'[ -~]{8,}', seg)]
        print(f'=== log_buf at 0x{i:x}, {len(lines)} lines ===')

        # Print key events
        for idx, l in enumerate(lines):
            if any(k in l for k in ('panic', 'Run /init', 'Freeing unused',
                                    'Kernel Offset', 'Unable to handle',
                                    'blacklist')):
                print(f'  [{idx:4d}] {l[:130]}')
        print(f'--- last {min(20,len(lines))} lines ---')
        for l in lines[-20:]:
            print(f'  {l[:130]}')
    else:
        print('log_buf not found (kernel may not have booted yet)')

    # --- exploit markers (current CLI / wrapper) ---
    print('\n=== exploit markers ===')
    for pat in [b'init: ghostlock_exe[', b'perf-kaslr base=', b'KASLR OK',
                b'slide ', b'bench:', b'root: ', b'glsh-proof',
                b'boot_id raw=', b'Internal error', b'PASSED', b'FAILED']:
        ms = [m.start() for m in re.finditer(re.escape(pat), data)][:4]
        status = ', '.join(hex(x) for x in ms) if ms else 'NOT FOUND'
        print(f'  {pat.decode():28s} {status}')
        if ms and pat in (b'init: ghostlock_exe[', b'perf-kaslr base='):
            j = ms[0]
            print(f'    -> {data[max(0,j-40):j+80]}')

    # --- boot_id values ---
    print('\n=== boot_id candidates ===')
    ids = set()
    for m in re.finditer(
            rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            data):
        ids.add(m.group().decode())
    for bid in sorted(ids):
        cnt = data.count(bid.encode())
        print(f'  {bid} ({cnt} occurrences)')

if __name__ == '__main__':
    main()

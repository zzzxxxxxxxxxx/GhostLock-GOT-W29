/* sc_kpm_load - minimal supercall KPM_LOAD tester for GOT-W29/FolkPatch.
 *
 * usage: sc_kpm_load [key] [kpm_path] [args]
 *   default key: KernelPatch, path: /sdcard/Download/rtmutex-dbg.kpm
 *
 * Mirrors apd's ver_and_cmd packaging (KernelPatch supercall ABI).
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define __NR_supercall 45 /* arm64: __NR3264_truncate */

#define SUPERCALL_KPM_LOAD 0x1020
#define SUPERCALL_KPM_UNLOAD 0x1021
#define SUPERCALL_KPM_NUMS 0x1030
#define SUPERCALL_KPM_LIST 0x1031

#define MAJOR 0
#define MINOR 13
#define PATCH 5

static long ver_and_cmd(const char *key, long cmd)
{
    uint32_t version_code = (MAJOR << 16) + (MINOR << 8) + PATCH;
    return ((long)version_code << 32) | (0x1158L << 16) | (cmd & 0xFFFF);
}

int main(int argc, char **argv)
{
    const char *key = argc > 1 ? argv[1] : "KernelPatch";
    const char *path = argc > 2 ? argv[2] : "/sdcard/Download/rtmutex-dbg.kpm";
    const char *args = argc > 3 ? argv[3] : "";
    long rc;

    if (argc >= 2 && strcmp(argv[1], "unload") == 0) {
        const char *name = argc > 2 ? argv[2] : "rtmutex-dbg";
        key = argc > 3 ? argv[3] : "su";
        rc = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_KPM_UNLOAD),
                     name, 0);
        printf("unload(%s) rc=%ld\n", name, rc);
        return 0;
    }

    /* 1. probe: KPM_NUMS works without any module */
    rc = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_KPM_NUMS));
    printf("nums(key=%s) rc=%ld\n", key, rc);

    /* 2. load */
    rc = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_KPM_LOAD),
                 path, args, 0);
    printf("load(path=%s) rc=%ld\n", path, rc);

    /* 3. list modules */
    {
        char buf[4096] = {0};
        rc = syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_KPM_LIST),
                     buf, sizeof(buf));
        printf("list rc=%ld buf=[%.200s]\n", rc, buf);
    }
    return 0;
}

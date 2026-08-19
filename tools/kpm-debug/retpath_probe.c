/* retpath_probe - low-risk probe: compare do_notify_resume() trigger rate
 * across fast select() vs ppoll() return paths.
 *
 * usage: retpath_probe [select|ppoll] [count]
 * The KPM ctl "notify" counter delta across the run tells whether the
 * return path stays clean (fewer do_notify_resume calls).  If ppoll's
 * pollfd array sits at a stack depth the return-path frame does not reach,
 * it may be a better overlay carrier than select/pselect.
 */
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "select";
    int n = argc > 2 ? atoi(argv[2]) : 200;
    int p[2];
    if (pipe(p) != 0)
        return 1;
    (void)write(p[1], "x", 1);

    for (int i = 0; i < n; i++) {
        volatile double fp = 1.0;
        fp = fp * 3.141592653589793 + 0.577215664901532;
        (void)fp;               /* force FPU use -> clear FOREIGN_FPSTATE */
        (void)syscall(SYS_sched_yield); /* consume pending NEED_RESCHED */

        if (strcmp(mode, "ppoll") == 0) {
            struct pollfd pf = {.fd = p[0], .events = POLLIN};
            (void)syscall(SYS_ppoll, &pf, 1, NULL, NULL, 8);
        } else {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(p[0], &rfds);
            struct timeval tv = {0, 0};
            (void)select(p[0] + 1, &rfds, NULL, NULL, &tv);
        }
    }
    return 0;
}

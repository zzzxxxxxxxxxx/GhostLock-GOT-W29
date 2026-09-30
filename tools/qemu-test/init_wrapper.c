/* QEMU /init wrapper: prepare /proc + stdio + log dir, then run the exploit's
 * --verify-all self test on kernel.patched (nokaslr, --probe-cycle):
 * pointer write, leaf zero write, read primitive (boot_id ctl_table redirect)
 * + restore.
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

  pid_t pid = fork();
  if (pid == 0) {
    char *argv[] = {
      "/ghostlock_exe", "--probe-cycle", "--verify-all",
      "--attempts", "1", "--kaslr-base", "0xffffff8008080800",
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
  for (;;) {
    pause(); /* keep PID 1 alive: its exit would panic the kernel */
  }
}

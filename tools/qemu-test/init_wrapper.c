/* QEMU /init wrapper: prepare /proc + stdio + log dir, then run the exploit's
 * --verify-write self test on kernel.patched (nokaslr, --probe-cycle).
 *
 * The kernel has no console on QEMU (GENI UART), so fds 0/1/2 may be closed;
 * give them /dev/null first, otherwise pipe() steals fd 0/1 and the child's
 * printf output lands in the result pipe.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

int main(void) {
  mkdir("/proc", 0755);
  if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
    perror("mount proc");
  }
  mkdir("/dev", 0755);
  mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3));
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

  char *argv[] = {
    "/ghostlock_exe", "--probe-cycle", "--verify-write",
    "--attempts", "1", "--kaslr-base", "0xffffff8008080800",
    "--log-file", "/data/local/tmp/ghostlock.log",
    NULL
  };
  char *envp[] = { NULL };
  execve(argv[0], argv, envp);
  perror("execve");
  for (;;) pause();
}

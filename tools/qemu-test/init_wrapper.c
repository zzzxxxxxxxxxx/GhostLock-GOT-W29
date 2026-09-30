/* QEMU /init wrapper: prepare /proc + /dev + perf, then run the exploit as
 * uid 2000 (the device shell uid) on kernel.patched (nokaslr,
 * --probe-cycle): perf-leak current task -> point real_cred/cred at
 * init_cred -> getuid()==0, plus optional endgame / self tests.
 *
 * Modes come from /glmode (';'-separated command lines, e.g.
 * "--root; --bench 8"); build_and_run.sh writes it when GLMODE is set.
 * Multiple groups run as separate children in one boot to amortize the slow
 * TCG boot.  Without /glmode the default is the --escalate flow.
 *
 * The kernel has no console on QEMU (GENI UART), so fds 0/1/2 may be closed;
 * give them /dev/null first, otherwise pipe() steals fd 0/1 and the child's
 * printf output lands in the result pipe.
 *
 * The wrapper stays alive as PID 1 forever after the runs: if PID 1 exits
 * (even with status 0) the kernel panics with "Attempted to kill init",
 * which would wipe the log before the harness can read it.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
  mkdir("/data/local/tmp", 0777); /* the exploit runs as uid 2000 */

  /* Device analogue: perf_event_paranoid=-1 lets unprivileged shells use
     perf_event_open (the GOT-W29 device runs with -1 too). */
  int pfd = open("/proc/sys/kernel/perf_event_paranoid", O_WRONLY);
  if (pfd >= 0) {
    (void)!write(pfd, "-1\n", 3);
    close(pfd);
  }
  /* /dev/kmsg logging is ratelimited by default and the exploit logs a lot:
     the final result lines were suppressed in earlier runs
     ("ghostlock_exe: N output lines suppressed due to ratelimiting").
     Note: interval=0 alone did NOT disable it on this Huawei kernel, so raise
     the burst budget as well. */
  const char *rl_files[] = {"/proc/sys/kernel/printk_ratelimit",
                            "/proc/sys/kernel/printk_ratelimit_burst"};
  const char *rl_vals[] = {"0\n", "1000000\n"};
  for (int i = 0; i < 2; i++) {
    int fd = open(rl_files[i], O_WRONLY);
    if (fd >= 0) {
      (void)!write(fd, rl_vals[i], strlen(rl_vals[i]));
      close(fd);
    }
  }

  /* /glmode: up to 4 ';'-separated groups, each up to 7 argv words. */
  static char groups[4][8][32];
  static int gwords[4];
  int ngroups = 0;
  int mf = open("/glmode", O_RDONLY);
  if (mf >= 0) {
    char mbuf[512];
    ssize_t mn = read(mf, mbuf, sizeof(mbuf) - 1);
    close(mf);
    if (mn > 0) {
      mbuf[mn] = 0;
      char *gsave = NULL;
      for (char *g = strtok_r(mbuf, ";\n", &gsave); g && ngroups < 4;
           g = strtok_r(NULL, ";\n", &gsave)) {
        int nt = 0;
        char *tsave = NULL;
        for (char *tok = strtok_r(g, " \t", &tsave); tok && nt < 7;
             tok = strtok_r(NULL, " \t", &tsave)) {
          strncpy(groups[ngroups][nt], tok, sizeof(groups[0][0]) - 1);
          groups[ngroups][nt][sizeof(groups[0][0]) - 1] = 0;
          nt++;
        }
        if (nt > 0) {
          gwords[ngroups] = nt;
          ngroups++;
        }
      }
    }
  }
  if (ngroups == 0) {
    strcpy(groups[0][0], "--escalate");
    gwords[0] = 1;
    ngroups = 1;
  }

  for (int gi = 0; gi < ngroups; gi++) {
    pid_t pid = fork();
    if (pid == 0) {
      /* Drop to the shell uid the exploit expects on the device (uid 2000),
         with AID_INET in the supplementary groups: CONFIG_ANDROID_PARANOID_NETWORK
         refuses AF_INET socket() with EACCES for uids outside the "inet" group
         (the real device shell has gid 3003).  AID_SHELL=2000, AID_INET=3003. */
      gid_t shell_groups[1] = {3003};
      if (setgroups(1, shell_groups) != 0) {
        perror("setgroups");
      }
      if (setgid(2000) != 0 || setuid(2000) != 0) {
        perror("setuid 2000");
      }
      char *argv[20];
      int ai = 0;
      argv[ai++] = "/ghostlock_exe";
      argv[ai++] = "--probe-cycle";
      argv[ai++] = "--no-rt";
      for (int k = 0; k < gwords[gi]; k++) {
        argv[ai++] = groups[gi][k];
      }
      argv[ai++] = "--attempts";
      argv[ai++] = "4";
      argv[ai++] = "--kaslr-base";
      argv[ai++] = "0xffffff8008080800";
      argv[ai++] = "--log-file";
      argv[ai++] = "/dev/kmsg";
      argv[ai] = NULL;
      char *envp[] = { NULL };
      execve(argv[0], argv, envp);
      perror("execve");
      _exit(1);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    /* Independent completion marker (the exploit's own lines can be rate
       limited/lost): exit code 0 == the mode returned success. */
    char msg[128];
    int kn = open("/dev/kmsg", O_WRONLY);
    if (kn >= 0) {
      int m = snprintf(msg, sizeof(msg),
                       "init: ghostlock_exe[%s] exited status=0x%x%s\n",
                       groups[gi][0], status,
                       (WIFEXITED(status) && WEXITSTATUS(status) == 0)
                           ? " (SUCCESS)"
                           : "");
      if (m > 0) {
        (void)!write(kn, msg, (size_t)m);
      }
      close(kn);
    }
  }

  for (;;) {
    pause(); /* keep PID 1 alive: its exit would panic the kernel */
  }
}

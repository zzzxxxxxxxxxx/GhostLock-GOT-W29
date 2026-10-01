/* glsh - the smallest "sh -c CMD" that the QEMU initramfs can carry.
 *
 * The device has /system/bin/sh, so the broker's generic path ("anything that
 * is not STATUS/GLCAP/GLMOUNT/GLUMOUNT goes to the server's shell") cannot be
 * exercised in a QEMU guest without one.  glsh implements just enough of
 * `sh -c CMD` for --su-selftest to drive that path end to end: it is exec'd by
 * the server, inherits the server's credentials, and its stdout is the pipe
 * back to the client -- so `id` answering uid=0 proves the root creds, the exec
 * plumbing and the reply path all work.
 *
 * Build: aarch64-linux-gnu-gcc -static -O2 -o glsh glsh.c
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int cmd_cat(char *path) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    printf("cat: %s: %s\n", path, strerror(errno));
    return 1;
  }
  char buf[4096];
  ssize_t n;
  while ((n = read(fd, buf, sizeof(buf))) > 0) {
    if (fwrite(buf, 1, (size_t)n, stdout) != (size_t)n) {
      break;
    }
  }
  close(fd);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 3 || strcmp(argv[1], "-c") != 0) {
    fprintf(stderr, "usage: glsh -c CMD\n");
    return 2;
  }
  char *cmd = argv[2];
  char *rest = strchr(cmd, ' ');
  if (rest) {
    *rest++ = 0;
  }
  if (!strcmp(cmd, "id")) {
    printf("uid=%d euid=%d gid=%d egid=%d\n", (int)getuid(), (int)geteuid(),
           (int)getgid(), (int)getegid());
    return 0;
  }
  if (!strcmp(cmd, "proof")) {
    printf("glsh-proof: uid=%d euid=%d\n", (int)getuid(), (int)geteuid());
    return 0;
  }
  if (!strcmp(cmd, "echo")) {
    printf("%s\n", rest ? rest : "");
    return 0;
  }
  if (!strcmp(cmd, "cat")) {
    return cmd_cat(rest ? rest : "");
  }
  fprintf(stderr, "glsh: unknown command '%s'\n", cmd);
  return 127;
}

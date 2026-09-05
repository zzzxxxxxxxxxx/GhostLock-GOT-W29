/* EDEADLK trigger diagnostic - run one variant, clean exit */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define FUTEX_LOCK_PI 6
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define FUTEX_WAKE 1
#define FUTEX_PRIVATE_FLAG 128
#define SYS_futex 98
#define FUTEX_BITSET_MATCH_ANY 0xffffffff

static uint32_t futex1, futex2, cycle_futex;
static volatile int owner_ready, owner_blocking, waiter_ready, waiter_waiting, waiter_returned;
static volatile long owner_lockpi_ret = -999;
static volatile int owner_futex2 = 1;
static volatile int owner_lockpi_errno;
static volatile long waiter_ret = -999;
static volatile int waiter_errno;

static long gettid_l(void) { return syscall(SYS_gettid); }
static void logf(const char *fmt, ...) {
  va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap); fflush(stderr);
}

static void *owner_thread(void *u) {
  (void)u;
  if (owner_futex2) __atomic_store_n(&futex2, (uint32_t)gettid_l(), __ATOMIC_RELEASE);
  __atomic_store_n(&owner_ready, 1, __ATOMIC_RELEASE);
  while (!waiter_ready) usleep(1000);
  __atomic_store_n(&owner_blocking, 1, __ATOMIC_RELEASE);
  errno = 0;
  long r = syscall(SYS_futex, &cycle_futex, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
  owner_lockpi_ret = r; owner_lockpi_errno = errno;
  logf("[O] LOCK_PI(cycle) ret=%ld errno=%d\n", r, errno);
  return NULL;
}

static void *waiter_thread(void *u) {
  int variant = (int)(long)u;
  struct timespec timeout;
  while (!owner_ready) usleep(1000);
  __atomic_store_n(&cycle_futex, (uint32_t)gettid_l(), __ATOMIC_RELEASE);
  if (variant & 8) __atomic_store_n(&futex2, (uint32_t)gettid_l(), __ATOMIC_RELEASE);
  __atomic_store_n(&waiter_ready, 1, __ATOMIC_RELEASE);
  while (!owner_blocking) usleep(1000);
  usleep(20000);
  int use_timeout = variant & 1;
  int use_private = variant & 2;
  if (use_timeout) {
    clock_gettime(CLOCK_MONOTONIC, &timeout);
    timeout.tv_sec += 1;
  }
  __atomic_store_n(&waiter_waiting, 1, __ATOMIC_RELEASE);
  int op = FUTEX_WAIT_REQUEUE_PI | (use_private ? FUTEX_PRIVATE_FLAG : 0);
  errno = 0;
  long r = syscall(SYS_futex, &futex1, op, 0, use_timeout ? &timeout : NULL, &futex2, 0);
  int e = errno;
  waiter_ret = r; waiter_errno = e;
  logf("[W] variant=%d private=%d timeout=%d WAIT_REQUEUE_PI ret=%ld errno=%d\n",
       variant, use_private, use_timeout, r, e);
  __atomic_store_n(&waiter_returned, 1, __ATOMIC_RELEASE);
  return NULL;
}

int main(int argc, char **argv) {
  int variant = argc > 1 ? atoi(argv[1]) : 2;
  futex1 = 0; futex2 = 0; cycle_futex = 0;
  logf("[M] pid=%d variant=%d futex1=%p futex2=%p cycle=%p\n",
       getpid(), variant, &futex1, &futex2, &cycle_futex);
  pthread_t ot, wt;
  pthread_create(&ot, NULL, owner_thread, NULL);
  pthread_create(&wt, NULL, waiter_thread, (void*)(long)variant);
  /* wait for the waiter to be inside WAIT_REQUEUE_PI (or returned) */
  while (!waiter_waiting && !waiter_returned) usleep(1000);
  usleep(50000);
  errno = 0;
  long r = syscall(SYS_futex, &futex1,
                   FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, (void*)1, &futex2, 0);
  int e = errno;
  logf("[M] CMP_REQUEUE_PI ret=%ld errno=%d %s\n", r, e, e == 35 ? "(EDEADLK!)" : "");
  /* wake the waiter on futex1 (rollback leaves it blocked there) */
  syscall(SYS_futex, &futex1, FUTEX_WAKE | (e == 35 ? FUTEX_PRIVATE_FLAG : 0), 1, NULL, NULL, 0);
  /* wait briefly for waiter to return */
  for (int i = 0; i < 20 && !waiter_returned; i++) usleep(100000);
  logf("[M] waiter_returned=%d\n", waiter_returned);
  logf("[M] owner_lockpi_ret=%ld owner_lockpi_errno=%d (was the PI cycle formed?)\n",
       owner_lockpi_ret, owner_lockpi_errno);
  logf("[M] waiter_ret=%ld waiter_errno=%d\n", waiter_ret, waiter_errno);
  /* detach threads and exit; futexes will be cleaned up on process exit */
  pthread_detach(ot); pthread_detach(wt);
  logf("[M] variant %d EDEADLK=%s\n", variant, e == 35 ? "YES" : "no");
  return 0;
}

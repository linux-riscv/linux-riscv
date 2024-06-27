// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <linux/elf.h>
#include <linux/unistd.h>
#include <asm/ptrace.h>

#include "../../kselftest_harness.h"

#define ORIG_A0_MODIFY      0x01
#define A0_MODIFY           0x02
#define A0_OLD              0x03
#define A0_NEW              0x04

#define perr_and_exit(fmt, ...)					\
	({								\
	 	char buf[256];						\
		snprintf(buf, sizeof(buf), "%s:%d: " fmt ": %m\n",	\
			__func__, __LINE__, ##__VA_ARGS__);		\
		perror(buf);						\
		exit(-1);						\
	})

static inline void resume_and_wait_tracee(pid_t pid, int flag)
{
	int status;

	if (ptrace(flag, pid, 0, 0))
		perr_and_exit("failed to resume the tracee %d\n", pid);

	if (waitpid(pid, &status, 0) != pid)
		perr_and_exit("failed to wait for the tracee %d\n", pid);
}

static void ptrace_test(int opt, int *result)
{
	int status;
	pid_t pid;
	struct user_regs_struct regs;
	struct iovec iov = {
		.iov_base = &regs,
		.iov_len = sizeof(regs),
	};

	pid = fork();
	if (pid == 0) {
		/* Mark oneself being traced */
		long val = ptrace(PTRACE_TRACEME, 0, 0, 0);
		if (val)
			perr_and_exit("failed to request for tracer to trace me: %ld\n", val);

		kill(getpid(), SIGSTOP);

		/* Perform exit syscall that will be intercepted */
		exit(A0_OLD);
	}
	if (pid < 0)
		exit(1);

	if (waitpid(pid, &status, 0) != pid)
		perr_and_exit("failed to wait for the tracee %d\n", pid);

	/* Stop at the entry point of the syscall */
	resume_and_wait_tracee(pid, PTRACE_SYSCALL);

	/* Check tracee orig_a0 before the syscall */
	if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov))
		perr_and_exit("failed to get tracee registers\n");
	if (regs.orig_a0 != A0_OLD)
		perr_and_exit("unexpected orig_a0: 0x%lx\n", regs.orig_a0);

	/* Modify a0/orig_a0 for the syscall */
	switch (opt) {
	case A0_MODIFY:
		regs.a0 = A0_NEW;
		break;
	case ORIG_A0_MODIFY:
		regs.orig_a0 = A0_NEW;
		break;
	}

	if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov))
		perr_and_exit("failed to set tracee registers\n");

	/* Resume the tracee */
	ptrace(PTRACE_CONT, pid, 0, 0);
	if (waitpid(pid, &status, 0) != pid)
		perr_and_exit("failed to wait for the tracee\n");

	*result = WEXITSTATUS(status);
}

TEST(ptrace_modify_a0)
{
	int result;

	ptrace_test(A0_MODIFY, &result);

	/* The modification of a0 cannot affect the first argument of the syscall */
	EXPECT_EQ(A0_OLD, result);
}

TEST(ptrace_modify_orig_a0)
{
	int result;

	ptrace_test(ORIG_A0_MODIFY, &result);

	/* Only modify orig_a0 to change the first argument of the syscall */
	EXPECT_EQ(A0_NEW, result);
}

TEST_HARNESS_MAIN

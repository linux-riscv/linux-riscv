// SPDX-License-Identifier: GPL-2.0-only

#include "../../kselftest.h"
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <asm-generic/unistd.h>
#include <sys/mman.h>
#include "shadowstack.h"
#include "cfi_rv_test.h"

/* do not optimize shadow stack related test functions */
#pragma GCC push_options
#pragma GCC optimize("O0")

void zar(void)
{
	unsigned long ssp = 0;

	ssp = csr_read(CSR_SSP);
	printf("inside %s and shadow stack ptr is %lx\n", __func__, ssp);
}

void bar(void)
{
	printf("inside %s\n", __func__);
	zar();
}

void foo(void)
{
	printf("inside %s\n", __func__);
	bar();
}

void zar_child(void)
{
	unsigned long ssp = 0;

	ssp = csr_read(CSR_SSP);
	printf("inside %s and shadow stack ptr is %lx\n", __func__, ssp);
}

void bar_child(void)
{
	printf("inside %s\n", __func__);
	zar_child();
}

void foo_child(void)
{
	printf("inside %s\n", __func__);
	bar_child();
}

typedef void (call_func_ptr)(void);
/*
 * call couple of functions to test push pop.
 */
int shadow_stack_call_tests(call_func_ptr fn_ptr, bool parent)
{
	if (parent)
		printf("call test for parent\n");
	else
		printf("call test for child\n");

	(fn_ptr)();

	return 0;
}

/* forks a thread, and ensure shadow stacks fork out */
bool shadow_stack_fork_test(unsigned long test_num, void *ctx)
{
	int pid = 0, child_status = 0, parent_pid = 0, ret = 0;
	unsigned long ss_status = 0;

	printf("exercising shadow stack fork test\n");

	ret = my_syscall5(__NR_prctl, PR_GET_SHADOW_STACK_STATUS, &ss_status, 0, 0, 0);
	if (ret) {
		printf("shadow stack get status prctl failed with errorcode %d\n", ret);
		return false;
	}

	if (!(ss_status & PR_SHADOW_STACK_ENABLE))
		ksft_exit_skip("shadow stack is not enabled, should be enabled via glibc\n");

	parent_pid = getpid();
	pid = fork();

	if (pid) {
		printf("Parent pid %d and child pid %d\n", parent_pid, pid);
		shadow_stack_call_tests(&foo, true);
	} else
		shadow_stack_call_tests(&foo_child, false);

	if (pid) {
		printf("waiting on child to finish\n");
		wait(&child_status);
	} else {
		/* exit child gracefully */
		exit(0);
	}

	if (pid && WIFSIGNALED(child_status)) {
		printf("child faulted");
		return false;
	}

	return true;
}

/* exercise `map_shadow_stack`, pivot to it and call some functions to ensure it works */
#define SHADOW_STACK_ALLOC_SIZE 4096
bool shadow_stack_map_test(unsigned long test_num, void *ctx)
{
	unsigned long shdw_addr;
	int ret = 0;

	shdw_addr = my_syscall3(__NR_map_shadow_stack, NULL, SHADOW_STACK_ALLOC_SIZE, 0);

	if (((long) shdw_addr) <= 0) {
		printf("map_shadow_stack failed with error code %d\n", (int) shdw_addr);
		return false;
	}

	ret = munmap((void *) shdw_addr, SHADOW_STACK_ALLOC_SIZE);

	if (ret) {
		printf("munmap failed with error code %d\n", ret);
		return false;
	}

	return true;
}

/*
 * shadow stack protection tests. map a shadow stack and
 * validate all memory protections work on it
 */
bool shadow_stack_protection_test(unsigned long test_num, void *ctx)
{
	unsigned long shdw_addr;
	unsigned long *write_addr = NULL;
	int ret = 0, pid = 0, child_status = 0;

	shdw_addr = my_syscall3(__NR_map_shadow_stack, NULL, SHADOW_STACK_ALLOC_SIZE, 0);

	if (((long) shdw_addr) <= 0) {
		printf("map_shadow_stack failed with error code %d\n", (int) shdw_addr);
		return false;
	}

	write_addr = (unsigned long *) shdw_addr;
	pid = fork();

	/* no child was created, return false */
	if (pid == -1)
		return false;

	/*
	 * try to perform a store from child on shadow stack memory
	 * it should result in SIGSEGV
	 */
	if (!pid) {
		/* below write must lead to SIGSEGV */
		*write_addr = 0xdeadbeef;
	} else {
		wait(&child_status);
	}

	/* test fail, if 0xdeadbeef present on shadow stack address */
	if (*write_addr == 0xdeadbeef) {
		printf("write suceeded\n");
		return false;
	}

	/* if child reached here, then fail */
	if (!pid) {
		printf("child reached unreachable state\n");
		return false;
	}

	/* if child exited via signal handler but not for write on ss */
	if (WIFEXITED(child_status) &&
		WEXITSTATUS(child_status) != CHILD_EXIT_CODE_SSWRITE) {
		printf("child wasn't signaled for write on shadow stack\n");
		return false;
	}

	ret = munmap(write_addr, SHADOW_STACK_ALLOC_SIZE);
	if (ret) {
		printf("munmap failed with error code %d\n", ret);
		return false;
	}

	return true;
}

#define SS_MAGIC_WRITE_VAL 0xbeefdead

int gup_tests(int mem_fd, unsigned long *shdw_addr)
{
	unsigned long val = 0;

	lseek(mem_fd, (unsigned long)shdw_addr, SEEK_SET);
	if (read(mem_fd, &val, sizeof(val)) < 0) {
		printf("reading shadow stack mem via gup failed\n");
		return 1;
	}

	val = SS_MAGIC_WRITE_VAL;
	lseek(mem_fd, (unsigned long)shdw_addr, SEEK_SET);
	if (write(mem_fd, &val, sizeof(val)) < 0) {
		printf("writing shadow stack mem via gup failed\n");
		return 1;
	}

	if (*shdw_addr != SS_MAGIC_WRITE_VAL) {
		printf("GUP write to shadow stack memory didn't happen\n");
		return 1;
	}

	return 0;
}

bool shadow_stack_gup_tests(unsigned long test_num, void *ctx)
{
	unsigned long shdw_addr = 0;
	unsigned long *write_addr = NULL;
	int fd = 0;
	bool ret = false;

	shdw_addr = my_syscall3(__NR_map_shadow_stack, NULL, SHADOW_STACK_ALLOC_SIZE, 0);

	if (((long) shdw_addr) <= 0) {
		printf("map_shadow_stack failed with error code %d\n", (int) shdw_addr);
		return false;
	}

	write_addr = (unsigned long *) shdw_addr;

	fd = open("/proc/self/mem", O_RDWR);
	if (fd == -1)
		return false;

	if (gup_tests(fd, write_addr)) {
		printf("gup tests failed\n");
		goto out;
	}

	ret = true;
out:
	if (shdw_addr && munmap(write_addr, SHADOW_STACK_ALLOC_SIZE)) {
		printf("munmap failed with error code %d\n", ret);
		ret = false;
	}

	return ret;
}

volatile bool break_loop;

void sigusr1_handler(int signo)
{
	printf("In sigusr1 handler\n");
	break_loop = true;
}

bool sigusr1_signal_test(void)
{
	struct sigaction sa = {};

	sa.sa_handler = sigusr1_handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGUSR1, &sa, NULL)) {
		printf("registering signal handler for SIGUSR1 failed\n");
		return false;
	}

	return true;
}
/*
 * shadow stack signal test. shadow stack must be enabled.
 * register a signal, fork another thread which is waiting
 * on signal. Send a signal from parent to child, verify
 * that signal was received by child. If not test fails
 */
bool shadow_stack_signal_test(unsigned long test_num, void *ctx)
{
	int pid = 0, child_status = 0, ret = 0;
	unsigned long ss_status = 0;

	ret = my_syscall5(__NR_prctl, PR_GET_SHADOW_STACK_STATUS, &ss_status, 0, 0, 0);
	if (ret) {
		printf("shadow stack get status prctl failed with errorcode %d\n", ret);
		return false;
	}

	if (!(ss_status & PR_SHADOW_STACK_ENABLE))
		ksft_exit_skip("shadow stack is not enabled, should be enabled via glibc\n");

	/* this should be caught by signal handler and do an exit */
	if (!sigusr1_signal_test()) {
		printf("registering sigusr1 handler failed\n");
		exit(-1);
	}

	pid = fork();

	if (pid == -1) {
		printf("signal test: fork failed\n");
		goto out;
	}

	if (pid == 0) {
		while (!break_loop)
			sleep(1);

		exit(11);
		/* child shouldn't go beyond here */
	}

	/* send SIGUSR1 to child */
	kill(pid, SIGUSR1);
	wait(&child_status);

out:

	return (WIFEXITED(child_status) &&
			WEXITSTATUS(child_status) == 11);
}

int execute_shadow_stack_tests(void)
{
	int ret = 0;
	unsigned long test_count = 0;
	unsigned long shstk_status = 0;

	printf("Executing RISC-V shadow stack self tests\n");

	ret = my_syscall5(__NR_prctl, PR_GET_SHADOW_STACK_STATUS, &shstk_status, 0, 0, 0);

	if (ret != 0)
		ksft_exit_skip("Get shadow stack status failed with %d\n", ret);

	/*
	 * If we are here that means get shadow stack status succeeded and
	 * thus shadow stack support is baked in the kernel.
	 */
	while (test_count < ARRAY_SIZE(shstk_tests)) {
		ksft_test_result((*shstk_tests[test_count].t_func)(test_count, NULL),
						 shstk_tests[test_count].name);
		test_count++;
	}

	return 0;
}

#pragma GCC pop_options

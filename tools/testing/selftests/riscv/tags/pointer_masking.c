// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../kselftest.h"

#ifndef PR_PMLEN_SHIFT
#define PR_PMLEN_SHIFT			24
#endif
#ifndef PR_PMLEN_MASK
#define PR_PMLEN_MASK			(0x7fUL << PR_PMLEN_SHIFT)
#endif

static int dev_zero;

static sigjmp_buf jmpbuf;

static void sigsegv_handler(int sig)
{
	siglongjmp(jmpbuf, 1);
}

static int min_pmlen;
static int max_pmlen;

static inline bool valid_pmlen(int pmlen)
{
	return pmlen == 0 || pmlen == 7 || pmlen == 16;
}

static void test_pmlen(void)
{
	ksft_print_msg("Testing available PMLEN values\n");

	for (int request = 0; request <= 16; request++) {
		int pmlen, ret;

		ret = prctl(PR_SET_TAGGED_ADDR_CTRL, request << PR_PMLEN_SHIFT, 0, 0, 0);
		if (ret) {
			ksft_test_result_skip("PMLEN=%d PR_GET_TAGGED_ADDR_CTRL\n", request);
			ksft_test_result_skip("PMLEN=%d constraint\n", request);
			ksft_test_result_skip("PMLEN=%d validity\n", request);
			continue;
		}

		ret = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
		ksft_test_result(ret >= 0, "PMLEN=%d PR_GET_TAGGED_ADDR_CTRL\n", request);
		if (ret < 0) {
			ksft_test_result_skip("PMLEN=%d constraint\n", request);
			ksft_test_result_skip("PMLEN=%d validity\n", request);
			continue;
		}

		pmlen = (ret & PR_PMLEN_MASK) >> PR_PMLEN_SHIFT;
		ksft_test_result(pmlen >= request, "PMLEN=%d constraint\n", request);
		ksft_test_result(valid_pmlen(pmlen), "PMLEN=%d validity\n", request);

		if (min_pmlen == 0)
			min_pmlen = pmlen;
		if (max_pmlen < pmlen)
			max_pmlen = pmlen;
	}

	if (max_pmlen == 0)
		ksft_exit_fail_msg("Failed to enable pointer masking\n");
}

static int set_tagged_addr_ctrl(int pmlen, bool tagged_addr_abi)
{
	int arg, ret;

	arg = pmlen << PR_PMLEN_SHIFT | tagged_addr_abi;
	ret = prctl(PR_SET_TAGGED_ADDR_CTRL, arg, 0, 0, 0);
	if (!ret) {
		ret = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
		if (ret == arg)
			return 0;
	}

	return ret < 0 ? -errno : -ENODATA;
}

static void test_dereference_pmlen(int pmlen)
{
	static volatile int i;
	volatile int *p;
	int ret;

	ret = set_tagged_addr_ctrl(pmlen, false);
	if (ret)
		return ksft_test_result_error("PMLEN=%d setup (%d)\n", pmlen, ret);

	i = pmlen;

	if (pmlen) {
		p = (volatile int *)((uintptr_t)&i | 1UL << __riscv_xlen - pmlen);

		/* These dereferences should succeed. */
		if (sigsetjmp(jmpbuf, 1))
			return ksft_test_result_fail("PMLEN=%d valid tag\n", pmlen);
		if (*p != pmlen)
			return ksft_test_result_fail("PMLEN=%d bad value\n", pmlen);
		*p++;
	}

	p = (volatile int *)((uintptr_t)&i | 1UL << __riscv_xlen - pmlen - 1);

	/* These dereferences should raise SIGSEGV. */
	if (sigsetjmp(jmpbuf, 1))
		return ksft_test_result_pass("PMLEN=%d dereference\n", pmlen);
	*p++;
	ksft_test_result_fail("PMLEN=%d invalid tag\n", pmlen);
}

static void test_dereference(void)
{
	ksft_print_msg("Testing userspace pointer dereference\n");

	signal(SIGSEGV, sigsegv_handler);

	test_dereference_pmlen(0);
	test_dereference_pmlen(min_pmlen);
	test_dereference_pmlen(max_pmlen);

	signal(SIGSEGV, SIG_DFL);
}

static void test_fork_exec(void)
{
	int ret, status;

	ksft_print_msg("Testing fork/exec behavior\n");

	ret = set_tagged_addr_ctrl(min_pmlen, false);
	if (ret)
		return ksft_test_result_error("setup (%d)\n", ret);

	if (fork()) {
		wait(&status);
		ksft_test_result(WIFEXITED(status) && WEXITSTATUS(status) == 0,
				 "dereference after fork\n");
	} else {
		static volatile int i;
		volatile int *p = (volatile int *)((uintptr_t)&i | 1UL << __riscv_xlen - min_pmlen);

		exit(*p);
	}

	if (fork()) {
		wait(&status);
		ksft_test_result(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV,
				 "dereference after fork+exec\n");
	} else {
		execl("/proc/self/exe", "", NULL);
	}
}

static void test_tagged_addr_abi_sysctl(void)
{
	char value;
	int fd;

	ksft_print_msg("Testing tagged address ABI sysctl\n");

	fd = open("/proc/sys/abi/tagged_addr_disabled", O_WRONLY);
	if (fd < 0) {
		ksft_test_result_skip("failed to open sysctl file\n");
		ksft_test_result_skip("failed to open sysctl file\n");
		return;
	}

	value = '1';
	pwrite(fd, &value, 1, 0);
	ksft_test_result(set_tagged_addr_ctrl(min_pmlen, true) == -EINVAL,
			 "sysctl disabled\n");

	value = '0';
	pwrite(fd, &value, 1, 0);
	ksft_test_result(set_tagged_addr_ctrl(min_pmlen, true) == 0,
			 "sysctl enabled\n");

	set_tagged_addr_ctrl(0, false);

	close(fd);
}

static void test_tagged_addr_abi_pmlen(int pmlen)
{
	int i, *p, ret;

	i = ~pmlen;

	if (pmlen) {
		p = (int *)((uintptr_t)&i | 1UL << __riscv_xlen - pmlen);

		ret = set_tagged_addr_ctrl(pmlen, false);
		if (ret)
			return ksft_test_result_error("PMLEN=%d ABI disabled setup (%d)\n",
						      pmlen, ret);

		ret = write(dev_zero, p, sizeof(*p));
		if (ret >= 0 || errno != EFAULT)
			return ksft_test_result_fail("PMLEN=%d ABI disabled write\n", pmlen);

		ret = read(dev_zero, p, sizeof(*p));
		if (ret >= 0 || errno != EFAULT)
			return ksft_test_result_fail("PMLEN=%d ABI disabled read\n", pmlen);

		if (i != ~pmlen)
			return ksft_test_result_fail("PMLEN=%d ABI disabled value\n", pmlen);

		ret = set_tagged_addr_ctrl(pmlen, true);
		if (ret)
			return ksft_test_result_error("PMLEN=%d ABI enabled setup (%d)\n",
						      pmlen, ret);

		ret = write(dev_zero, p, sizeof(*p));
		if (ret != sizeof(*p))
			return ksft_test_result_fail("PMLEN=%d ABI enabled write\n", pmlen);

		ret = read(dev_zero, p, sizeof(*p));
		if (ret != sizeof(*p))
			return ksft_test_result_fail("PMLEN=%d ABI enabled read\n", pmlen);

		if (i)
			return ksft_test_result_fail("PMLEN=%d ABI enabled value\n", pmlen);

		i = ~pmlen;
	} else {
		/* The tagged address ABI cannot be enabled when PMLEN == 0. */
		ret = set_tagged_addr_ctrl(pmlen, true);
		if (ret != -EINVAL)
			return ksft_test_result_error("PMLEN=%d ABI setup (%d)\n",
						      pmlen, ret);
	}

	p = (int *)((uintptr_t)&i | 1UL << __riscv_xlen - pmlen - 1);

	ret = write(dev_zero, p, sizeof(*p));
	if (ret >= 0 || errno != EFAULT)
		return ksft_test_result_fail("PMLEN=%d invalid tag write (%d)\n", pmlen, errno);

	ret = read(dev_zero, p, sizeof(*p));
	if (ret >= 0 || errno != EFAULT)
		return ksft_test_result_fail("PMLEN=%d invalid tag read\n", pmlen);

	if (i != ~pmlen)
		return ksft_test_result_fail("PMLEN=%d invalid tag value\n", pmlen);

	ksft_test_result_pass("PMLEN=%d tagged address ABI\n", pmlen);
}

static void test_tagged_addr_abi(void)
{
	ksft_print_msg("Testing tagged address ABI\n");

	test_tagged_addr_abi_pmlen(0);
	test_tagged_addr_abi_pmlen(min_pmlen);
	test_tagged_addr_abi_pmlen(max_pmlen);
}

static struct test_info {
	unsigned int nr_tests;
	void (*test_fn)(void);
} tests[] = {
	{ .nr_tests = 17 * 3, test_pmlen },
	{ .nr_tests = 3, test_dereference },
	{ .nr_tests = 2, test_fork_exec },
	{ .nr_tests = 2, test_tagged_addr_abi_sysctl },
	{ .nr_tests = 3, test_tagged_addr_abi },
};

int main(int argc, char **argv)
{
	unsigned int plan = 0;

	/* Check if this is the child process after execl(). */
	if (!argv[0][0]) {
		static volatile int i;
		volatile int *p = (volatile int *)((uintptr_t)&i | 1UL << __riscv_xlen - 7);

		return *p;
	}

	dev_zero = open("/dev/zero", O_RDWR);
	if (dev_zero < 0)
		return 1;

	ksft_print_header();

	for (int i = 0; i < ARRAY_SIZE(tests); ++i)
		plan += tests[i].nr_tests;

	ksft_set_plan(plan);

	for (int i = 0; i < ARRAY_SIZE(tests); ++i)
		tests[i].test_fn();

	ksft_finished();
}

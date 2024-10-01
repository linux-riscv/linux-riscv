/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef SELFTEST_SHADOWSTACK_TEST_H
#define SELFTEST_SHADOWSTACK_TEST_H
#include <stddef.h>
#include <linux/prctl.h>

/*
 * a cfi test returns true for success or false for fail
 * takes a number for test number to index into array and void pointer.
 */
typedef bool (*shstk_test_func)(unsigned long test_num, void *);

struct shadow_stack_tests {
	char *name;
	shstk_test_func t_func;
};

bool shadow_stack_fork_test(unsigned long test_num, void *ctx);
bool shadow_stack_map_test(unsigned long test_num, void *ctx);
bool shadow_stack_protection_test(unsigned long test_num, void *ctx);
bool shadow_stack_gup_tests(unsigned long test_num, void *ctx);
bool shadow_stack_signal_test(unsigned long test_num, void *ctx);

static struct shadow_stack_tests shstk_tests[] = {
	{ "shstk fork test\n", shadow_stack_fork_test },
	{ "map shadow stack syscall\n", shadow_stack_map_test },
	{ "shadow stack gup tests\n", shadow_stack_gup_tests },
	{ "shadow stack signal tests\n", shadow_stack_signal_test},
	{ "memory protections of shadow stack memory\n", shadow_stack_protection_test }
};

#define RISCV_SHADOW_STACK_TESTS ARRAY_SIZE(shstk_tests)

int execute_shadow_stack_tests(void);

#endif

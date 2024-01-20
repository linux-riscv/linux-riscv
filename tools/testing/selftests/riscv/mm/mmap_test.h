/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _TESTCASES_MMAP_TEST_H
#define _TESTCASES_MMAP_TEST_H
#include <sys/mman.h>
#include <sys/resource.h>
#include <stddef.h>

#define TOP_DOWN 0
#define BOTTOM_UP 1

struct addresses {
	int *no_hint;
};

// Only works on 64 bit
#if __riscv_xlen == 64
static inline void do_mmaps(struct addresses *mmap_addresses)
{
	int prot = PROT_READ | PROT_WRITE;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;

	mmap_addresses->no_hint =
		mmap(NULL, 5 * sizeof(int), prot, flags, 0, 0);
}
#endif /* __riscv_xlen == 64 */

static inline int memory_layout(void)
{
	int prot = PROT_READ | PROT_WRITE;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;

	void *value1 = mmap(NULL, sizeof(int), prot, flags, 0, 0);
	void *value2 = mmap(NULL, sizeof(int), prot, flags, 0, 0);

	return value2 > value1;
}
#endif /* _TESTCASES_MMAP_TEST_H */

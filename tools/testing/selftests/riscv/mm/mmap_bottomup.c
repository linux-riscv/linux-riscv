// SPDX-License-Identifier: GPL-2.0-only
#include <sys/mman.h>
#include <mmap_test.h>

#include "../../kselftest_harness.h"

TEST(infinite_rlimit)
{
// Only works on 64 bit
#if __riscv_xlen == 64
	struct addresses mmap_addresses;

	EXPECT_EQ(BOTTOM_UP, memory_layout());

	do_mmaps(&mmap_addresses);

	EXPECT_NE(MAP_FAILED, mmap_addresses.no_hint);

	EXPECT_GT(1UL << 47, (unsigned long)mmap_addresses.no_hint);
#endif
}

TEST_HARNESS_MAIN

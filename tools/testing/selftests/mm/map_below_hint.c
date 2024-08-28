// SPDX-License-Identifier: GPL-2.0
/*
 * Test the MAP_BELOW_HINT mmap flag.
 */
#include <sys/mman.h>
#include "../kselftest.h"

#define ADDR 0x1000000UL
#define LENGTH (ADDR / 100)

#define MAP_BELOW_HINT	  0x8000000	/* Not defined in all libc */

/*
 * Map memory with MAP_BELOW_HINT until no memory left. Ensure that all returned
 * addresses are below the hint.
 */
int main(int argc, char **argv)
{
	void *addr;

	do {
		addr = mmap((void *)ADDR, LENGTH, MAP_ANONYMOUS, MAP_BELOW_HINT, -1, 0);
	} while (addr == MAP_FAILED && (unsigned long)addr <= ADDR);

	if (addr != MAP_FAILED && (unsigned long)addr > ADDR)
		ksft_exit_fail_msg("mmap returned address above hint with MAP_BELOW_HINT\n");

	ksft_test_result_pass("MAP_BELOW_HINT works\n");
}

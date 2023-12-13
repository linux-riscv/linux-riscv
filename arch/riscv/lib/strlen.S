/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/alternative-macros.h>
#include <asm/hwcap.h>

#define REP_80 __REG_SEL(0x8080808080808080, 0x80808080)
#define REP_01 __REG_SEL(0x0101010101010101, 0x01010101)

/* size_t strlen(const char *s) */
SYM_FUNC_START(strlen)
	ALTERNATIVE("nop", "j strlen_zbb", 0, RISCV_ISA_EXT_ZBB, CONFIG_RISCV_ISA_ZBB)

	/*
         * Returns
         *   a0 - string length
         *
         * Parameters
         *   a0 - String to measure
         *
         * Clobbers:
         *   t0, t1, t2, t3, t4
         */


	mv t4, a0

	/* Check the address memory alignment */
	andi t2, a0, SZREG-1
	beqz t2, 2f

	/* Get SZREG - (address remainder) */
	xori t2, t2, SZREG-1
	addi t2, t2, 1

	/* align the address */
	add t2, a0, t2
1:
	beq a0, t2, 2f
	lbu t1, 0(a0)
	beqz t1, 5f
	addi a0, a0, 1
	j 1b
2:
	li t2, REP_80
	li t3, REP_01
3:
	/* v contains 0 byte if (v - 0x0101..01) & ~v & 0x8080..80 != 0 */
	REG_L t0, 0(a0)
	sub t1, t0, t3
	not t0, t0
	and t1, t1, t0
	and t1, t1, t2
	bnez t1, 4f
	addi a0, a0, SZREG
	j 3b
4:
	/*
	 * We found the word with 0, iterate it byte-wise to find the actual
	 * string length.
	 */
	lbu t0, 0(a0)
	beqz t0, 5f
	addi a0, a0, 1
	j 4b
5:
	sub a0, a0, t4
	ret

/*
 * Variant of strlen using the ZBB extension if available
 */
#ifdef CONFIG_RISCV_ISA_ZBB
strlen_zbb:

#ifdef CONFIG_CPU_BIG_ENDIAN
# define CZ	clz
# define SHIFT	sll
#else
# define CZ	ctz
# define SHIFT	srl
#endif

.option push
.option arch,+zbb

	/*
	 * Returns
	 *   a0 - string length
	 *
	 * Parameters
	 *   a0 - String to measure
	 *
	 * Clobbers
	 *   t0, t1, t2, t3
	 */

	/* Number of irrelevant bytes in the first word. */
	andi	t2, a0, SZREG-1

	/* Align pointer. */
	andi	t0, a0, -SZREG

	li	t3, SZREG
	sub	t3, t3, t2
	slli	t2, t2, 3

	/* Get the first word.  */
	REG_L	t1, 0(t0)

	/*
	 * Shift away the partial data we loaded to remove the irrelevant bytes
	 * preceding the string with the effect of adding NUL bytes at the
	 * end of the string's first word.
	 */
	SHIFT	t1, t1, t2

	/* Convert non-NUL into 0xff and NUL into 0x00. */
	orc.b	t1, t1

	/* Convert non-NUL into 0x00 and NUL into 0xff. */
	not	t1, t1

	/*
	 * Search for the first set bit (corresponding to a NUL byte in the
	 * original chunk).
	 */
	CZ	t1, t1

	/*
	 * The first chunk is special: compare against the number
	 * of valid bytes in this chunk.
	 */
	srli	a0, t1, 3
	bgtu	t3, a0, 2f

	/* Prepare for the word comparison loop. */
	addi	t2, t0, SZREG
	li	t3, -1

	/*
	 * Our critical loop is 4 instructions and processes data in
	 * 4 byte or 8 byte chunks.
	 */
	.p2align 3
1:
	REG_L	t1, SZREG(t0)
	addi	t0, t0, SZREG
	orc.b	t1, t1
	beq	t1, t3, 1b

	not	t1, t1
	CZ	t1, t1
	srli	t1, t1, 3

	/* Get number of processed bytes. */
	sub	t2, t0, t2

	/* Add number of characters in the first word.  */
	add	a0, a0, t2

	/* Add number of characters in the last word.  */
	add	a0, a0, t1
2:
	ret

.option pop
#endif
SYM_FUNC_END(strlen)
SYM_FUNC_ALIAS(__pi_strlen, strlen)

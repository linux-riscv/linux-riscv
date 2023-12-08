/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Codethink Ltd.
 * Author: Ivan Orlov <ivan.orlov@codethink.co.uk>
 */

#include <linux/linkage.h>
#include <asm/asm.h>

#define REP_01 __REG_SEL(0x0101010101010101, 0x01010101)
#define REP_80 __REG_SEL(0x8080808080808080, 0x80808080)

#define MIN_BORDER 128

SYM_FUNC_START(memchr)
	andi a1, a1, 0xFF

	// use byte-wide iteration for small numbers
	add t1, x0, a2
	sltiu t2, a2, MIN_BORDER
	bnez t2, 6f

	// get the number of bytes we should iterate before alignment
	andi t0, a0, SZREG - 1
	beqz t0, 4f

	# get the SZREG - t0
	xor t0, t0, SZREG - 1
	addi t0, t0, 1

	sub a2, a2, t0
	// iterate before alignment
1:
	beq t0, x0, 4f
	lbu t2, 0(a0)
	beq t2, a1, 3f
	addi t0, t0, -1
	addi a0, a0, 1
	j 1b

2:
	// found a word. Iterate it until we find the target byte
	li t1, SZREG
	j 6f
3:
	ret

4:
	// get the count remainder
	andi t1, a2, SZREG - 1

	// align the count
	sub a2, a2, t1

	// if we have no words to iterate, iterate the remainder
	beqz a2, 6f

	// from 0xBA we will get 0xBABABABABABABABA
	li t3, REP_01
	mul t3, t3, a1

	add a2, a2, a0

	li t4, REP_01
	li t5, REP_80

5:
	REG_L t2, 0(a0)

	// after this xor we will get one zero byte in the word if it contains the target byte
	xor t2, t2, t3

	// word v contains the target byte if (v - 0x01010101) & (~v) & 0x80808080 is positive
	sub t0, t2, t4

	not t2, t2

	and t0, t0, t2
	and t0, t0, t5

	bnez t0, 2b
	addi a0, a0, SZREG
	bne a0, a2, 5b

6:
	// iterate the remainder
	beq t1, x0, 7f
	lbu t4, 0(a0)
	beq t4, a1, 3b
	addi a0, a0, 1
	addi t1, t1, -1
	j 6b

7:
	addi a0, x0, 0
	ret
SYM_FUNC_END(memchr)
SYM_FUNC_ALIAS(__pi_memchr, memchr)

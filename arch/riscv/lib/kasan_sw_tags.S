/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 Google LLC
 * Copyright (C) 2024 SiFive
 */

#include <linux/linkage.h>

/*
 * Report a tag mismatch detected by tag-based KASAN.
 *
 * A compiler-generated thunk calls this with a custom calling convention.
 * Upon entry to this function, the following registers have been modified:
 *
 *   x1/ra:     clobbered by call to this function
 *   x2/sp:     decremented by 256
 *   x6/t1:     tag from shadow memory
 *   x7/t2:     tag from pointer
 *   x10/a0:    fault address
 *   x11/a1:    fault description
 *   x28/t3:    clobbered by thunk
 *   x29/t4:    clobbered by thunk
 *   x30/t5:    clobbered by thunk
 *   x31/t6:    clobbered by thunk
 *
 * The caller has decremented the SP by 256 bytes, and stored the following
 * registers in slots on the stack according to their number (sp + 8 * xN):
 *
 *   x1/ra:     return address to user code
 *   x8/s0/fp:  saved value from user code
 *   x10/a0:    saved value from user code
 *   x11/a1:    saved value from user code
 */
SYM_CODE_START(__hwasan_tag_mismatch)
	/* Store the remaining unclobbered caller-saved regs */
	sd	t0, (8 *  5)(sp)
	sd	a2, (8 * 12)(sp)
	sd	a3, (8 * 13)(sp)
	sd	a4, (8 * 14)(sp)
	sd	a5, (8 * 15)(sp)
	sd	a6, (8 * 16)(sp)
	sd	a7, (8 * 17)(sp)

	/* a0 and a1 are already set by the thunk */
	ld	a2, (8 *  1)(sp)
	call	kasan_tag_mismatch

	ld	ra, (8 *  1)(sp)
	ld	t0, (8 *  5)(sp)
	ld	a0, (8 * 10)(sp)
	ld	a1, (8 * 11)(sp)
	ld	a2, (8 * 12)(sp)
	ld	a3, (8 * 13)(sp)
	ld	a4, (8 * 14)(sp)
	ld	a5, (8 * 15)(sp)
	ld	a6, (8 * 16)(sp)
	ld	a7, (8 * 17)(sp)
	addi	sp, sp, 256
	ret
SYM_CODE_END(__hwasan_tag_mismatch)
EXPORT_SYMBOL(__hwasan_tag_mismatch)

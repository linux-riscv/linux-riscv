/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015 Regents of the University of California
 */

#ifndef _ASM_RISCV_LINKAGE_H
#define _ASM_RISCV_LINKAGE_H

#ifdef __ASSEMBLY__
#include <asm/assembler.h>
#endif

#define __ALIGN		.balign 4
#define __ALIGN_STR	".balign 4"

#ifdef __riscv_zicfilp
/*
 * A landing pad instruction is needed at start of asm routines
 * re-define macros for asm routines to have a landing pad at
 * the beginning of function. Currently use label value of 0x1.
 * Eventually, label should be calculated as a hash over function
 * signature.
 */
#define SYM_FUNC_START(name)				\
	SYM_START(name, SYM_L_GLOBAL, SYM_A_ALIGN)	\
	lpad 0x1;

#define SYM_FUNC_START_NOALIGN(name)			\
	SYM_START(name, SYM_L_GLOBAL, SYM_A_NONE)	\
	lpad 0x1;

#define SYM_FUNC_START_LOCAL(name)			\
	SYM_START(name, SYM_L_LOCAL, SYM_A_ALIGN)	\
	lpad 0x1;

#define SYM_FUNC_START_LOCAL_NOALIGN(name)		\
	SYM_START(name, SYM_L_LOCAL, SYM_A_NONE)	\
	lpad 0x1;

#define SYM_FUNC_START_WEAK(name)			\
	SYM_START(name, SYM_L_WEAK, SYM_A_ALIGN)	\
	lpad 0x1;

#define SYM_FUNC_START_WEAK_NOALIGN(name)		\
	SYM_START(name, SYM_L_WEAK, SYM_A_NONE)		\
	lpad 0x1;

#define SYM_TYPED_FUNC_START(name)				\
	SYM_TYPED_START(name, SYM_L_GLOBAL, SYM_A_ALIGN)	\
	lpad 0x1;

#endif

#endif /* _ASM_RISCV_LINKAGE_H */

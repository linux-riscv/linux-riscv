/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/linkage.h>
#include <asm-generic/export.h>
#include <asm/asm.h>
#include <asm/asm-extable.h>
#include <asm/csr.h>

#define pDst a0
#define pSrc a1
#define iNum a2

#define iVL a3

#define ELEM_LMUL_SETTING m8
#define vData v0

	.macro fixup op reg addr lbl
100:
	\op \reg, \addr
	_asm_extable	100b, \lbl
	.endm

SYM_FUNC_START(__asm_vector_usercopy)
	/* Enable access to user memory */
	li t6, SR_SUM
	csrs CSR_STATUS, t6

loop:
	vsetvli iVL, iNum, e8, ELEM_LMUL_SETTING, ta, ma
	fixup vle8.v vData, (pSrc), 10f
	fixup vse8.v vData, (pDst), 10f
	sub iNum, iNum, iVL
	add pSrc, pSrc, iVL
	add pDst, pDst, iVL
	bnez iNum, loop

	/* Exception fixup code. It's the same as normal exit */
10:
	/* Disable access to user memory */
	csrc	CSR_STATUS, t6
	mv	a0, iNum
	ret
SYM_FUNC_END(__asm_vector_usercopy)

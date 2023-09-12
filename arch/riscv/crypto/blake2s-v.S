/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * BLAKE2s RISC-V V implementation
 *
 * Copyright (C) 2022 Rivos, Inc. All Rights Reserved.
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2017-2019 Samuel Neves <sneves@dei.uc.pt>. All Rights Reserved.
 */

#include <linux/linkage.h>
#include <asm/asm.h>

.section .rodata, "a", @progbits

.align 8
IV:
.octa 0xA54FF53A3C6EF372BB67AE856A09E667
.octa 0x5BE0CD191F83D9AB9B05688C510E527F

.align 8
SIGMA2:
.long  0,  2,  4,  6,  1,  3,  5,  7, 14,  8, 10, 12, 15,  9, 11, 13
.long  8,  2, 13, 15, 10,  9, 12,  3,  6,  4,  0, 14,  5, 11,  1,  7
.long 11, 13,  8,  6,  5, 10, 14,  3,  2,  4, 12, 15,  1,  0,  7,  9
.long 11, 10,  7,  0,  8, 15,  1, 13,  3,  6,  2, 12,  4, 14,  9,  5
.long  4, 10,  9, 14, 15,  0, 11,  8,  1,  7,  3, 13,  2,  5,  6, 12
.long  2, 11,  4, 15, 14,  3, 10,  8, 13,  6,  5,  7,  0, 12,  1,  9
.long  4,  8, 15,  9, 14, 11, 13,  5,  3,  2,  1, 12,  6, 10,  7,  0
.long  6, 13,  0, 14, 12,  2,  1, 11, 15,  4,  5,  8,  7,  9,  3, 10
.long 15,  5,  4, 13, 10,  7,  3, 11, 12,  2,  0,  6,  9,  8,  1, 14
.long  8,  7, 14, 11, 13, 15,  0, 12, 10,  4,  5,  6,  3,  2,  1,  9

.align 8
GATHER_DIAG1:
.long  3, 0, 1, 2
.align 8
GATHER_DIAG2:
.long  2, 3, 0, 1
.align 8
GATHER_DIAG3:
.long  1, 2, 3, 0

.section .text

.macro VROR REG BITS TMPREG
	vmv.v.v		\TMPREG, \REG
	vsrl.vi		\REG, \REG, \BITS
	vsll.vi		\TMPREG, \TMPREG, 32-\BITS
	vor.vv		\REG, \REG, \TMPREG
.endm

/*
 * void blake2s_compress_vector(struct blake2s_state *state,
 *        const u8 *block, size_t nblocks, const u32 inc)
 *
 * blake2s_compress_vector is a translation of the AVX512 variant
 * (arch/x86/blake2s-core.S) to RISC-V V. The implementation requires
 * VLEN>=256b.
 *
 */
SYM_FUNC_START(blake2s_compress_vector)
	vsetivli	t0, 1, e32, m1, ta, ma
	vmv.v.x		v5, a3
	vsetivli	t0, 4, e32, m1, ta, ma
	vle32.v		v0, (a0)
	addi		t0, a0, 0x10
	vle32.v		v1, (t0)
	addi		t0, t0, 0x10
	vle32.v		v4, (t0)
	la		t0, IV
	vle32.v		v14, (t0)
	la		t0, IV+16
	vle32.v		v15, (t0)
	la		t0, GATHER_DIAG1
	vle32.v		v16, (t0)
	la		t0, GATHER_DIAG2
	vle32.v		v18, (t0)
	la		t0, GATHER_DIAG3
	vle32.v		v19, (t0)
.Lblake2s_compress_vector_mainloop:
	vmv.v.v		v10, v0
	vmv.v.v		v11, v1
	vadd.vv		v4, v5, v4
	vmv.v.v		v2, v14
	vxor.vv		v3, v15, v4
	vsetivli	t0, 8, e32, m1, ta, ma
	vle32.v		v6, (a1)
	addi		a1, a1, 0x20
	vle32.v		v7, (a1)
	addi		a1, a1, 0x20
	la		t1, SIGMA2
	li		t2, 0xa
.Lblake2s_compress_vector_roundloop:
	vsetivli	t0, 8, e32, m1, ta, ma
	vle32.v		v12, (t1)
	addi		t1, t1, 0x20
	vle32.v		v13, (t1)
	addi		t1, t1, 0x20
	vsetivli	t0, 16, e32, m2, ta, ma
	vrgather.vv	v8, v6, v12
	vmv.v.v		v6, v8
	vsetivli	t0, 4, e32, m1, ta, ma
	vadd.vv		v0, v8, v0
	vadd.vv		v0, v1, v0
	vxor.vv		v3, v0, v3
	VROR		v3 16 v17
	vadd.vv		v2, v3, v2
	vxor.vv		v1, v2, v1
	VROR		v1 12 v17
	vsetivli	t0, 8, e32, m1, ta, ma
	vslidedown.vi	v8, v8, 4
	vsetivli	t0, 4, e32, m1, ta, ma
	vadd.vv		v0, v8, v0
	vadd.vv		v0, v1, v0
	vxor.vv		v3, v0, v3
	VROR		v3 8 v17
	vadd.vv		v2, v3, v2
	vxor.vv		v1, v2, v1
	VROR		v1, 7, v17
	vmv.v.v		v17, v0
	vrgather.vv	v0, v17, v16
	vmv.v.v		v17, v3
	vrgather.vv	v3, v17, v18
	vmv.v.v		v17, v2
	vrgather.vv	v2, v17, v19
	vadd.vv		v0, v9, v0
	vadd.vv		v0, v1, v0
	vxor.vv		v3, v0, v3
	VROR		v3 16 v17
	vadd.vv		v2, v3, v2
	vxor.vv		v1, v2, v1
	VROR		v1 12 v17
	vsetivli	t0, 8, e32, m1, ta, ma
	vslidedown.vi	v9, v9, 4
	vsetivli	t0, 4, e32, m1, ta, ma
	vadd.vv		v0, v9, v0
	vadd.vv		v0, v1, v0
	vxor.vv		v3, v0, v3
	VROR		v3, 8, v17
	vadd.vv		v2, v3, v2
	vxor.vv		v1, v2, v1
	VROR		v1 7 v17
	vmv.v.v		v17, v0
	vrgather.vv	v0, v17, v19
	vmv.v.v		v17, v3
	vrgather.vv	v3, v17, v18
	vmv.v.v		v17, v2
	vrgather.vv	v2, v17, v16
	addi		t2, t2, -1
	bne		t2, x0, .Lblake2s_compress_vector_roundloop
	vxor.vv		v0, v10, v0
	vxor.vv		v1, v11, v1
	vxor.vv		v0, v2, v0
	vxor.vv		v1, v3, v1
	addi		a2, a2, -1
	bne		a2, x0, .Lblake2s_compress_vector_mainloop
	vse32.v		v0, (a0)
	addi		a0, a0, 0x10
	vse32.v		v1, (a0)
	addi		a0, a0, 0x10
	vse32.v		v4, (a0)
	ret
SYM_FUNC_END(blake2s_compress_vector)


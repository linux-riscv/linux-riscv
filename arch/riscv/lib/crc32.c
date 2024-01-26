// SPDX-License-Identifier: GPL-2.0-only
/*
 * Accelerated CRC32 implementation with Zbc extension.
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Authors:
 *     Xiao Wang <xiao.w.wang@intel.com>
 */

#include <asm/hwcap.h>
#include <asm/alternative-macros.h>
#include <asm/byteorder.h>

#include <linux/types.h>
#include <linux/minmax.h>
#include <linux/crc32poly.h>
#include <linux/crc32.h>
#include <linux/byteorder/generic.h>

/*
 * Refer to https://www.corsix.org/content/barrett-reduction-polynomials for
 * better understanding of how this math works.
 *
 * let "+" denotes polynomial add (XOR)
 * let "-" denotes polynomial sub (XOR)
 * let "*" denotes polynomial multiplication
 * let "/" denotes polynomial floor division
 * let "S" denotes source data, XLEN bit wide
 * let "P" denotes CRC32 polynomial
 * let "T" denotes 2^(XLEN+32)
 * let "QT" denotes quotient of T/P, with the bit for 2^XLEN being implicit
 *
 * crc32(S, P)
 * => S * (2^32) - S * (2^32) / P * P
 * => lowest 32 bits of: S * (2^32) / P * P
 * => lowest 32 bits of: S * (2^32) * (T / P) / T * P
 * => lowest 32 bits of: S * (2^32) * quotient / T * P
 * => lowest 32 bits of: S * quotient / 2^XLEN * P
 * => lowest 32 bits of: (clmul_high_part(S, QT) + S) * P
 * => clmul_low_part(clmul_high_part(S, QT) + S, P)
 *
 * In terms of below implementations, the BE case is more intuitive, since the
 * higher order bit sits at more significant position.
 */

#if __riscv_xlen == 64
/* Slide by XLEN bits per iteration */
# define STEP_ORDER 3

/* Each below polynomial quotient has an implicit bit for 2^XLEN */

/* Polynomial quotient of (2^(XLEN+32))/CRC32_POLY, in LE format */
# define CRC32_POLY_QT_LE	0x5a72d812fb808b20

/* Polynomial quotient of (2^(XLEN+32))/CRC32C_POLY, in LE format */
# define CRC32C_POLY_QT_LE	0xa434f61c6f5389f8

/* Polynomial quotient of (2^(XLEN+32))/CRC32_POLY, in BE format, it should be
 * the same as the bit-reversed version of CRC32_POLY_QT_LE
 */
# define CRC32_POLY_QT_BE	0x04d101df481b4e5a

static inline u32 crc32_le_zbc(u32 crc, const unsigned long *ptr, u32 poly,
			       unsigned long poly_qt)
{
		u64 s = (u64)crc ^ (__force u64)__cpu_to_le64(*ptr);
		/*
		 * We don't have a "clmulrh" insn, so use clmul + slli instead.
		 */
		asm volatile (".option push\n"
			      ".option arch,+zbc\n"
			      "clmul	%0, %1, %2\n"
			      "slli	%0, %0, 1\n"
			      "xor	%0, %0, %1\n"
			      "clmulr	%0, %0, %3\n"
			      "srli	%0, %0, 32\n"
			      ".option pop\n"
			      : "=&r" (crc)
			      : "r" (s),
				"r" (poly_qt),
				"r" ((u64)poly << 32)
			      :);
		return crc;
}

#elif __riscv_xlen == 32
# define STEP_ORDER 2
/* Each quotient should match the upper half of its analog in RV64 */
# define CRC32_POLY_QT_LE	0xfb808b20
# define CRC32C_POLY_QT_LE	0x6f5389f8
# define CRC32_POLY_QT_BE	0x04d101df

static inline u32 crc32_le_zbc(u32 crc, const unsigned long *ptr, u32 poly,
			       unsigned long poly_qt)
{
		u32 s = crc ^ (__force u32)__cpu_to_le32(*ptr);
		/*
		 * We don't have a "clmulrh" insn, so use clmul + slli instead.
		 */
		asm volatile (".option push\n"
			      ".option arch,+zbc\n"
			      "clmul	%0, %1, %2\n"
			      "slli	%0, %0, 1\n"
			      "xor	%0, %0, %1\n"
			      "clmulr	%0, %0, %3\n"
			      ".option pop\n"
			      : "=&r" (crc)
			      : "r" (s),
				"r" (poly_qt),
				"r" (poly)
			      :);
		return crc;
}

#else
# error "Unexpected __riscv_xlen"
#endif

#define STEP		(1 << STEP_ORDER)
#define OFFSET_MASK	(STEP - 1)

typedef u32 (*fallback)(u32 crc, unsigned char const *p, size_t len);

static inline u32 __pure crc32_le_generic(u32 crc, unsigned char const *p,
					  size_t len, u32 poly,
					  unsigned long poly_qt,
					  fallback crc_fb)
{
	size_t offset, head_len, tail_len;
	const unsigned long *p_ul;

	asm_volatile_goto(ALTERNATIVE("j %l[legacy]", "nop", 0,
				      RISCV_ISA_EXT_ZBC, 1)
			  : : : : legacy);

	/* Handle the unalignment head. */
	offset = (unsigned long)p & OFFSET_MASK;
	if (offset) {
		head_len = min(STEP - offset, len);
		crc = crc_fb(crc, p, head_len);
		len -= head_len;
		p += head_len;
	}

	tail_len = len & OFFSET_MASK;
	len = len >> STEP_ORDER;
	p_ul = (unsigned long *)p;

	for (int i = 0; i < len; i++) {
		crc = crc32_le_zbc(crc, p_ul, poly, poly_qt);
		p_ul++;
	}

	/* Handle the tail bytes. */
	if (tail_len)
		crc = crc_fb(crc, (unsigned char const *)p_ul, tail_len);
	return crc;

legacy:
	return crc_fb(crc, p, len);
}

u32 __pure crc32_le(u32 crc, unsigned char const *p, size_t len)
{
	return crc32_le_generic(crc, p, len, CRC32_POLY_LE, CRC32_POLY_QT_LE,
				crc32_le_base);
}

u32 __pure __crc32c_le(u32 crc, unsigned char const *p, size_t len)
{
	return crc32_le_generic(crc, p, len, CRC32C_POLY_LE,
				CRC32C_POLY_QT_LE, __crc32c_le_base);
}

u32 __pure crc32_be(u32 crc, unsigned char const *p, size_t len)
{
	size_t offset, head_len, tail_len;
	const unsigned long *p_ul;
	unsigned long s;

	asm_volatile_goto(ALTERNATIVE("j %l[legacy]", "nop", 0,
				      RISCV_ISA_EXT_ZBC, 1)
			  : : : : legacy);

	/* Handle the unalignment head. */
	offset = (unsigned long)p & OFFSET_MASK;
	if (offset) {
		head_len = min(STEP - offset, len);
		crc = crc32_be_base(crc, p, head_len);
		len -= head_len;
		p += head_len;
	}

	tail_len = len & OFFSET_MASK;
	len = len >> STEP_ORDER;
	p_ul = (unsigned long *)p;

	for (int i = 0; i < len; i++) {
#if __riscv_xlen == 64
		s = (u64)crc << 32;
		s ^= (__force u64)__cpu_to_be64(*p_ul++);
#else
		s = crc ^ (__force u32)__cpu_to_be32(*p_ul++);
#endif
		asm volatile (".option push\n"
			      ".option arch,+zbc\n"
			      "clmulh	%0, %1, %2\n"
			      "xor	%0, %0, %1\n"
			      "clmul	%0, %0, %3\n"
			      ".option pop\n"
			      : "=&r" (crc)
			      : "r" (s),
				"r" (CRC32_POLY_QT_BE),
				"r" (CRC32_POLY_BE)
			      :);
	}

	/* Handle the tail bytes. */
	if (tail_len)
		crc = crc32_be_base(crc, (unsigned char const *)p_ul, tail_len);
	return crc;

legacy:
	return crc32_be_base(crc, p, len);
}

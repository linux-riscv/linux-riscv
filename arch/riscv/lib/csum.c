// SPDX-License-Identifier: GPL-2.0
/*
 * IP checksum library
 *
 * Influenced by arch/arm64/lib/csum.c
 * Copyright (C) 2023 Rivos Inc.
 */
#include <linux/bitops.h>
#include <linux/compiler.h>
#include <linux/kasan-checks.h>
#include <linux/kernel.h>

#include <net/checksum.h>

/* Default version is sufficient for 32 bit */
#ifndef CONFIG_32BIT
__sum16 csum_ipv6_magic(const struct in6_addr *saddr,
			const struct in6_addr *daddr,
			__u32 len, __u8 proto, __wsum csum)
{
	unsigned int ulen, uproto;
	unsigned long sum = csum;

	sum += saddr->s6_addr32[0];
	sum += saddr->s6_addr32[1];
	sum += saddr->s6_addr32[2];
	sum += saddr->s6_addr32[3];

	sum += daddr->s6_addr32[0];
	sum += daddr->s6_addr32[1];
	sum += daddr->s6_addr32[2];
	sum += daddr->s6_addr32[3];

	ulen = htonl((unsigned int)len);
	sum += ulen;

	uproto = htonl(proto);
	sum += uproto;

	/*
	 * Zbb support saves 4 instructions, so not worth checking without
	 * alternatives if supported
	 */
	if (IS_ENABLED(CONFIG_RISCV_ISA_ZBB) &&
	    IS_ENABLED(CONFIG_RISCV_ALTERNATIVE)) {
		unsigned long fold_temp;

		/*
		 * Zbb is likely available when the kernel is compiled with Zbb
		 * support, so nop when Zbb is available and jump when Zbb is
		 * not available.
		 */
		asm_volatile_goto(ALTERNATIVE("j %l[no_zbb]", "nop", 0,
					      RISCV_ISA_EXT_ZBB, 1)
				  :
				  :
				  :
				  : no_zbb);
		asm(".option push					\n\
		.option arch,+zbb					\n\
			rori	%[fold_temp], %[sum], 32		\n\
			add	%[sum], %[fold_temp], %[sum]		\n\
			srli	%[sum], %[sum], 32			\n\
			not	%[fold_temp], %[sum]			\n\
			roriw	%[sum], %[sum], 16			\n\
			subw	%[sum], %[fold_temp], %[sum]		\n\
		.option pop"
		: [sum] "+r" (sum), [fold_temp] "=&r" (fold_temp));
		return (__force __sum16)(sum >> 16);
	}
no_zbb:
	sum += ror64(sum, 32);
	sum >>= 32;
	return csum_fold((__force __wsum)sum);
}
EXPORT_SYMBOL(csum_ipv6_magic);
#endif // !CONFIG_32BIT

#ifdef CONFIG_32BIT
#define OFFSET_MASK 3
#elif CONFIG_64BIT
#define OFFSET_MASK 7
#endif

/*
 * Perform a checksum on an arbitrary memory address.
 * Algorithm accounts for buff being misaligned.
 * If buff is not aligned, will over-read bytes but not use the bytes that it
 * shouldn't. The same thing will occur on the tail-end of the read.
 */
unsigned int __no_sanitize_address do_csum(const unsigned char *buff, int len)
{
	unsigned int offset, shift;
	unsigned long csum = 0, carry = 0, data;
	const unsigned long *ptr, *end;

	if (unlikely(len <= 0))
		return 0;

	end = (const unsigned long *)(buff + len);

	/*
	 * Align address to closest word (double word on rv64) that comes before
	 * buff. This should always be in the same page and cache line.
	 * Directly call KASAN with the alignment we will be using.
	 */
	offset = (unsigned long)buff & OFFSET_MASK;
	kasan_check_read(buff, len);
	ptr = (const unsigned long *)(buff - offset);

	/*
	 * Clear the most significant bytes that were over-read if buff was not
	 * aligned.
	 */
	shift = offset * 8;
	data = *(ptr++);
#ifdef __LITTLE_ENDIAN
	data = (data >> shift) << shift;
#else
	data = (data << shift) >> shift;
#endif
	/*
	 * Do 32-bit reads on RV32 and 64-bit reads otherwise. This should be
	 * faster than doing 32-bit reads on architectures that support larger
	 * reads.
	 */
	while (ptr < end) {
		csum += data;
		carry += csum < data;
		len -= sizeof(long);
		data = *(ptr++);
	}

	/*
	 * Perform alignment (and over-read) bytes on the tail if any bytes
	 * leftover.
	 */
	shift = ((long)ptr - (long)end) * 8;
#ifdef __LITTLE_ENDIAN
	data = (data << shift) >> shift;
#else
	data = (data >> shift) << shift;
#endif
	csum += data;
	carry += csum < data;
	csum += carry;
	csum += csum < carry;

	/*
	 * Zbb support saves 6 instructions, so not worth checking without
	 * alternatives if supported
	 */
	if (IS_ENABLED(CONFIG_RISCV_ISA_ZBB) &&
	    IS_ENABLED(CONFIG_RISCV_ALTERNATIVE)) {
		unsigned long fold_temp;

		/*
		 * Zbb is likely available when the kernel is compiled with Zbb
		 * support, so nop when Zbb is available and jump when Zbb is
		 * not available.
		 */
		asm_volatile_goto(ALTERNATIVE("j %l[no_zbb]", "nop", 0,
					      RISCV_ISA_EXT_ZBB, 1)
				  :
				  :
				  :
				  : no_zbb);

#ifdef CONFIG_32BIT
		asm_volatile_goto(".option push			\n\
		.option arch,+zbb				\n\
			rori	%[fold_temp], %[csum], 16	\n\
			andi	%[offset], %[offset], 1		\n\
			add	%[csum], %[fold_temp], %[csum]	\n\
			beq	%[offset], zero, %l[end]	\n\
			rev8	%[csum], %[csum]		\n\
		.option pop"
			: [csum] "+r" (csum),
				[fold_temp] "=&r" (fold_temp)
			: [offset] "r" (offset)
			:
			: end);

		return (unsigned short)csum;
#else // !CONFIG_32BIT
		asm_volatile_goto(".option push			\n\
		.option arch,+zbb				\n\
			rori	%[fold_temp], %[csum], 32	\n\
			add	%[csum], %[fold_temp], %[csum]	\n\
			srli	%[csum], %[csum], 32		\n\
			roriw	%[fold_temp], %[csum], 16	\n\
			addw	%[csum], %[fold_temp], %[csum]	\n\
			andi	%[offset], %[offset], 1		\n\
			beq	%[offset], zero, %l[end]	\n\
			rev8	%[csum], %[csum]		\n\
		.option pop"
			: [csum] "+r" (csum),
				[fold_temp] "=&r" (fold_temp)
			: [offset] "r" (offset)
			:
			: end);

		return (csum << 16) >> 48;
#endif // !CONFIG_32BIT
end:
		return csum >> 16;
	}
no_zbb:
#ifndef CONFIG_32BIT
	csum += ror64(csum, 32);
	csum >>= 32;
#endif
	csum = (u32)csum + ror32((u32)csum, 16);
	if (offset & 1)
		return (u16)swab32(csum);
	return csum >> 16;
}

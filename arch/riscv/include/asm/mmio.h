/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * {read,write}{b,w,l,q} based on arch/arm64/include/asm/io.h
 *   which was based on arch/arm/include/io.h
 *
 * Copyright (C) 1996-2000 Russell King
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2014 Regents of the University of California
 */

#ifndef _ASM_RISCV_MMIO_H
#define _ASM_RISCV_MMIO_H

#include <linux/types.h>
#include <asm/mmiowb.h>

/* Generic IO read/write.  These perform native-endian accesses. */
#define __raw_writeb __raw_writeb
static inline void __raw_writeb(u8 val, volatile void __iomem *addr)
{
	asm volatile("sb %0, 0(%1)" : : "r" (val), "r" (addr));
}

#define __raw_writew __raw_writew
static inline void __raw_writew(u16 val, volatile void __iomem *addr)
{
	asm volatile("sh %0, 0(%1)" : : "r" (val), "r" (addr));
}

#define __raw_writel __raw_writel
static inline void __raw_writel(u32 val, volatile void __iomem *addr)
{
	asm volatile("sw %0, 0(%1)" : : "r" (val), "r" (addr));
}

#ifdef CONFIG_64BIT
#define __raw_writeq __raw_writeq
static inline void __raw_writeq(u64 val, volatile void __iomem *addr)
{
	asm volatile("sd %0, 0(%1)" : : "r" (val), "r" (addr));
}
#endif

#define __raw_readb __raw_readb
static inline u8 __raw_readb(const volatile void __iomem *addr)
{
	u8 val;

	asm volatile("lb %0, 0(%1)" : "=r" (val) : "r" (addr));
	return val;
}

#define __raw_readw __raw_readw
static inline u16 __raw_readw(const volatile void __iomem *addr)
{
	u16 val;

	asm volatile("lh %0, 0(%1)" : "=r" (val) : "r" (addr));
	return val;
}

#define __raw_readl __raw_readl
static inline u32 __raw_readl(const volatile void __iomem *addr)
{
	u32 val;

	asm volatile("lw %0, 0(%1)" : "=r" (val) : "r" (addr));
	return val;
}

#ifdef CONFIG_64BIT
#define __raw_readq __raw_readq
static inline u64 __raw_readq(const volatile void __iomem *addr)
{
	u64 val;

	asm volatile("ld %0, 0(%1)" : "=r" (val) : "r" (addr));
	return val;
}
#endif

/*
 * I/O barriers. The memory barriers here are necessary as RISC-V
 * doesn't define any ordering between the memory space and the I/O space.
 */
#define __io_br()	do {} while (0)
#define __io_ar(v)	({ __asm__ __volatile__ ("fence i,ir" : : : "memory"); })
#define __io_bw()	({ __asm__ __volatile__ ("fence w,o" : : : "memory"); })
#define __io_aw()	mmiowb_set_pending()

#endif /* _ASM_RISCV_MMIO_H */

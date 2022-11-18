/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_TIMEX_H
#define _ASM_RISCV_TIMEX_H

#include <asm/csr.h>

typedef unsigned long cycles_t;


#ifdef CONFIG_CLINT_TIMER_MMIO

#include <asm/clint.h>

#ifdef CONFIG_64BIT
static inline cycles_t get_cycles(void)
{
	return readq_relaxed(clint_time_val);
}
#else /* !CONFIG_64BIT */
static inline u32 get_cycles(void)
{
	return readl_relaxed(((u32 *)clint_time_val));
}
#define get_cycles get_cycles

static inline u32 get_cycles_hi(void)
{
	return readl_relaxed(((u32 *)clint_time_val) + 1);
}
#define get_cycles_hi get_cycles_hi
#endif /* CONFIG_64BIT */

/*
 * Much like MIPS, we may not have a viable counter to use at an early point
 * in the boot process. Unfortunately we don't have a fallback, so instead
 * we just return 0.
 */
static inline unsigned long random_get_entropy(void)
{
	if (unlikely(clint_time_val == NULL))
		return random_get_entropy_fallback();
	return get_cycles();
}
#define random_get_entropy()	random_get_entropy()

#else /* CONFIG_CLINT_TIMER_MMIO */

#ifdef CONFIG_RISCV_FAKE_TIMER
extern u64 _hack_fake_time;
#endif

static inline cycles_t get_cycles(void)
{
#ifdef CONFIG_RISCV_FAKE_TIMER
	return _hack_fake_time++;
#else
	return csr_read(CSR_TIME);
#endif
}
#define get_cycles get_cycles

static inline u32 get_cycles_hi(void)
{
	return csr_read(CSR_TIMEH);
}
#define get_cycles_hi get_cycles_hi

#endif /* !CONFIG_CLINT_TIMER_MMIO */

#ifdef CONFIG_64BIT
static inline u64 get_cycles64(void)
{
	return get_cycles();
}
#else /* CONFIG_64BIT */
static inline u64 get_cycles64(void)
{
	u32 hi, lo;

	do {
		hi = get_cycles_hi();
		lo = get_cycles();
	} while (hi != get_cycles_hi());

	return ((u64)hi << 32) | lo;
}
#endif /* CONFIG_64BIT */

#define ARCH_HAS_READ_CURRENT_TIMER
static inline int read_current_timer(unsigned long *timer_val)
{
	*timer_val = get_cycles();
	return 0;
}

extern void time_init(void);

#endif /* _ASM_RISCV_TIMEX_H */

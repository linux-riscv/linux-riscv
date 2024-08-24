/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_PERCPU_H
#define __ASM_PERCPU_H

static inline void set_my_cpu_offset(unsigned long off)
{
	asm volatile("addi gp, %0, 0" :: "r" (off));
}

static inline unsigned long __kern_my_cpu_offset(void)
{
	unsigned long off;

	asm ("mv %0, gp":"=r" (off) :);
	return off;
}

#define __my_cpu_offset __kern_my_cpu_offset()

#include <asm-generic/percpu.h>

#endif /* __ASM_PERCPU_H */


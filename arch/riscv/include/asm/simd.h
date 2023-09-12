/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2017 Linaro Ltd. <ard.biesheuvel@linaro.org>
 * Copyright (C) 2023 SiFive
 */

#ifndef __ASM_SIMD_H
#define __ASM_SIMD_H

#include <linux/compiler.h>
#include <linux/irqflags.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/types.h>
#include <linux/thread_info.h>

#ifdef CONFIG_RISCV_ISA_V

DECLARE_PER_CPU(bool, vector_context_busy);

/*
 * may_use_simd - whether it is allowable at this time to issue vector
 *                instructions or access the vector register file
 *
 * Callers must not assume that the result remains true beyond the next
 * preempt_enable() or return from softirq context.
 */
static __must_check inline bool may_use_simd(void)
{
	/*
	 * vector_context_busy is only set while preemption is disabled,
	 * and is clear whenever preemption is enabled. Since
	 * this_cpu_read() is atomic w.r.t. preemption, vector_context_busy
	 * cannot change under our feet -- if it's set we cannot be
	 * migrated, and if it's clear we cannot be migrated to a CPU
	 * where it is set.
	 */
	return !in_irq() && !irqs_disabled() && !in_nmi() &&
	       !this_cpu_read(vector_context_busy) &&
	       !test_thread_flag(TIF_RISCV_V_KERNEL_MODE);
}

#else /* ! CONFIG_RISCV_ISA_V */

static __must_check inline bool may_use_simd(void)
{
	return false;
}

#endif /* ! CONFIG_RISCV_ISA_V */

#endif

/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Christoph Muellner <christoph.muellner@vrull.eu>
 */

#ifndef __ASM_RISCV_DTSO_H
#define __ASM_RISCV_DTSO_H

#ifdef CONFIG_RISCV_ISA_SSDTSO

#include <linux/sched/task_stack.h>
#include <asm/cpufeature.h>
#include <asm/csr.h>

static __always_inline bool has_dtso(void)
{
	return riscv_has_extension_unlikely(RISCV_ISA_EXT_SSDTSO);
}

static inline bool dtso_is_enabled(void)
{
	if (has_dtso())
		return csr_read(CSR_SENVCFG) & ENVCFG_DTSO;
	return 0;
}

static inline void dtso_disable(void)
{
	if (has_dtso())
		csr_clear(CSR_SENVCFG, ENVCFG_DTSO);
}

static inline void dtso_enable(void)
{
	if (has_dtso())
		csr_set(CSR_SENVCFG, ENVCFG_DTSO);
}

static inline void dtso_save(struct task_struct *task)
{
	task->thread.dtso_ena = dtso_is_enabled();
}

static inline void dtso_restore(struct task_struct *task)
{
	if (task->thread.dtso_ena)
		dtso_enable();
	else
		dtso_disable();
}

static inline void __switch_to_dtso(struct task_struct *prev,
				    struct task_struct *next)
{
	struct pt_regs *regs;

	regs = task_pt_regs(prev);
	dtso_save(prev);
	dtso_restore(next);
}

#else /* ! CONFIG_RISCV_ISA_SSDTSO */

static __always_inline bool has_dtso(void) { return false; }
static __always_inline bool dtso_is_enabled(void) { return false; }
#define dtso_disable() do { } while (0)
#define dtso_enable() do { } while (0)
#define dtso_save(task) do { } while (0)
#define dtso_restore(task) do { } while (0)
#define __switch_to_dtso(prev, next) do { } while (0)

#endif /* CONFIG_RISCV_ISA_SSDTSO */

#endif /* ! __ASM_RISCV_DTSO_H */

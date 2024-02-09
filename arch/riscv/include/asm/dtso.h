/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Christoph Muellner <christoph.muellner@vrull.eu>
 */

#ifndef __ASM_RISCV_DTSO_H
#define __ASM_RISCV_DTSO_H

#define RISCV_MEMORY_CONSISTENCY_MODEL_WMO     0
#define RISCV_MEMORY_CONSISTENCY_MODEL_TSO     1

#ifdef CONFIG_RISCV_ISA_SSDTSO

#include <linux/sched/task_stack.h>
#include <asm/cpufeature.h>
#include <asm/csr.h>

static __always_inline bool has_dtso(void)
{
	return riscv_has_extension_unlikely(RISCV_ISA_EXT_SSDTSO);
}

static __always_inline bool has_ztso(void)
{
	return riscv_has_extension_unlikely(RISCV_ISA_EXT_ZTSO);
}

static inline bool dtso_is_enabled(void)
{
	if (has_dtso())
		return csr_read(CSR_SENVCFG) & ENVCFG_DTSO;
	return 0;
}

static inline void dtso_disable(void)
{
	if (has_dtso() && !has_ztso())
		csr_clear(CSR_SENVCFG, ENVCFG_DTSO);
}

static inline void dtso_enable(void)
{
	if (has_dtso() && !has_ztso())
		csr_set(CSR_SENVCFG, ENVCFG_DTSO);
}

static inline unsigned long get_memory_consistency_model(
		struct task_struct *task)
{
	return task->memory_consistency_model;
}

static inline void set_memory_consitency_model(struct task_struct *task,
		unsigned long model)
{
	task->memory_consistency_model = model;
}

static inline void dtso_restore(struct task_struct *task)
{
	unsigned long cur_model = get_memory_consistency_model(task);

	if (cur_model == RISCV_MEMORY_CONSISTENCY_MODEL_TSO)
		dtso_enable();
	else
		dtso_disable();
}

static inline void __switch_to_dtso(struct task_struct *prev,
				    struct task_struct *next)
{
	struct pt_regs *regs;

	regs = task_pt_regs(prev);

	/*
	 * We don't need to save the DTSO bit, because we don't expect it to
	 * change. So any mechanism that changes the DTSO bit, needs to take
	 * care to write to task->memory_consistency_model (and reschedule
	 * all threads of the process).
	 */

	dtso_restore(next);
}

#else /* ! CONFIG_RISCV_ISA_SSDTSO */

static __always_inline bool has_dtso(void) { return false; }
static __always_inline bool dtso_is_enabled(void) { return false; }
#define dtso_disable() do { } while (0)
#define dtso_enable() do { } while (0)
#define dtso_restore(task) do { } while (0)
#define __switch_to_dtso(prev, next) do { } while (0)

#endif /* CONFIG_RISCV_ISA_SSDTSO */

#endif /* ! __ASM_RISCV_DTSO_H */

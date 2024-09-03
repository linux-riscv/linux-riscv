/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_SWITCH_TO_H
#define _ASM_RISCV_SWITCH_TO_H

#include <linux/jump_label.h>
#include <linux/sched/task_stack.h>
#include <linux/mm_types.h>
#include <asm/vector.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/csr.h>

#ifdef CONFIG_FPU
extern void __fstate_save(struct task_struct *save_to);
extern void __fstate_restore(struct task_struct *restore_from);

static inline void __fstate_clean(struct pt_regs *regs)
{
	regs->status = (regs->status & ~SR_FS) | SR_FS_CLEAN;
}

static inline void fstate_off(struct task_struct *task,
			      struct pt_regs *regs)
{
	regs->status = (regs->status & ~SR_FS) | SR_FS_OFF;
}

static inline void fstate_save(struct task_struct *task,
			       struct pt_regs *regs)
{
	if ((regs->status & SR_FS) == SR_FS_DIRTY) {
		__fstate_save(task);
		__fstate_clean(regs);
	}
}

static inline void fstate_restore(struct task_struct *task,
				  struct pt_regs *regs)
{
	if ((regs->status & SR_FS) != SR_FS_OFF) {
		__fstate_restore(task);
		__fstate_clean(regs);
	}
}

static inline void __switch_to_fpu(struct task_struct *prev,
				   struct task_struct *next)
{
	struct pt_regs *regs;

	regs = task_pt_regs(prev);
	fstate_save(prev, regs);
	fstate_restore(next, task_pt_regs(next));
}

static __always_inline bool has_fpu(void)
{
	return riscv_has_extension_likely(RISCV_ISA_EXT_f) ||
		riscv_has_extension_likely(RISCV_ISA_EXT_d);
}
#else
static __always_inline bool has_fpu(void) { return false; }
#define fstate_save(task, regs) do { } while (0)
#define fstate_restore(task, regs) do { } while (0)
#define __switch_to_fpu(__prev, __next) do { } while (0)
#endif

extern struct task_struct *__switch_to(struct task_struct *,
				       struct task_struct *);

static inline bool switch_to_should_flush_icache(struct task_struct *task)
{
#ifdef CONFIG_SMP
	bool stale_mm = false;
	bool thread_migrated = smp_processor_id() != task->thread.prev_cpu;
	bool stale_thread;

	/*
	 * This pairs with the smp_wmb() in each case of the switch statement in
	 * riscv_set_icache_flush_ctx() as well as the smp_wmb() in set_icache_stale_mask().
	 *
	 * The pairings with the smp_wmb() in the PR_RISCV_SCOPE_PER_PROCESS
	 * cases in riscv_set_icache_flush_ctx() synchronizes this hart with the
	 * updated value of current->mm->context.force_icache_flush.
	 *
	 * The pairings with the smp_wmb() in the PR_RISCV_SCOPE_PER_THREAD cases
	 * in riscv_set_icache_flush_ctx() synchronizes this hart with the
	 * updated value of task->thread.force_icache_flush.
	 *
	 * The pairing with the smp_wmb() in set_icache_stale_mask()
	 * synchronizes this hart with the updated value of task->mm->context.icache_stale_mask.
	 */
	smp_rmb();
	stale_thread = thread_migrated && task->thread.force_icache_flush;

	if (task->mm) {
		/*
		 * The mm is only stale if the respective CPU bit in
		 * icache_stale_mask is set.
		 */
		stale_mm = cpumask_test_cpu(smp_processor_id(),
					    &task->mm->context.icache_stale_mask);

		/*
		 * force_icache_flush indicates that icache_stale_mask should be
		 * set again for this hart before returning to userspace. This
		 * ensures that next time this mm is switched to on this hart,
		 * the icache is flushed only if necessary.
		 */
		cpumask_assign_cpu(smp_processor_id(),
				   &task->mm->context.icache_stale_mask,
				   task->mm->context.force_icache_flush);
	}

	return stale_mm || stale_thread;
#else
	return false;
#endif
}

#ifdef CONFIG_SMP
#define __set_prev_cpu(thread) ((thread).prev_cpu = smp_processor_id())
#else
#define __set_prev_cpu(thread)
#endif

#define switch_to(prev, next, last)			\
do {							\
	struct task_struct *__prev = (prev);		\
	struct task_struct *__next = (next);		\
	__set_prev_cpu(__prev->thread);			\
	if (has_fpu())					\
		__switch_to_fpu(__prev, __next);	\
	if (has_vector())					\
		__switch_to_vector(__prev, __next);	\
	if (switch_to_should_flush_icache(__next))	\
		local_flush_icache_all();		\
	((last) = __switch_to(__prev, __next));		\
} while (0)

#endif /* _ASM_RISCV_SWITCH_TO_H */

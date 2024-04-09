/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shadow Call Stack support.
 *
 * Copyright (C) 2019 Google LLC
 */

#ifndef _LINUX_SCS_H
#define _LINUX_SCS_H

#include <linux/gfp.h>
#include <linux/poison.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <asm/scs.h>

#ifdef CONFIG_SHADOW_CALL_STACK

#define SCS_ORDER		0
#define SCS_SIZE		(PAGE_SIZE << SCS_ORDER)
#define GFP_SCS			(GFP_KERNEL | __GFP_ZERO)

/* An illegal pointer value to mark the end of the shadow stack. */
#define SCS_END_MAGIC		(0x5f6UL + POISON_POINTER_DELTA)

#define task_scs(tsk)		(task_thread_info(tsk)->scs_base)
#define task_scs_sp(tsk)	(task_thread_info(tsk)->scs_sp)

void *scs_alloc(int node);
void scs_free(void *s);
void scs_init(void);
int scs_prepare(struct task_struct *tsk, int node);
void scs_release(struct task_struct *tsk);

#ifdef CONFIG_DYNAMIC_SCS
/* dynamic_scs_enabled set to true if RISCV dynamic SCS */
#ifdef CONFIG_RISCV
DECLARE_STATIC_KEY_TRUE(dynamic_scs_enabled);
#else
DECLARE_STATIC_KEY_FALSE(dynamic_scs_enabled);
#endif
#endif

static inline bool scs_is_dynamic(void)
{
	if (!IS_ENABLED(CONFIG_DYNAMIC_SCS))
		return false;
	return static_branch_likely(&dynamic_scs_enabled);
}

static inline bool scs_is_enabled(void)
{
	if (!IS_ENABLED(CONFIG_DYNAMIC_SCS))
		return true;
	return scs_is_dynamic();
}

static inline void scs_task_reset(struct task_struct *tsk)
{
	/*
	 * Reset the shadow stack to the base address in case the task
	 * is reused.
	 */
	task_scs_sp(tsk) = task_scs(tsk);
}

static inline unsigned long *__scs_magic(void *s)
{
	if (scs_is_dynamic())
		return (unsigned long *)(s);

	return (unsigned long *)(s + SCS_SIZE) - 1;
}

static inline bool task_scs_end_corrupted(struct task_struct *tsk)
{
	unsigned long *magic = __scs_magic(task_scs(tsk));
	unsigned long sz = task_scs_sp(tsk) - task_scs(tsk);

	if (scs_is_dynamic())
		sz = (task_scs(tsk) + SCS_SIZE) - task_scs_sp(tsk);

	return sz >= SCS_SIZE - 1 || READ_ONCE_NOCHECK(*magic) != SCS_END_MAGIC;
}

static inline void __scs_store_magic(unsigned long *s, unsigned long magic_val)
{
	if (scs_is_dynamic())
		arch_scs_store(s, magic_val);
	else
		*__scs_magic(s) = SCS_END_MAGIC;
}

#else /* CONFIG_SHADOW_CALL_STACK */

static inline void *scs_alloc(int node) { return NULL; }
static inline void scs_free(void *s) {}
static inline void scs_init(void) {}
static inline void scs_task_reset(struct task_struct *tsk) {}
static inline int scs_prepare(struct task_struct *tsk, int node) { return 0; }
static inline void scs_release(struct task_struct *tsk) {}
static inline bool task_scs_end_corrupted(struct task_struct *tsk) { return false; }
static inline bool scs_is_enabled(void) { return false; }
static inline bool scs_is_dynamic(void) { return false; }

#endif /* CONFIG_SHADOW_CALL_STACK */

#endif /* _LINUX_SCS_H */

/* SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2024 Rivos, Inc.
 * Deepak Gupta <debug@rivosinc.com>
 */
#ifndef _ASM_RISCV_USERCFI_H
#define _ASM_RISCV_USERCFI_H

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/prctl.h>

struct task_struct;
struct kernel_clone_args;

#ifdef CONFIG_RISCV_USER_CFI
struct cfi_status {
	unsigned long ubcfi_en : 1; /* Enable for backward cfi. */
	unsigned long ubcfi_locked : 1;
	unsigned long rsvd : ((sizeof(unsigned long)*8) - 2);
	unsigned long user_shdw_stk; /* Current user shadow stack pointer */
	unsigned long shdw_stk_base; /* Base address of shadow stack */
	unsigned long shdw_stk_size; /* size of shadow stack */
};

unsigned long shstk_alloc_thread_stack(struct task_struct *tsk,
							const struct kernel_clone_args *args);
void shstk_release(struct task_struct *tsk);
void set_shstk_base(struct task_struct *task, unsigned long shstk_addr, unsigned long size);
unsigned long get_shstk_base(struct task_struct *task, unsigned long *size);
void set_active_shstk(struct task_struct *task, unsigned long shstk_addr);
bool is_shstk_enabled(struct task_struct *task);
bool is_shstk_locked(struct task_struct *task);
bool is_shstk_allocated(struct task_struct *task);
void set_shstk_lock(struct task_struct *task);
void set_shstk_status(struct task_struct *task, bool enable);

#define PR_SHADOW_STACK_SUPPORTED_STATUS_MASK (PR_SHADOW_STACK_ENABLE)

#else

static inline unsigned long shstk_alloc_thread_stack(struct task_struct *tsk,
					   const struct kernel_clone_args *args)
{
	return 0;
}

static inline void shstk_release(struct task_struct *tsk)
{

}

unsigned long get_shstk_base(struct task_struct *task, unsigned long *size)
{
	return 0;
}

static inline void set_shstk_base(struct task_struct *task, unsigned long shstk_addr,
								unsigned long size)
{

}

static inline void set_active_shstk(struct task_struct *task, unsigned long shstk_addr)
{

}

static inline bool is_shstk_enabled(struct task_struct *task)
{
	return false;
}

static inline bool is_shstk_locked(struct task_struct *task)
{
	return false;
}

bool is_shstk_allocated(struct task_struct *task)
{
	return false;
}

void set_shstk_lock(struct task_struct *task)
{

}

static inline void set_shstk_status(struct task_struct *task, bool enable)
{

}

#endif /* CONFIG_RISCV_USER_CFI */

#endif /* __ASSEMBLY__ */

#endif /* _ASM_RISCV_USERCFI_H */

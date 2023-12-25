/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ASM_RISCV_SPINLOCK_H
#define __ASM_RISCV_SPINLOCK_H

#ifdef CONFIG_QUEUED_SPINLOCKS
#define _Q_PENDING_LOOPS	(1 << 9)
#endif

#ifdef CONFIG_RISCV_COMBO_SPINLOCKS
#define __no_arch_spinlock_redefine
#include <asm/ticket_spinlock.h>
#include <asm/qspinlock.h>
#include <linux/jump_label.h>

DECLARE_STATIC_KEY_TRUE(combo_qspinlock_key);

#define COMBO_SPINLOCK_BASE_DECLARE(op)					\
static __always_inline void arch_spin_##op(arch_spinlock_t *lock)	\
{									\
	if (static_branch_likely(&combo_qspinlock_key))			\
		queued_spin_##op(lock);					\
	else								\
		ticket_spin_##op(lock);					\
}
COMBO_SPINLOCK_BASE_DECLARE(lock)
COMBO_SPINLOCK_BASE_DECLARE(unlock)

#define COMBO_SPINLOCK_IS_DECLARE(op)					\
static __always_inline int arch_spin_##op(arch_spinlock_t *lock)	\
{									\
	if (static_branch_likely(&combo_qspinlock_key))			\
		return queued_spin_##op(lock);				\
	else								\
		return ticket_spin_##op(lock);				\
}
COMBO_SPINLOCK_IS_DECLARE(is_locked)
COMBO_SPINLOCK_IS_DECLARE(is_contended)

static __always_inline bool arch_spin_trylock(arch_spinlock_t *lock)
{
	if (static_branch_likely(&combo_qspinlock_key))
		return queued_spin_trylock(lock);
	else
		return ticket_spin_trylock(lock);
}

static __always_inline int arch_spin_value_unlocked(arch_spinlock_t lock)
{
	if (static_branch_likely(&combo_qspinlock_key))
		return queued_spin_value_unlocked(lock);
	else
		return ticket_spin_value_unlocked(lock);
}

#else /* CONFIG_RISCV_COMBO_SPINLOCKS */
#ifdef CONFIG_QUEUED_SPINLOCKS
#include <asm/qspinlock.h>
#else
#include <asm/ticket_spinlock.h>
#endif

#endif /* CONFIG_RISCV_COMBO_SPINLOCKS */
#include <asm/qrwlock.h>

#endif /* __ASM_RISCV_SPINLOCK_H */

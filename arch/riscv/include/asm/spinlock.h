/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ASM_RISCV_SPINLOCK_H
#define __ASM_RISCV_SPINLOCK_H

#ifdef CONFIG_QUEUED_SPINLOCKS
#define _Q_PENDING_LOOPS	(1 << 9)

#define __no_arch_spinlock_redefine
#include <asm/ticket_spinlock.h>
#include <asm/qspinlock.h>
#include <asm/alternative.h>

DECLARE_STATIC_KEY_TRUE(qspinlock_key);

#define SPINLOCK_BASE_DECLARE(op, type, type_lock)			\
static __always_inline type arch_spin_##op(type_lock lock)		\
{									\
	if (static_branch_unlikely(&qspinlock_key))			\
		return queued_spin_##op(lock);				\
	return ticket_spin_##op(lock);					\
}

SPINLOCK_BASE_DECLARE(lock, void, arch_spinlock_t *)
SPINLOCK_BASE_DECLARE(unlock, void, arch_spinlock_t *)
SPINLOCK_BASE_DECLARE(is_locked, int, arch_spinlock_t *)
SPINLOCK_BASE_DECLARE(is_contended, int, arch_spinlock_t *)
SPINLOCK_BASE_DECLARE(trylock, bool, arch_spinlock_t *)
SPINLOCK_BASE_DECLARE(value_unlocked, int, arch_spinlock_t)

#else

#include <asm/ticket_spinlock.h>

#endif

#include <asm/qrwlock.h>

#endif /* __ASM_RISCV_SPINLOCK_H */

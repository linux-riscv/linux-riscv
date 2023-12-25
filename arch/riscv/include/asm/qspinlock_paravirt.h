/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c), 2023 Alibaba Cloud
 * Authors:
 *	Guo Ren <guoren@linux.alibaba.com>
 */

#ifndef _ASM_RISCV_QSPINLOCK_PARAVIRT_H
#define _ASM_RISCV_QSPINLOCK_PARAVIRT_H

void pv_wait(u8 *ptr, u8 val);
void pv_kick(int cpu);

void dummy_queued_spin_lock_slowpath(struct qspinlock *lock, u32 val);
void dummy_queued_spin_unlock(struct qspinlock *lock);

DECLARE_STATIC_CALL(pv_queued_spin_lock_slowpath, dummy_queued_spin_lock_slowpath);
DECLARE_STATIC_CALL(pv_queued_spin_unlock, dummy_queued_spin_unlock);

void __init pv_qspinlock_init(void);

static inline bool pv_is_native_spin_unlock(void)
{
	return false;
}

void __pv_queued_spin_unlock(struct qspinlock *lock);

#endif /* _ASM_RISCV_QSPINLOCK_PARAVIRT_H */

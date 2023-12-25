// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c), 2023 Alibaba Cloud
 * Authors:
 *	Guo Ren <guoren@linux.alibaba.com>
 */

#include <linux/static_call.h>
#include <asm/qspinlock_paravirt.h>
#include <asm/sbi.h>

void pv_kick(int cpu)
{
	sbi_ecall(SBI_EXT_PVLOCK, SBI_EXT_PVLOCK_KICK_CPU,
		  cpuid_to_hartid_map(cpu), 0, 0, 0, 0, 0);
	return;
}

void pv_wait(u8 *ptr, u8 val)
{
	unsigned long flags;

	if (in_nmi())
		return;

	local_irq_save(flags);
	if (READ_ONCE(*ptr) != val)
		goto out;

	wait_for_interrupt();
out:
	local_irq_restore(flags);
}

static void native_queued_spin_unlock(struct qspinlock *lock)
{
	smp_store_release(&lock->locked, 0);
}

DEFINE_STATIC_CALL(pv_queued_spin_lock_slowpath, native_queued_spin_lock_slowpath);
EXPORT_STATIC_CALL(pv_queued_spin_lock_slowpath);

DEFINE_STATIC_CALL(pv_queued_spin_unlock, native_queued_spin_unlock);
EXPORT_STATIC_CALL(pv_queued_spin_unlock);

void __init pv_qspinlock_init(void)
{
	if (num_possible_cpus() == 1)
		return;

	if(sbi_get_firmware_id() != SBI_EXT_BASE_IMPL_ID_KVM)
		return;

	if (!sbi_probe_extension(SBI_EXT_PVLOCK))
		return;

	pr_info("PV qspinlocks enabled\n");
	__pv_init_lock_hash();

	static_call_update(pv_queued_spin_lock_slowpath, __pv_queued_spin_lock_slowpath);
	static_call_update(pv_queued_spin_unlock, __pv_queued_spin_unlock);
}

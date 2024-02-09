/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2024 Christoph Muellner <christoph.muellner@vrull.eu>
 */

#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/prctl.h>

#include <asm/cpu.h>
#include <asm/dtso.h>

#include <trace/events/ipi.h>

int dtso_set_memory_consistency_model(unsigned long arg)
{
	int cpu;
	unsigned long cur_model = get_memory_consistency_model(current);
	unsigned long new_model;

	switch (arg) {
	case PR_MEMORY_CONSISTENCY_MODEL_RISCV_WMO:
		new_model = RISCV_MEMORY_CONSISTENCY_MODEL_WMO;
		break;
	case PR_MEMORY_CONSISTENCY_MODEL_RISCV_TSO:
		new_model = RISCV_MEMORY_CONSISTENCY_MODEL_TSO;
		break;
	default:
		return -EINVAL;
	}

	/* No change requested. */
	if (cur_model == new_model)
		return 0;

	/* Enabling TSO only works if DTSO is available. */
	if (new_model == PR_MEMORY_CONSISTENCY_MODEL_RISCV_TSO && !has_dtso())
		return -EINVAL;

	/* Switching TSO->WMO is not allowed. */
	if (new_model == RISCV_MEMORY_CONSISTENCY_MODEL_WMO)
		return -EINVAL;

	/* Set the new model in the task struct. */
	set_memory_consitency_model(current, new_model);

	/*
	 * We need to reschedule all threads of the current process.
	 * Let's do this by rescheduling all CPUs.
	 * This is stricter than necessary, but since this call is
	 * not expected to happen frequently the impact is low.
	 */
	for_each_cpu(cpu, cpu_online_mask)
		smp_send_reschedule(cpu);

	return 0;
}

int dtso_get_memory_consistency_model(void)
{
	unsigned long cur_model = get_memory_consistency_model(current);

	if (cur_model == RISCV_MEMORY_CONSISTENCY_MODEL_TSO)
		return PR_MEMORY_CONSISTENCY_MODEL_RISCV_TSO;

	return PR_MEMORY_CONSISTENCY_MODEL_RISCV_WMO;
}

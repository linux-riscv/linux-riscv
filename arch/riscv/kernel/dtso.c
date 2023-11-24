/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Christoph Muellner <christoph.muellner@vrull.eu>
 */

#include <linux/export.h>
#include <linux/prctl.h>
#include <asm/dtso.h>

int riscv_set_memory_consistency_model(unsigned long arg)
{
	switch (arg) {
	case PR_MEMORY_CONSISTENCY_MODEL_RISCV_WMO:
		dtso_disable();
		break;
	case PR_MEMORY_CONSISTENCY_MODEL_RISCV_TSO:
		if (!has_dtso())
			return -EINVAL;
		dtso_enable();
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

int riscv_get_memory_consistency_model(void)
{
	if (has_dtso() && dtso_is_enabled())
		return PR_MEMORY_CONSISTENCY_MODEL_RISCV_TSO;
	return PR_MEMORY_CONSISTENCY_MODEL_RISCV_WMO;
}

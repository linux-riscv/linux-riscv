// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright Rivos Inc 2024
 * Author(s): Atish Patra <atishp@rivosinc.com>
 */

#include <string.h>
#include <stdio.h>
#include <asm/hwprobe.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "pmu.h"

static bool counter_deleg_present;

bool perf_pmu_riscv_cdeleg_present(void)
{
	return counter_deleg_present;
}

void perf_pmu__arch_init(struct perf_pmu *pmu __maybe_unused)
{
	struct riscv_hwprobe isa_ext;
	int ret;

	isa_ext.key = RISCV_HWPROBE_KEY_IMA_EXT_0;

	ret = syscall(__NR_riscv_hwprobe, &isa_ext, 1, 0, NULL, 0);
	if (ret)
		return;

	if (isa_ext.key < 0)
		return;

	if ((isa_ext.value & RISCV_HWPROBE_EXT_SSCSRIND) &&
	    (isa_ext.value & RISCV_HWPROBE_EXT_SMCDELEG) &&
	    (isa_ext.value & RISCV_HWPROBE_EXT_SSCCFG))
		counter_deleg_present = true;
}

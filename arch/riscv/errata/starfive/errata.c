// SPDX-License-Identifier: GPL-2.0-only
/*
 * Erratas to be applied for StarFive CPU cores
 *
 * Copyright (C) 2024 Shanghai StarFive Technology Co., Ltd.
 *
 * Author: Joshua Yeong <joshua.yeong@starfivetech.com>
 */

#include <linux/memory.h>
#include <linux/module.h>

#include <asm/alternative.h>
#include <asm/cacheflush.h>
#include <asm/errata_list.h>
#include <asm/patch.h>
#include <asm/processor.h>
#include <asm/sbi.h>
#include <asm/vendorid_list.h>

#define STARFIVE_JH8100_DUBHE90_MARCHID	0x80000000DB000090UL
#define STARFIVE_JH8100_DUBHE90_MIMPID	0x0000000020230930UL
#define STARFIVE_JH8100_DUBHE80_MARCHID	0x80000000DB000080UL
#define STARFIVE_JH8100_DUBHE80_MIMPID	0x0000000020230831UL
#define STARFIVE_JH8100_L3		0x40

static bool errata_probe_cmo(unsigned int stage, unsigned long arch_id,
			      unsigned long impid)
{
	if (!IS_ENABLED(CONFIG_ERRATA_STARFIVE_CMO))
		return false;

	if ((arch_id != STARFIVE_JH8100_DUBHE90_MARCHID ||
	    impid != STARFIVE_JH8100_DUBHE90_MIMPID) &&
	    (arch_id != STARFIVE_JH8100_DUBHE80_MARCHID ||
	    impid != STARFIVE_JH8100_DUBHE80_MIMPID))
		return false;

	if (stage == RISCV_ALTERNATIVES_EARLY_BOOT)
		return false;

	riscv_cbom_block_size = STARFIVE_JH8100_L3;
	riscv_noncoherent_supported();

	return true;
}

static u32 starfive_errata_probe(unsigned int stage,
			      unsigned long archid, unsigned long impid)
{
	u32 cpu_req_errata = 0;

	if (errata_probe_cmo(stage, archid, impid))
		cpu_req_errata |= BIT(ERRATA_STARFIVE_CMO);

	return cpu_req_errata;
}

void __init_or_module starfive_errata_patch_func(struct alt_entry *begin,
					         struct alt_entry *end,
					         unsigned long archid,
						 unsigned long impid,
						 unsigned int stage)
{
	struct alt_entry *alt;
	u32 cpu_apply_errata = 0;
	u32 tmp;
	u32 cpu_req_errata;

	if (stage == RISCV_ALTERNATIVES_EARLY_BOOT)
		return;

	cpu_req_errata = starfive_errata_probe(stage, archid, impid);

	for (alt = begin; alt < end; alt++) {
		if (alt->vendor_id != STARFIVE_VENDOR_ID)
			continue;
		if (alt->patch_id >= ERRATA_STARFIVE_NUMBER)
			continue;

		tmp = (1U << alt->patch_id);
		if (cpu_req_errata & tmp) {
			mutex_lock(&text_mutex);
			patch_text_nosync(ALT_OLD_PTR(alt), ALT_ALT_PTR(alt),
					  alt->alt_len);
			mutex_unlock(&text_mutex);
			cpu_apply_errata |= tmp;
		}
	}

	if (stage != RISCV_ALTERNATIVES_MODULE &&
	    cpu_apply_errata != cpu_req_errata) {
		pr_warn("WARNING: Missing StarFive errata patches! \n");
	    }
}

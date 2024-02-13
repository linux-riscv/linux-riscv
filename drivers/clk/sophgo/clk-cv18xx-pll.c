// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Inochi Amaoto <inochiama@outlook.com>
 */

#include <linux/clk-provider.h>
#include <linux/io.h>
#include <linux/limits.h>
#include <linux/spinlock.h>

#include "clk-cv18xx-pll.h"

const struct clk_ops cv1800_clk_ipll_ops = {
	.disable = NULL,
	.enable = NULL,
	.is_enabled = NULL,

	.recalc_rate = NULL,
	.determine_rate = NULL,
	.set_rate = NULL,
};

const struct clk_ops cv1800_clk_fpll_ops = {
	.disable = NULL,
	.enable = NULL,
	.is_enabled = NULL,

	.recalc_rate = NULL,
	.determine_rate = NULL,
	.set_rate = NULL,

	.set_parent = NULL,
	.get_parent = NULL,
};

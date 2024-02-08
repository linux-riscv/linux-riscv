// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Inochi Amaoto <inochiama@outlook.com>
 */

#include <linux/clk-provider.h>
#include <linux/io.h>
#include <linux/gcd.h>
#include <linux/spinlock.h>

#include "clk-cv18xx-ip.h"

/* GATE */
const struct clk_ops cv1800_clk_gate_ops = {
	.disable = NULL,
	.enable = NULL,
	.is_enabled = NULL,

	.recalc_rate = NULL,
	.round_rate = NULL,
	.set_rate = NULL,
};

/* DIV */
const struct clk_ops cv1800_clk_div_ops = {
	.disable = NULL,
	.enable = NULL,
	.is_enabled = NULL,

	.determine_rate = NULL,
	.recalc_rate	= NULL,
	.set_rate = NULL,
};

const struct clk_ops cv1800_clk_bypass_div_ops = {
	.disable = NULL,
	.enable = NULL,
	.is_enabled = NULL,

	.determine_rate = NULL,
	.recalc_rate = NULL,
	.set_rate = NULL,

	.set_parent = NULL,
	.get_parent = NULL,
};

/* MUX */
const struct clk_ops cv1800_clk_mux_ops = {
	.disable = NULL,
	.enable = NULL,
	.is_enabled = NULL,

	.determine_rate = NULL,
	.recalc_rate = NULL,
	.set_rate = NULL,

	.set_parent = NULL,
	.get_parent = NULL,
};

const struct clk_ops cv1800_clk_bypass_mux_ops = {
	.disable = NULL,
	.enable = NULL,
	.is_enabled = NULL,

	.determine_rate = NULL,
	.recalc_rate = NULL,
	.set_rate = NULL,

	.set_parent = NULL,
	.get_parent = NULL,
};

/* MMUX */
const struct clk_ops cv1800_clk_mmux_ops = {
	.disable = NULL,
	.enable = NULL,
	.is_enabled = NULL,

	.determine_rate = NULL,
	.recalc_rate = NULL,
	.set_rate = NULL,

	.set_parent = NULL,
	.get_parent = NULL,
};

/* AUDIO CLK */
const struct clk_ops cv1800_clk_audio_ops = {
	.disable = NULL,
	.enable = NULL,
	.is_enabled = NULL,

	.determine_rate = NULL,
	.recalc_rate = NULL,
	.set_rate = NULL,
};

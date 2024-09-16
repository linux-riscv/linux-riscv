// SPDX-License-Identifier: GPL-2.0-only
/*
 * Spacemit clock type mix(div/mux/gate/factor)
 *
 * Copyright (c) 2024 SpacemiT Technology Co. Ltd
 * Copyright (c) 2024 Haylen Chu <heylenay@outlook.com>
 */

#include <linux/clk-provider.h>

#include "ccu_mix.h"

#define MIX_TIMEOUT	10000

#define mix_read_sel(c, val)		ccu_read(sel, c, val)
#define mix_read_ctrl(c, val)		ccu_read(ctrl, c, val)
#define mix_update_sel(c, m, v)		ccu_update(sel, c, m, v)
#define mix_update_ctrl(c, m, v)	ccu_update(ctrl, c, m, v)

#define mix_hwparam_in_sel(c) \
	((c)->reg_type == CLK_DIV_TYPE_2REG_NOFC_V3 || \
	 (c)->reg_type == CLK_DIV_TYPE_2REG_FC_V4)

static void ccu_mix_disable(struct clk_hw *hw)
{
	struct ccu_mix *mix = hw_to_ccu_mix(hw);
	struct ccu_common *common = &mix->common;
	struct ccu_gate_config *gate = mix->gate;
	unsigned long flags = 0;

	if (!gate)
		return;

	spin_lock_irqsave(common->lock, flags);

	if (mix_hwparam_in_sel(common))
		mix_update_sel(common, gate->gate_mask, gate->val_disable);
	else
		mix_update_ctrl(common, gate->gate_mask, gate->val_disable);

	spin_unlock_irqrestore(common->lock, flags);
}

static int ccu_mix_enable(struct clk_hw *hw)
{
	struct ccu_mix *mix = hw_to_ccu_mix(hw);
	struct ccu_common *common = &mix->common;
	struct ccu_gate_config *gate = mix->gate;
	u32 val_enable, mask;
	unsigned long flags;
	u32 tmp;

	if (!gate)
		return 0;

	val_enable	= gate->val_enable;
	mask		= gate->gate_mask;

	spin_lock_irqsave(common->lock, flags);

	if (mix_hwparam_in_sel(common))
		mix_update_sel(common, mask, val_enable);
	else
		mix_update_ctrl(common, mask, val_enable);

	spin_unlock_irqrestore(common->lock, flags);

	if (common->reg_type == CLK_DIV_TYPE_2REG_NOFC_V3 ||
	    common->reg_type == CLK_DIV_TYPE_2REG_FC_V4)
		return ccu_poll(sel, common, tmp, (tmp & mask) == val_enable,
				10, MIX_TIMEOUT);
	else
		return ccu_poll(ctrl, common, tmp, (tmp & mask) == val_enable,
				10, MIX_TIMEOUT);
}

static int ccu_mix_is_enabled(struct clk_hw *hw)
{
	struct ccu_mix *mix = hw_to_ccu_mix(hw);
	struct ccu_common *common = &mix->common;
	struct ccu_gate_config *gate = mix->gate;
	unsigned long flags = 0;
	u32 tmp;

	if (!gate)
		return 1;

	spin_lock_irqsave(common->lock, flags);

	if (mix_hwparam_in_sel(common))
		mix_read_sel(common, &tmp);
	else
		mix_read_ctrl(common, &tmp);

	spin_unlock_irqrestore(common->lock, flags);

	return (tmp & gate->gate_mask) == gate->val_enable;
}

static unsigned long ccu_mix_recalc_rate(struct clk_hw *hw,
					unsigned long parent_rate)
{
	struct ccu_mix *mix = hw_to_ccu_mix(hw);
	struct ccu_common *common = &mix->common;
	struct ccu_div_config *div = mix->div;
	unsigned long val;
	u32 reg;

	if (!div) {
		if (mix->factor)
			return parent_rate * mix->factor->mul / mix->factor->div;

		return parent_rate;
	}

	if (mix_hwparam_in_sel(common))
		mix_read_sel(common, &reg);
	else
		mix_read_ctrl(common, &reg);

	val = reg >> div->shift;
	val &= (1 << div->width) - 1;

	val = divider_recalc_rate(hw, parent_rate, val, div->table,
				  div->flags, div->width);

	return val;
}


static int ccu_mix_trigger_fc(struct clk_hw *hw)
{
	struct ccu_mix *mix = hw_to_ccu_mix(hw);
	struct ccu_common *common = &mix->common;
	int ret = 0, timeout = 50;
	unsigned int val = 0;

	if (common->reg_type == CLK_DIV_TYPE_1REG_FC_V2 ||
	    common->reg_type == CLK_DIV_TYPE_2REG_FC_V4 ||
	    common->reg_type == CLK_DIV_TYPE_1REG_FC_DIV_V5 ||
	    common->reg_type == CLK_DIV_TYPE_1REG_FC_MUX_V6) {
		timeout = 50;
		mix_update_ctrl(common, common->fc, common->fc);

		ret = ccu_poll(ctrl, common, val, !(val & common->fc),
			       5, MIX_TIMEOUT);
	}

	return ret;
}

static int ccu_mix_determine_rate(struct clk_hw *hw,
				  struct clk_rate_request *req)
{
	return 0;
}

static long ccu_mix_round_rate(struct clk_hw *hw, unsigned long rate,
				unsigned long *prate)
{
	return rate;
}

static unsigned long
ccu_mix_calc_best_rate(struct clk_hw *hw, unsigned long rate, u32 *mux_val,
		       u32 *div_val)
{
	struct ccu_mix *mix = hw_to_ccu_mix(hw);
	struct ccu_common *common = &mix->common;
	struct ccu_div_config *div = mix->div ? mix->div : NULL;
	struct clk_hw *parent;
	unsigned long parent_rate = 0, best_rate = 0;
	u32 i, j, div_max;

	for (i = 0; i < common->num_parents; i++) {
		parent = clk_hw_get_parent_by_index(hw, i);
		if (!parent)
			continue;

		parent_rate = clk_hw_get_rate(parent);

		if (div)
			div_max = 1 << div->width;
		else
			div_max = 1;

		for (j = 1; j <= div_max; j++) {
			if (abs(parent_rate/j - rate) < abs(best_rate - rate)) {
				best_rate = DIV_ROUND_UP_ULL(parent_rate, j);
				*mux_val = i;
				*div_val = j - 1;
			}
		}
	}

	return best_rate;
}

static int ccu_mix_set_rate(struct clk_hw *hw, unsigned long rate,
			   unsigned long parent_rate)
{
	struct ccu_mix *mix = hw_to_ccu_mix(hw);
	struct ccu_common *common = &mix->common;
	struct ccu_div_config *div = mix->div;
	struct ccu_mux_config *mux = mix->mux;
	u32 cur_mux, cur_div, mux_val = 0, div_val = 0;
	unsigned long best_rate = 0;
	unsigned long flags;
	int ret = 0, tmp = 0;

	if (!div && !mux)
		return 0;

	best_rate = ccu_mix_calc_best_rate(hw, rate, &mux_val, &div_val);

	if (mix_hwparam_in_sel(common))
		mix_read_sel(common, &tmp);
	else
		mix_read_ctrl(common, &tmp);

	if (mux) {
		cur_mux = tmp >> mux->shift;
		cur_mux &= (1 << mux->width) - 1;

		if (cur_mux != mux_val)
			clk_hw_set_parent(hw,
					  clk_hw_get_parent_by_index(hw,
								     mux_val));
	}

	if (div) {
		cur_div = tmp >> div->shift;
		cur_div &= (1 << div->width) - 1;

		if (cur_div == div_val)
			return 0;
	} else {
		return 0;
	}

	tmp = GENMASK(div->width + div->shift - 1, div->shift);

	spin_lock_irqsave(common->lock, flags);

	if (mix_hwparam_in_sel(common))
		mix_update_sel(common, tmp, div_val << div->shift);
	else
		mix_update_ctrl(common, tmp, div_val << div->shift);

	if (common->reg_type == CLK_DIV_TYPE_1REG_FC_V2 ||
	    common->reg_type == CLK_DIV_TYPE_2REG_FC_V4 ||
	    common->reg_type == CLK_DIV_TYPE_1REG_FC_DIV_V5)
		ret = ccu_mix_trigger_fc(hw);

	spin_unlock_irqrestore(common->lock, flags);

	return ret;
}

static u8 ccu_mix_get_parent(struct clk_hw *hw)
{
	struct ccu_mix *mix = hw_to_ccu_mix(hw);
	struct ccu_common *common = &mix->common;
	struct ccu_mux_config *mux = mix->mux;
	u32 reg;
	u8 parent;

	if (!mux)
		return 0;

	if (mix_hwparam_in_sel(common))
		mix_read_sel(common, &reg);
	else
		mix_read_ctrl(common, &reg);

	parent = reg >> mux->shift;
	parent &= (1 << mux->width) - 1;

	if (mux->table) {
		int num_parents = clk_hw_get_num_parents(&common->hw);
		int i;

		for (i = 0; i < num_parents; i++)
			if (mux->table[i] == parent)
				return i;
	}

	return parent;
}

static int ccu_mix_set_parent(struct clk_hw *hw, u8 index)
{
	struct ccu_mix *mix = hw_to_ccu_mix(hw);
	struct ccu_common *common = &mix->common;
	struct ccu_mux_config *mux = mix->mux;
	unsigned long flags;
	int ret = 0;
	u32 mask;

	if (!mux)
		return 0;

	if (mux->table)
		index = mux->table[index];

	mask = GENMASK(mux->width + mux->shift - 1, mux->shift);

	spin_lock_irqsave(common->lock, flags);

	if (mix_hwparam_in_sel(common))
		mix_update_sel(common, mask, index << mux->shift);
	else
		mix_update_ctrl(common, mask, index << mux->shift);

	if (common->reg_type == CLK_DIV_TYPE_1REG_FC_V2 ||
	    common->reg_type == CLK_DIV_TYPE_2REG_FC_V4 ||
	    common->reg_type == CLK_DIV_TYPE_1REG_FC_MUX_V6)
		ret = ccu_mix_trigger_fc(hw);

	spin_unlock_irqrestore(common->lock, flags);

	return ret;
}

const struct clk_ops spacemit_ccu_mix_ops = {
	.disable	 = ccu_mix_disable,
	.enable		 = ccu_mix_enable,
	.is_enabled	 = ccu_mix_is_enabled,
	.get_parent	 = ccu_mix_get_parent,
	.set_parent	 = ccu_mix_set_parent,
	.determine_rate  = ccu_mix_determine_rate,
	.round_rate	 = ccu_mix_round_rate,
	.recalc_rate	 = ccu_mix_recalc_rate,
	.set_rate	 = ccu_mix_set_rate,
};


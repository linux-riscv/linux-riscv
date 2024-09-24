// SPDX-License-Identifier: GPL-2.0-only
/*
 * Spacemit clock type pll
 *
 * Copyright (c) 2024 SpacemiT Technology Co. Ltd
 * Copyright (c) 2024 Haylen Chu <heylenay@outlook.com>
 */

#include <linux/clk-provider.h>
#include <linux/regmap.h>

#include "ccu_common.h"
#include "ccu_pll.h"

#define PLL_MIN_FREQ	600000000
#define PLL_MAX_FREQ	3400000000
#define PLL_DELAY_TIME	3000

#define pll_read_swcr1(c, v)	ccu_read(ctrl, c, v)
#define pll_read_swcr2(c, v)	ccu_read(sel, c, v)
#define pll_read_swcr3(c, v)	ccu_read(xtc, c, v)

#define pll_update_swcr1(c, m, v)	ccu_update(ctrl, c, m, v)
#define pll_update_swcr2(c, m, v)	ccu_update(sel, c, m, v)
#define pll_update_swcr3(c, m, v)	ccu_update(xtc, c, m, v)

#define PLL_SWCR1_REG5_OFF	0
#define PLL_SWCR1_REG5_MASK	GENMASK(7, 0)
#define PLL_SWCR1_REG6_OFF	8
#define PLL_SWCR1_REG6_MASK	GENMASK(15, 8)
#define PLL_SWCR1_REG7_OFF	16
#define PLL_SWCR1_REG7_MASK	GENMASK(23, 16)
#define PLL_SWCR1_REG8_OFF	24
#define PLL_SWCR1_REG8_MASK	GENMASK(31, 24)

#define PLL_SWCR2_DIVn_EN(n)	BIT(n + 1)
#define PLL_SWCR2_ATEST_EN	BIT(12)
#define PLL_SWCR2_CKTEST_EN	BIT(13)
#define PLL_SWCR2_DTEST_EN	BIT(14)

#define PLL_SWCR3_DIV_FRC_OFF	0
#define PLL_SWCR3_DIV_FRC_MASK	GENMASK(23, 0)
#define PLL_SWCR3_DIV_INT_OFF	24
#define PLL_SWCR3_DIV_INT_MASK	GENMASK(30, 24)
#define PLL_SWCR3_EN		BIT(31)

static int ccu_pll_is_enabled(struct clk_hw *hw)
{
	struct ccu_pll *p = hw_to_ccu_pll(hw);
	u32 tmp;

	pll_read_swcr3(&p->common, &tmp);

	return tmp & PLL_SWCR3_EN;
}

/* frequency unit Mhz, return pll vco freq */
static unsigned long __get_vco_freq(struct clk_hw *hw)
{
	unsigned int reg5, reg6, reg7, reg8, size, i;
	unsigned int div_int, div_frc;
	struct ccu_pll_rate_tbl *freq_pll_regs_table;
	struct ccu_pll *p = hw_to_ccu_pll(hw);
	struct ccu_common *common = &p->common;
	u32 tmp;

	pll_read_swcr1(common, &tmp);
	reg5 = (tmp & PLL_SWCR1_REG5_MASK) >> PLL_SWCR1_REG5_OFF;
	reg6 = (tmp & PLL_SWCR1_REG6_MASK) >> PLL_SWCR1_REG6_OFF;
	reg7 = (tmp & PLL_SWCR1_REG7_MASK) >> PLL_SWCR1_REG7_OFF;
	reg8 = (tmp & PLL_SWCR1_REG8_MASK) >> PLL_SWCR1_REG8_OFF;

	pll_read_swcr3(common, &tmp);
	div_int = (tmp & PLL_SWCR3_DIV_INT_MASK) >> PLL_SWCR3_DIV_INT_OFF;
	div_frc = (tmp & PLL_SWCR3_DIV_FRC_MASK) >> PLL_SWCR3_DIV_FRC_OFF;

	freq_pll_regs_table = p->pll.rate_tbl;
	size = p->pll.tbl_size;

	for (i = 0; i < size; i++)
		if ((freq_pll_regs_table[i].reg5 == reg5) &&
		    (freq_pll_regs_table[i].reg6 == reg6) &&
		    (freq_pll_regs_table[i].reg7 == reg7) &&
		    (freq_pll_regs_table[i].reg8 == reg8) &&
		    (freq_pll_regs_table[i].div_int == div_int) &&
		    (freq_pll_regs_table[i].div_frac == div_frc))
			return freq_pll_regs_table[i].rate;

	WARN_ON_ONCE(1);

	return 0;
}

static int ccu_pll_enable(struct clk_hw *hw)
{
	struct ccu_pll *p = hw_to_ccu_pll(hw);
	struct ccu_common *common = &p->common;
	unsigned long flags;
	unsigned int tmp;
	int ret;

	if (ccu_pll_is_enabled(hw))
		return 0;

	spin_lock_irqsave(common->lock, flags);

	pll_update_swcr3(common, PLL_SWCR3_EN, PLL_SWCR3_EN);

	spin_unlock_irqrestore(common->lock, flags);

	/* check lock status */
	ret = regmap_read_poll_timeout_atomic(common->lock_base,
					      p->pll.reg_lock,
					      tmp,
					      tmp & p->pll.lock_enable_bit,
					      5, PLL_DELAY_TIME);

	return ret;
}

static void ccu_pll_disable(struct clk_hw *hw)
{
	struct ccu_pll *p = hw_to_ccu_pll(hw);
	struct ccu_common *common = &p->common;
	unsigned long flags;

	spin_lock_irqsave(p->common.lock, flags);

	pll_update_swcr3(common, PLL_SWCR3_EN, 0);

	spin_unlock_irqrestore(common->lock, flags);
}

/*
 * pll rate change requires sequence:
 * clock off -> change rate setting -> clock on
 * This function doesn't really change rate, but cache the config
 */
static int ccu_pll_set_rate(struct clk_hw *hw, unsigned long rate,
			       unsigned long parent_rate)
{
	struct ccu_pll *p = hw_to_ccu_pll(hw);
	struct ccu_common *common = &p->common;
	struct ccu_pll_config *params = &p->pll;
	struct ccu_pll_rate_tbl *entry;
	unsigned long old_rate;
	unsigned long flags;
	bool found = false;
	u32 mask, val;
	int i;

	if (ccu_pll_is_enabled(hw)) {
		pr_err("%s %s is enabled, ignore the setrate!\n",
		       __func__, __clk_get_name(hw->clk));
		return 0;
	}

	old_rate = __get_vco_freq(hw);

	for (i = 0; i < params->tbl_size; i++) {
		if (rate == params->rate_tbl[i].rate) {
			found = true;
			entry = &params->rate_tbl[i];
			break;
		}
	}
	WARN_ON_ONCE(!found);

	spin_lock_irqsave(common->lock, flags);

	mask = PLL_SWCR1_REG5_MASK | PLL_SWCR1_REG6_MASK;
	mask |= PLL_SWCR1_REG7_MASK | PLL_SWCR1_REG8_MASK;
	val |= entry->reg5 << PLL_SWCR1_REG5_OFF;
	val |= entry->reg6 << PLL_SWCR1_REG6_OFF;
	val |= entry->reg7 << PLL_SWCR1_REG7_OFF;
	val |= entry->reg8 << PLL_SWCR1_REG8_OFF;
	pll_update_swcr1(common, mask, val);

	mask = PLL_SWCR3_DIV_INT_MASK | PLL_SWCR3_DIV_FRC_MASK;
	val = entry->div_int << PLL_SWCR3_DIV_INT_OFF;
	val |= entry->div_frac << PLL_SWCR3_DIV_FRC_OFF;
	pll_update_swcr3(common, mask, val);

	spin_unlock_irqrestore(common->lock, flags);

	return 0;
}

static unsigned long ccu_pll_recalc_rate(struct clk_hw *hw,
					 unsigned long parent_rate)
{
	return __get_vco_freq(hw);
}

static long ccu_pll_round_rate(struct clk_hw *hw, unsigned long rate,
			       unsigned long *prate)
{
	struct ccu_pll *p = hw_to_ccu_pll(hw);
	struct ccu_pll_config *params = &p->pll;
	unsigned long max_rate = 0;
	unsigned int i;

	if (rate > PLL_MAX_FREQ || rate < PLL_MIN_FREQ) {
		pr_err("%lu rate out of range!\n", rate);
		return -EINVAL;
	}

	for (i = 0; i < params->tbl_size; i++) {
		if (params->rate_tbl[i].rate <= rate) {
			if (max_rate < params->rate_tbl[i].rate)
				max_rate = params->rate_tbl[i].rate;
		}
	}

	return max_rate;
}

const struct clk_ops spacemit_ccu_pll_ops = {
	.enable = ccu_pll_enable,
	.disable = ccu_pll_disable,
	.set_rate = ccu_pll_set_rate,
	.recalc_rate = ccu_pll_recalc_rate,
	.round_rate = ccu_pll_round_rate,
	.is_enabled = ccu_pll_is_enabled,
};


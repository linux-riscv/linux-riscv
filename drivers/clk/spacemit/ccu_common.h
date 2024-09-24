/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2024 SpacemiT Technology Co. Ltd
 * Copyright (c) 2024 Haylen Chu <heylenay@outlook.com>
 */

#ifndef _CCU_COMMON_H_
#define _CCU_COMMON_H_

#include <linux/regmap.h>
#include <linux/spinlock.h>

enum ccu_div_type {
	CLK_DIV_TYPE_1REG_NOFC_V1 = 0,
	CLK_DIV_TYPE_1REG_FC_V2,
	CLK_DIV_TYPE_2REG_NOFC_V3,
	CLK_DIV_TYPE_2REG_FC_V4,
	CLK_DIV_TYPE_1REG_FC_DIV_V5,
	CLK_DIV_TYPE_1REG_FC_MUX_V6,
};

struct ccu_common {
	struct regmap *base;
	struct regmap *lock_base;
	spinlock_t *lock;

	enum ccu_div_type reg_type;
	u32 reg_ctrl;
	u32 reg_sel;
	u32 reg_xtc;
	u32 fc;
	bool is_pll;

	unsigned long flags;
	const char *name;
	const char * const *parent_names;
	int num_parents;

	struct clk_hw hw;
};

static inline struct ccu_common *hw_to_ccu_common(struct clk_hw *hw)
{
	return container_of(hw, struct ccu_common, hw);
}

#define ccu_read(reg, c, val)	regmap_read((c)->base, (c)->reg_##reg, val)
#define ccu_write(reg, c, val)	regmap_write((c)->base, (c)->reg_##reg, val)
#define ccu_update(reg, c, mask, val) \
	regmap_update_bits((c)->base, (c)->reg_##reg, mask, val)
#define ccu_poll(reg, c, tmp, cond, sleep, timeout) \
	regmap_read_poll_timeout_atomic((c)->base, (c)->reg_##reg,	\
					tmp, cond, sleep, timeout)

#endif /* _CCU_COMMON_H_ */

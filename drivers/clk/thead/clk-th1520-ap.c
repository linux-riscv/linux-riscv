// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Jisheng Zhang <jszhang@kernel.org>
 * Copyright (C) 2023 Vivo Communication Technology Co. Ltd.
 *  Authors: Yangtao Li <frank.li@vivo.com>
 */

#include <dt-bindings/clock/thead,th1520-clk-ap.h>
#include <linux/clk-provider.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>

struct ccu_internal {
	u8	shift;
	u8	width;
};

struct ccu_div_internal {
	u8	shift;
	u8	width;
	u32	flags;
};

struct ccu_common {
	struct regmap	*map;
	u16		reg;
	struct clk_hw	hw;
};

struct ccu_mux {
	struct ccu_internal	mux;
	struct ccu_common	common;
};

struct ccu_gate {
	u32			enable;
	struct ccu_common	common;
};

struct ccu_div {
	u32			enable;
	struct ccu_div_internal	div;
	struct ccu_internal	mux;
	struct ccu_common	common;
};

/*
 * struct ccu_mdiv - Definition of an M-D-I-V clock
 *
 * Clocks based on the formula (parent * M) / (D * I * V)
 */
struct ccu_mdiv {
	struct ccu_internal	m;
	struct ccu_internal	d;
	struct ccu_internal	i;
	struct ccu_internal	v;
	struct ccu_common	common;
};

#define TH_CCU_ARG(_shift, _width)					\
	{								\
		.shift	= _shift,					\
		.width	= _width,					\
	}

#define TH_CCU_DIV_FLAGS(_shift, _width, _flags)			\
	{								\
		.shift	= _shift,					\
		.width	= _width,					\
		.flags	= _flags,					\
	}

#define CCU_GATE(_struct, _name, _parent, _reg, _gate, _flags)		\
	struct ccu_gate _struct = {					\
		.enable	= _gate,					\
		.common	= {						\
			.reg		= _reg,				\
			.hw.init	= CLK_HW_INIT(_name,		\
						      _parent,		\
						      &ccu_gate_ops,	\
						      _flags),		\
		}							\
	}

static inline struct ccu_common *hw_to_ccu_common(struct clk_hw *hw)
{
	return container_of(hw, struct ccu_common, hw);
}

static inline struct ccu_mux *hw_to_ccu_mux(struct clk_hw *hw)
{
	struct ccu_common *common = hw_to_ccu_common(hw);

	return container_of(common, struct ccu_mux, common);
}

static inline struct ccu_mdiv *hw_to_ccu_mdiv(struct clk_hw *hw)
{
	struct ccu_common *common = hw_to_ccu_common(hw);

	return container_of(common, struct ccu_mdiv, common);
}

static inline struct ccu_div *hw_to_ccu_div(struct clk_hw *hw)
{
	struct ccu_common *common = hw_to_ccu_common(hw);

	return container_of(common, struct ccu_div, common);
}

static inline struct ccu_gate *hw_to_ccu_gate(struct clk_hw *hw)
{
	struct ccu_common *common = hw_to_ccu_common(hw);

	return container_of(common, struct ccu_gate, common);
}

static u8 ccu_get_parent_helper(struct ccu_common *common,
				struct ccu_internal *mux)
{
	unsigned int val;
	u8 parent;

	regmap_read(common->map, common->reg, &val);
	parent = val >> mux->shift;
	parent &= GENMASK(mux->width - 1, 0);

	return parent;
}

static int ccu_set_parent_helper(struct ccu_common *common,
				 struct ccu_internal *mux,
				 u8 index)
{
	return regmap_update_bits(common->map, common->reg,
			GENMASK(mux->width - 1, 0) << mux->shift,
			index << mux->shift);
}

static u8 ccu_mux_get_parent(struct clk_hw *hw)
{
	struct ccu_mux *cm = hw_to_ccu_mux(hw);

	return ccu_get_parent_helper(&cm->common, &cm->mux);
}

static int ccu_mux_set_parent(struct clk_hw *hw, u8 index)
{
	struct ccu_mux *cm = hw_to_ccu_mux(hw);

	return ccu_set_parent_helper(&cm->common, &cm->mux, index);
}

static const struct clk_ops ccu_mux_ops = {
	.get_parent	= ccu_mux_get_parent,
	.set_parent	= ccu_mux_set_parent,
	.determine_rate	= __clk_mux_determine_rate,
};

void ccu_disable_helper(struct ccu_common *common, u32 gate)
{
	if (!gate)
		return;

	regmap_update_bits(common->map, common->reg,
			   gate, ~gate);
}

int ccu_enable_helper(struct ccu_common *common, u32 gate)
{
	if (!gate)
		return 0;

	return regmap_update_bits(common->map, common->reg,
				  gate, gate);
}

static int ccu_is_enabled_helper(struct ccu_common *common, u32 gate)
{
	unsigned int val;

	if (!gate)
		return true;

	regmap_read(common->map, common->reg, &val);
	return val & gate;
}

static int ccu_gate_is_enabled(struct clk_hw *hw)
{
	struct ccu_gate *cg = hw_to_ccu_gate(hw);

	return ccu_is_enabled_helper(&cg->common, cg->enable);
}

static void ccu_gate_disable(struct clk_hw *hw)
{
	struct ccu_gate *cg = hw_to_ccu_gate(hw);

	ccu_disable_helper(&cg->common, cg->enable);
}

static int ccu_gate_enable(struct clk_hw *hw)
{
	struct ccu_gate *cg = hw_to_ccu_gate(hw);

	return ccu_enable_helper(&cg->common, cg->enable);
}

static const struct clk_ops ccu_gate_ops = {
	.disable	= ccu_gate_disable,
	.enable		= ccu_gate_enable,
	.is_enabled	= ccu_gate_is_enabled,
};

static unsigned long ccu_div_recalc_rate(struct clk_hw *hw,
					 unsigned long parent_rate)
{
	struct ccu_div *cd = hw_to_ccu_div(hw);
	unsigned int val;

	regmap_read(cd->common.map, cd->common.reg, &val);
	val = val >> cd->div.shift;
	val &= GENMASK(cd->div.width - 1, 0);

	val = divider_recalc_rate(hw, parent_rate, val, NULL,
				  cd->div.flags, cd->div.width);

	return val;
}

static u8 ccu_div_get_parent(struct clk_hw *hw)
{
	struct ccu_div *cd = hw_to_ccu_div(hw);

	return ccu_get_parent_helper(&cd->common, &cd->mux);
}

static int ccu_div_set_parent(struct clk_hw *hw, u8 index)
{
	struct ccu_div *cd = hw_to_ccu_div(hw);

	return ccu_set_parent_helper(&cd->common, &cd->mux, index);
}

static void ccu_div_disable(struct clk_hw *hw)
{
	struct ccu_div *cd = hw_to_ccu_div(hw);

	ccu_disable_helper(&cd->common, cd->enable);
}

static int ccu_div_enable(struct clk_hw *hw)
{
	struct ccu_div *cd = hw_to_ccu_div(hw);

	return ccu_enable_helper(&cd->common, cd->enable);
}

static int ccu_div_is_enabled(struct clk_hw *hw)
{
	struct ccu_div *cd = hw_to_ccu_div(hw);

	return ccu_is_enabled_helper(&cd->common, cd->enable);
}

static const struct clk_ops ccu_div_ops = {
	.disable	= ccu_div_disable,
	.enable		= ccu_div_enable,
	.is_enabled	= ccu_div_is_enabled,
	.get_parent	= ccu_div_get_parent,
	.set_parent	= ccu_div_set_parent,
	.recalc_rate	= ccu_div_recalc_rate,
	.determine_rate	= clk_hw_determine_rate_no_reparent,
};

static unsigned long ccu_mdiv_recalc_rate(struct clk_hw *hw,
					  unsigned long parent_rate)
{
	struct ccu_mdiv *mdiv = hw_to_ccu_mdiv(hw);
	unsigned long div, rate = parent_rate;
	unsigned int m, d, i, v, val;

	regmap_read(mdiv->common.map, mdiv->common.reg, &val);

	m = val >> mdiv->m.shift;
	m &= GENMASK(mdiv->m.width - 1, 0);

	d = val >> mdiv->d.shift;
	d &= GENMASK(mdiv->d.width - 1, 0);

	i = val >> mdiv->i.shift;
	i &= GENMASK(mdiv->i.width - 1, 0);

	v = val >> mdiv->v.shift;
	v &= GENMASK(mdiv->v.width - 1, 0);

	rate = parent_rate * m;
	div = d * i * v;
	do_div(rate, div);

	return rate;
}

static const struct clk_ops clk_mdiv_ops = {
	.recalc_rate	= ccu_mdiv_recalc_rate,
};

static struct ccu_mdiv cpu_pll0_clk = {
	.m		= TH_CCU_ARG(8, 12),
	.d		= TH_CCU_ARG(24, 3),
	.i		= TH_CCU_ARG(20, 3),
	.v		= TH_CCU_ARG(0, 6),
	.common		= {
		.reg		= 0x000,
		.hw.init	= CLK_HW_INIT("cpu-pll0", "osc_24m",
					      &clk_mdiv_ops,
					      0),
	},
};

static struct ccu_mdiv cpu_pll1_clk = {
	.m		= TH_CCU_ARG(8, 12),
	.d		= TH_CCU_ARG(24, 3),
	.i		= TH_CCU_ARG(20, 3),
	.v		= TH_CCU_ARG(0, 6),
	.common		= {
		.reg		= 0x010,
		.hw.init	= CLK_HW_INIT("cpu-pll1", "osc_24m",
					      &clk_mdiv_ops,
					      0),
	},
};

static struct ccu_mdiv gmac_pll_clk = {
	.m		= TH_CCU_ARG(8, 12),
	.d		= TH_CCU_ARG(24, 3),
	.i		= TH_CCU_ARG(20, 3),
	.v		= TH_CCU_ARG(0, 6),
	.common		= {
		.reg		= 0x020,
		.hw.init	= CLK_HW_INIT("gmac-pll", "osc_24m",
					      &clk_mdiv_ops,
					      0),
	},
};

static struct ccu_mdiv video_pll_clk = {
	.m		= TH_CCU_ARG(8, 12),
	.d		= TH_CCU_ARG(24, 3),
	.i		= TH_CCU_ARG(20, 3),
	.v		= TH_CCU_ARG(0, 6),
	.common		= {
		.reg		= 0x030,
		.hw.init	= CLK_HW_INIT("video-pll", "osc_24m",
					      &clk_mdiv_ops,
					      0),
	},
};

static struct ccu_mdiv dpu0_pll_clk = {
	.m		= TH_CCU_ARG(8, 12),
	.d		= TH_CCU_ARG(24, 3),
	.i		= TH_CCU_ARG(20, 3),
	.v		= TH_CCU_ARG(0, 6),
	.common		= {
		.reg		= 0x040,
		.hw.init	= CLK_HW_INIT("dpu0-pll", "osc_24m",
					      &clk_mdiv_ops,
					      0),
	},
};

static struct ccu_mdiv dpu1_pll_clk = {
	.m		= TH_CCU_ARG(8, 12),
	.d		= TH_CCU_ARG(24, 3),
	.i		= TH_CCU_ARG(20, 3),
	.v		= TH_CCU_ARG(0, 6),
	.common		= {
		.reg		= 0x050,
		.hw.init	= CLK_HW_INIT("dpu1-pll", "osc_24m",
					      &clk_mdiv_ops,
					      0),
	},
};

static struct ccu_mdiv tee_pll_clk = {
	.m		= TH_CCU_ARG(8, 12),
	.d		= TH_CCU_ARG(24, 3),
	.i		= TH_CCU_ARG(20, 3),
	.v		= TH_CCU_ARG(0, 6),
	.common		= {
		.reg		= 0x060,
		.hw.init	= CLK_HW_INIT("tee-pll", "osc_24m",
					      &clk_mdiv_ops,
					      0),
	},
};

static const char * const c910_i0_parents[] = { "cpu-pll0", "osc_24m" };
struct ccu_mux c910_i0_clk = {
	.mux	= TH_CCU_ARG(1, 1),
	.common	= {
		.reg		= 0x100,
		.hw.init	= CLK_HW_INIT_PARENTS("c910-i0",
					      c910_i0_parents,
					      &ccu_mux_ops,
					      0),
	}
};

static const char * const c910_parents[] = { "c910-i0", "cpu-pll1" };
struct ccu_mux c910_clk = {
	.mux	= TH_CCU_ARG(0, 1),
	.common	= {
		.reg		= 0x100,
		.hw.init	= CLK_HW_INIT_PARENTS("c910",
					      c910_parents,
					      &ccu_mux_ops,
					      0),
	}
};

static CCU_GATE(brom_clk, "brom", "ahb2-cpusys-hclk",
		0x100, BIT(4), 0);

static CCU_GATE(bmu_clk, "bmu", "axi4-cpusys2-aclk",
		0x100, BIT(5), 0);

static const char * const ahb2_cpusys_parents[] = { "gmac-pll", "osc_24m" };
static struct ccu_div ahb2_cpusys_hclk = {
	.div		= TH_CCU_DIV_FLAGS(0, 3, CLK_DIVIDER_ONE_BASED),
	.mux		= TH_CCU_ARG(5, 1),
	.common		= {
		.reg		= 0x120,
		.hw.init	= CLK_HW_INIT_PARENTS("ahb2-cpusys-hclk",
						      ahb2_cpusys_parents,
						      &ccu_div_ops,
						      0),
	},
};

static struct ccu_div apb3_cpusys_pclk = {
	.div		= TH_CCU_ARG(0, 3),
	.common		= {
		.reg		= 0x130,
		.hw.init	= CLK_HW_INIT("apb3-cpusys-pclk", "ahb2-cpusys-hclk",
					      &ccu_div_ops,
					      0),
	},
};

static struct ccu_div axi4_cpusys2_aclk = {
	.div		= TH_CCU_DIV_FLAGS(0, 3, CLK_DIVIDER_ONE_BASED),
	.common		= {
		.reg		= 0x134,
		.hw.init	= CLK_HW_INIT("axi4-cpusys2-aclk", "gmac-pll",
					      &ccu_div_ops,
					      0),
	},
};

static CCU_GATE(aon2cpu_a2x_clk, "aon2cpu-a2x", "axi4-cpusys2-aclk",
		0x134, BIT(8), 0);

static CCU_GATE(x2x_cpusys_clk, "x2x-cpusys", "axi4-cpusys2-aclk",
		0x134, BIT(7), 0);

static const char * const axi_parents[] = { "video-pll", "osc_24m" };
static struct ccu_div axi_aclk = {
	.div		= TH_CCU_DIV_FLAGS(0, 4, CLK_DIVIDER_ONE_BASED),
	.mux		= TH_CCU_ARG(5, 1),
	.common		= {
		.reg		= 0x138,
		.hw.init	= CLK_HW_INIT_PARENTS("axi-aclk",
						      axi_parents,
						      &ccu_div_ops,
						      0),
	},
};

static CCU_GATE(cpu2aon_x2h_clk, "cpu2aon-x2h", "axi-aclk",
		0x138, BIT(8), 0);

static const char * const perisys_ahb_hclk_parents[] = { "gmac-pll", "osc_24m" };
static struct ccu_div perisys_ahb_hclk = {
	.enable		= BIT(6),
	.div		= TH_CCU_DIV_FLAGS(0, 4, CLK_DIVIDER_ONE_BASED),
	.mux		= TH_CCU_ARG(5, 1),
	.common		= {
		.reg		= 0x140,
		.hw.init	= CLK_HW_INIT_PARENTS("perisys-ahb-hclk",
						      perisys_ahb_hclk_parents,
						      &ccu_div_ops,
						      0),
	},
};

static CCU_GATE(cpu2peri_x2h_clk, "cpu2peri-x2h", "axi4-cpusys2-aclk",
		0x140, BIT(9), 0);

static struct ccu_div perisys_apb_pclk = {
	.div		= TH_CCU_ARG(0, 3),
	.common		= {
		.reg		= 0x150,
		.hw.init	= CLK_HW_INIT("perisys-apb-pclk", "perisys-ahb-hclk",
					      &ccu_div_ops,
					      0),
	},
};

static struct ccu_div peri2sys_apb_pclk = {
	.div		= TH_CCU_DIV_FLAGS(4, 3, CLK_DIVIDER_ONE_BASED),
	.common		= {
		.reg		= 0x150,
		.hw.init	= CLK_HW_INIT("peri2sys-apb-pclk",
					      "gmac-pll",
					      &ccu_div_ops,
					      0),
	},
};

static CCU_GATE(perisys_apb1_hclk, "perisys-apb1-hclk", "perisys-ahb-hclk",
		0x150, BIT(9), 0);

static CCU_GATE(perisys_apb2_hclk, "perisys-apb2-hclk", "perisys-ahb-hclk",
		0x150, BIT(10), 0);

static CCU_GATE(perisys_apb3_hclk, "perisys-apb3-hclk", "perisys-ahb-hclk",
		0x150, BIT(11), 0);

static CCU_GATE(perisys_apb4_hclk, "perisys-apb4-hclk", "perisys-ahb-hclk",
		0x150, BIT(12), 0);

static CLK_FIXED_FACTOR_FW_NAME(osc12m_clk, "osc_12m", "osc_24m", 2, 1, 0);

static const char * const out_parents[] = { "osc_24m", "osc_12m" };

static struct ccu_div out1_clk = {
	.enable		= BIT(5),
	.div		= TH_CCU_DIV_FLAGS(0, 3, CLK_DIVIDER_ONE_BASED),
	.mux		= TH_CCU_ARG(4, 1),
	.common		= {
		.reg		= 0x1b4,
		.hw.init	= CLK_HW_INIT_PARENTS("out1",
						      out_parents,
						      &ccu_div_ops,
						      0),
	},
};

static struct ccu_div out2_clk = {
	.enable		= BIT(5),
	.div		= TH_CCU_DIV_FLAGS(0, 3, CLK_DIVIDER_ONE_BASED),
	.mux		= TH_CCU_ARG(4, 1),
	.common		= {
		.reg		= 0x1b8,
		.hw.init	= CLK_HW_INIT_PARENTS("out2",
						      out_parents,
						      &ccu_div_ops,
						      0),
	},
};

static struct ccu_div out3_clk = {
	.enable		= BIT(5),
	.div		= TH_CCU_DIV_FLAGS(0, 3, CLK_DIVIDER_ONE_BASED),
	.mux		= TH_CCU_ARG(4, 1),
	.common		= {
		.reg		= 0x1bc,
		.hw.init	= CLK_HW_INIT_PARENTS("out3",
						      out_parents,
						      &ccu_div_ops,
						      0),
	},
};

static struct ccu_div out4_clk = {
	.enable		= BIT(5),
	.div		= TH_CCU_DIV_FLAGS(0, 3, CLK_DIVIDER_ONE_BASED),
	.mux		= TH_CCU_ARG(4, 1),
	.common		= {
		.reg		= 0x1c0,
		.hw.init	= CLK_HW_INIT_PARENTS("out4",
						      out_parents,
						      &ccu_div_ops,
						      0),
	},
};

static const char * const apb_parents[] = { "gmac-pll", "osc_24m" };
static struct ccu_div apb_pclk = {
	.enable		= BIT(5),
	.div		= TH_CCU_DIV_FLAGS(0, 4, CLK_DIVIDER_ONE_BASED),
	.mux		= TH_CCU_ARG(7, 1),
	.common		= {
		.reg		= 0x1c4,
		.hw.init	= CLK_HW_INIT_PARENTS("apb-pclk",
						      apb_parents,
						      &ccu_div_ops,
						      0),
	},
};

static const char * const npu_parents[] = { "gmac-pll", "video-pll" };
static struct ccu_div npu_clk = {
	.enable		= BIT(4),
	.div		= TH_CCU_DIV_FLAGS(0, 3, CLK_DIVIDER_ONE_BASED),
	.mux		= TH_CCU_ARG(6, 1),
	.common		= {
		.reg		= 0x1c8,
		.hw.init	= CLK_HW_INIT_PARENTS("npu",
						      npu_parents,
						      &ccu_div_ops,
						      0),
	},
};

static CCU_GATE(npu_axi_clk, "npu-axi", "npu-ahb",
		0x1c8, BIT(5), 0);

static struct ccu_div vi_clk = {
	.div		= TH_CCU_DIV_FLAGS(16, 4, CLK_DIVIDER_ONE_BASED),
	.common		= {
		.reg		= 0x1d0,
		.hw.init	= CLK_HW_INIT("vi",
					      "video-pll",
					      &ccu_div_ops,
					      0),
	},
};

static struct ccu_div vi_ahb_clk = {
	.div		= TH_CCU_DIV_FLAGS(0, 4, CLK_DIVIDER_ONE_BASED),
	.common		= {
		.reg		= 0x1d0,
		.hw.init	= CLK_HW_INIT("vi-ahb",
					      "video-pll",
					      &ccu_div_ops,
					      0),
	},
};

static struct ccu_div vo_axi_clk = {
	.enable		= BIT(5),
	.div		= TH_CCU_DIV_FLAGS(0, 4, CLK_DIVIDER_ONE_BASED),
	.common		= {
		.reg		= 0x1dc,
		.hw.init	= CLK_HW_INIT("vo-axi",
					      "video-pll",
					      &ccu_div_ops,
					      0),
	},
};

static struct ccu_div vp_apb_clk = {
	.div		= TH_CCU_DIV_FLAGS(0, 3, CLK_DIVIDER_ONE_BASED),
	.common		= {
		.reg		= 0x1e0,
		.hw.init	= CLK_HW_INIT("vp-apb",
					      "gmac-pll",
					      &ccu_div_ops,
					      0),
	},
};

static struct ccu_div vp_axi_clk = {
	.enable		= BIT(15),
	.div		= TH_CCU_DIV_FLAGS(8, 4, CLK_DIVIDER_ONE_BASED),
	.common		= {
		.reg		= 0x1e0,
		.hw.init	= CLK_HW_INIT("vp-axi",
					      "video-pll",
					      &ccu_div_ops,
					      0),
	},
};

static CCU_GATE(cpu2vp_clk, "cpu2vp", "axi-aclk",
		0x1e0, BIT(13), 0);

static struct ccu_div venc_clk = {
	.enable		= BIT(5),
	.div		= TH_CCU_DIV_FLAGS(0, 3, CLK_DIVIDER_ONE_BASED),
	.common		= {
		.reg		= 0x1e4,
		.hw.init	= CLK_HW_INIT("venc",
					      "gmac-pll",
					      &ccu_div_ops,
					      0),
	},
};

static struct ccu_div dpu0_clk = {
	.div		= TH_CCU_DIV_FLAGS(0, 8, CLK_DIVIDER_ONE_BASED),
	.common		= {
		.reg		= 0x1e8,
		.hw.init	= CLK_HW_INIT("dpu0",
					      "dpu0-pll",
					      &ccu_div_ops,
					      0),
	},
};

static struct ccu_div dpu1_clk = {
	.div		= TH_CCU_DIV_FLAGS(0, 8, CLK_DIVIDER_ONE_BASED),
	.common		= {
		.reg		= 0x1ec,
		.hw.init	= CLK_HW_INIT("dpu1",
					      "dpu1-pll",
					      &ccu_div_ops,
					      0),
	},
};

static CCU_GATE(emmc_sdio_clk, "emmc-sdio", "video-pll", 0x204, BIT(30), 0);
static CCU_GATE(gmac1_clk, "gmac1", "gmac-pll", 0x204, BIT(26), 0);
static CCU_GATE(padctrl1_clk, "padctrl1", "perisys-apb-pclk", 0x204, BIT(24), 0);
static CCU_GATE(dsmart_clk, "dsmart", "perisys-apb-pclk", 0x204, BIT(23), 0);
static CCU_GATE(padctrl0_clk, "padctrl0", "perisys-apb-pclk", 0x204, BIT(22), 0);
static CCU_GATE(gmac_axi_clk, "gmac-axi", "axi4-cpusys2-aclk", 0x204, BIT(21), 0);
static CCU_GATE(gpio3_clk, "gpio3-clk", "peri2sys-apb-pclk", 0x204, BIT(20), 0);
static CCU_GATE(gmac0_clk, "gmac0", "gmac-pll", 0x204, BIT(19), 0);
static CCU_GATE(pwm_clk, "pwm", "perisys-apb-pclk", 0x204, BIT(18), 0);
static CCU_GATE(qspi0_clk, "qspi0", "video-pll", 0x204, BIT(17), 0);
static CCU_GATE(qspi1_clk, "qspi1", "video-pll", 0x204, BIT(16), 0);
static CCU_GATE(spi_clk, "spi", "video-pll", 0x204, BIT(15), 0);
static CCU_GATE(uart0_pclk, "uart0-pclk", "perisys-apb-pclk", 0x204, BIT(14), 0);
static CCU_GATE(uart1_pclk, "uart1-pclk", "perisys-apb-pclk", 0x204, BIT(13), 0);
static CCU_GATE(uart2_pclk, "uart2-pclk", "perisys-apb-pclk", 0x204, BIT(12), 0);
static CCU_GATE(uart3_pclk, "uart3-pclk", "perisys-apb-pclk", 0x204, BIT(11), 0);
static CCU_GATE(uart4_pclk, "uart4-pclk", "perisys-apb-pclk", 0x204, BIT(10), 0);
static CCU_GATE(uart5_pclk, "uart5-pclk", "perisys-apb-pclk", 0x204, BIT(9), 0);
static CCU_GATE(gpio0_clk, "gpio0-clk", "perisys-apb-pclk", 0x204, BIT(8), 0);
static CCU_GATE(gpio1_clk, "gpio1-clk", "perisys-apb-pclk", 0x204, BIT(7), 0);
static CCU_GATE(gpio2_clk, "gpio2-clk", "peri2sys-apb-pclk", 0x204, BIT(6), 0);
static CCU_GATE(i2c0_clk, "i2c0", "perisys-apb-pclk", 0x204, BIT(5), 0);
static CCU_GATE(i2c1_clk, "i2c1", "perisys-apb-pclk", 0x204, BIT(4), 0);
static CCU_GATE(i2c2_clk, "i2c2", "perisys-apb-pclk", 0x204, BIT(3), 0);
static CCU_GATE(i2c3_clk, "i2c3", "perisys-apb-pclk", 0x204, BIT(2), 0);
static CCU_GATE(i2c4_clk, "i2c4", "perisys-apb-pclk", 0x204, BIT(1), 0);
static CCU_GATE(i2c5_clk, "i2c5", "perisys-apb-pclk", 0x204, BIT(0), 0);

static CCU_GATE(spinlock_clk, "spinlock", "ahb2-cpusys-hclk", 0x208, BIT(10), 0);
static CCU_GATE(dma_clk, "dma", "axi4-cpusys2-aclk", 0x208, BIT(8), 0);
static CCU_GATE(mbox0_clk, "mbox0", "apb3-cpusys-pclk", 0x208, BIT(7), 0);
static CCU_GATE(mbox1_clk, "mbox1", "apb3-cpusys-pclk", 0x208, BIT(6), 0);
static CCU_GATE(mbox2_clk, "mbox2", "apb3-cpusys-pclk", 0x208, BIT(5), 0);
static CCU_GATE(mbox3_clk, "mbox3", "apb3-cpusys-pclk", 0x208, BIT(4), 0);
static CCU_GATE(wdt0_clk, "wdt0", "apb3-cpusys-pclk", 0x208, BIT(3), 0);
static CCU_GATE(wdt1_clk, "wdt1", "apb3-cpusys-pclk", 0x208, BIT(2), 0);
static CCU_GATE(timer0_clk, "timer0", "apb3-cpusys-pclk", 0x208, BIT(1), 0);
static CCU_GATE(timer1_clk, "timer1", "apb3-cpusys-pclk", 0x208, BIT(0), 0);

static CCU_GATE(sram0_clk, "sram0", "axi-aclk", 0x20c, BIT(4), 0);
static CCU_GATE(sram1_clk, "sram1", "axi-aclk", 0x20c, BIT(3), 0);
static CCU_GATE(sram2_clk, "sram2", "axi-aclk", 0x20c, BIT(2), 0);
static CCU_GATE(sram3_clk, "sram3", "axi-aclk", 0x20c, BIT(1), 0);

static CLK_FIXED_FACTOR_HW(gmac_pll_clk_100m, "gmac-pll-clk-100m",
			   &gmac_pll_clk.common.hw,
			   10, 1, 0);

static const char * const uart_sclk_parents[] = { "gmac-pll-clk-100m", "osc_24m" };
struct ccu_mux uart_sclk = {
	.mux	= TH_CCU_ARG(0, 1),
	.common	= {
		.reg		= 0x210,
		.hw.init	= CLK_HW_INIT_PARENTS("uart-sclk",
					      uart_sclk_parents,
					      &ccu_mux_ops,
					      0),
	}
};

static struct ccu_common *th1520_clks[] = {
	&cpu_pll0_clk.common,
	&cpu_pll1_clk.common,
	&gmac_pll_clk.common,
	&video_pll_clk.common,
	&dpu0_pll_clk.common,
	&dpu1_pll_clk.common,
	&tee_pll_clk.common,
	&c910_i0_clk.common,
	&c910_clk.common,
	&brom_clk.common,
	&bmu_clk.common,
	&ahb2_cpusys_hclk.common,
	&apb3_cpusys_pclk.common,
	&axi4_cpusys2_aclk.common,
	&aon2cpu_a2x_clk.common,
	&x2x_cpusys_clk.common,
	&axi_aclk.common,
	&cpu2aon_x2h_clk.common,
	&perisys_ahb_hclk.common,
	&cpu2peri_x2h_clk.common,
	&perisys_apb_pclk.common,
	&peri2sys_apb_pclk.common,
	&perisys_apb1_hclk.common,
	&perisys_apb2_hclk.common,
	&perisys_apb3_hclk.common,
	&perisys_apb4_hclk.common,
	&out1_clk.common,
	&out2_clk.common,
	&out3_clk.common,
	&out4_clk.common,
	&apb_pclk.common,
	&npu_clk.common,
	&npu_axi_clk.common,
	&vi_clk.common,
	&vi_ahb_clk.common,
	&vo_axi_clk.common,
	&vp_apb_clk.common,
	&vp_axi_clk.common,
	&cpu2vp_clk.common,
	&venc_clk.common,
	&dpu0_clk.common,
	&dpu1_clk.common,
	&emmc_sdio_clk.common,
	&gmac1_clk.common,
	&padctrl1_clk.common,
	&dsmart_clk.common,
	&padctrl0_clk.common,
	&gmac_axi_clk.common,
	&gpio3_clk.common,
	&gmac0_clk.common,
	&pwm_clk.common,
	&qspi0_clk.common,
	&qspi1_clk.common,
	&spi_clk.common,
	&uart0_pclk.common,
	&uart1_pclk.common,
	&uart2_pclk.common,
	&uart3_pclk.common,
	&uart4_pclk.common,
	&uart5_pclk.common,
	&gpio0_clk.common,
	&gpio1_clk.common,
	&gpio2_clk.common,
	&i2c0_clk.common,
	&i2c1_clk.common,
	&i2c2_clk.common,
	&i2c3_clk.common,
	&i2c4_clk.common,
	&i2c5_clk.common,
	&spinlock_clk.common,
	&dma_clk.common,
	&mbox0_clk.common,
	&mbox1_clk.common,
	&mbox2_clk.common,
	&mbox3_clk.common,
	&wdt0_clk.common,
	&wdt1_clk.common,
	&timer0_clk.common,
	&timer1_clk.common,
	&sram0_clk.common,
	&sram1_clk.common,
	&sram2_clk.common,
	&sram3_clk.common,
	&uart_sclk.common,
};

#define NR_CLKS	(CLK_UART_SCLK + 1)

static struct clk_hw_onecell_data th1520_hw_clks = {
	.hws	= {
		[CLK_OSC12M]		= &osc12m_clk.hw,
		[CLK_CPU_PLL0]		= &cpu_pll0_clk.common.hw,
		[CLK_CPU_PLL1]		= &cpu_pll1_clk.common.hw,
		[CLK_GMAC_PLL]		= &gmac_pll_clk.common.hw,
		[CLK_VIDEO_PLL]		= &video_pll_clk.common.hw,
		[CLK_DPU0_PLL]		= &dpu0_pll_clk.common.hw,
		[CLK_DPU1_PLL]		= &dpu1_pll_clk.common.hw,
		[CLK_TEE_PLL]		= &tee_pll_clk.common.hw,
		[CLK_C910_I0]		= &c910_i0_clk.common.hw,
		[CLK_C910]		= &c910_clk.common.hw,
		[CLK_BROM]		= &brom_clk.common.hw,
		[CLK_BMU]		= &bmu_clk.common.hw,
		[CLK_AHB2_CPUSYS_HCLK]	= &ahb2_cpusys_hclk.common.hw,
		[CLK_APB3_CPUSYS_PCLK]	= &apb3_cpusys_pclk.common.hw,
		[CLK_AXI4_CPUSYS2_ACLK]	= &axi4_cpusys2_aclk.common.hw,
		[CLK_AON2CPU_A2X]	= &aon2cpu_a2x_clk.common.hw,
		[CLK_X2X_CPUSYS]	= &x2x_cpusys_clk.common.hw,
		[CLK_AXI_ACLK]		= &axi_aclk.common.hw,
		[CLK_CPU2AON_X2H]	= &cpu2aon_x2h_clk.common.hw,
		[CLK_PERI_AHB_HCLK]	= &perisys_ahb_hclk.common.hw,
		[CLK_CPU2PERI_X2H]	= &cpu2peri_x2h_clk.common.hw,
		[CLK_PERI_APB_PCLK]	= &perisys_apb_pclk.common.hw,
		[CLK_PERI2APB_PCLK]	= &peri2sys_apb_pclk.common.hw,
		[CLK_PERI_APB1_HCLK]	= &perisys_apb1_hclk.common.hw,
		[CLK_PERI_APB2_HCLK]	= &perisys_apb2_hclk.common.hw,
		[CLK_PERI_APB3_HCLK]	= &perisys_apb3_hclk.common.hw,
		[CLK_PERI_APB4_HCLK]	= &perisys_apb4_hclk.common.hw,
		[CLK_OUT1]		= &out1_clk.common.hw,
		[CLK_OUT2]		= &out2_clk.common.hw,
		[CLK_OUT3]		= &out3_clk.common.hw,
		[CLK_OUT4]		= &out4_clk.common.hw,
		[CLK_APB_PCLK]		= &apb_pclk.common.hw,
		[CLK_NPU]		= &npu_clk.common.hw,
		[CLK_NPU_AXI]		= &npu_axi_clk.common.hw,
		[CLK_VI]		= &vi_clk.common.hw,
		[CLK_VI_AHB]		= &vi_ahb_clk.common.hw,
		[CLK_VO_AXI]		= &vo_axi_clk.common.hw,
		[CLK_VP_APB]		= &vp_apb_clk.common.hw,
		[CLK_VP_AXI]		= &vp_axi_clk.common.hw,
		[CLK_CPU2VP]		= &cpu2vp_clk.common.hw,
		[CLK_VENC]		= &venc_clk.common.hw,
		[CLK_DPU0]		= &dpu0_clk.common.hw,
		[CLK_DPU1]		= &dpu1_clk.common.hw,
		[CLK_EMMC_SDIO]		= &emmc_sdio_clk.common.hw,
		[CLK_GMAC1]		= &gmac1_clk.common.hw,
		[CLK_PADCTRL1]		= &padctrl1_clk.common.hw,
		[CLK_DSMART]		= &dsmart_clk.common.hw,
		[CLK_PADCTRL0]		= &padctrl0_clk.common.hw,
		[CLK_GMAC_AXI]		= &gmac_axi_clk.common.hw,
		[CLK_GPIO3]		= &gpio3_clk.common.hw,
		[CLK_GMAC0]		= &gmac0_clk.common.hw,
		[CLK_PWM]		= &pwm_clk.common.hw,
		[CLK_QSPI0]		= &qspi0_clk.common.hw,
		[CLK_QSPI1]		= &qspi1_clk.common.hw,
		[CLK_SPI]		= &spi_clk.common.hw,
		[CLK_UART0_PCLK]	= &uart0_pclk.common.hw,
		[CLK_UART1_PCLK]	= &uart1_pclk.common.hw,
		[CLK_UART2_PCLK]	= &uart2_pclk.common.hw,
		[CLK_UART3_PCLK]	= &uart3_pclk.common.hw,
		[CLK_UART4_PCLK]	= &uart4_pclk.common.hw,
		[CLK_UART5_PCLK]	= &uart5_pclk.common.hw,
		[CLK_GPIO0]		= &gpio0_clk.common.hw,
		[CLK_GPIO1]		= &gpio1_clk.common.hw,
		[CLK_GPIO2]		= &gpio2_clk.common.hw,
		[CLK_I2C0]		= &i2c0_clk.common.hw,
		[CLK_I2C1]		= &i2c1_clk.common.hw,
		[CLK_I2C2]		= &i2c2_clk.common.hw,
		[CLK_I2C3]		= &i2c3_clk.common.hw,
		[CLK_I2C4]		= &i2c4_clk.common.hw,
		[CLK_I2C5]		= &i2c5_clk.common.hw,
		[CLK_SPINLOCK]		= &spinlock_clk.common.hw,
		[CLK_DMA]		= &dma_clk.common.hw,
		[CLK_MBOX0]		= &mbox0_clk.common.hw,
		[CLK_MBOX1]		= &mbox1_clk.common.hw,
		[CLK_MBOX2]		= &mbox2_clk.common.hw,
		[CLK_MBOX3]		= &mbox3_clk.common.hw,
		[CLK_WDT0]		= &wdt0_clk.common.hw,
		[CLK_WDT1]		= &wdt1_clk.common.hw,
		[CLK_TIMER0]		= &timer0_clk.common.hw,
		[CLK_TIMER1]		= &timer1_clk.common.hw,
		[CLK_SRAM0]		= &sram0_clk.common.hw,
		[CLK_SRAM1]		= &sram1_clk.common.hw,
		[CLK_SRAM2]		= &sram2_clk.common.hw,
		[CLK_SRAM3]		= &sram3_clk.common.hw,
		[CLK_PLL_GMAC_100M]	= &gmac_pll_clk_100m.hw,
		[CLK_UART_SCLK]		= &uart_sclk.common.hw,
	},
	.num = NR_CLKS,
};

static const struct regmap_config th1520_clk_regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
	.fast_io = true,
};

static int th1520_clk_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct regmap *map;
	void __iomem *regs;
	int ret, i;

	regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(regs))
		return PTR_ERR(regs);

	map = devm_regmap_init_mmio(dev, regs, &th1520_clk_regmap_config);
	if (IS_ERR(map))
		return PTR_ERR(map);

	for (i = 0; i < ARRAY_SIZE(th1520_clks); i++)
		th1520_clks[i]->map = map;

	for (i = 0; i < th1520_hw_clks.num; i++) {
		ret = devm_clk_hw_register(dev, th1520_hw_clks.hws[i]);
		if (ret)
			return ret;
	}

	ret = devm_of_clk_add_hw_provider(dev, of_clk_hw_onecell_get,
					  &th1520_hw_clks);
	if (ret)
		return ret;

	return 0;
}

static const struct of_device_id th1520_clk_match[] = {
	{
		.compatible = "thead,th1520-clk-ap",
	},
	{ /* sentinel */ },
};
MODULE_DEVICE_TABLE(of, th1520_clk_match);

static struct platform_driver th1520_clk_driver = {
	.probe		= th1520_clk_probe,
	.driver		= {
		.name	= "th1520-clk",
		.of_match_table = th1520_clk_match,
	},
};
module_platform_driver(th1520_clk_driver);

MODULE_DESCRIPTION("T-HEAD TH1520 AP Clock driver");
MODULE_AUTHOR("Yangtao Li <frank.li@vivo.com>");
MODULE_AUTHOR("Jisheng Zhang <jszhang@kernel.org>");
MODULE_LICENSE("GPL");

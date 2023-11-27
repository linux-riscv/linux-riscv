/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __CLK_SOPHGO_SG2042_H
#define __CLK_SOPHGO_SG2042_H

#include <linux/regmap.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>

#define R_PLL_STAT		0xC0
#define R_PLL_CLKEN_CONTROL	0xC4
#define R_MPLL_CONTROL		0xE8
#define R_FPLL_CONTROL		0xF4
#define R_DPLL0_CONTROL		0xF8
#define R_DPLL1_CONTROL		0xFC

#define R_CLKENREG0		0x2000
#define R_CLKENREG1		0x2004
#define R_CLKSELREG0		0x2020
#define R_CLKDIVREG0		0x2040
#define R_CLKDIVREG1		0x2044
#define R_CLKDIVREG2		0x2048
#define R_CLKDIVREG3		0x204C
#define R_CLKDIVREG4		0x2050
#define R_CLKDIVREG5		0x2054
#define R_CLKDIVREG6		0x2058
#define R_CLKDIVREG7		0x205C
#define R_CLKDIVREG8		0x2060
#define R_CLKDIVREG9		0x2064
#define R_CLKDIVREG10		0x2068
#define R_CLKDIVREG11		0x206C
#define R_CLKDIVREG12		0x2070
#define R_CLKDIVREG13		0x2074
#define R_CLKDIVREG14		0x2078
#define R_CLKDIVREG15		0x207C
#define R_CLKDIVREG16		0x2080
#define R_CLKDIVREG17		0x2084
#define R_CLKDIVREG18		0x2088
#define R_CLKDIVREG19		0x208C
#define R_CLKDIVREG20		0x2090
#define R_CLKDIVREG21		0x2094
#define R_CLKDIVREG22		0x2098
#define R_CLKDIVREG23		0x209C
#define R_CLKDIVREG24		0x20A0
#define R_CLKDIVREG25		0x20A4
#define R_CLKDIVREG26		0x20A8
#define R_CLKDIVREG27		0x20AC
#define R_CLKDIVREG28		0x20B0
#define R_CLKDIVREG29		0x20B4
#define R_CLKDIVREG30		0x20B8

#define R_RP_RXU_CLK_ENABLE	0x0368
#define R_MP0_STATUS_REG	0x0380
#define R_MP0_CONTROL_REG	0x0384
#define R_MP1_STATUS_REG	0x0388
#define R_MP1_CONTROL_REG	0x038C
#define R_MP2_STATUS_REG	0x0390
#define R_MP2_CONTROL_REG	0x0394
#define R_MP3_STATUS_REG	0x0398
#define R_MP3_CONTROL_REG	0x039C
#define R_MP4_STATUS_REG	0x03A0
#define R_MP4_CONTROL_REG	0x03A4
#define R_MP5_STATUS_REG	0x03A8
#define R_MP5_CONTROL_REG	0x03AC
#define R_MP6_STATUS_REG	0x03B0
#define R_MP6_CONTROL_REG	0x03B4
#define R_MP7_STATUS_REG	0x03B8
#define R_MP7_CONTROL_REG	0x03BC
#define R_MP8_STATUS_REG	0x03C0
#define R_MP8_CONTROL_REG	0x03C4
#define R_MP9_STATUS_REG	0x03C8
#define R_MP9_CONTROL_REG	0x03CC
#define R_MP10_STATUS_REG	0x03D0
#define R_MP10_CONTROL_REG	0x03D4
#define R_MP11_STATUS_REG	0x03D8
#define R_MP11_CONTROL_REG	0x03DC
#define R_MP12_STATUS_REG	0x03E0
#define R_MP12_CONTROL_REG	0x03E4
#define R_MP13_STATUS_REG	0x03E8
#define R_MP13_CONTROL_REG	0x03EC
#define R_MP14_STATUS_REG	0x03F0
#define R_MP14_CONTROL_REG	0x03F4
#define R_MP15_STATUS_REG	0x03F8
#define R_MP15_CONTROL_REG	0x03FC

/*
 * clock common data
 * @iobase & @syscon: point to the same address (top of syscon), the reason
 *  we use two different type of pointer just due to pll uses regmap while
 *  others use iomem.
 * @lock: clock register access lock
 * @onecell_data: used for adding provider
 */
struct sg2042_clk_data {
	void __iomem *iobase;
	struct regmap *syscon;
	struct clk_hw_onecell_data onecell_data;
};

/*
 * PLL clock
 * @id:				used to map clk_onecell_data
 * @name:			used for print even when clk registration failed
 * @map:			used for regmap read/write, regmap is more useful
 *				then iomem address when we have multiple offsets
 *				for different registers
 * @lock:			spinlock to protect register access
 * @offset_status:		offset of pll status registers
 * @offset_enable:		offset of pll enable registers
 * @offset_ctrl:		offset of pll control registers
 * @shift_status_lock:		shift of XXX_LOCK in pll status register
 * @shift_status_updating:	shift of UPDATING_XXX in pll status register
 * @shift_enable:		shift of XXX_CLK_EN in pll enable register
 */
struct sg2042_pll_clock {
	struct clk_hw	hw;

	/* private data */
	unsigned int id;
	const char *name;

	struct regmap *map;
	spinlock_t *lock;

	u32 offset_status;
	u32 offset_enable;
	u32 offset_ctrl;
	u8 shift_status_lock;
	u8 shift_status_updating;
	u8 shift_enable;
};

#define to_sg2042_pll_clk(_hw) container_of(_hw, struct sg2042_pll_clock, hw)

/*
 * Divider clock
 * @id:			used to map clk_onecell_data
 * @name:		used for print even when clk registration failed
 * @reg:		used for readl/writel.
 * @lock:		spinlock to protect register access
 * @offset_ctrl:	offset of divider control registers
 * @shift:		shift of "Clock Divider Factor" in divider control register
 * @width:		width of "Clock Divider Factor" in divider control register
 * @div_flags:		private flags for this clock, not for framework-specific
 * @initial_val:	initial value of the divider, a value < 0 means ignoring
 *			setting of initial value.
 * @table:		the div table that the divider supports
 */
struct sg2042_divider_clock {
	struct clk_hw	hw;

	/* private data */
	unsigned int id;
	const char *name;

	void __iomem *reg;
	spinlock_t *lock;

	unsigned long offset_ctrl;
	u8 shift;
	u8 width;
	u8 div_flags;
	s32 initial_val;
	struct clk_div_table *table;
};

#define to_sg2042_clk_divider(_hw)	\
	container_of(_hw, struct sg2042_divider_clock, hw)

/*
 * Gate clock
 * @id:			used to map clk_onecell_data
 * @name:		string of this clock name
 * @parent_name:	string of parent clock name
 * @flags:		framework-specific flags for this clock
 * @offset_enable:	offset of gate enable registers
 * @bit_idx:		which bit in the register controls gating of this clock
 */
struct sg2042_gate_clock {
	unsigned int id;
	const char *name;
	const char *parent_name;
	unsigned long flags;
	unsigned long offset_enable;
	u8 bit_idx;
};

/*
 * Gate clock
 * @id:			used to map clk_onecell_data
 * @name:		string of this clock name
 * @parent_name:	string array of parents' clock name
 * @flags:		framework-specific flags for this clock
 * @offset_select:	offset of mux selection registers
 * @shift:		shift of "Clock Select" in mux selection register
 * @width:		width of "Clock Select" in mux selection register
 * @clk_nb:		used for notification
 * @original_index:	set by notifier callback
 */
struct sg2042_mux_clock {
	unsigned int id;
	const char *name;
	const char * const *parent_names;
	u8 num_parents;
	unsigned long flags;
	unsigned long offset_select;
	u8 shift;
	u8 width;
	struct notifier_block clk_nb;
	u8 original_index;
};

#define to_sg2042_mux_nb(_nb) container_of(_nb, struct sg2042_mux_clock, clk_nb)

#ifdef DEBUG
	#define dbg_info(format, arg...) \
		pr_info("--> %s: "format"", __func__, ## arg)
#else
	#define dbg_info(format, arg...)
#endif

#endif /* __CLK_SOPHGO_SG2042_H */

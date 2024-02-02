/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __CLK_SOPHGO_SG2042_H
#define __CLK_SOPHGO_SG2042_H

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/regmap.h>

/* Registers defined in SYS_CTRL */
#define R_PLL_BEGIN		0xC0
#define R_PLL_STAT		(0xC0 - R_PLL_BEGIN)
#define R_PLL_CLKEN_CONTROL	(0xC4 - R_PLL_BEGIN)
#define R_MPLL_CONTROL		(0xE8 - R_PLL_BEGIN)
#define R_FPLL_CONTROL		(0xF4 - R_PLL_BEGIN)
#define R_DPLL0_CONTROL		(0xF8 - R_PLL_BEGIN)
#define R_DPLL1_CONTROL		(0xFC - R_PLL_BEGIN)

#define R_SYSGATE_BEGIN		0x0368
#define R_RP_RXU_CLK_ENABLE	(0x0368 - R_SYSGATE_BEGIN)
#define R_MP0_STATUS_REG	(0x0380 - R_SYSGATE_BEGIN)
#define R_MP0_CONTROL_REG	(0x0384 - R_SYSGATE_BEGIN)
#define R_MP1_STATUS_REG	(0x0388 - R_SYSGATE_BEGIN)
#define R_MP1_CONTROL_REG	(0x038C - R_SYSGATE_BEGIN)
#define R_MP2_STATUS_REG	(0x0390 - R_SYSGATE_BEGIN)
#define R_MP2_CONTROL_REG	(0x0394 - R_SYSGATE_BEGIN)
#define R_MP3_STATUS_REG	(0x0398 - R_SYSGATE_BEGIN)
#define R_MP3_CONTROL_REG	(0x039C - R_SYSGATE_BEGIN)
#define R_MP4_STATUS_REG	(0x03A0 - R_SYSGATE_BEGIN)
#define R_MP4_CONTROL_REG	(0x03A4 - R_SYSGATE_BEGIN)
#define R_MP5_STATUS_REG	(0x03A8 - R_SYSGATE_BEGIN)
#define R_MP5_CONTROL_REG	(0x03AC - R_SYSGATE_BEGIN)
#define R_MP6_STATUS_REG	(0x03B0 - R_SYSGATE_BEGIN)
#define R_MP6_CONTROL_REG	(0x03B4 - R_SYSGATE_BEGIN)
#define R_MP7_STATUS_REG	(0x03B8 - R_SYSGATE_BEGIN)
#define R_MP7_CONTROL_REG	(0x03BC - R_SYSGATE_BEGIN)
#define R_MP8_STATUS_REG	(0x03C0 - R_SYSGATE_BEGIN)
#define R_MP8_CONTROL_REG	(0x03C4 - R_SYSGATE_BEGIN)
#define R_MP9_STATUS_REG	(0x03C8 - R_SYSGATE_BEGIN)
#define R_MP9_CONTROL_REG	(0x03CC - R_SYSGATE_BEGIN)
#define R_MP10_STATUS_REG	(0x03D0 - R_SYSGATE_BEGIN)
#define R_MP10_CONTROL_REG	(0x03D4 - R_SYSGATE_BEGIN)
#define R_MP11_STATUS_REG	(0x03D8 - R_SYSGATE_BEGIN)
#define R_MP11_CONTROL_REG	(0x03DC - R_SYSGATE_BEGIN)
#define R_MP12_STATUS_REG	(0x03E0 - R_SYSGATE_BEGIN)
#define R_MP12_CONTROL_REG	(0x03E4 - R_SYSGATE_BEGIN)
#define R_MP13_STATUS_REG	(0x03E8 - R_SYSGATE_BEGIN)
#define R_MP13_CONTROL_REG	(0x03EC - R_SYSGATE_BEGIN)
#define R_MP14_STATUS_REG	(0x03F0 - R_SYSGATE_BEGIN)
#define R_MP14_CONTROL_REG	(0x03F4 - R_SYSGATE_BEGIN)
#define R_MP15_STATUS_REG	(0x03F8 - R_SYSGATE_BEGIN)
#define R_MP15_CONTROL_REG	(0x03FC - R_SYSGATE_BEGIN)

/* Registers defined in CLOCK */
#define R_CLKENREG0		0x00
#define R_CLKENREG1		0x04
#define R_CLKSELREG0		0x20
#define R_CLKDIVREG0		0x40
#define R_CLKDIVREG1		0x44
#define R_CLKDIVREG2		0x48
#define R_CLKDIVREG3		0x4C
#define R_CLKDIVREG4		0x50
#define R_CLKDIVREG5		0x54
#define R_CLKDIVREG6		0x58
#define R_CLKDIVREG7		0x5C
#define R_CLKDIVREG8		0x60
#define R_CLKDIVREG9		0x64
#define R_CLKDIVREG10		0x68
#define R_CLKDIVREG11		0x6C
#define R_CLKDIVREG12		0x70
#define R_CLKDIVREG13		0x74
#define R_CLKDIVREG14		0x78
#define R_CLKDIVREG15		0x7C
#define R_CLKDIVREG16		0x80
#define R_CLKDIVREG17		0x84
#define R_CLKDIVREG18		0x88
#define R_CLKDIVREG19		0x8C
#define R_CLKDIVREG20		0x90
#define R_CLKDIVREG21		0x94
#define R_CLKDIVREG22		0x98
#define R_CLKDIVREG23		0x9C
#define R_CLKDIVREG24		0xA0
#define R_CLKDIVREG25		0xA4
#define R_CLKDIVREG26		0xA8
#define R_CLKDIVREG27		0xAC
#define R_CLKDIVREG28		0xB0
#define R_CLKDIVREG29		0xB4
#define R_CLKDIVREG30		0xB8

/*
 * Common data of clock-controller
 * Note: this structure will be used both by clkgen & sysclk.
 * @iobase: base address of clock-controller
 * @regmap: base address of clock-controller for pll, just due to PLL uses
 *  regmap while others use iomem.
 * @lock: clock register access lock
 * @onecell_data: used for adding providers.
 */
struct sg2042_clk_data {
	void __iomem *iobase;
	struct regmap *regmap;
	struct clk_hw_onecell_data onecell_data;
};

/*
 * PLL clock
 * @id:				used to map clk_onecell_data
 * @name:			used for print even when clk registration failed
 * @map:			used for regmap read/write, regmap is more useful
 *				then iomem address when we have multiple offsets
 *				for different registers.
 *				NOTE: PLL registers are all in SYS_CTRL!
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
	/* modification of frequency can only be served one at the time */
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
 *			NOTE: DIV registers are ALL in CLOCK!
 * @lock:		spinlock to protect register access
 * @offset_ctrl:	offset of divider control registers
 * @shift:		shift of "Clock Divider Factor" in divider control register
 * @width:		width of "Clock Divider Factor" in divider control register
 * @div_flags:		private flags for this clock, not for framework-specific
 * @initval:		In the divider control register, we can configure whether
 *			to use the value of "Clock Divider Factor" or just use
 *			the initial value pre-configured by IC. BIT[3] controls
 *			this and by default (value is 0), means initial value
 *			is used.
 *			**NOTE** that we cannot read the initial value (default
 *			value when poweron) and default value of "Clock Divider
 *			Factor" is zero, which I think is a hardware design flaw
 *			and should be sync-ed with the initial value. So in
 *			software we have to add a configuration item (initval)
 *			to manually configure this value and use it when BIT[3]
 *			is zero.
 */
struct sg2042_divider_clock {
	struct clk_hw	hw;

	/* private data */
	unsigned int id;
	const char *name;

	void __iomem *reg;
	/* modification of frequency can only be served one at the time */
	spinlock_t *lock;

	unsigned long offset_ctrl;
	u8 shift;
	u8 width;
	u8 div_flags;
	u32 initval;
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
 * Mux clock
 * @id:			used to map clk_onecell_data
 * @name:		string of this clock name
 * @parent_name:	string array of parents' clock name
 * @flags:		framework-specific flags for this clock
 * @offset_select:	offset of mux selection registers
 *			NOTE: MUX registers are ALL in CLOCK!
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

#endif /* __CLK_SOPHGO_SG2042_H */

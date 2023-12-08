/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __CLK_SOPHGO_SG2042_H
#define __CLK_SOPHGO_SG2042_H

#include <linux/regmap.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>

/* Registers defined in SYS_CTRL */
#define R_PLL_STAT		0xC0
#define R_PLL_CLKEN_CONTROL	0xC4
#define R_MPLL_CONTROL		0xE8
#define R_FPLL_CONTROL		0xF4
#define R_DPLL0_CONTROL		0xF8
#define R_DPLL1_CONTROL		0xFC

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
 * clock common data
 * @iobase: address of clock-controller
 * @iobase_syscon & @regmap_syscon: point to the same address of system-controller,
 *  the reason we use two different type of pointer just due to PLL uses
 *  regmap while others use iomem.
 * @lock: clock register access lock
 * @onecell_data: used for adding providers.
 */
struct sg2042_clk_data {
	void __iomem *iobase;
	void __iomem *iobase_syscon;
	struct regmap *regmap_syscon;
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
 * @flag_sysctrl:	flag if this clock is controlled by registers defined
 *			in SYS_CTRL, 1: yes, 0: no, it's in CLOCK.
 *			NOTE: Gate registers are scattered in SYS_CTRL and CLOCK!
 */
struct sg2042_gate_clock {
	unsigned int id;
	const char *name;
	const char *parent_name;
	unsigned long flags;
	unsigned long offset_enable;
	u8 bit_idx;
	u8 flag_sysctrl;
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

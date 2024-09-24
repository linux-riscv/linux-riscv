// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2016-2017 Linaro Ltd.
 * Copyright (C) 2022-2024 Canaan Bright Sight Co., Ltd
 * Copyright (C) 2024 Junhui Liu <liujh2818@outlook.com>
 */

#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/reset-controller.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <dt-bindings/reset/canaan,k230-rst.h>

/**
 * enum k230_rst_type - K230 reset types
 * @RST_TYPE_CPU0: Reset type for CPU0
 *	Automatically clears, has write enable and done bit, active high
 * @RST_TYPE_CPU1: Reset type for CPU1
 *	Manually clears, has write enable and done bit, active high
 * @RST_TYPE_FLUSH: Reset type for CPU L2 cache flush
 *	Automatically clears, has write enable, no done bit, active high
 * @RST_TYPE_HW_DONE: Reset type for hardware auto clear
 *	Automatically clears, no write enable, has done bit, active high
 * @RST_TYPE_SW_DONE: Reset type for software manual clear
 *	Manually clears, no write enable and done bit,
 *	active high if ID is RST_SPI2AXI, otherwise active low
 */
enum k230_rst_type {
	RST_TYPE_CPU0 = 0,
	RST_TYPE_CPU1,
	RST_TYPE_FLUSH,
	RST_TYPE_HW_DONE,
	RST_TYPE_SW_DONE,
};

struct k230_rst_map {
	u32			offset;
	enum k230_rst_type	type;
	u32			done;
	u32			reset;
};

struct k230_rst {
	struct reset_controller_dev	rcdev;
	struct device			*dev;
	void __iomem			*base;
	spinlock_t			lock;
};

static const struct k230_rst_map k230_resets[] = {
	[RST_CPU0]		= { 0x4,  RST_TYPE_CPU0,    BIT(12), BIT(0) },
	[RST_CPU1]		= { 0xc,  RST_TYPE_CPU1,    BIT(12), BIT(0) },
	[RST_CPU0_FLUSH]	= { 0x4,  RST_TYPE_FLUSH,   0,       BIT(4) },
	[RST_CPU1_FLUSH]	= { 0xc,  RST_TYPE_FLUSH,   0,       BIT(4) },
	[RST_AI]		= { 0x14, RST_TYPE_HW_DONE, BIT(31), BIT(0) },
	[RST_VPU]		= { 0x1c, RST_TYPE_HW_DONE, BIT(31), BIT(0) },
	[RST_HS]		= { 0x2c, RST_TYPE_HW_DONE, BIT(4),  BIT(0) },
	[RST_HS_AHB]		= { 0x2c, RST_TYPE_HW_DONE, BIT(5),  BIT(1) },
	[RST_SDIO0]		= { 0x34, RST_TYPE_HW_DONE, BIT(28), BIT(0) },
	[RST_SDIO1]		= { 0x34, RST_TYPE_HW_DONE, BIT(29), BIT(1) },
	[RST_SDIO_AXI]		= { 0x34, RST_TYPE_HW_DONE, BIT(30), BIT(2) },
	[RST_USB0]		= { 0x3c, RST_TYPE_HW_DONE, BIT(28), BIT(0) },
	[RST_USB1]		= { 0x3c, RST_TYPE_HW_DONE, BIT(29), BIT(1) },
	[RST_USB0_AHB]		= { 0x3c, RST_TYPE_HW_DONE, BIT(30), BIT(0) },
	[RST_USB1_AHB]		= { 0x3c, RST_TYPE_HW_DONE, BIT(31), BIT(1) },
	[RST_SPI0]		= { 0x44, RST_TYPE_HW_DONE, BIT(28), BIT(0) },
	[RST_SPI1]		= { 0x44, RST_TYPE_HW_DONE, BIT(29), BIT(1) },
	[RST_SPI2]		= { 0x44, RST_TYPE_HW_DONE, BIT(30), BIT(2) },
	[RST_SEC]		= { 0x4c, RST_TYPE_HW_DONE, BIT(31), BIT(0) },
	[RST_PDMA]		= { 0x54, RST_TYPE_HW_DONE, BIT(28), BIT(0) },
	[RST_SDMA]		= { 0x54, RST_TYPE_HW_DONE, BIT(29), BIT(1) },
	[RST_DECOMPRESS]	= { 0x5c, RST_TYPE_HW_DONE, BIT(31), BIT(0) },
	[RST_SRAM]		= { 0x64, RST_TYPE_HW_DONE, BIT(28), BIT(0) },
	[RST_SHRM_AXIM]		= { 0x64, RST_TYPE_HW_DONE, BIT(30), BIT(2) },
	[RST_SHRM_AXIS]		= { 0x64, RST_TYPE_HW_DONE, BIT(31), BIT(3) },
	[RST_NONAI2D]		= { 0x6c, RST_TYPE_HW_DONE, BIT(31), BIT(0) },
	[RST_MCTL]		= { 0x74, RST_TYPE_HW_DONE, BIT(31), BIT(0) },
	[RST_ISP]		= { 0x80, RST_TYPE_HW_DONE, BIT(29), BIT(6) },
	[RST_ISP_DW]		= { 0x80, RST_TYPE_HW_DONE, BIT(28), BIT(5) },
	[RST_DPU]		= { 0x88, RST_TYPE_HW_DONE, BIT(31), BIT(0) },
	[RST_DISP]		= { 0x90, RST_TYPE_HW_DONE, BIT(31), BIT(0) },
	[RST_GPU]		= { 0x98, RST_TYPE_HW_DONE, BIT(31), BIT(0) },
	[RST_AUDIO]		= { 0xa4, RST_TYPE_HW_DONE, BIT(31), BIT(0) },
	[RST_TIMER0]		= { 0x20, RST_TYPE_SW_DONE, 0,       BIT(0) },
	[RST_TIMER1]		= { 0x20, RST_TYPE_SW_DONE, 0,       BIT(1) },
	[RST_TIMER2]		= { 0x20, RST_TYPE_SW_DONE, 0,       BIT(2) },
	[RST_TIMER3]		= { 0x20, RST_TYPE_SW_DONE, 0,       BIT(3) },
	[RST_TIMER4]		= { 0x20, RST_TYPE_SW_DONE, 0,       BIT(4) },
	[RST_TIMER5]		= { 0x20, RST_TYPE_SW_DONE, 0,       BIT(5) },
	[RST_TIMER_APB]		= { 0x20, RST_TYPE_SW_DONE, 0,       BIT(6) },
	[RST_HDI]		= { 0x20, RST_TYPE_SW_DONE, 0,       BIT(7) },
	[RST_WDT0]		= { 0x20, RST_TYPE_SW_DONE, 0,       BIT(12) },
	[RST_WDT1]		= { 0x20, RST_TYPE_SW_DONE, 0,       BIT(13) },
	[RST_WDT0_APB]		= { 0x20, RST_TYPE_SW_DONE, 0,       BIT(14) },
	[RST_WDT1_APB]		= { 0x20, RST_TYPE_SW_DONE, 0,       BIT(15) },
	[RST_TS_APB]		= { 0x20, RST_TYPE_SW_DONE, 0,       BIT(16) },
	[RST_MAILBOX]		= { 0x20, RST_TYPE_SW_DONE, 0,       BIT(17) },
	[RST_STC]		= { 0x20, RST_TYPE_SW_DONE, 0,       BIT(18) },
	[RST_PMU]		= { 0x20, RST_TYPE_SW_DONE, 0,       BIT(19) },
	[RST_LS_APB]		= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(0) },
	[RST_UART0]		= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(1) },
	[RST_UART1]		= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(2) },
	[RST_UART2]		= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(3) },
	[RST_UART3]		= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(4) },
	[RST_UART4]		= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(5) },
	[RST_I2C0]		= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(6) },
	[RST_I2C1]		= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(7) },
	[RST_I2C2]		= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(8) },
	[RST_I2C3]		= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(9) },
	[RST_I2C4]		= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(10) },
	[RST_JAMLINK0_APB]	= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(11) },
	[RST_JAMLINK1_APB]	= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(12) },
	[RST_JAMLINK2_APB]	= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(13) },
	[RST_JAMLINK3_APB]	= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(14) },
	[RST_CODEC_APB]		= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(17) },
	[RST_GPIO_DB]		= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(18) },
	[RST_GPIO_APB]		= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(19) },
	[RST_ADC]		= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(20) },
	[RST_ADC_APB]		= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(21) },
	[RST_PWM_APB]		= { 0x24, RST_TYPE_SW_DONE, 0,       BIT(22) },
	[RST_SHRM_APB]		= { 0x64, RST_TYPE_SW_DONE, 0,       BIT(1) },
	[RST_CSI0]		= { 0x80, RST_TYPE_SW_DONE, 0,       BIT(0) },
	[RST_CSI1]		= { 0x80, RST_TYPE_SW_DONE, 0,       BIT(1) },
	[RST_CSI2]		= { 0x80, RST_TYPE_SW_DONE, 0,       BIT(2) },
	[RST_CSI_DPHY]		= { 0x80, RST_TYPE_SW_DONE, 0,       BIT(3) },
	[RST_ISP_AHB]		= { 0x80, RST_TYPE_SW_DONE, 0,       BIT(4) },
	[RST_M0]		= { 0x80, RST_TYPE_SW_DONE, 0,       BIT(7) },
	[RST_M1]		= { 0x80, RST_TYPE_SW_DONE, 0,       BIT(8) },
	[RST_M2]		= { 0x80, RST_TYPE_SW_DONE, 0,       BIT(9) },
	[RST_SPI2AXI]		= { 0xa8, RST_TYPE_SW_DONE, 0,       BIT(0) }
};

#define to_k230_rst(p) container_of((p), struct k230_rst, rcdev)

static void k230_rst_clear_done(struct k230_rst *rstc, unsigned long id,
				bool write_en)
{
	const struct k230_rst_map *rmap = &k230_resets[id];
	unsigned long flags;
	u32 reg;

	spin_lock_irqsave(&rstc->lock, flags);

	reg = readl(rstc->base + rmap->offset);

	/* write 1 to clear */
	reg |= rmap->done;
	if (write_en)
		reg |= rmap->done << 16;

	writel(reg, rstc->base + rmap->offset);

	spin_unlock_irqrestore(&rstc->lock, flags);
}

static int k230_rst_wait_and_clear_done(struct k230_rst *rstc, unsigned long id,
					bool write_en)
{
	const struct k230_rst_map *rmap = &k230_resets[id];
	u32 reg;
	int ret;

	ret = readl_poll_timeout(rstc->base + rmap->offset, reg,
				 reg & rmap->done, 10, 1000);
	if (ret) {
		dev_err(rstc->dev, "Wait for reset done timeout\n");
		return ret;
	}

	k230_rst_clear_done(rstc, id, write_en);

	return 0;
}

static void k230_rst_update(struct k230_rst *rstc, unsigned long id,
			    bool assert, bool write_en, bool active_low)
{
	const struct k230_rst_map *rmap = &k230_resets[id];
	unsigned long flags;
	u32 reg;

	spin_lock_irqsave(&rstc->lock, flags);

	reg = readl(rstc->base + rmap->offset);

	if (assert ^ active_low)
		reg |= rmap->reset;
	else
		reg &= ~rmap->reset;

	if (write_en)
		reg |= rmap->reset << 16;

	writel(reg, rstc->base + rmap->offset);

	spin_unlock_irqrestore(&rstc->lock, flags);
}

static int k230_rst_assert(struct reset_controller_dev *rcdev, unsigned long id)
{
	struct k230_rst *rstc = to_k230_rst(rcdev);
	const struct k230_rst_map *rmap = &k230_resets[id];
	int ret;

	switch (rmap->type) {
	case RST_TYPE_CPU0:
		k230_rst_clear_done(rstc, id, true);
		k230_rst_update(rstc, id, true, true, false);
		ret = k230_rst_wait_and_clear_done(rstc, id, true);
		break;
	case RST_TYPE_CPU1:
	case RST_TYPE_FLUSH:
		k230_rst_update(rstc, id, true, true, false);
		break;
	case RST_TYPE_HW_DONE:
		k230_rst_clear_done(rstc, id, false);
		k230_rst_update(rstc, id, true, false, false);
		ret = k230_rst_wait_and_clear_done(rstc, id, false);
		break;
	case RST_TYPE_SW_DONE:
		k230_rst_update(rstc, id, true, false,
				id == RST_SPI2AXI ? false : true);
		break;
	default:
		return -EINVAL;
	}

	return ret;
}

static int k230_rst_deassert(struct reset_controller_dev *rcdev,
			     unsigned long id)
{
	struct k230_rst *rstc = to_k230_rst(rcdev);
	int ret;

	switch (k230_resets[id].type) {
	case RST_TYPE_CPU0:
		break;
	case RST_TYPE_CPU1:
		k230_rst_update(rstc, id, false, true, false);
		ret = k230_rst_wait_and_clear_done(rstc, id, true);
		break;
	case RST_TYPE_FLUSH:
	case RST_TYPE_HW_DONE:
		break;
	case RST_TYPE_SW_DONE:
		k230_rst_update(rstc, id, false, false,
				id == RST_SPI2AXI ? false : true);
		break;
	default:
		return -EINVAL;
	}

	return ret;
}

static int k230_rst_reset(struct reset_controller_dev *rcdev, unsigned long id)
{
	int ret;

	ret = k230_rst_assert(rcdev, id);
	if (ret)
		return ret;

	udelay(10);

	return k230_rst_deassert(rcdev, id);
}

static const struct reset_control_ops k230_rst_ops = {
	.reset		= k230_rst_reset,
	.assert		= k230_rst_assert,
	.deassert	= k230_rst_deassert,
};

static int k230_rst_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct k230_rst *rstc;

	rstc = devm_kzalloc(dev, sizeof(*rstc), GFP_KERNEL);
	if (!rstc)
		return -ENOMEM;

	rstc->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(rstc->base))
		return PTR_ERR(rstc->base);

	spin_lock_init(&rstc->lock);

	rstc->dev		= dev;
	rstc->rcdev.owner	= THIS_MODULE;
	rstc->rcdev.ops		= &k230_rst_ops;
	rstc->rcdev.nr_resets	= ARRAY_SIZE(k230_resets);
	rstc->rcdev.of_node	= dev->of_node;

	return devm_reset_controller_register(dev, &rstc->rcdev);
}

static const struct of_device_id k230_rst_match[] = {
	{ .compatible = "canaan,k230-rst", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, k230_rst_match);

static struct platform_driver k230_rst_driver = {
	.probe = k230_rst_probe,
	.driver = {
		.name = "k230-rst",
		.of_match_table = k230_rst_match,
	}
};
module_platform_driver(k230_rst_driver);

MODULE_AUTHOR("Junhui Liu <liujh2818@outlook.com>");
MODULE_DESCRIPTION("Canaan K230 reset driver");
MODULE_LICENSE("GPL v2");

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Sophgo Inc.
 * Copyright (C) 2024 Haylen Chu <heylenay@4d2.org>
 */

#include <linux/bits.h>
#include <linux/clk.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/thermal.h>
#include <linux/units.h>

#define TEMPSEN_VERSION					0x0
#define TEMPSEN_CTRL					0x4
#define  TEMPSEN_CTRL_EN				BIT(0)
#define  TEMPSEN_CTRL_SEL_MASK				GENMASK(7, 4)
#define  TEMPSEN_CTRL_SEL_OFFSET			4
#define TEMPSEN_STATUS					0x8
#define TEMPSEN_SET					0xc
#define  TEMPSEN_SET_CHOPSEL_MASK			GENMASK(5, 4)
#define  TEMPSEN_SET_CHOPSEL_OFFSET			4
#define  TEMPSEN_SET_CHOPSEL_128T			0
#define  TEMPSEN_SET_CHOPSEL_256T			1
#define  TEMPSEN_SET_CHOPSEL_512T			2
#define  TEMPSEN_SET_CHOPSEL_1024T			3
#define  TEMPSEN_SET_ACCSEL_MASK			GENMASK(7, 6)
#define  TEMPSEN_SET_ACCSEL_OFFSET			6
#define  TEMPSEN_SET_ACCSEL_512T			0
#define  TEMPSEN_SET_ACCSEL_1024T			1
#define  TEMPSEN_SET_ACCSEL_2048T			2
#define  TEMPSEN_SET_ACCSEL_4096T			3
#define  TEMPSEN_SET_CYC_CLKDIV_MASK			GENMASK(15, 8)
#define  TEMPSEN_SET_CYC_CLKDIV_OFFSET			8
#define TEMPSEN_INTR_EN					0x10
#define TEMPSEN_INTR_CLR				0x14
#define TEMPSEN_INTR_STA				0x18
#define TEMPSEN_INTR_RAW				0x1c
#define  TEMPSEN_INTR_THRESHOLD_HIGH(n)			BIT(4 + (n))
#define  TEMPSEN_INTR_THRESHOLD_LOW(n)			BIT(8 + (n))
#define TEMPSEN_RESULT(n)				(0x20 + (n) * 4)
#define  TEMPSEN_RESULT_RESULT_MASK			GENMASK(12, 0)
#define  TEMPSEN_RESULT_MAX_RESULT_MASK			GENMASK(28, 16)
#define  TEMPSEN_RESULT_CLR_MAX_RESULT			BIT(31)
#define TEMPSEN_THRESHOLD(n)				(0x40 + (n) * 4)
#define  TEMPSEN_THRESHOLD_HIGH_OFFSET			0
#define  TEMPSEN_THRESHOLD_LOW_OFFSET			16
#define TEMPSEN_AUTO_PERIOD				0x64
#define  TEMPSEN_AUTO_PERIOD_AUTO_CYCLE_MASK		GENMASK(23, 0)
#define  TEMPSEN_AUTO_PERIOD_AUTO_CYCLE_OFFSET		0

struct cv1800_thermal_zone {
	struct device *dev;
	void __iomem *base;
	struct clk *clk_tempsen;
	u32 sample_cycle;
};

static void cv1800_thermal_init(struct cv1800_thermal_zone *ctz)
{
	void __iomem *base = ctz->base;
	u32 regval;

	writel(readl(base + TEMPSEN_INTR_RAW), base + TEMPSEN_INTR_CLR);
	writel(TEMPSEN_RESULT_CLR_MAX_RESULT, base + TEMPSEN_RESULT(0));

	regval = readl(base + TEMPSEN_SET);
	regval &= ~TEMPSEN_SET_CHOPSEL_MASK;
	regval &= ~TEMPSEN_SET_ACCSEL_MASK;
	regval &= ~TEMPSEN_SET_CYC_CLKDIV_MASK;
	regval |= TEMPSEN_SET_CHOPSEL_1024T << TEMPSEN_SET_CHOPSEL_OFFSET;
	regval |= TEMPSEN_SET_ACCSEL_2048T << TEMPSEN_SET_ACCSEL_OFFSET;
	regval |= 0x31 << TEMPSEN_SET_CYC_CLKDIV_OFFSET;
	writel(regval, base + TEMPSEN_SET);

	regval = readl(base + TEMPSEN_AUTO_PERIOD);
	regval &= ~TEMPSEN_AUTO_PERIOD_AUTO_CYCLE_MASK;
	regval |= ctz->sample_cycle << TEMPSEN_AUTO_PERIOD_AUTO_CYCLE_OFFSET;
	writel(regval, base + TEMPSEN_AUTO_PERIOD);

	regval = readl(base + TEMPSEN_CTRL);
	regval &= ~TEMPSEN_CTRL_SEL_MASK;
	regval |= 1 << TEMPSEN_CTRL_SEL_OFFSET;
	regval |= TEMPSEN_CTRL_EN;
	writel(regval, base + TEMPSEN_CTRL);
}

static void cv1800_thermal_deinit(struct cv1800_thermal_zone *ctz)
{
	void __iomem *base = ctz->base;
	u32 regval;

	regval = readl(base + TEMPSEN_CTRL);
	regval &= ~(TEMPSEN_CTRL_SEL_MASK | TEMPSEN_CTRL_EN);
	writel(regval, base + TEMPSEN_CTRL);

	writel(0, base + TEMPSEN_INTR_EN);
}

/*
 *	Raw register value to temperature (mC) formula:
 *
 *		       read_val * 1000 * 716
 *	Temperature = ----------------------- - 273000
 *				divider
 *
 *	where divider should be ticks number of accumulation period,
 *	e.g. 2048 for TEMPSEN_CTRL_ACCSEL_2048T
 */
static int cv1800_calc_temp(u32 result)
{
	return (result * 1000) * 716 / 2048 - 273000;
}

static u32 cv1800_calc_raw(int temp)
{
	return (temp + 273000) * 2048 / (1000 * 716);
}

static int cv1800_set_threshold(struct cv1800_thermal_zone *ctz,
				int low, int high)
{
	writel((cv1800_calc_raw(low) << TEMPSEN_THRESHOLD_LOW_OFFSET) |
	       (cv1800_calc_raw(high) << TEMPSEN_THRESHOLD_HIGH_OFFSET),
	       ctz->base + TEMPSEN_THRESHOLD(0));
	writel(TEMPSEN_INTR_THRESHOLD_LOW(0) | TEMPSEN_INTR_THRESHOLD_HIGH(0),
	       ctz->base + TEMPSEN_INTR_EN);

	return 0;
}

static irqreturn_t cv1800_irq_thread(int irq, void *dev)
{
	struct thermal_zone_device *tdev = dev;
	struct cv1800_thermal_zone *ctz = thermal_zone_device_priv(tdev);

	writel(readl(ctz->base + TEMPSEN_INTR_RAW),
	       ctz->base + TEMPSEN_INTR_CLR);

	thermal_zone_device_update(tdev, THERMAL_EVENT_UNSPECIFIED);

	return IRQ_HANDLED;
}

static int cv1800_get_temp(struct thermal_zone_device *tdev, int *temperature)
{
	struct cv1800_thermal_zone *ctz = thermal_zone_device_priv(tdev);
	void __iomem *base = ctz->base;
	u32 result;

	result = readl(base + TEMPSEN_RESULT(0)) & TEMPSEN_RESULT_RESULT_MASK;
	*temperature = cv1800_calc_temp(result);

	return 0;
}

static int cv1800_set_trips(struct thermal_zone_device *tdev, int low, int high)
{
	struct cv1800_thermal_zone *ctz = thermal_zone_device_priv(tdev);

	return cv1800_set_threshold(ctz,
				    clamp(low, -273 * 1000, 200 * 1000),
				    clamp(high, -273 * 1000, 200 * 1000));
}

static const struct thermal_zone_device_ops cv1800_thermal_ops = {
	.get_temp	= cv1800_get_temp,
	.set_trips	= cv1800_set_trips,
};

static const struct of_device_id cv1800_thermal_of_match[] = {
	{ .compatible = "sophgo,cv1800-thermal" },
	{},
};
MODULE_DEVICE_TABLE(of, cv1800_thermal_of_match);

static int
cv1800_parse_dt(struct cv1800_thermal_zone *ctz)
{
	struct device_node *np = ctz->dev->of_node;
	u32 tmp;

	if (of_property_read_u32(np, "sample-rate-hz", &tmp)) {
		ctz->sample_cycle = 1000000;
	} else {
		/* sample cycle should be at least 524us */
		if (tmp > 1000000 / 524) {
			dev_err(ctz->dev, "invalid sample rate %d\n", tmp);
			return -EINVAL;
		}

		ctz->sample_cycle = 1000000 / tmp;
	}

	return 0;
}

static int cv1800_thermal_probe(struct platform_device *pdev)
{
	struct thermal_zone_device *tdev;
	struct cv1800_thermal_zone *ctz;
	struct resource *res;
	int ret, irq;

	ctz = devm_kzalloc(&pdev->dev, sizeof(*ctz), GFP_KERNEL);
	if (!ctz)
		return -ENOMEM;

	ctz->dev = &pdev->dev;

	ret = cv1800_parse_dt(ctz);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "failed to parse dt\n");

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	ctz->base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(ctz->base))
		return dev_err_probe(&pdev->dev, PTR_ERR(ctz->base),
				     "failed to map tempsen registers\n");

	ctz->clk_tempsen = devm_clk_get_enabled(&pdev->dev, NULL);
	if (IS_ERR(ctz->clk_tempsen))
		return dev_err_probe(&pdev->dev, PTR_ERR(ctz->clk_tempsen),
				     "failed to get clk_tempsen\n");

	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return irq;

	cv1800_thermal_init(ctz);

	tdev = devm_thermal_of_zone_register(&pdev->dev, 0, ctz,
					     &cv1800_thermal_ops);
	if (IS_ERR(tdev))
		return dev_err_probe(&pdev->dev, PTR_ERR(tdev),
				     "failed to register thermal zone\n");

	ret = devm_request_threaded_irq(&pdev->dev, irq, NULL,
					cv1800_irq_thread, IRQF_ONESHOT,
					"cv1800_thermal", tdev);
	if (ret < 0)
		return dev_err_probe(&pdev->dev, ret, "failed to request irq\n");

	platform_set_drvdata(pdev, ctz);

	return 0;
}

static void cv1800_thermal_remove(struct platform_device *pdev)
{
	struct cv1800_thermal_zone *ctz = platform_get_drvdata(pdev);

	cv1800_thermal_deinit(ctz);
}

static int __maybe_unused cv1800_thermal_suspend(struct device *dev)
{
	struct cv1800_thermal_zone *ctz = dev_get_drvdata(dev);

	cv1800_thermal_deinit(ctz);
	clk_disable_unprepare(ctz->clk_tempsen);

	return 0;
}

static int __maybe_unused cv1800_thermal_resume(struct device *dev)
{
	struct cv1800_thermal_zone *ctz = dev_get_drvdata(dev);

	clk_prepare_enable(ctz->clk_tempsen);
	cv1800_thermal_init(ctz);

	return 0;
}

static SIMPLE_DEV_PM_OPS(cv1800_thermal_pm_ops,
			 cv1800_thermal_suspend, cv1800_thermal_resume);

static struct platform_driver cv1800_thermal_driver = {
	.probe = cv1800_thermal_probe,
	.remove = cv1800_thermal_remove,
	.driver = {
		.name = "cv1800-thermal",
		.pm = &cv1800_thermal_pm_ops,
		.of_match_table = cv1800_thermal_of_match,
	},
};

module_platform_driver(cv1800_thermal_driver);

MODULE_DESCRIPTION("Sophgo CV1800 thermal driver");
MODULE_AUTHOR("Haylen Chu <heylenay@4d2.org>");
MODULE_LICENSE("GPL");

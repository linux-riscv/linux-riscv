// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Sophgo SARADC Driver
 *
 *  Copyright (C) Bootlin 2024
 *  Author: Thomas Bonnefille <thomas.bonnefille@bootlin.com>
 */

#include <linux/clk.h>
#include <linux/completion.h>
#include <linux/dev_printk.h>
#include <linux/interrupt.h>
#include <linux/iio/iio.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/platform_device.h>

#define SOPHGO_SARADC_CTRL_REG			0x04
#define		SOPHGO_SARADC_EN		BIT(0)
#define		SOPHGO_SARADC_SEL(x)		BIT((x)+4)
#define SOPHGO_SARADC_STATUS_REG		0x08
#define		SOPHGO_SARADC_BUSY		BIT(0)
#define SOPHGO_SARADC_CYC_SET_REG		0x0C
#define		SOPHGO_SARADC_DEF_CYC_SETTINGS	0xF1F0F
#define SOPHGO_SARADC_CH_RESULT_REG(x)		(0x10+4*(x))
#define		SARADC_CH_RESULT(x)		((x) & 0xfff)
#define		SARADC_CH_VALID(x)		((x) & BIT(15))
#define SOPHGO_SARADC_INTR_EN_REG		0x20
#define SOPHGO_SARADC_INTR_CLR_REG		0x24

#define SOPHGO_SARADC_CHANNEL(index)					\
	{								\
		.type = IIO_VOLTAGE,					\
		.indexed = 1,						\
		.channel = index,					\
		.info_mask_separate = BIT(IIO_CHAN_INFO_RAW),		\
		.info_mask_shared_by_type = BIT(IIO_CHAN_INFO_SCALE),	\
		.scan_index = index,					\
		.scan_type = {						\
			.sign = 'u',					\
			.realbits = 12,					\
		},							\
	}

struct sophgo_saradc {
	struct completion completion;
	struct iio_info info;
	void __iomem *regs;
	struct mutex lock;
	struct clk *clk;
	int irq;
};

static const struct iio_chan_spec sophgo_channels[] = {
	SOPHGO_SARADC_CHANNEL(1),
	SOPHGO_SARADC_CHANNEL(2),
	SOPHGO_SARADC_CHANNEL(3),
};

static void sophgo_saradc_start_measurement(struct sophgo_saradc *saradc,
					    int channel)
{
	writel(0, saradc->regs + SOPHGO_SARADC_CTRL_REG);
	writel(SOPHGO_SARADC_SEL(channel) | SOPHGO_SARADC_EN,
	       saradc->regs + SOPHGO_SARADC_CTRL_REG);
}

static int sophgo_saradc_wait(struct sophgo_saradc *saradc)
{
	if (saradc->irq < 0) {
		u32 reg;

		return readl_poll_timeout(saradc->regs + SOPHGO_SARADC_STATUS_REG,
					  reg, !(reg & SOPHGO_SARADC_BUSY),
					  500, 1000000);
	} else {
		int ret;

		ret = wait_for_completion_timeout(&saradc->completion,
						  msecs_to_jiffies(1000)) > 0
						  ? 0 : -ETIMEDOUT;
		return ret;
	}
}

static int sophgo_saradc_read_raw(struct iio_dev *indio_dev,
				  struct iio_chan_spec const *chan,
				  int *val, int *val2, long mask)
{
	switch (mask) {
	case IIO_CHAN_INFO_RAW:
		struct sophgo_saradc *saradc = iio_priv(indio_dev);
		u32 sample;
		int ret;

		mutex_lock(&saradc->lock);
		sophgo_saradc_start_measurement(saradc, chan->scan_index);
		ret = sophgo_saradc_wait(saradc);
		if (ret < 0) {
			mutex_unlock(&saradc->lock);
			return ret;
		}

		sample = readl(saradc->regs + SOPHGO_SARADC_CH_RESULT_REG(chan->scan_index));
		mutex_unlock(&saradc->lock);

		if (SARADC_CH_VALID(sample)) {
			*val = SARADC_CH_RESULT(sample);
			return IIO_VAL_INT;
		}
		return -ENODATA;
	case IIO_CHAN_INFO_SCALE:
		*val = 3300;
		*val2 = 12;
		return IIO_VAL_FRACTIONAL_LOG2;
	default:
		return -EINVAL;
	}
}

static irqreturn_t sophgo_saradc_interrupt_handler(int irq, void *dev_id)
{
	struct sophgo_saradc *saradc = dev_id;

	writel(1, saradc->regs + SOPHGO_SARADC_INTR_CLR_REG);
	complete(&saradc->completion);
	return IRQ_HANDLED;
}


static const struct of_device_id sophgo_saradc_match[] = {
	{ .compatible = "sophgo,cv18xx-saradc", },
	{ },
};
MODULE_DEVICE_TABLE(of, sophgo_saradc_match);

static int sophgo_saradc_probe(struct platform_device *pdev)
{
	struct sophgo_saradc *saradc;
	struct iio_dev *indio_dev;
	int ret;

	indio_dev = devm_iio_device_alloc(&pdev->dev, sizeof(*saradc));
	if (!indio_dev)
		return -ENOMEM;

	saradc = iio_priv(indio_dev);
	indio_dev->name = "Sophgo SARADC";
	indio_dev->info = &saradc->info;
	indio_dev->modes = INDIO_DIRECT_MODE;
	indio_dev->num_channels = 3;
	indio_dev->channels = sophgo_channels;

	saradc->clk = devm_clk_get(&pdev->dev, NULL);
	if (IS_ERR(saradc->clk)) {
		dev_dbg(&pdev->dev, "Can't get clock from device tree, using No-Die domain");
	} else {
		ret = clk_prepare_enable(saradc->clk);
		if (ret)
			return ret;
	}

	saradc->regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(saradc->regs)) {
		ret = PTR_ERR(saradc->regs);
		goto error_disable_clock;
	}

	saradc->irq = platform_get_irq_optional(pdev, 0);
	if (saradc->irq >= 0) {
		ret = devm_request_irq(&pdev->dev, saradc->irq,
				sophgo_saradc_interrupt_handler, 0,
				dev_name(&pdev->dev), saradc);
		if (ret)
			goto error_disable_clock;

		writel(1, saradc->regs + SOPHGO_SARADC_INTR_EN_REG);

		init_completion(&saradc->completion);
	}

	saradc->info.read_raw = &sophgo_saradc_read_raw;

	mutex_init(&saradc->lock);
	platform_set_drvdata(pdev, indio_dev);
	writel(SOPHGO_SARADC_DEF_CYC_SETTINGS, saradc->regs + SOPHGO_SARADC_CYC_SET_REG);
	ret = devm_iio_device_register(&pdev->dev, indio_dev);
	if (ret)
		goto error_disable_clock;

	return 0;

error_disable_clock:
	if (!IS_ERR(saradc->clk))
		clk_disable_unprepare(saradc->clk);
	return ret;
}

static void sophgo_saradc_remove(struct platform_device *pdev)
{
	struct iio_dev *indio_dev = platform_get_drvdata(pdev);
	struct sophgo_saradc *saradc = iio_priv(indio_dev);

	if (!IS_ERR(saradc->clk))
		clk_disable_unprepare(saradc->clk);
}


static struct platform_driver sophgo_saradc_driver = {
	.driver	= {
		.name		= "sophgo-saradc",
		.of_match_table	= sophgo_saradc_match,
	},
	.probe = sophgo_saradc_probe,
	.remove_new = sophgo_saradc_remove,
};
module_platform_driver(sophgo_saradc_driver);

MODULE_AUTHOR("Thomas Bonnefille <thomas.bonnefille@bootlin.com>");
MODULE_DESCRIPTION("Sophgo SARADC driver");
MODULE_LICENSE("GPL");

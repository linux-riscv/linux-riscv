// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Sophgo CV18XX series SARADC Driver
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
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>

#define CV18XX_ADC_CTRL_REG			0x04
#define		CV18XX_ADC_EN			BIT(0)
#define		CV18XX_ADC_SEL(x)		BIT((x)+4)
#define CV18XX_ADC_STATUS_REG			0x08
#define		CV18XX_ADC_BUSY			BIT(0)
#define CV18XX_ADC_CYC_SET_REG			0x0C
#define		CV18XX_ADC_DEF_CYC_SETTINGS	0xF1F0F
#define CV18XX_ADC_CH_RESULT_REG(x)		(0x10+4*(x))
#define		CV18XX_ADC_CH_RESULT		0xfff
#define		CV18XX_ADC_CH_VALID		BIT(15)
#define CV18XX_ADC_INTR_EN_REG			0x20
#define CV18XX_ADC_INTR_CLR_REG			0x24
#define CV18XX_ADC_INTR_STA_REG			0x28

#define CV18XX_ADC_CHANNEL(index)					\
	{								\
		.type = IIO_VOLTAGE,					\
		.indexed = 1,						\
		.channel = index,					\
		.info_mask_separate = BIT(IIO_CHAN_INFO_RAW),		\
		.info_mask_shared_by_type = BIT(IIO_CHAN_INFO_SCALE),	\
		.scan_index = index,					\
	}

struct cv18xx_adc {
	struct completion completion;
	void __iomem *regs;
	struct mutex lock; /* ADC Control and Result register */
	int irq;
};

static const struct iio_chan_spec sophgo_channels[] = {
	CV18XX_ADC_CHANNEL(1),
	CV18XX_ADC_CHANNEL(2),
	CV18XX_ADC_CHANNEL(3),
};

static void cv18xx_adc_start_measurement(struct cv18xx_adc *saradc,
					    int channel)
{
	writel(0, saradc->regs + CV18XX_ADC_CTRL_REG);
	writel(CV18XX_ADC_SEL(channel) | CV18XX_ADC_EN,
	       saradc->regs + CV18XX_ADC_CTRL_REG);
}

static int cv18xx_adc_wait(struct cv18xx_adc *saradc)
{
	if (saradc->irq < 0) {
		u32 reg;

		return readl_poll_timeout(saradc->regs + CV18XX_ADC_STATUS_REG,
					  reg, !(reg & CV18XX_ADC_BUSY),
					  500, 1000000);
	}
	return wait_for_completion_timeout(&saradc->completion,
					  msecs_to_jiffies(1000)) > 0
					  ? 0 : -ETIMEDOUT;
}

static int cv18xx_adc_read_raw(struct iio_dev *indio_dev,
				  struct iio_chan_spec const *chan,
				  int *val, int *val2, long mask)
{
	switch (mask) {
	case IIO_CHAN_INFO_RAW:
		struct cv18xx_adc *saradc = iio_priv(indio_dev);
		u32 sample;
		int ret;

		scoped_guard(mutex, &saradc->lock) {
			cv18xx_adc_start_measurement(saradc, chan->scan_index);
			ret = cv18xx_adc_wait(saradc);
			if (ret < 0)
				return ret;

			sample = readl(saradc->regs + CV18XX_ADC_CH_RESULT_REG(chan->scan_index));
		}
		if (!(sample & CV18XX_ADC_CH_VALID))
			return -ENODATA;

		*val = sample & CV18XX_ADC_CH_RESULT;
		return IIO_VAL_INT;
	case IIO_CHAN_INFO_SCALE:
		*val = 3300;
		*val2 = 12;
		return IIO_VAL_FRACTIONAL_LOG2;
	default:
		return -EINVAL;
	}
}

static irqreturn_t cv18xx_adc_interrupt_handler(int irq, void *private)
{
	struct cv18xx_adc *saradc = private;

	if (!(readl(saradc->regs + CV18XX_ADC_INTR_STA_REG) & BIT(0)))
		return IRQ_NONE;

	writel(1, saradc->regs + CV18XX_ADC_INTR_CLR_REG);
	complete(&saradc->completion);
	return IRQ_HANDLED;
}

static const struct iio_info cv18xx_adc_info = {
	.read_raw = &cv18xx_adc_read_raw,
};

static int cv18xx_adc_probe(struct platform_device *pdev)
{
	struct cv18xx_adc *saradc;
	struct iio_dev *indio_dev;
	int ret;

	indio_dev = devm_iio_device_alloc(&pdev->dev, sizeof(*saradc));
	if (!indio_dev)
		return -ENOMEM;

	saradc = iio_priv(indio_dev);
	indio_dev->name = "sophgo-cv18xx-adc";
	indio_dev->modes = INDIO_DIRECT_MODE;
	indio_dev->info = &cv18xx_adc_info;
	indio_dev->num_channels = ARRAY_SIZE(sophgo_channels);
	indio_dev->channels = sophgo_channels;


	if (IS_ERR(devm_clk_get_optional_enabled(&pdev->dev, NULL)))
		dev_dbg(&pdev->dev, "Can't get clock from device tree, using No-Die domain");

	saradc->regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(saradc->regs)) {
		ret = PTR_ERR(saradc->regs);
		return ret;
	}

	saradc->irq = platform_get_irq_optional(pdev, 0);
	if (saradc->irq >= 0) {
		init_completion(&saradc->completion);
		ret = devm_request_irq(&pdev->dev, saradc->irq,
				cv18xx_adc_interrupt_handler, 0,
				dev_name(&pdev->dev), saradc);
		if (ret)
			return ret;

		writel(1, saradc->regs + CV18XX_ADC_INTR_EN_REG);

	}


	mutex_init(&saradc->lock);
	platform_set_drvdata(pdev, indio_dev);
	writel(CV18XX_ADC_DEF_CYC_SETTINGS, saradc->regs + CV18XX_ADC_CYC_SET_REG);
	ret = devm_iio_device_register(&pdev->dev, indio_dev);
	if (ret)
		return ret;

	return 0;
}

static const struct of_device_id cv18xx_adc_match[] = {
	{ .compatible = "sophgo,cv18xx-saradc", },
	{ }
};
MODULE_DEVICE_TABLE(of, cv18xx_adc_match);

static struct platform_driver cv18xx_adc_driver = {
	.driver	= {
		.name		= "sophgo-saradc",
		.of_match_table	= cv18xx_adc_match,
	},
	.probe = cv18xx_adc_probe,
};
module_platform_driver(cv18xx_adc_driver);

MODULE_AUTHOR("Thomas Bonnefille <thomas.bonnefille@bootlin.com>");
MODULE_DESCRIPTION("Sophgo SARADC driver");
MODULE_LICENSE("GPL");

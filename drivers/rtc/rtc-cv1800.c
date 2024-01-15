// SPDX-License-Identifier: GPL-2.0-only
/*
 * rtc-cv1800.c: RTC driver for Sophgo cv1800 RTC
 *
 * Author: Jingbao Qiu <qiujingbao.dlmu@gmail.com>
 */
#include <linux/kernel.h>
#include <linux/clk.h>
#include <linux/module.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/rtc.h>
#include <linux/platform_device.h>
#include <linux/mfd/syscon.h>
#include <linux/regmap.h>
#include <linux/of.h>

#define ANA_CALIB                   0x1000
#define SEC_PULSE_GEN               0x1004
#define ALARM_TIME                  0x1008
#define ALARM_ENABLE                0x100C
#define SET_SEC_CNTR_VAL            0x1010
#define SET_SEC_CNTR_TRIG           0x1014
#define SEC_CNTR_VAL                0x1018
#define APB_RDATA_SEL               0x103C
#define POR_DB_MAGIC_KEY            0x1068
#define EN_PWR_WAKEUP               0x10BC

/*
 * When in VDDBKUP domain, this MACRO register
 * does not power down
 */
#define MACRO_DA_CLEAR_ALL          0x1480
#define MACRO_DA_SOC_READY          0x148C
#define MACRO_RO_T                  0x14A8
#define MACRO_RG_SET_T              0x1498
#define CTRL                        0x08
#define FC_COARSE_EN                0x40
#define FC_COARSE_CAL               0x44
#define FC_FINE_EN                  0x48
#define FC_FINE_CAL                 0x50
#define CTRL_MODE_MASK              BIT(10)
#define CTRL_MODE_OSC32K            0x00UL
#define CTRL_MODE_XTAL32K           BIT(0)
#define FC_COARSE_CAL_VAL_SHIFT     0
#define FC_COARSE_CAL_VAL_MASK      GENMASK(15, 0)
#define FC_COARSE_CAL_TIME_SHIFT    16
#define FC_COARSE_CAL_TIME_MASK     GENMASK(31, 16)
#define FC_FINE_CAL_VAL_SHIFT       0
#define FC_FINE_CAL_VAL_MASK        GENMASK(23, 0)
#define FC_FINE_CAL_TIME_SHIFT      24
#define FC_FINE_CAL_TIME_MASK       GENMASK(31, 24)
#define SEC_PULSE_GEN_INT_SHIFT     0
#define SEC_PULSE_GEN_INT_MASK      GENMASK(7, 0)
#define SEC_PULSE_GEN_FRAC_SHIFT    8
#define SEC_PULSE_GEN_FRAC_MASK     GENMASK(24, 8)
#define SEC_PULSE_GEN_SEL_SHIFT     31
#define SEC_PULSE_GEN_SEL_MASK      GENMASK(30, 0)
#define SEC_PULSE_SEL_INNER         BIT(31)
#define CALIB_INIT_VAL              (BIT(8) || BIT(16))
#define CALIB_SEL_FTUNE_MASK        GENMASK(30, 0)
#define CALIB_SEL_FTUNE_INNER       0x00UL
#define CALIB_OFFSET_INIT           128
#define CALIB_OFFSET_SHIFT          BIT(0)
#define CALIB_FREQ                  256000000000
#define CALIB_FRAC_EXT              10000
#define CALIB_FREQ_NS               40
#define CALIB_FREQ_MULT             256
#define CALIB_FC_COARSE_PLUS_OFFSET 770
#define CALIB_FC_COARSE_SUB_OFFSET  755
#define REG_ENABLE_FUN              BIT(0)
#define REG_DISABLE_FUN             0x00UL
#define REG_INIT_TIMEOUT            100
#define SEC_MAX_VAL                 0xFFFFFFFF
#define ALARM_ENABLE_MASK           BIT(0)
#define SET_SEC_CNTR_VAL_INIT       (BIT(28) || BIT(29))
#define DEALY_TIME_PREPARE          400
#define DEALY_TIME_LOOP             100

struct cv1800_rtc_priv {
	struct rtc_device *rtc_dev;
	struct device *dev;
	struct regmap *rtc_map;
	struct clk *clk;
	int irq;
};

static int cv1800_rtc_alarm_irq_enable(struct device *dev, unsigned int enabled)
{
	struct cv1800_rtc_priv *info = dev_get_drvdata(dev);

	regmap_write(info->rtc_map, ALARM_ENABLE, enabled);

	return 0;
}

static int cv1800_rtc_set_alarm(struct device *dev, struct rtc_wkalrm *alrm)
{
	struct cv1800_rtc_priv *info = dev_get_drvdata(dev);
	unsigned long alarm_time;

	alarm_time = rtc_tm_to_time64(&alrm->time);

	cv1800_rtc_alarm_irq_enable(dev, REG_DISABLE_FUN);

	regmap_write(info->rtc_map, ALARM_TIME, alarm_time);

	cv1800_rtc_alarm_irq_enable(dev, alrm->enabled);

	return 0;
}

static int cv1800_rtc_read_alarm(struct device *dev, struct rtc_wkalrm *alarm)
{
	struct cv1800_rtc_priv *info = dev_get_drvdata(dev);
	uint32_t enabled;
	uint32_t time;

	regmap_read(info->rtc_map, ALARM_ENABLE, &enabled);

	alarm->enabled = enabled & ALARM_ENABLE_MASK;

	regmap_read(info->rtc_map, ALARM_TIME, &time);

	rtc_time64_to_tm(time, &alarm->time);

	return 0;
}

/**
 * cv1800_rtc_32k_coarse_val_calib() - Using an external
 * clock to coarse calibrate the crystal oscillator
 * @info: the device of calibrated
 *
 * @return 0 on success, or -1 on fail
 *
 * This RTC has an independent 32KHz oscillator. However,
 * the accuracy of this oscillator is easily affected by
 * external environmental interference,resulting in lower
 * accuracy than the internal oscillator.Therefore, a 25M
 * crystal oscillator is used as a reference source to
 * calibrate the RTC and improve its accuracy.Calibration
 * is completed through two steps, namely rough calibration
 * and fine calibration.
 */
static int cv1800_rtc_32k_coarse_val_calib(struct cv1800_rtc_priv *info)
{
	uint32_t calib_val = 0;
	uint32_t coarse_val = 0;
	uint32_t time_now = 0;
	uint32_t time_next = 0;
	uint32_t offset = CALIB_OFFSET_INIT;
	uint32_t coarse_timeout = REG_INIT_TIMEOUT;
	uint32_t get_val_timeout = 0;

	regmap_write(info->rtc_map, ANA_CALIB, CALIB_INIT_VAL);

	udelay(DEALY_TIME_PREPARE);

	/* Select 32K OSC tuning val source from rtc_sys */
	regmap_update_bits(info->rtc_map, SEC_PULSE_GEN,
			   (unsigned int)(~SEC_PULSE_GEN_SEL_MASK),
			   (unsigned int)(~SEC_PULSE_SEL_INNER));

	regmap_read(info->rtc_map, ANA_CALIB, &calib_val);

	regmap_write(info->rtc_map, FC_COARSE_EN, REG_ENABLE_FUN);

	while (--coarse_timeout) {
		regmap_read(info->rtc_map, FC_COARSE_CAL, &time_now);
		time_now >>= FC_COARSE_CAL_TIME_SHIFT;

		get_val_timeout = REG_INIT_TIMEOUT;

		while (time_next <= time_now && --get_val_timeout) {
			regmap_read(info->rtc_map, FC_COARSE_CAL, &time_next);
			time_next >>= FC_COARSE_CAL_TIME_SHIFT;
			udelay(DEALY_TIME_LOOP);
		}

		if (!get_val_timeout)
			return -1;

		udelay(DEALY_TIME_PREPARE);

		regmap_read(info->rtc_map, FC_COARSE_CAL, &coarse_val);
		coarse_val &= FC_COARSE_CAL_VAL_MASK;

		if (coarse_val > CALIB_FC_COARSE_PLUS_OFFSET) {
			calib_val += offset;
			offset >>= CALIB_OFFSET_SHIFT;
			regmap_write(info->rtc_map, ANA_CALIB, calib_val);
		} else if (coarse_val < CALIB_FC_COARSE_SUB_OFFSET) {
			calib_val -= offset;
			offset >>= CALIB_OFFSET_SHIFT;
			regmap_write(info->rtc_map, ANA_CALIB, calib_val);
		} else {
			regmap_write(info->rtc_map, FC_COARSE_EN,
				     REG_DISABLE_FUN);
			break;
		}

		if (offset == 0)
			return -1;
	}

	return 0;
}

static int cv1800_rtc_32k_fine_val_calib(struct cv1800_rtc_priv *info)
{
	uint32_t val;
	uint64_t freq = CALIB_FREQ;
	uint32_t sec_cnt;
	uint32_t timeout = REG_INIT_TIMEOUT;
	uint32_t time_now = 0;
	uint32_t time_next = 0;

	regmap_write(info->rtc_map, FC_FINE_EN, REG_ENABLE_FUN);

	regmap_read(info->rtc_map, FC_FINE_CAL, &time_now);
	time_now >>= FC_FINE_CAL_TIME_SHIFT;

	while (time_next <= time_now && --timeout) {
		regmap_read(info->rtc_map, FC_FINE_CAL, &time_next);
		time_next >>= FC_FINE_CAL_TIME_SHIFT;
		udelay(DEALY_TIME_LOOP);
	}

	if (!timeout)
		return -1;

	regmap_read(info->rtc_map, FC_FINE_CAL, &val);
	val &= FC_FINE_CAL_VAL_MASK;

	do_div(freq, CALIB_FREQ_NS);
	freq = freq * CALIB_FRAC_EXT;
	do_div(freq, val);

	sec_cnt = ((do_div(freq, CALIB_FRAC_EXT) * CALIB_FREQ_MULT) /
			   CALIB_FRAC_EXT &
		   SEC_PULSE_GEN_INT_MASK) +
		  (freq << SEC_PULSE_GEN_FRAC_SHIFT);

	regmap_write(info->rtc_map, SEC_PULSE_GEN, sec_cnt);
	regmap_write(info->rtc_map, FC_FINE_EN, REG_DISABLE_FUN);

	return 0;
}

static void rtc_enable_sec_counter(struct cv1800_rtc_priv *info)
{
	unsigned int sec_ro_t;
	unsigned int sec;

	/* select inner sec pulse and select reg set calibration val */
	regmap_update_bits(info->rtc_map, SEC_PULSE_GEN,
			   (unsigned int)(~SEC_PULSE_GEN_SEL_MASK),
			   (unsigned int)(~SEC_PULSE_SEL_INNER));

	regmap_update_bits(info->rtc_map, ANA_CALIB,
			   (unsigned int)(~CALIB_SEL_FTUNE_MASK),
			   CALIB_SEL_FTUNE_INNER);

	sec = SET_SEC_CNTR_VAL_INIT;

	/* load from MACRO register */
	regmap_read(info->rtc_map, MACRO_RO_T, &sec_ro_t);
	if (sec_ro_t > (SET_SEC_CNTR_VAL_INIT))
		sec = sec_ro_t;

	regmap_write(info->rtc_map, SET_SEC_CNTR_VAL, sec);
	regmap_write(info->rtc_map, SET_SEC_CNTR_TRIG, REG_ENABLE_FUN);
}

static int cv1800_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	struct cv1800_rtc_priv *info = dev_get_drvdata(dev);
	unsigned int sec;

	regmap_read(info->rtc_map, SEC_CNTR_VAL, &sec);

	rtc_time64_to_tm(sec, tm);

	return 0;
}

static int cv1800_rtc_set_time(struct device *dev, struct rtc_time *tm)
{
	struct cv1800_rtc_priv *info = dev_get_drvdata(dev);
	unsigned long sec;

	sec = rtc_tm_to_time64(tm);

	regmap_write(info->rtc_map, SET_SEC_CNTR_VAL, sec);
	regmap_write(info->rtc_map, SET_SEC_CNTR_TRIG, REG_ENABLE_FUN);

	regmap_write(info->rtc_map, MACRO_RG_SET_T, sec);

	return 0;
}

static irqreturn_t cv1800_rtc_irq_handler(int irq, void *dev_id)
{
	struct rtc_device *rtc = dev_id;

	rtc_update_irq(rtc, 1, RTC_IRQF | RTC_AF);

	return IRQ_HANDLED;
}

static const struct rtc_class_ops cv800b_rtc_ops = {
	.read_time = cv1800_rtc_read_time,
	.set_time = cv1800_rtc_set_time,
	.read_alarm = cv1800_rtc_read_alarm,
	.set_alarm = cv1800_rtc_set_alarm,
	.alarm_irq_enable = cv1800_rtc_alarm_irq_enable,
};

static int cv1800_rtc_probe(struct platform_device *pdev)
{
	struct cv1800_rtc_priv *rtc;
	uint32_t ctrl_val;
	int ret;

	rtc = devm_kzalloc(&pdev->dev, sizeof(struct cv1800_rtc_priv),
			   GFP_KERNEL);
	if (!rtc)
		return -ENOMEM;

	rtc->dev = &pdev->dev;

	rtc->rtc_map = syscon_node_to_regmap(rtc->dev->of_node->parent);
	if (IS_ERR(rtc->rtc_map))
		return PTR_ERR(rtc->rtc_map);

	rtc->irq = platform_get_irq(pdev, 0);
	if (rtc->irq < 0)
		return rtc->irq;

	ret = devm_request_irq(&pdev->dev, rtc->irq, cv1800_rtc_irq_handler,
			       IRQF_TRIGGER_HIGH, "alarm", &pdev->dev);
	if (ret)
		return dev_err_probe(&pdev->dev, ret,
				     "cannot register interrupt handler\n");

	rtc->clk = devm_clk_get_enabled(&pdev->dev, NULL);
	if (IS_ERR(rtc->clk))
		return dev_err_probe(&pdev->dev, PTR_ERR(rtc->clk),
				     "clk not found\n");

	platform_set_drvdata(pdev, rtc);

	rtc->rtc_dev = devm_rtc_allocate_device(&pdev->dev);
	if (IS_ERR(rtc->rtc_dev))
		return PTR_ERR(rtc->rtc_dev);

	rtc->rtc_dev->ops = &cv800b_rtc_ops;
	rtc->rtc_dev->range_max = U32_MAX;

	/* if use internal clk,so coarse calibrate rtc */
	regmap_read(rtc->rtc_map, CTRL, &ctrl_val);
	ctrl_val &= CTRL_MODE_MASK;

	if (ctrl_val == CTRL_MODE_OSC32K) {
		ret = cv1800_rtc_32k_coarse_val_calib(rtc);
		if (ret)
			dev_err(&pdev->dev, "failed to coarse RTC val !\n");

		ret = cv1800_rtc_32k_fine_val_calib(rtc);
		if (ret)
			dev_err(&pdev->dev, "failed to fine RTC val !\n");

		rtc_enable_sec_counter(rtc);
	}

	return devm_rtc_register_device(rtc->rtc_dev);
}

static const struct of_device_id cv1800_dt_ids[] = {
	{ .compatible = "sophgo,cv1800b-rtc" },
	{ /* sentinel */ },
};
MODULE_DEVICE_TABLE(of, cv1800_dt_ids);

static struct platform_driver cv1800_rtc_driver = {
	.driver = {
		.name = "sophgo-cv800b-rtc",
		.of_match_table = cv1800_dt_ids,
	},
	.probe = cv1800_rtc_probe,
};

module_platform_driver(cv1800_rtc_driver);
MODULE_AUTHOR("Jingbao Qiu");
MODULE_DESCRIPTION("Sophgo cv1800 RTC Driver");
MODULE_LICENSE("GPL");

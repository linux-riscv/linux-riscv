// SPDX-License-Identifier: GPL-2.0
/*
 * Sophgo SG2042 PWM Controller Driver
 *
 * Copyright (C) 2024 Sophgo Technology Inc.
 * Copyright (C) 2024 Chen Wang <unicorn_wang@outlook.com>
 */

#include <linux/clk.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pwm.h>

#include <asm/div64.h>

/*
 * Offset RegisterName
 * 0x0000 HLPERIOD0
 * 0x0004 PERIOD0
 * 0x0008 HLPERIOD1
 * 0x000C PERIOD1
 * 0x0010 HLPERIOD2
 * 0x0014 PERIOD2
 * 0x0018 HLPERIOD3
 * 0x001C PERIOD3
 * Four groups and every group is composed of HLPERIOD & PERIOD
 */
#define REG_HLPERIOD	0x0
#define REG_PERIOD	0x4

#define REG_GROUP	0x8

#define SG2042_PWM_CHANNELNUM	4

/**
 * struct sg2042_pwm_chip - private data of PWM chip
 * @base:		base address of mapped PWM registers
 * @base_clk:		base clock used to drive the pwm controller
 */
struct sg2042_pwm_chip {
	void __iomem *base;
	struct clk *base_clk;
};

static inline
struct sg2042_pwm_chip *to_sg2042_pwm_chip(struct pwm_chip *chip)
{
	return pwmchip_get_drvdata(chip);
}

static void pwm_sg2042_config(void __iomem *base, unsigned int channo, u32 period, u32 hlperiod)
{
	writel(period, base + REG_GROUP * channo + REG_PERIOD);
	writel(hlperiod, base + REG_GROUP * channo + REG_HLPERIOD);
}

static int pwm_sg2042_apply(struct pwm_chip *chip, struct pwm_device *pwm,
			    const struct pwm_state *state)
{
	struct sg2042_pwm_chip *sg2042_pwm = to_sg2042_pwm_chip(chip);
	u32 hlperiod;
	u32 period;
	u64 f_clk;
	u64 p;

	if (!state->enabled) {
		pwm_sg2042_config(sg2042_pwm->base, pwm->hwpwm, 0, 0);
		return 0;
	}

	/*
	 * Period of High level (duty_cycle) = HLPERIOD x Period_clk
	 * Period of One Cycle (period) = PERIOD x Period_clk
	 */
	f_clk = clk_get_rate(sg2042_pwm->base_clk);

	p = f_clk * state->period;
	do_div(p, NSEC_PER_SEC);
	period = (u32)p;

	p = f_clk * state->duty_cycle;
	do_div(p, NSEC_PER_SEC);
	hlperiod = (u32)p;

	dev_dbg(pwmchip_parent(chip), "chan[%d]: period=%u, hlperiod=%u\n",
		pwm->hwpwm, period, hlperiod);

	pwm_sg2042_config(sg2042_pwm->base, pwm->hwpwm, period, hlperiod);

	return 0;
}

static const struct pwm_ops pwm_sg2042_ops = {
	.apply		= pwm_sg2042_apply,
};

static const struct of_device_id sg2042_pwm_match[] = {
	{ .compatible = "sophgo,sg2042-pwm" },
	{ },
};
MODULE_DEVICE_TABLE(of, sg2042_pwm_match);

static int pwm_sg2042_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct sg2042_pwm_chip *sg2042_pwm;
	struct pwm_chip *chip;
	int ret;

	chip = devm_pwmchip_alloc(&pdev->dev, SG2042_PWM_CHANNELNUM, sizeof(*sg2042_pwm));
	if (IS_ERR(chip))
		return PTR_ERR(chip);
	sg2042_pwm = to_sg2042_pwm_chip(chip);

	chip->ops = &pwm_sg2042_ops;

	sg2042_pwm->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(sg2042_pwm->base))
		return PTR_ERR(sg2042_pwm->base);

	sg2042_pwm->base_clk = devm_clk_get_enabled(&pdev->dev, "apb");
	if (IS_ERR(sg2042_pwm->base_clk))
		return dev_err_probe(dev, PTR_ERR(sg2042_pwm->base_clk),
				     "failed to get base clk\n");

	ret = devm_pwmchip_add(&pdev->dev, chip);
	if (ret < 0)
		return dev_err_probe(dev, ret, "failed to register PWM chip\n");

	platform_set_drvdata(pdev, chip);

	return 0;
}

static struct platform_driver pwm_sg2042_driver = {
	.driver	= {
		.name	= "sg2042-pwm",
		.of_match_table = of_match_ptr(sg2042_pwm_match),
	},
	.probe = pwm_sg2042_probe,
};
module_platform_driver(pwm_sg2042_driver);

MODULE_AUTHOR("Chen Wang");
MODULE_DESCRIPTION("Sophgo SG2042 PWM driver");
MODULE_LICENSE("GPL");

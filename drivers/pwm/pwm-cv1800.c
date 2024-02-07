// SPDX-License-Identifier: GPL-2.0-only
/*
 * rtc-cv1800.c: PWM driver for Sophgo cv1800 RTC
 *
 * Author: Jingbao Qiu <qiujingbao.dlmu@gmail.com>
 */

#include <linux/clk.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pwm.h>
#include <linux/regmap.h>

#define HLPERIOD_BASE  0x00
#define PERIOD_BASE    0x04
#define POLARITY       0x040
#define PWMSTART       0x044
#define PWMDONE        0x048
#define PWMUPDATE      0x4c
#define PWM_OE         0xd0
#define HLPERIOD_SHIFT 0x08
#define PERIOD_SHIFT   0x08

#define HLPERIOD(n)    (HLPERIOD_BASE + ((n) * HLPERIOD_SHIFT))
#define PERIOD(n)      (PERIOD_BASE + ((n) * PERIOD_SHIFT))
#define UPDATE(n)      (BIT(0) << (n))
#define OE_MASK(n)     (BIT(0) << (n))
#define START_MASK(n)  (BIT(0) << (n))

#define PERIOD_RESET   0x02
#define HLPERIOD_RESET 0x1
#define REG_DISABLE    0x0U
#define REG_ENABLE     BIT(0)

struct soc_info {
	unsigned int num_pwms;
};

struct cv1800_pwm {
	struct pwm_chip chip;
	struct regmap *map;
	struct clk *clk;
};

static inline struct cv1800_pwm *to_cv1800_pwm_dev(struct pwm_chip *chip)
{
	return container_of(chip, struct cv1800_pwm, chip);
}

static int cv1800_pwm_enable(struct pwm_chip *chip, struct pwm_device *pwm,
			     u32 enable)
{
	struct cv1800_pwm *priv = to_cv1800_pwm_dev(chip);
	u32 pwm_enable;

	regmap_read(priv->map, PWMSTART, &pwm_enable);
	pwm_enable >>= pwm->hwpwm;

	if (enable)
		clk_prepare_enable(priv->clk);
	else
		clk_disable_unprepare(priv->clk);

	/*
	 * If the parameters are changed during runtime, Register needs
	 * to be updated to take effect.
	 */
	if (pwm_enable) {
		regmap_update_bits(priv->map, PWMUPDATE, UPDATE(pwm->hwpwm),
				   REG_ENABLE << pwm->hwpwm);
		regmap_update_bits(priv->map, PWMUPDATE, UPDATE(pwm->hwpwm),
				   REG_DISABLE << pwm->hwpwm);
	} else {
		regmap_update_bits(priv->map, PWM_OE, OE_MASK(pwm->hwpwm),
				   enable << pwm->hwpwm);
		regmap_update_bits(priv->map, PWMSTART, START_MASK(pwm->hwpwm),
				   enable << pwm->hwpwm);
	}

	return 0;
}

static int cv1800_pwm_apply(struct pwm_chip *chip, struct pwm_device *pwm,
			    const struct pwm_state *state)
{
	struct cv1800_pwm *priv = to_cv1800_pwm_dev(chip);
	u64 period_ns, duty_ns;
	u32 period_val, hlperiod_val;
	unsigned long long rate, div;

	period_ns = state->period;
	duty_ns = state->duty_cycle;

	rate = (unsigned long long)clk_get_rate(priv->clk);

	div = rate * period_ns;
	do_div(div, NSEC_PER_SEC);
	period_val = div;

	div = rate * (period_ns - duty_ns);
	do_div(div, NSEC_PER_SEC);
	hlperiod_val = div;

	regmap_write(priv->map, PERIOD(pwm->hwpwm), period_val);
	regmap_write(priv->map, HLPERIOD(pwm->hwpwm), hlperiod_val);

	cv1800_pwm_enable(chip, pwm, state->enabled);

	return 0;
}

static int cv1800_pwm_get_state(struct pwm_chip *chip, struct pwm_device *pwm,
				 struct pwm_state *state)
{
	struct cv1800_pwm *priv = to_cv1800_pwm_dev(chip);
	u32 period_val, hlperiod_val, tem;
	u64 rate;
	u64 period_ns = 0;
	u64 duty_ns = 0;
	u32 enable = 0;

	regmap_read(priv->map, PERIOD(pwm->hwpwm), &period_val);
	regmap_read(priv->map, HLPERIOD(pwm->hwpwm), &hlperiod_val);

	if (period_val != PERIOD_RESET || hlperiod_val != HLPERIOD_RESET) {
		rate = (u64)clk_get_rate(priv->clk);

		tem = NSEC_PER_SEC * period_val;
		do_div(tem, rate);
		period_ns = tem;

		tem = period_val * period_ns;
		do_div(tem, hlperiod_val);
		duty_ns = tem;

		regmap_read(priv->map, PWMSTART, &enable);
		enable >>= pwm->hwpwm;
	}

	state->period = period_ns;
	state->duty_cycle = duty_ns;
	state->enabled = enable;

	return 0;
}

static const struct pwm_ops cv1800_pwm_ops = {
	.apply = cv1800_pwm_apply,
	.get_state = cv1800_pwm_get_state,
};

static const struct regmap_config cv1800_pwm_regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
};

static int cv1800_pwm_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct cv1800_pwm *cv_pwm;
	void __iomem *base;
	const struct soc_info *info;

	info = device_get_match_data(dev);
	if (!info)
		return -EINVAL;

	cv_pwm = devm_kzalloc(dev, sizeof(*cv_pwm), GFP_KERNEL);
	if (!cv_pwm)
		return -ENOMEM;

	base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(base))
		return PTR_ERR(base);

	cv_pwm->map = devm_regmap_init_mmio(&pdev->dev, base,
					    &cv1800_pwm_regmap_config);
	if (IS_ERR(cv_pwm->map))
		return PTR_ERR(cv_pwm->map);

	cv_pwm->clk = devm_clk_get(&pdev->dev, NULL);
	if (IS_ERR(cv_pwm->clk))
		return dev_err_probe(&pdev->dev, PTR_ERR(cv_pwm->clk),
				     "clk not found\n");

	cv_pwm->chip.dev = dev;
	cv_pwm->chip.ops = &cv1800_pwm_ops;
	cv_pwm->chip.npwm = info->num_pwms;

	return devm_pwmchip_add(dev, &cv_pwm->chip);
}

static const struct soc_info cv1800b_soc_info = {
	.num_pwms = 4,
};

static const struct of_device_id cv1800_pwm_dt_ids[] = {
	{ .compatible = "sophgo,cv1800-pwm", .data = &cv1800b_soc_info },
	{},
};
MODULE_DEVICE_TABLE(of, cv1800_pwm_dt_ids);

static struct platform_driver cv1800_pwm_driver = {
	.driver = {
		.name = "cv1800-pwm",
		.of_match_table = cv1800_pwm_dt_ids,
	},
	.probe = cv1800_pwm_probe,
};
module_platform_driver(cv1800_pwm_driver);

MODULE_ALIAS("platform:cv1800-pwm");
MODULE_AUTHOR("Jingbao Qiu");
MODULE_DESCRIPTION("Sophgo cv1800 RTC Driver");
MODULE_LICENSE("GPL");

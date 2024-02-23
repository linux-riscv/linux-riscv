// SPDX-License-Identifier: GPL-2.0-only
/*
 * pwm-cv1800.c: PWM driver for Sophgo cv1800
 *
 * Author: Jingbao Qiu <qiujingbao.dlmu@gmail.com>
 *
 * Limitations:
 * - It output low when PWM channel disabled.
 * - This pwm device supports dynamic loading of PWM parameters. When PWMSTART
 *   is written from 0 to 1, the register value (HLPERIODn, PERIODn) will be
 *   temporarily stored inside the PWM. If you want to dynamically change the
 *   waveform during PWM output, after writing the new value to HLPERIODn and
 *   PERIODn, write 1 and then 0 to PWMUPDATE[n] to make the new value effective.
 * - Supports up to Rate/2 output, and the lowest is about Rate/(2^30-1).
 * - By setting HLPERIODn to 0, can produce 100% duty cycle.
 */

#include <linux/clk.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pwm.h>
#include <linux/regmap.h>

#define PWM_CV1800_HLPERIOD_BASE 0x00
#define PWM_CV1800_PERIOD_BASE 0x04
#define PWM_CV1800_PWM_CV1800_POLARITY 0x40
#define PWM_CV1800_START 0x44
#define PWM_CV1800_DONE 0x48
#define PWM_CV1800_UPDATE 0x4c
#define PWM_CV1800_OE 0xd0

#define PWM_CV1800_HLPERIOD(n) (PWM_CV1800_HLPERIOD_BASE + ((n) * 0x08))
#define PWM_CV1800_PERIOD(n) (PWM_CV1800_PERIOD_BASE + ((n) * 0x08))

#define PWM_CV1800_UPDATE_MASK(n) (BIT(0) << (n))
#define PWM_CV1800_OE_MASK(n) (BIT(0) << (n))
#define PWM_CV1800_START_MASK(n) (BIT(0) << (n))

#define PWM_CV1800_MAXPERIOD (BIT(30) - 1)
#define PWM_CV1800_MINPERIOD BIT(1)
#define PWM_CV1800_MINHLPERIOD BIT(0)
#define PWM_CV1800_PERIOD_RESET BIT(1)
#define PWM_CV1800_HLPERIOD_RESET BIT(0)
#define PWM_CV1800_REG_DISABLE 0x0U
#define PWM_CV1800_REG_ENABLE(n) (BIT(0) << (n))

struct cv1800_pwm {
	struct regmap *map;
	struct clk *clk;
	unsigned long clk_rate;
};

static inline struct cv1800_pwm *to_cv1800_pwm_dev(struct pwm_chip *chip)
{
	return pwmchip_get_drvdata(chip);
}

static const struct regmap_config cv1800_pwm_regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
};

static int cv1800_pwm_enable(struct pwm_chip *chip, struct pwm_device *pwm,
			     bool enable)
{
	struct cv1800_pwm *priv = to_cv1800_pwm_dev(chip);
	u32 pwm_enable;

	regmap_read(priv->map, PWM_CV1800_START, &pwm_enable);
	pwm_enable &= PWM_CV1800_START_MASK(pwm->hwpwm);

	/*
	 * If the parameters are changed during runtime, Register needs
	 * to be updated to take effect.
	 */
	if (pwm_enable && enable) {
		regmap_update_bits(priv->map, PWM_CV1800_UPDATE,
				   PWM_CV1800_UPDATE_MASK(pwm->hwpwm),
				   PWM_CV1800_REG_ENABLE(pwm->hwpwm));
		regmap_update_bits(priv->map, PWM_CV1800_UPDATE,
				   PWM_CV1800_UPDATE_MASK(pwm->hwpwm),
				   PWM_CV1800_REG_DISABLE);
	} else if (!pwm_enable && enable) {
		regmap_update_bits(priv->map, PWM_CV1800_OE,
				   PWM_CV1800_OE_MASK(pwm->hwpwm),
				   PWM_CV1800_REG_ENABLE(pwm->hwpwm));
		regmap_update_bits(priv->map, PWM_CV1800_START,
				   PWM_CV1800_START_MASK(pwm->hwpwm),
				   PWM_CV1800_REG_ENABLE(pwm->hwpwm));
	} else if (pwm_enable && !enable) {
		regmap_update_bits(priv->map, PWM_CV1800_OE,
				   PWM_CV1800_OE_MASK(pwm->hwpwm),
				   PWM_CV1800_REG_DISABLE);
		regmap_update_bits(priv->map, PWM_CV1800_START,
				   PWM_CV1800_START_MASK(pwm->hwpwm),
				   PWM_CV1800_REG_DISABLE);
	}

	return 0;
}

static int cv1800_pwm_apply(struct pwm_chip *chip, struct pwm_device *pwm,
			    const struct pwm_state *state)
{
	struct cv1800_pwm *priv = to_cv1800_pwm_dev(chip);
	u32 period_val, hlperiod_val;
	u64 tem;

	if (state->polarity != PWM_POLARITY_NORMAL)
		return -EINVAL;

	/*
	 * This hardware use PERIOD and HLPERIOD registers to represent PWM waves.
	 *
	 * The meaning of PERIOD is how many clock cycles (from the clock source)
	 * are used to represent PWM waves.
	 * PERIOD = rate(MHz) / target(MHz)
	 * PERIOD = period(ns) * rate(Hz) / NSEC_PER_SEC
	 * The meaning of HLPERIOD is the number of low-level cycles in PERIOD.
	 * HLPERIOD = PERIOD - rate(MHz) / duty(MHz)
	 * HLPERIOD = PERIOD - (duty(ns) * rate(Hz) / NSEC_PER_SEC)
	 */
	tem = mul_u64_u64_div_u64(state->period, priv->clk_rate, NSEC_PER_SEC);
	if (tem < PWM_CV1800_MINPERIOD)
		return -EINVAL;

	if (tem > PWM_CV1800_MAXPERIOD)
		tem = PWM_CV1800_MAXPERIOD;

	period_val = (u32)tem;

	tem = mul_u64_u64_div_u64(state->duty_cycle, priv->clk_rate,
				  NSEC_PER_SEC);
	if (tem > period_val)
		return -EINVAL;
	hlperiod_val = period_val - (u32)tem;

	regmap_write(priv->map, PWM_CV1800_PERIOD(pwm->hwpwm), period_val);
	regmap_write(priv->map, PWM_CV1800_HLPERIOD(pwm->hwpwm), hlperiod_val);

	cv1800_pwm_enable(chip, pwm, state->enabled);

	return 0;
}

static int cv1800_pwm_get_state(struct pwm_chip *chip, struct pwm_device *pwm,
				struct pwm_state *state)
{
	struct cv1800_pwm *priv = to_cv1800_pwm_dev(chip);
	u32 period_val, hlperiod_val;
	u64 period_ns = 0;
	u64 duty_ns = 0;
	u32 enable = 0;

	regmap_read(priv->map, PWM_CV1800_PERIOD(pwm->hwpwm), &period_val);
	regmap_read(priv->map, PWM_CV1800_HLPERIOD(pwm->hwpwm), &hlperiod_val);

	if (period_val != PWM_CV1800_PERIOD_RESET ||
	    hlperiod_val != PWM_CV1800_HLPERIOD_RESET) {
		period_ns = DIV_ROUND_UP_ULL(period_val * NSEC_PER_SEC, priv->clk_rate);
		duty_ns = DIV_ROUND_UP_ULL(hlperiod_val * period_ns, period_val);

		regmap_read(priv->map, PWM_CV1800_START, &enable);

		enable &= PWM_CV1800_START_MASK(pwm->hwpwm);
	}

	state->period = period_ns;
	state->duty_cycle = duty_ns;
	state->enabled = enable;
	state->polarity = PWM_POLARITY_NORMAL;

	return 0;
}

static const struct pwm_ops cv1800_pwm_ops = {
	.apply = cv1800_pwm_apply,
	.get_state = cv1800_pwm_get_state,
};

static void devm_clk_rate_exclusive_put(void *data)
{
	struct clk *clk = data;

	clk_rate_exclusive_put(clk);
}

static int cv1800_pwm_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct cv1800_pwm *priv;
	struct pwm_chip *chip;
	void __iomem *base;
	int ret;

	chip = devm_pwmchip_alloc(dev, 4, sizeof(*priv));
	if (!chip)
		return PTR_ERR(chip);

	priv = to_cv1800_pwm_dev(chip);

	base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(base))
		return PTR_ERR(base);

	priv->map = devm_regmap_init_mmio(&pdev->dev, base,
					  &cv1800_pwm_regmap_config);
	if (IS_ERR(priv->map))
		return PTR_ERR(priv->map);

	priv->clk = devm_clk_get_enabled(&pdev->dev, NULL);
	if (IS_ERR(priv->clk))
		return dev_err_probe(&pdev->dev, PTR_ERR(priv->clk),
				     "clk not found\n");

	ret = clk_rate_exclusive_get(priv->clk);
	if (ret)
		return dev_err_probe(&pdev->dev, ret,
				     "failed to get exclusive rate\n");

	ret = devm_add_action_or_reset(&pdev->dev, devm_clk_rate_exclusive_put,
				       priv->clk);
	if (ret) {
		clk_rate_exclusive_put(priv->clk);
		return ret;
	}

	priv->clk_rate = clk_get_rate(priv->clk);
	if (!priv->clk_rate)
		return dev_err_probe(&pdev->dev, -EINVAL,
				     "Invalid clock rate: %lu\n",
				     priv->clk_rate);

	chip->ops = &cv1800_pwm_ops;

	return devm_pwmchip_add(dev, chip);
}

static const struct of_device_id cv1800_pwm_dt_ids[] = {
	{ .compatible = "sophgo,cv1800-pwm" },
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

MODULE_AUTHOR("Jingbao Qiu");
MODULE_DESCRIPTION("Sophgo cv1800 PWM Driver");
MODULE_LICENSE("GPL");

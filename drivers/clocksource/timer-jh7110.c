// SPDX-License-Identifier: GPL-2.0
/*
 * Starfive JH7110 Timer driver
 *
 * Copyright (C) 2023 StarFive Technology Co., Ltd.
 *
 * This timer has four free-running and independent 32-bit counters and runs in 24MHz
 * clock on the StarFive JH7110 SoC. Each channel(counter) can trigger an interrupt
 * when timeout even CPU is sleeping. They support one-shot mode and continuous-run mode.
 *
 * Each channel is used as a global timer that serves each cpu core:
 * JH7110 Timer Channel 0 -- CPU 0
 * JH7110 Timer Channel 1 -- CPU 1
 * JH7110 Timer Channel 2 -- CPU 2
 * JH7110 Timer Channel 3 -- CPU 3
 */

#include <linux/clk.h>
#include <linux/clockchips.h>
#include <linux/cpu.h>
#include <linux/iopoll.h>
#include <linux/irq.h>
#include <linux/platform_device.h>
#include <linux/reset.h>

/* Bias: Ch0-0x0, Ch1-0x40, Ch2-0x80, and so on. */
#define JH7110_TIMER_CH_LEN		0x40
#define JH7110_TIMER_CH_BASE(x)		((x) * JH7110_TIMER_CH_LEN)
#define JH7110_TIMER_CH_MAX		4

#define JH7110_DELAY_US			0
#define JH7110_TIMEOUT_US		10000
#define JH7110_CLOCKEVENT_RATING	300
#define JH7110_TIMER_MAX_TICKS		0xffffffff
#define JH7110_TIMER_MIN_TICKS		0xf

#define JH7110_TIMER_INT_STATUS		0x00 /* RO[0:4]: Interrupt Status for channel0~4 */
#define JH7110_TIMER_CTL		0x04 /* RW[0]: 0-continuous run, 1-single run */
#define JH7110_TIMER_LOAD		0x08 /* RW: load value to counter */
#define JH7110_TIMER_ENABLE		0x10 /* RW[0]: timer enable register */
#define JH7110_TIMER_RELOAD		0x14 /* RW: write 1 or 0 both reload counter */
#define JH7110_TIMER_VALUE		0x18 /* RO: timer value register */
#define JH7110_TIMER_INT_CLR		0x20 /* RW: timer interrupt clear register */
#define JH7110_TIMER_INT_MASK		0x24 /* RW[0]: timer interrupt mask register */

#define JH7110_TIMER_INT_CLR_ENA	BIT(0)
#define JH7110_TIMER_INT_CLR_AVA_MASK	BIT(1)

#define JH7110_PERCPU_GET_CLKEVT	(&jh7110_timer_info.clkevt[smp_processor_id()])

/**
 * struct jh7110_clkevt - Description of each timer channel
 * @clk:		Clock of each timer channel
 * @rst:		Reset of each timer channel
 * @base:		Virtual address of each timer channel
 * @irq:                Interrupt number of each timer channel
 * @timer_enabled:      Enabled flag for each timer channel
 * @name:		Name of each timer channel
 */
struct jh7110_clkevt {
	struct clk		*clk;
	struct reset_control	*rst;
	void __iomem		*base;
	int			irq;
	bool			timer_enabled;
	char			name[sizeof("jh7110-timer.chX")];
};

struct jh7110_timer_priv {
	struct clk		*pclk;
	struct reset_control	*prst;
	struct device		*dev;
	struct jh7110_clkevt	clkevt[JH7110_TIMER_CH_MAX];
};

static struct jh7110_timer_priv jh7110_timer_info;

/* 0:continuous-run mode, 1:single-run mode */
enum jh7110_timer_mode {
	JH7110_TIMER_MODE_CONTIN,
	JH7110_TIMER_MODE_SINGLE,
};

/* Interrupt Mask, 0:Unmask, 1:Mask */
enum jh7110_timer_int_mask {
	JH7110_TIMER_INT_ENA,
	JH7110_TIMER_INT_DIS,
};

enum jh7110_timer_enable {
	JH7110_TIMER_DIS,
	JH7110_TIMER_ENA,
};

/*
 * BIT(0): Read value represent channel int status.
 * Write 1 to this bit to clear interrupt. Write 0 has no effects.
 * BIT(1): "1" means that it is clearing interrupt. BIT(0) can not be written.
 */
static inline int jh7110_timer_int_clear(struct jh7110_clkevt *clkevt)
{
	u32 value;
	int ret;

	/* Waiting interrupt can be cleared */
	ret = readl_poll_timeout_atomic(clkevt->base + JH7110_TIMER_INT_CLR, value,
					!(value & JH7110_TIMER_INT_CLR_AVA_MASK),
					JH7110_DELAY_US, JH7110_TIMEOUT_US);
	if (!ret)
		writel(JH7110_TIMER_INT_CLR_ENA, clkevt->base + JH7110_TIMER_INT_CLR);

	return ret;
}

static int jh7110_timer_start(struct jh7110_clkevt *clkevt)
{
	int ret;

	/* Disable and clear interrupt first */
	writel(JH7110_TIMER_INT_DIS, clkevt->base + JH7110_TIMER_INT_MASK);
	ret = jh7110_timer_int_clear(clkevt);

	writel(JH7110_TIMER_INT_ENA, clkevt->base + JH7110_TIMER_INT_MASK);
	writel(JH7110_TIMER_ENA, clkevt->base + JH7110_TIMER_ENABLE);

	return ret;
}

static int jh7110_timer_shutdown(struct clock_event_device *evt)
{
	struct jh7110_clkevt *clkevt = JH7110_PERCPU_GET_CLKEVT;

	writel(JH7110_TIMER_DIS, clkevt->base + JH7110_TIMER_ENABLE);
	return jh7110_timer_int_clear(clkevt);
}

/* IRQ handler for the timer */
static irqreturn_t jh7110_timer_interrupt(int irq, void *data)
{
	struct clock_event_device *evt = (struct clock_event_device *)data;
	struct jh7110_clkevt *clkevt = &jh7110_timer_info.clkevt[0];
	u32 reg = readl(clkevt->base + JH7110_TIMER_INT_STATUS);
	u8 cpu_id = smp_processor_id();

	/* Check interrupt status and channel(cpu) ID */
	if (!(reg & BIT(cpu_id)))
		return IRQ_NONE;

	clkevt = &jh7110_timer_info.clkevt[cpu_id];
	writel(JH7110_TIMER_INT_CLR_ENA, (clkevt->base + JH7110_TIMER_INT_CLR));

	if (evt->event_handler)
		evt->event_handler(evt);

	return IRQ_HANDLED;
}

static int jh7110_timer_set_periodic(struct clock_event_device *evt)
{
	struct jh7110_clkevt *clkevt = JH7110_PERCPU_GET_CLKEVT;

	writel(JH7110_TIMER_MODE_CONTIN, clkevt->base + JH7110_TIMER_CTL);
	return 0;
}

static int jh7110_timer_set_oneshot(struct clock_event_device *evt)
{
	struct jh7110_clkevt *clkevt = JH7110_PERCPU_GET_CLKEVT;

	writel(JH7110_TIMER_MODE_SINGLE, clkevt->base + JH7110_TIMER_CTL);
	return 0;
}

static int jh7110_timer_set_next_event(unsigned long next,
				       struct clock_event_device *evt)
{
	struct jh7110_clkevt *clkevt = JH7110_PERCPU_GET_CLKEVT;

	writel(JH7110_TIMER_MODE_SINGLE, clkevt->base + JH7110_TIMER_CTL);
	writel(next, clkevt->base + JH7110_TIMER_LOAD);

	return jh7110_timer_start(clkevt);
}

static DEFINE_PER_CPU(struct clock_event_device, jh7110_clock_event) = {
	.features			= CLOCK_EVT_FEAT_PERIODIC |
					  CLOCK_EVT_FEAT_ONESHOT,
	.rating				= JH7110_CLOCKEVENT_RATING,
	.set_state_shutdown		= jh7110_timer_shutdown,
	.set_state_periodic		= jh7110_timer_set_periodic,
	.set_state_oneshot		= jh7110_timer_set_oneshot,
	.set_state_oneshot_stopped	= jh7110_timer_shutdown,
	.set_next_event			= jh7110_timer_set_next_event,
};

static int jh7110_timer_dying_cpu(unsigned int cpu)
{
	struct jh7110_timer_priv *priv = &jh7110_timer_info;

	if (!priv->clkevt[cpu].timer_enabled)
		return 0;

	writel(JH7110_TIMER_DIS, priv->clkevt[cpu].base + JH7110_TIMER_ENABLE);
	jh7110_timer_int_clear(&priv->clkevt[cpu]);
	reset_control_assert(priv->clkevt[cpu].rst);
	clk_disable_unprepare(priv->clkevt[cpu].clk);

	return 0;
}

static int jh7110_timer_starting_cpu(unsigned int cpu)
{
	struct clock_event_device *evt = per_cpu_ptr(&jh7110_clock_event, cpu);
	struct jh7110_timer_priv *priv = &jh7110_timer_info;
	int err;
	u32 rate;

	if (cpu >= JH7110_TIMER_CH_MAX)
		return -ENOMEM;

	err = clk_prepare_enable(priv->clkevt[cpu].clk);
	if (err)
		goto err_starting_cpu;

	err = reset_control_deassert(priv->clkevt[cpu].rst);
	if (err)
		goto err_soft_reset;

	rate = clk_get_rate(priv->clkevt[cpu].clk);
	evt->cpumask = cpumask_of(cpu);
	evt->irq = priv->clkevt[cpu].irq;

	err = irq_force_affinity(evt->irq, cpumask_of(cpu));
	if (err)
		goto err_affinity;

	clockevents_config_and_register(evt, rate, JH7110_TIMER_MIN_TICKS,
					JH7110_TIMER_MAX_TICKS);

	/* Use one-shot mode */
	writel(JH7110_TIMER_MODE_SINGLE, (priv->clkevt[cpu].base + JH7110_TIMER_CTL));

	priv->clkevt[cpu].timer_enabled = true;

	err = jh7110_timer_start(&priv->clkevt[cpu]);
	if (err)
		goto err_affinity;
	return 0;

err_affinity:
	reset_control_assert(priv->clkevt[cpu].rst);
err_soft_reset:
	clk_disable_unprepare(priv->clkevt[cpu].clk);
err_starting_cpu:
	free_irq(evt->irq, evt);
	return err;
}

static int jh7110_timer_probe(struct platform_device *pdev)
{
	struct jh7110_timer_priv *priv = &jh7110_timer_info;
	struct clock_event_device *evt;
	struct jh7110_clkevt *clkevt;
	char name[sizeof("chX")];
	int ch;
	int ret;
	void __iomem *base;

	base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(base))
		return dev_err_probe(&pdev->dev, PTR_ERR(base),
				     "failed to map registers\n");

	priv->prst = devm_reset_control_get_exclusive(&pdev->dev, "apb");
	if (IS_ERR(priv->prst))
		return dev_err_probe(&pdev->dev, PTR_ERR(priv->prst),
				     "failed to get apb reset\n");

	priv->pclk = devm_clk_get_enabled(&pdev->dev, "apb");
	if (IS_ERR(priv->pclk))
		return dev_err_probe(&pdev->dev, PTR_ERR(priv->pclk),
				     "failed to get & enable apb clock\n");

	ret = reset_control_deassert(priv->prst);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "failed to deassert apb reset\n");

	for (ch = 0; ch < JH7110_TIMER_CH_MAX; ch++) {
		evt = per_cpu_ptr(&jh7110_clock_event, ch);
		clkevt = &priv->clkevt[ch];
		snprintf(name, sizeof(name), "ch%d", ch);

		clkevt->base = base + JH7110_TIMER_CH_BASE(ch);
		/* Ensure timer is disabled */
		writel(JH7110_TIMER_DIS, clkevt->base + JH7110_TIMER_ENABLE);
		ret = jh7110_timer_int_clear(clkevt);
		if (ret)
			return ret;

		clkevt->rst = devm_reset_control_get_exclusive(&pdev->dev, name);
		if (IS_ERR(clkevt->rst))
			return PTR_ERR(clkevt->rst);

		clkevt->clk = devm_clk_get(&pdev->dev, name);
		if (IS_ERR(clkevt->clk))
			return PTR_ERR(clkevt->clk);

		clkevt->irq = platform_get_irq(pdev, ch);
		if (clkevt->irq < 0)
			return clkevt->irq;

		snprintf(clkevt->name, sizeof(clkevt->name), "jh7110-timer.ch%d", ch);
		ret = devm_request_irq(&pdev->dev, clkevt->irq, jh7110_timer_interrupt,
				       IRQF_TIMER | IRQF_IRQPOLL,
				       clkevt->name, evt);

		if (ret)
			return ret;

		clkevt->timer_enabled = false;
	}

	return cpuhp_setup_state(CPUHP_AP_JH7110_TIMER_STARTING,
				"clockevents/jh7110/timer:starting",
				jh7110_timer_starting_cpu, jh7110_timer_dying_cpu);
}

static const struct of_device_id jh7110_timer_match[] = {
	{ .compatible = "starfive,jh7110-timer", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, jh7110_timer_match);

static struct platform_driver jh7110_timer_driver = {
	.probe = jh7110_timer_probe,
	.driver = {
		.name = "jh7110-timer",
		.of_match_table = jh7110_timer_match,
	},
};
module_platform_driver(jh7110_timer_driver);

MODULE_AUTHOR("Xingyu Wu <xingyu.wu@starfivetech.com>");
MODULE_DESCRIPTION("StarFive JH7110 timer driver");
MODULE_LICENSE("GPL");

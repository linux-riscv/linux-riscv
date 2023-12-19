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

#define JH7110_TIMER_INT_STATUS		0x00 /*
					      * RO[0:4]: Interrupt Status for channel0~4
					      * Only valid on the JH7110_TIMER_CH_BASE(0)
					      */
#define JH7110_TIMER_CTL		0x04 /* RW[0]: 0-continuous run, 1-single run */
#define JH7110_TIMER_LOAD		0x08 /* RW: load value to counter */
#define JH7110_TIMER_ENABLE		0x10 /* RW[0]: timer enable register */
#define JH7110_TIMER_RELOAD		0x14 /* RW: write 1 or 0 both reload counter */
#define JH7110_TIMER_VALUE		0x18 /* RO: timer value register */
#define JH7110_TIMER_INT_CLR		0x20 /* RW: timer interrupt clear register */
#define JH7110_TIMER_INT_MASK		0x24 /* RW[0]: timer interrupt mask register */

#define JH7110_TIMER_RELOAD_VALID	0
#define JH7110_TIMER_INT_CLR_ENA	BIT(0)
#define JH7110_TIMER_INT_CLR_AVA_MASK	BIT(1)

#define JH7110_PERCPU_GET_CLKEVT	(&jh7110_timer_info.clkevt[smp_processor_id()])

struct jh7110_clkevt {
	struct clk *clk;
	struct reset_control *rst;
	void __iomem *base;
	u32 reload_val;
	int irq;
	char name[sizeof("jh7110-timer.chX")];
};

struct jh7110_timer_priv {
	struct reset_control *prst;
	struct device *dev;
	struct jh7110_clkevt clkevt[JH7110_TIMER_CH_MAX];
};

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

static struct jh7110_timer_priv jh7110_timer_info;

/*
 * BIT(0): Read value represent channel int status.
 * Write 1 to this bit to clear interrupt. Write 0 has no effects.
 * BIT(1): "1" means that it is clearing interrupt. BIT(0) can not be written.
 */
static int jh7110_timer_int_is_clearing(struct jh7110_clkevt *clkevt)
{
	u32 value;

	/* Waiting interrupt can be cleared */
	return readl_poll_timeout_atomic(clkevt->base + JH7110_TIMER_INT_CLR, value,
					 !(value & JH7110_TIMER_INT_CLR_AVA_MASK),
					 JH7110_DELAY_US, JH7110_TIMEOUT_US);
}

static int jh7110_timer_start(struct jh7110_clkevt *clkevt)
{
	int ret;

	/* Disable and clear interrupt first */
	writel(JH7110_TIMER_INT_DIS, clkevt->base + JH7110_TIMER_INT_MASK);
	ret = jh7110_timer_int_is_clearing(clkevt);
	if (ret)
		return ret;

	writel(JH7110_TIMER_INT_CLR_ENA, (clkevt->base + JH7110_TIMER_INT_CLR));
	writel(JH7110_TIMER_INT_ENA, clkevt->base + JH7110_TIMER_INT_MASK);
	writel(JH7110_TIMER_ENA, clkevt->base + JH7110_TIMER_ENABLE);

	return 0;
}

static int jh7110_timer_shutdown(struct clock_event_device *evt)
{
	struct jh7110_clkevt *clkevt = JH7110_PERCPU_GET_CLKEVT;
	int ret = 0;

	writel(JH7110_TIMER_DIS, clkevt->base + JH7110_TIMER_ENABLE);
	ret = jh7110_timer_int_is_clearing(clkevt);
	if (!ret)
		writel(JH7110_TIMER_INT_CLR_ENA, (clkevt->base + JH7110_TIMER_INT_CLR));

	return ret;
}

static void jh7110_timer_suspend(struct clock_event_device *evt)
{
	struct jh7110_clkevt *clkevt = JH7110_PERCPU_GET_CLKEVT;

	clkevt->reload_val = readl(clkevt->base + JH7110_TIMER_LOAD);
	jh7110_timer_shutdown(evt);
}

static int jh7110_timer_tick_resume(struct clock_event_device *evt)
{
	struct jh7110_clkevt *clkevt = JH7110_PERCPU_GET_CLKEVT;

	writel(clkevt->reload_val, clkevt->base + JH7110_TIMER_LOAD);
	writel(JH7110_TIMER_RELOAD_VALID, clkevt->base + JH7110_TIMER_RELOAD);
	return jh7110_timer_start(clkevt);
}

static void jh7110_timer_resume(struct clock_event_device *evt)
{
	jh7110_timer_tick_resume(evt);
}

/* IRQ handler for the timer */
static irqreturn_t jh7110_timer_interrupt(int irq, void *data)
{
	struct clock_event_device *evt = data;
	struct jh7110_clkevt *clkevt = &jh7110_timer_info.clkevt[0];
	u8 cpu_id = smp_processor_id();
	u32 reg = readl(clkevt->base + JH7110_TIMER_INT_STATUS);

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
	.features = CLOCK_EVT_FEAT_PERIODIC | CLOCK_EVT_FEAT_ONESHOT,
	.rating = JH7110_CLOCKEVENT_RATING,
	.set_state_shutdown = jh7110_timer_shutdown,
	.set_state_periodic = jh7110_timer_set_periodic,
	.set_state_oneshot = jh7110_timer_set_oneshot,
	.set_state_oneshot_stopped = jh7110_timer_shutdown,
	.tick_resume = jh7110_timer_tick_resume,
	.set_next_event = jh7110_timer_set_next_event,
	.suspend = jh7110_timer_suspend,
	.resume = jh7110_timer_resume,
};

static int jh7110_timer_starting_cpu(unsigned int cpu)
{
	struct clock_event_device *evt = per_cpu_ptr(&jh7110_clock_event, cpu);
	struct jh7110_timer_priv *priv = &jh7110_timer_info;
	int ret;
	u32 rate;

	if (cpu >= JH7110_TIMER_CH_MAX)
		return -ENOMEM;

	ret = clk_prepare_enable(priv->clkevt[cpu].clk);
	if (ret)
		return ret;

	ret = reset_control_deassert(priv->clkevt[cpu].rst);
	if (ret)
		return ret;

	rate = clk_get_rate(priv->clkevt[cpu].clk);
	evt->cpumask = cpumask_of(cpu);
	evt->irq = priv->clkevt[cpu].irq;
	evt->name = priv->clkevt[cpu].name;
	clockevents_config_and_register(evt, rate, JH7110_TIMER_MIN_TICKS,
					JH7110_TIMER_MAX_TICKS);

	ret = devm_request_irq(priv->dev, evt->irq, jh7110_timer_interrupt,
			       IRQF_TIMER | IRQF_IRQPOLL,
			       evt->name, evt);
	if (ret)
		return ret;

	ret = irq_set_affinity(evt->irq, cpumask_of(cpu));
	if (ret)
		return ret;

	/* Use one-shot mode */
	writel(JH7110_TIMER_MODE_SINGLE, (priv->clkevt[cpu].base + JH7110_TIMER_CTL));

	return jh7110_timer_start(&priv->clkevt[cpu]);
}

static void jh7110_timer_release(void *data)
{
	struct jh7110_timer_priv *priv = data;
	int i;

	for (i = 0; i < JH7110_TIMER_CH_MAX; i++) {
		/* Disable each channel of timer */
		if (priv->clkevt[i].base)
			writel(JH7110_TIMER_DIS, priv->clkevt[i].base + JH7110_TIMER_ENABLE);

		/* Avoid no initialization in the loop of the probe */
		if (!IS_ERR_OR_NULL(priv->clkevt[i].rst))
			reset_control_assert(priv->clkevt[i].rst);

		if (!IS_ERR_OR_NULL(priv->clkevt[i].clk))
			clk_disable_unprepare(priv->clkevt[i].clk);
	}

	reset_control_assert(priv->prst);
}

static int jh7110_timer_probe(struct platform_device *pdev)
{
	struct jh7110_timer_priv *priv = &jh7110_timer_info;
	struct jh7110_clkevt *clkevt;
	struct clk *pclk;
	void __iomem *base;
	int ch;
	int ret;
	char name[sizeof("chX")];

	base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(base))
		return dev_err_probe(&pdev->dev, PTR_ERR(base),
				     "failed to map registers\n");

	priv->prst = devm_reset_control_get_exclusive(&pdev->dev, "apb");
	if (IS_ERR(priv->prst))
		return dev_err_probe(&pdev->dev, PTR_ERR(priv->prst),
				     "failed to get apb reset\n");

	pclk = devm_clk_get_enabled(&pdev->dev, "apb");
	if (IS_ERR(pclk))
		return dev_err_probe(&pdev->dev, PTR_ERR(pclk),
				     "failed to get & enable apb clock\n");

	ret = reset_control_deassert(priv->prst);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "failed to deassert apb reset\n");

	ret = devm_add_action_or_reset(&pdev->dev, jh7110_timer_release, priv);
	if (ret)
		return ret;

	priv->dev = &pdev->dev;
	for (ch = 0; ch < JH7110_TIMER_CH_MAX; ch++) {
		clkevt = &priv->clkevt[ch];
		snprintf(name, sizeof(name), "ch%d", ch);

		clkevt->base = base + JH7110_TIMER_CH_BASE(ch);
		/* Ensure timer is disabled */
		writel(JH7110_TIMER_DIS, clkevt->base + JH7110_TIMER_ENABLE);
		if (!jh7110_timer_int_is_clearing(clkevt))
			writel(JH7110_TIMER_INT_CLR_ENA, (clkevt->base + JH7110_TIMER_INT_CLR));

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
	}

	return cpuhp_setup_state(CPUHP_AP_JH7110_TIMER_STARTING,
				 "clockevents/jh7110/timer:starting",
				 jh7110_timer_starting_cpu, NULL);
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

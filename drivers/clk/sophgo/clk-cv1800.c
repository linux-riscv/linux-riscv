// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Inochi Amaoto <inochiama@outlook.com>
 */

#include <linux/module.h>
#include <linux/clk-provider.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/spinlock.h>

#include "clk-cv18xx-common.h"

struct cv1800_clk_ctrl;

struct cv1800_clk_desc {
	struct clk_hw_onecell_data	*clks_data;

	int (*pre_init)(struct device *dev, void __iomem *base,
			struct cv1800_clk_ctrl *ctrl,
			const struct cv1800_clk_desc *desc);
};

struct cv1800_clk_ctrl {
	const struct cv1800_clk_desc	*desc;
	spinlock_t			lock;
};

static int cv1800_clk_init_ctrl(struct device *dev, void __iomem *reg,
				struct cv1800_clk_ctrl *ctrl,
				const struct cv1800_clk_desc *desc)
{
	int i, ret;

	ctrl->desc = desc;
	spin_lock_init(&ctrl->lock);

	for (i = 0; i < desc->clks_data->num; i++) {
		struct clk_hw *hw = desc->clks_data->hws[i];
		struct cv1800_clk_common *common;
		const char *name;

		if (!hw)
			continue;

		name = hw->init->name;

		common = hw_to_cv1800_clk_common(hw);
		common->base = reg;
		common->lock = &ctrl->lock;

		ret = devm_clk_hw_register(dev, hw);
		if (ret) {
			dev_err(dev, "Couldn't register clock %d - %s\n",
				i, name);
			return ret;
		}
	}

	ret = devm_of_clk_add_hw_provider(dev, of_clk_hw_onecell_get,
					  desc->clks_data);

	return ret;
}

static int cv1800_clk_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	void __iomem *reg;
	int ret;
	const struct cv1800_clk_desc *desc;
	struct cv1800_clk_ctrl *ctrl;

	reg = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(reg))
		return PTR_ERR(reg);

	desc = device_get_match_data(dev);
	if (!desc) {
		dev_err(dev, "no match data for platform\n");
		return -EINVAL;
	}

	ctrl = devm_kmalloc(dev, sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;

	if (desc->pre_init) {
		ret = desc->pre_init(dev, reg, ctrl, desc);
		if (ret)
			return ret;
	}

	ret = cv1800_clk_init_ctrl(dev, reg, ctrl, desc);

	return ret;
}

static const struct of_device_id cv1800_clk_ids[] = {
	{ }
};
MODULE_DEVICE_TABLE(of, cv1800_clk_ids);

static struct platform_driver cv1800_clk_driver = {
	.probe	= cv1800_clk_probe,
	.driver	= {
		.name			= "cv1800-clk",
		.suppress_bind_attrs	= true,
		.of_match_table		= cv1800_clk_ids,
	},
};
module_platform_driver(cv1800_clk_driver);
MODULE_LICENSE("GPL");

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Sophgo SoC eFuse driver
 *
 * Copyright (C) 2023 Jisheng Zhang <jszhang@kernel.org>
 */

#include <linux/clk.h>
#include <linux/io.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/nvmem-provider.h>
#include <linux/platform_device.h>

#define CV1800B_EFUSE_CONTENT_BASE	0x100
#define CV1800B_EFUSE_CONTENT_SIZE	0x100

struct sophgo_efuses_priv {
	void __iomem *base;
	struct clk *clk;
};

static int sophgo_efuses_read(void *context, unsigned int offset, void *val,
			     size_t bytes)
{
	struct sophgo_efuses_priv *priv = context;
	u32 *dst = val;
	int ret;

	ret = clk_prepare_enable(priv->clk);
	if (ret < 0)
		return ret;

	while (bytes >= sizeof(u32)) {
		*dst++ = readl_relaxed(priv->base + CV1800B_EFUSE_CONTENT_BASE + offset);
		bytes -= sizeof(u32);
		offset += sizeof(u32);
	}

	clk_disable_unprepare(priv->clk);

	return 0;
}

static int sophgo_efuses_probe(struct platform_device *pdev)
{
	struct sophgo_efuses_priv *priv;
	struct resource *res;
	struct nvmem_config config = {
		.dev = &pdev->dev,
		.add_legacy_fixed_of_cells = true,
		.read_only = true,
		.reg_read = sophgo_efuses_read,
		.stride = sizeof(u32),
		.word_size = sizeof(u32),
		.name = "sophgo_efuse_nvmem",
		.id = NVMEM_DEVID_AUTO,
		.root_only = true,
	};

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->base = devm_platform_get_and_ioremap_resource(pdev, 0, &res);
	if (IS_ERR(priv->base))
		return PTR_ERR(priv->base);

	priv->clk = devm_clk_get(&pdev->dev, NULL);
	if (IS_ERR(priv->clk))
		return PTR_ERR(priv->clk);

	config.priv = priv;
	config.size = CV1800B_EFUSE_CONTENT_SIZE;

	return PTR_ERR_OR_ZERO(devm_nvmem_register(config.dev, &config));
}

static const struct of_device_id sophgo_efuses_of_match[] = {
	{ .compatible = "sophgo,cv1800b-efuse", },
	{}
};

MODULE_DEVICE_TABLE(of, sophgo_efuses_of_match);

static struct platform_driver sophgo_efuses_driver = {
	.driver = {
		.name = "sophgo_efuse",
		.of_match_table = sophgo_efuses_of_match,
	},
	.probe = sophgo_efuses_probe,
};

module_platform_driver(sophgo_efuses_driver);

MODULE_AUTHOR("Jisheng Zhang <jszhang@kernel.org>");
MODULE_LICENSE("GPL");

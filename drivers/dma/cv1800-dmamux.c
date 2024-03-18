// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Inochi Amaoto <inochiama@outlook.com>
 */

#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/of_dma.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/spinlock.h>
#include <linux/mfd/syscon.h>

#include <soc/sophgo/cv1800-sysctl.h>
#include <dt-bindings/dma/cv1800-dma.h>

#define DMAMUX_NCELLS			3
#define MAX_DMA_MAPPING_ID		DMA_SPI_NOR1
#define MAX_DMA_CPU_ID			DMA_CPU_C906_1
#define MAX_DMA_CH_ID			7

#define DMAMUX_INTMUX_REGISTER_LEN	4
#define DMAMUX_NR_CH_PER_REGISTER	4
#define DMAMUX_BIT_PER_CH		8
#define DMAMUX_CH_MASk			GENMASK(5, 0)
#define DMAMUX_INT_BIT_PER_CPU		10
#define DMAMUX_CH_UPDATE_BIT		BIT(31)

#define DMAMUX_CH_SET(chid, val) \
	(((val) << ((chid) * DMAMUX_BIT_PER_CH)) | DMAMUX_CH_UPDATE_BIT)
#define DMAMUX_CH_MASK(chid) \
	DMAMUX_CH_SET(chid, DMAMUX_CH_MASk)

#define DMAMUX_INT_BIT(chid, cpuid) \
	BIT((cpuid) * DMAMUX_INT_BIT_PER_CPU + (chid))
#define DMAMUX_INTEN_BIT(cpuid) \
	DMAMUX_INT_BIT(8, cpuid)
#define DMAMUX_INT_CH_BIT(chid, cpuid) \
	(DMAMUX_INT_BIT(chid, cpuid) | DMAMUX_INTEN_BIT(cpuid))
#define DMAMUX_INT_MASK(chid) \
	(DMAMUX_INT_BIT(chid, DMA_CPU_A53) | \
	 DMAMUX_INT_BIT(chid, DMA_CPU_C906_0) | \
	 DMAMUX_INT_BIT(chid, DMA_CPU_C906_1))
#define DMAMUX_INT_CH_MASK(chid, cpuid) \
	(DMAMUX_INT_MASK(chid) | DMAMUX_INTEN_BIT(cpuid))

struct cv1800_dmamux_data {
	struct dma_router	dmarouter;
	struct regmap		*regmap;
	spinlock_t		lock;
	DECLARE_BITMAP(used_chans, MAX_DMA_CH_ID);
	DECLARE_BITMAP(mapped_peripherals, MAX_DMA_MAPPING_ID);
};

struct cv1800_dmamux_map {
	unsigned int channel;
	unsigned int peripheral;
	unsigned int cpu;
};

static void cv1800_dmamux_free(struct device *dev, void *route_data)
{
	struct cv1800_dmamux_data *dmamux = dev_get_drvdata(dev);
	struct cv1800_dmamux_map *map = route_data;
	u32 regoff = map->channel % DMAMUX_NR_CH_PER_REGISTER;
	u32 regpos = map->channel / DMAMUX_NR_CH_PER_REGISTER;
	unsigned long flags;

	spin_lock_irqsave(&dmamux->lock, flags);

	regmap_update_bits(dmamux->regmap,
			   regpos + CV1800_SDMA_DMA_CHANNEL_REMAP0,
			   DMAMUX_CH_MASK(regoff),
			   DMAMUX_CH_UPDATE_BIT);

	regmap_update_bits(dmamux->regmap, CV1800_SDMA_DMA_INT_MUX,
			   DMAMUX_INT_CH_MASK(map->channel, map->cpu),
			   DMAMUX_INTEN_BIT(map->cpu));

	clear_bit(map->channel, dmamux->used_chans);
	clear_bit(map->peripheral, dmamux->mapped_peripherals);

	spin_unlock_irqrestore(&dmamux->lock, flags);

	kfree(map);
}

static void *cv1800_dmamux_route_allocate(struct of_phandle_args *dma_spec,
					  struct of_dma *ofdma)
{
	struct platform_device *pdev = of_find_device_by_node(ofdma->of_node);
	struct cv1800_dmamux_data *dmamux = platform_get_drvdata(pdev);
	struct cv1800_dmamux_map *map;
	unsigned long flags;
	unsigned int chid, devid, cpuid;
	u32 regoff, regpos;

	if (dma_spec->args_count != DMAMUX_NCELLS) {
		dev_err(&pdev->dev, "invalid number of dma mux args\n");
		return ERR_PTR(-EINVAL);
	}

	chid = dma_spec->args[0];
	devid = dma_spec->args[1];
	cpuid = dma_spec->args[2];
	dma_spec->args_count -= 2;

	if (chid > MAX_DMA_CH_ID) {
		dev_err(&pdev->dev, "invalid channel id: %u\n", chid);
		return ERR_PTR(-EINVAL);
	}

	if (devid > MAX_DMA_MAPPING_ID) {
		dev_err(&pdev->dev, "invalid device id: %u\n", devid);
		return ERR_PTR(-EINVAL);
	}

	if (cpuid > MAX_DMA_CPU_ID) {
		dev_err(&pdev->dev, "invalid cpu id: %u\n", cpuid);
		return ERR_PTR(-EINVAL);
	}

	dma_spec->np = of_parse_phandle(ofdma->of_node, "dma-masters", 0);
	if (!dma_spec->np) {
		dev_err(&pdev->dev, "can't get dma master\n");
		return ERR_PTR(-EINVAL);
	}

	map = kzalloc(sizeof(*map), GFP_KERNEL);
	if (!map)
		return ERR_PTR(-ENOMEM);

	map->channel = chid;
	map->peripheral = devid;
	map->cpu = cpuid;

	regoff = chid % DMAMUX_NR_CH_PER_REGISTER;
	regpos = chid / DMAMUX_NR_CH_PER_REGISTER;

	spin_lock_irqsave(&dmamux->lock, flags);

	if (test_and_set_bit(devid, dmamux->mapped_peripherals)) {
		dev_err(&pdev->dev, "already used device mapping: %u\n", devid);
		goto failed;
	}

	if (test_and_set_bit(chid, dmamux->used_chans)) {
		clear_bit(devid, dmamux->mapped_peripherals);
		dev_err(&pdev->dev, "already used channel id: %u\n", chid);
		goto failed;
	}

	regmap_set_bits(dmamux->regmap,
			regpos + CV1800_SDMA_DMA_CHANNEL_REMAP0,
			DMAMUX_CH_SET(regoff, devid));

	regmap_update_bits(dmamux->regmap, CV1800_SDMA_DMA_INT_MUX,
			   DMAMUX_INT_CH_MASK(chid, cpuid),
			   DMAMUX_INT_CH_BIT(chid, cpuid));

	spin_unlock_irqrestore(&dmamux->lock, flags);

	dev_info(&pdev->dev, "register channel %u for req %u (cpu %u)\n",
		 chid, devid, cpuid);

	return map;

failed:
	spin_unlock_irqrestore(&dmamux->lock, flags);
	dev_err(&pdev->dev, "already used channel id: %u\n", chid);
	return ERR_PTR(-EBUSY);
}

static int cv1800_dmamux_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *mux_node = dev->of_node;
	struct cv1800_dmamux_data *data;
	struct device *parent = dev->parent;
	struct device_node *dma_master;
	struct regmap *map = NULL;

	if (!parent)
		return -ENODEV;

	map = device_node_to_regmap(parent->of_node);
	if (IS_ERR(map))
		return PTR_ERR(map);

	dma_master = of_parse_phandle(mux_node, "dma-masters", 0);
	if (!dma_master) {
		dev_err(dev, "invalid dma-requests property\n");
		return -ENODEV;
	}
	of_node_put(dma_master);

	data = devm_kmalloc(dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	spin_lock_init(&data->lock);
	data->regmap = map;
	data->dmarouter.dev = dev;
	data->dmarouter.route_free = cv1800_dmamux_free;

	platform_set_drvdata(pdev, data);

	return of_dma_router_register(mux_node,
				      cv1800_dmamux_route_allocate,
				      &data->dmarouter);
}

static const struct of_device_id cv1800_dmamux_ids[] = {
	{ .compatible = "sophgo,cv1800-dmamux", },
	{ }
};
MODULE_DEVICE_TABLE(of, cv1800_dmamux_ids);

static struct platform_driver cv1800_dmamux_driver = {
	.driver = {
		.name = "fsl-raideng",
		.of_match_table = cv1800_dmamux_ids,
	},
	.probe = cv1800_dmamux_probe,
};
module_platform_driver(cv1800_dmamux_driver);

MODULE_AUTHOR("Inochi Amaoto <inochiama@outlook.com>");
MODULE_DESCRIPTION("Sophgo CV1800/SG2000 Series Soc DMAMUX driver");
MODULE_LICENSE("GPL");

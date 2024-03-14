// SPDX-License-Identifier: GPL-2.0
/*
 * Non-coherent cache functions for StarFive's StarLink-500 cache controller
 *
 * Copyright (C) 2024 Shanghai StarFive Technology Co., Ltd.
 *
 * Author: Joshua Yeong <joshua.yeong@starfivetech.com>
 */

#include <linux/bitfield.h>
#include <linux/cacheflush.h>
#include <linux/cacheinfo.h>
#include <linux/delay.h>
#include <linux/dma-direction.h>
#include <linux/io.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/processor.h>

#include <asm/dma-noncoherent.h>

#define STARFIVE_SL500_CMO_FLUSH_START_ADDR		0x0
#define STARFIVE_SL500_CMO_FLUSH_END_ADDR		0x8
#define STARFIVE_SL500_CMO_FLUSH_CTL			0x10
#define STARFIVE_SL500_CMO_CACHE_ALIGN			0x40

#define STARFIVE_SL500_ADDRESS_RANGE_MASK		GENMASK(39, 0)
#define STARFIVE_SL500_FLUSH_CTL_MODE_MASK		GENMASK(2, 1)
#define STARFIVE_SL500_FLUSH_CTL_ENABLE_MASK		BIT(0)

#define STARFIVE_SL500_FLUSH_CTL_CLEAN_INVALIDATE	0
#define STARFIVE_SL500_FLUSH_CTL_MAKE_INVALIDATE	1
#define STARFIVE_SL500_FLUSH_CTL_CLEAN_SHARED		2

struct starfive_sl500_cache_priv {
	void __iomem *base_addr;
};

static struct starfive_sl500_cache_priv starfive_sl500_cache_priv;

static void starfive_sl500_cmo_flush_complete(void)
{
	ktime_t timeout;

	volatile void __iomem *_ctl = starfive_sl500_cache_priv.base_addr +
                                      STARFIVE_SL500_CMO_FLUSH_CTL;
	timeout = ktime_add_ms(ktime_get(), 5000);

	do {
		if(!(ioread64(_ctl) & STARFIVE_SL500_FLUSH_CTL_ENABLE_MASK))
			return;
		msleep(50);
	} while (ktime_before(ktime_get(), timeout));

	pr_err("StarFive CMO operation timeout\n");
	dump_stack();
}

void starfive_sl500_dma_cache_wback(phys_addr_t paddr, unsigned long size)
{
	writeq(FIELD_PREP(STARFIVE_SL500_ADDRESS_RANGE_MASK, paddr),
	       starfive_sl500_cache_priv.base_addr + STARFIVE_SL500_CMO_FLUSH_START_ADDR);
	writeq(FIELD_PREP(STARFIVE_SL500_ADDRESS_RANGE_MASK, paddr + size),
	       starfive_sl500_cache_priv.base_addr + STARFIVE_SL500_CMO_FLUSH_END_ADDR);

	mb();
	writeq(FIELD_PREP(STARFIVE_SL500_FLUSH_CTL_MODE_MASK,
	       STARFIVE_SL500_FLUSH_CTL_CLEAN_SHARED),
	       starfive_sl500_cache_priv.base_addr + STARFIVE_SL500_CMO_FLUSH_CTL);

	starfive_sl500_cmo_flush_complete();
}

void starfive_sl500_dma_cache_invalidate(phys_addr_t paddr, unsigned long size)
{
	writeq(FIELD_PREP(STARFIVE_SL500_ADDRESS_RANGE_MASK, paddr),
	       starfive_sl500_cache_priv.base_addr + STARFIVE_SL500_CMO_FLUSH_START_ADDR);
	writeq(FIELD_PREP(STARFIVE_SL500_ADDRESS_RANGE_MASK, paddr + size),
	       starfive_sl500_cache_priv.base_addr + STARFIVE_SL500_CMO_FLUSH_END_ADDR);

	mb();
	writeq(FIELD_PREP(STARFIVE_SL500_FLUSH_CTL_MODE_MASK,
	       STARFIVE_SL500_FLUSH_CTL_MAKE_INVALIDATE),
	       starfive_sl500_cache_priv.base_addr + STARFIVE_SL500_CMO_FLUSH_CTL);

	starfive_sl500_cmo_flush_complete();
}

void starfive_sl500_dma_cache_wback_inv(phys_addr_t paddr, unsigned long size)
{
	writeq(FIELD_PREP(STARFIVE_SL500_ADDRESS_RANGE_MASK, paddr),
	       starfive_sl500_cache_priv.base_addr + STARFIVE_SL500_CMO_FLUSH_START_ADDR);
	writeq(FIELD_PREP(STARFIVE_SL500_ADDRESS_RANGE_MASK, paddr + size),
	       starfive_sl500_cache_priv.base_addr + STARFIVE_SL500_CMO_FLUSH_END_ADDR);

	mb();
	writeq(FIELD_PREP(STARFIVE_SL500_FLUSH_CTL_MODE_MASK,
	       STARFIVE_SL500_FLUSH_CTL_CLEAN_INVALIDATE),
	       starfive_sl500_cache_priv.base_addr + STARFIVE_SL500_CMO_FLUSH_CTL);

	starfive_sl500_cmo_flush_complete();
}

static const struct riscv_nonstd_cache_ops starfive_sl500_cmo_ops = {
	.wback = &starfive_sl500_dma_cache_wback,
	.inv = &starfive_sl500_dma_cache_invalidate,
	.wback_inv = &starfive_sl500_dma_cache_wback_inv,
};

static const struct of_device_id starfive_sl500_cache_ids[] = {
	{ .compatible = "starfive,starlink-500-cache" },
	{ /* sentinel */ }
};

static int __init starfive_sl500_cache_init(void)
{
	struct device_node *np;
	struct resource res;
	int ret;

	np = of_find_matching_node(NULL, starfive_sl500_cache_ids);
	if (!of_device_is_available(np))
		return -ENODEV;

	ret = of_address_to_resource(np, 0, &res);
	if (ret)
		return ret;

	starfive_sl500_cache_priv.base_addr = ioremap(res.start, resource_size(&res));
	if (!starfive_sl500_cache_priv.base_addr)
		return -ENOMEM;

	riscv_noncoherent_register_cache_ops(&starfive_sl500_cmo_ops);

	return 0;
}
early_initcall(starfive_sl500_cache_init);

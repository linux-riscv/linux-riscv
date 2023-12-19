// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Western Digital Corporation or its affiliates.
 * Copyright (C) 2022 Ventana Micro Systems Inc.
 */

#include <linux/bitops.h>
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/irqchip.h>
#include <linux/irqchip/riscv-aplic.h>
#include <linux/irqchip/riscv-imsic.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/printk.h>
#include <linux/smp.h>

#include "irq-riscv-aplic-main.h"

static void aplic_msi_irq_unmask(struct irq_data *d)
{
	aplic_irq_unmask(d);
	irq_chip_unmask_parent(d);
}

static void aplic_msi_irq_mask(struct irq_data *d)
{
	aplic_irq_mask(d);
	irq_chip_mask_parent(d);
}

static void aplic_msi_irq_eoi(struct irq_data *d)
{
	struct aplic_priv *priv = irq_data_get_irq_chip_data(d);
	u32 reg_off, reg_mask;

	/*
	 * EOI handling only required only for level-triggered
	 * interrupts in APLIC MSI mode.
	 */

	reg_off = APLIC_CLRIP_BASE + ((d->hwirq / APLIC_IRQBITS_PER_REG) * 4);
	reg_mask = BIT(d->hwirq % APLIC_IRQBITS_PER_REG);
	switch (irqd_get_trigger_type(d)) {
	case IRQ_TYPE_LEVEL_LOW:
		if (!(readl(priv->regs + reg_off) & reg_mask))
			writel(d->hwirq, priv->regs + APLIC_SETIPNUM_LE);
		break;
	case IRQ_TYPE_LEVEL_HIGH:
		if (readl(priv->regs + reg_off) & reg_mask)
			writel(d->hwirq, priv->regs + APLIC_SETIPNUM_LE);
		break;
	}
}

static struct irq_chip aplic_msi_chip = {
	.name		= "APLIC-MSI",
	.irq_mask	= aplic_msi_irq_mask,
	.irq_unmask	= aplic_msi_irq_unmask,
	.irq_set_type	= aplic_irq_set_type,
	.irq_eoi	= aplic_msi_irq_eoi,
#ifdef CONFIG_SMP
	.irq_set_affinity = irq_chip_set_affinity_parent,
#endif
	.flags		= IRQCHIP_SET_TYPE_MASKED |
			  IRQCHIP_SKIP_SET_WAKE |
			  IRQCHIP_MASK_ON_SUSPEND,
};

static int aplic_msi_irqdomain_translate(struct irq_domain *d,
					 struct irq_fwspec *fwspec,
					 unsigned long *hwirq,
					 unsigned int *type)
{
	struct aplic_priv *priv = platform_msi_get_host_data(d);

	return aplic_irqdomain_translate(fwspec, priv->gsi_base, hwirq, type);
}

static int aplic_msi_irqdomain_alloc(struct irq_domain *domain,
				     unsigned int virq, unsigned int nr_irqs,
				     void *arg)
{
	int i, ret;
	unsigned int type;
	irq_hw_number_t hwirq;
	struct irq_fwspec *fwspec = arg;
	struct aplic_priv *priv = platform_msi_get_host_data(domain);

	ret = aplic_irqdomain_translate(fwspec, priv->gsi_base, &hwirq, &type);
	if (ret)
		return ret;

	ret = platform_msi_device_domain_alloc(domain, virq, nr_irqs);
	if (ret)
		return ret;

	for (i = 0; i < nr_irqs; i++) {
		irq_domain_set_info(domain, virq + i, hwirq + i,
				    &aplic_msi_chip, priv, handle_fasteoi_irq,
				    NULL, NULL);
		/*
		 * APLIC does not implement irq_disable() so Linux interrupt
		 * subsystem will take a lazy approach for disabling an APLIC
		 * interrupt. This means APLIC interrupts are left unmasked
		 * upon system suspend and interrupts are not processed
		 * immediately upon system wake up. To tackle this, we disable
		 * the lazy approach for all APLIC interrupts.
		 */
		irq_set_status_flags(virq + i, IRQ_DISABLE_UNLAZY);
	}

	return 0;
}

static const struct irq_domain_ops aplic_msi_irqdomain_ops = {
	.translate	= aplic_msi_irqdomain_translate,
	.alloc		= aplic_msi_irqdomain_alloc,
	.free		= platform_msi_device_domain_free,
};

static void aplic_msi_write_msg(struct msi_desc *desc, struct msi_msg *msg)
{
	unsigned int group_index, hart_index, guest_index, val;
	struct irq_data *d = irq_get_irq_data(desc->irq);
	struct aplic_priv *priv = irq_data_get_irq_chip_data(d);
	struct aplic_msicfg *mc = &priv->msicfg;
	phys_addr_t tppn, tbppn, msg_addr;
	void __iomem *target;

	/* For zeroed MSI, simply write zero into the target register */
	if (!msg->address_hi && !msg->address_lo && !msg->data) {
		target = priv->regs + APLIC_TARGET_BASE;
		target += (d->hwirq - 1) * sizeof(u32);
		writel(0, target);
		return;
	}

	/* Sanity check on message data */
	WARN_ON(msg->data > APLIC_TARGET_EIID_MASK);

	/* Compute target MSI address */
	msg_addr = (((u64)msg->address_hi) << 32) | msg->address_lo;
	tppn = msg_addr >> APLIC_xMSICFGADDR_PPN_SHIFT;

	/* Compute target HART Base PPN */
	tbppn = tppn;
	tbppn &= ~APLIC_xMSICFGADDR_PPN_HART(mc->lhxs);
	tbppn &= ~APLIC_xMSICFGADDR_PPN_LHX(mc->lhxw, mc->lhxs);
	tbppn &= ~APLIC_xMSICFGADDR_PPN_HHX(mc->hhxw, mc->hhxs);
	WARN_ON(tbppn != mc->base_ppn);

	/* Compute target group and hart indexes */
	group_index = (tppn >> APLIC_xMSICFGADDR_PPN_HHX_SHIFT(mc->hhxs)) &
		     APLIC_xMSICFGADDR_PPN_HHX_MASK(mc->hhxw);
	hart_index = (tppn >> APLIC_xMSICFGADDR_PPN_LHX_SHIFT(mc->lhxs)) &
		     APLIC_xMSICFGADDR_PPN_LHX_MASK(mc->lhxw);
	hart_index |= (group_index << mc->lhxw);
	WARN_ON(hart_index > APLIC_TARGET_HART_IDX_MASK);

	/* Compute target guest index */
	guest_index = tppn & APLIC_xMSICFGADDR_PPN_HART(mc->lhxs);
	WARN_ON(guest_index > APLIC_TARGET_GUEST_IDX_MASK);

	/* Update IRQ TARGET register */
	target = priv->regs + APLIC_TARGET_BASE;
	target += (d->hwirq - 1) * sizeof(u32);
	val = (hart_index & APLIC_TARGET_HART_IDX_MASK)
				<< APLIC_TARGET_HART_IDX_SHIFT;
	val |= (guest_index & APLIC_TARGET_GUEST_IDX_MASK)
				<< APLIC_TARGET_GUEST_IDX_SHIFT;
	val |= (msg->data & APLIC_TARGET_EIID_MASK);
	writel(val, target);
}

int aplic_msi_setup(struct device *dev, void __iomem *regs)
{
	const struct imsic_global_config *imsic_global;
	struct irq_domain *irqdomain;
	struct aplic_priv *priv;
	struct aplic_msicfg *mc;
	phys_addr_t pa;
	int rc;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	rc = aplic_setup_priv(priv, dev, regs);
	if (!priv) {
		dev_err(dev, "failed to create APLIC context\n");
		return rc;
	}
	mc = &priv->msicfg;

	/*
	 * The APLIC outgoing MSI config registers assume target MSI
	 * controller to be RISC-V AIA IMSIC controller.
	 */
	imsic_global = imsic_get_global_config();
	if (!imsic_global) {
		dev_err(dev, "IMSIC global config not found\n");
		return -ENODEV;
	}

	/* Find number of guest index bits (LHXS) */
	mc->lhxs = imsic_global->guest_index_bits;
	if (APLIC_xMSICFGADDRH_LHXS_MASK < mc->lhxs) {
		dev_err(dev, "IMSIC guest index bits big for APLIC LHXS\n");
		return -EINVAL;
	}

	/* Find number of HART index bits (LHXW) */
	mc->lhxw = imsic_global->hart_index_bits;
	if (APLIC_xMSICFGADDRH_LHXW_MASK < mc->lhxw) {
		dev_err(dev, "IMSIC hart index bits big for APLIC LHXW\n");
		return -EINVAL;
	}

	/* Find number of group index bits (HHXW) */
	mc->hhxw = imsic_global->group_index_bits;
	if (APLIC_xMSICFGADDRH_HHXW_MASK < mc->hhxw) {
		dev_err(dev, "IMSIC group index bits big for APLIC HHXW\n");
		return -EINVAL;
	}

	/* Find first bit position of group index (HHXS) */
	mc->hhxs = imsic_global->group_index_shift;
	if (mc->hhxs < (2 * APLIC_xMSICFGADDR_PPN_SHIFT)) {
		dev_err(dev, "IMSIC group index shift should be >= %d\n",
			(2 * APLIC_xMSICFGADDR_PPN_SHIFT));
		return -EINVAL;
	}
	mc->hhxs -= (2 * APLIC_xMSICFGADDR_PPN_SHIFT);
	if (APLIC_xMSICFGADDRH_HHXS_MASK < mc->hhxs) {
		dev_err(dev, "IMSIC group index shift big for APLIC HHXS\n");
		return -EINVAL;
	}

	/* Compute PPN base */
	mc->base_ppn = imsic_global->base_addr >> APLIC_xMSICFGADDR_PPN_SHIFT;
	mc->base_ppn &= ~APLIC_xMSICFGADDR_PPN_HART(mc->lhxs);
	mc->base_ppn &= ~APLIC_xMSICFGADDR_PPN_LHX(mc->lhxw, mc->lhxs);
	mc->base_ppn &= ~APLIC_xMSICFGADDR_PPN_HHX(mc->hhxw, mc->hhxs);

	/* Setup global config and interrupt delivery */
	aplic_init_hw_global(priv, true);

	/* Set the APLIC device MSI domain if not available */
	if (!dev_get_msi_domain(dev)) {
		/*
		 * The device MSI domain for OF devices is only set at the
		 * time of populating/creating OF device. If the device MSI
		 * domain is discovered later after the OF device is created
		 * then we need to set it explicitly before using any platform
		 * MSI functions.
		 *
		 * In case of APLIC device, the parent MSI domain is always
		 * IMSIC and the IMSIC MSI domains are created later through
		 * the platform driver probing so we set it explicitly here.
		 */
		if (is_of_node(dev->fwnode))
			of_msi_configure(dev, to_of_node(dev->fwnode));
	}

	/* Create irq domain instance for the APLIC MSI-mode */
	irqdomain = platform_msi_create_device_domain(
						dev, priv->nr_irqs + 1,
						aplic_msi_write_msg,
						&aplic_msi_irqdomain_ops,
						priv);
	if (!irqdomain) {
		dev_err(dev, "failed to create MSI irq domain\n");
		return -ENOMEM;
	}

	/* Advertise the interrupt controller */
	pa = priv->msicfg.base_ppn << APLIC_xMSICFGADDR_PPN_SHIFT;
	dev_info(dev, "%d interrupts forwared to MSI base %pa\n",
		 priv->nr_irqs, &pa);

	return 0;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Western Digital Corporation or its affiliates.
 * Copyright (C) 2022 Ventana Micro Systems Inc.
 */

#define pr_fmt(fmt) "riscv-imsic: " fmt
#include <linux/bitmap.h>
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/spinlock.h>
#include <linux/smp.h>

#include "irq-riscv-imsic-state.h"

static int imsic_cpu_page_phys(unsigned int cpu,
			       unsigned int guest_index,
			       phys_addr_t *out_msi_pa)
{
	struct imsic_global_config *global;
	struct imsic_local_config *local;

	global = &imsic->global;
	local = per_cpu_ptr(global->local, cpu);

	if (BIT(global->guest_index_bits) <= guest_index)
		return -EINVAL;

	if (out_msi_pa)
		*out_msi_pa = local->msi_pa +
			      (guest_index * IMSIC_MMIO_PAGE_SZ);

	return 0;
}

static void imsic_irq_mask(struct irq_data *d)
{
	imsic_vector_mask(irq_data_get_irq_chip_data(d));
}

static void imsic_irq_unmask(struct irq_data *d)
{
	imsic_vector_unmask(irq_data_get_irq_chip_data(d));
}

static void imsic_irq_compose_vector_msg(struct imsic_vector *vec,
					 struct msi_msg *msg)
{
	phys_addr_t msi_addr;
	int err;

	if (WARN_ON(vec == NULL))
		return;

	err = imsic_cpu_page_phys(vec->cpu, 0, &msi_addr);
	if (WARN_ON(err))
		return;

	msg->address_hi = upper_32_bits(msi_addr);
	msg->address_lo = lower_32_bits(msi_addr);
	msg->data = vec->local_id;
}

static void imsic_irq_compose_msg(struct irq_data *d, struct msi_msg *msg)
{
	imsic_irq_compose_vector_msg(irq_data_get_irq_chip_data(d), msg);
}

#ifdef CONFIG_SMP
static void imsic_msi_update_msg(struct irq_data *d, struct imsic_vector *vec)
{
	struct msi_msg msg[2] = { [1] = { }, };

	imsic_irq_compose_vector_msg(vec, msg);
	irq_data_get_irq_chip(d)->irq_write_msi_msg(d, msg);
}

static int imsic_irq_set_affinity(struct irq_data *d,
				  const struct cpumask *mask_val,
				  bool force)
{
	struct imsic_vector *old_vec, *new_vec;
	struct irq_data *pd = d->parent_data;

	old_vec = irq_data_get_irq_chip_data(pd);
	if (WARN_ON(old_vec == NULL))
		return -ENOENT;

	/* Get a new vector on the desired set of CPUs */
	new_vec = imsic_vector_alloc(old_vec->hwirq, mask_val);
	if (!new_vec)
		return -ENOSPC;

	/* If old vector belongs to the desired CPU then do nothing */
	if (old_vec->cpu == new_vec->cpu) {
		imsic_vector_free(new_vec);
		return IRQ_SET_MASK_OK_DONE;
	}

	/* Point device to the new vector */
	imsic_msi_update_msg(d, new_vec);

	/* Update irq descriptors with the new vector */
	pd->chip_data = new_vec;

	/* Update effective affinity of parent irq data */
	irq_data_update_effective_affinity(pd, cpumask_of(new_vec->cpu));

	/* Move state of the old vector to the new vector */
	imsic_vector_move(old_vec, new_vec);

	return IRQ_SET_MASK_OK_DONE;
}
#endif

static struct irq_chip imsic_irq_base_chip = {
	.name			= "IMSIC-BASE",
	.irq_mask		= imsic_irq_mask,
	.irq_unmask		= imsic_irq_unmask,
	.irq_compose_msi_msg	= imsic_irq_compose_msg,
	.flags			= IRQCHIP_SKIP_SET_WAKE |
				  IRQCHIP_MASK_ON_SUSPEND,
};

static int imsic_irq_domain_alloc(struct irq_domain *domain,
				  unsigned int virq, unsigned int nr_irqs,
				  void *args)
{
	struct imsic_vector *vec;
	int hwirq;

	/* Legacy-MSI or multi-MSI not supported yet. */
	if (nr_irqs > 1)
		return -ENOTSUPP;

	hwirq = imsic_hwirq_alloc();
	if (hwirq < 0)
		return hwirq;

	vec = imsic_vector_alloc(hwirq, cpu_online_mask);
	if (!vec) {
		imsic_hwirq_free(hwirq);
		return -ENOSPC;
	}

	irq_domain_set_info(domain, virq, hwirq,
			    &imsic_irq_base_chip, vec,
			    handle_simple_irq, NULL, NULL);
	irq_set_noprobe(virq);
	irq_set_affinity(virq, cpu_online_mask);

	/*
	 * IMSIC does not implement irq_disable() so Linux interrupt
	 * subsystem will take a lazy approach for disabling an IMSIC
	 * interrupt. This means IMSIC interrupts are left unmasked
	 * upon system suspend and interrupts are not processed
	 * immediately upon system wake up. To tackle this, we disable
	 * the lazy approach for all IMSIC interrupts.
	 */
	irq_set_status_flags(virq, IRQ_DISABLE_UNLAZY);

	return 0;
}

static void imsic_irq_domain_free(struct irq_domain *domain,
				  unsigned int virq,
				  unsigned int nr_irqs)
{
	struct irq_data *d = irq_domain_get_irq_data(domain, virq);

	imsic_vector_free(irq_data_get_irq_chip_data(d));
	imsic_hwirq_free(d->hwirq);
	irq_domain_free_irqs_parent(domain, virq, nr_irqs);
}

#ifdef CONFIG_GENERIC_IRQ_DEBUGFS
static void imsic_irq_debug_show(struct seq_file *m, struct irq_domain *d,
				 struct irq_data *irqd, int ind)
{
	if (!irqd) {
		imsic_vector_debug_show_summary(m, ind);
		return;
	}

	imsic_vector_debug_show(m, irq_data_get_irq_chip_data(irqd), ind);
}
#endif

static const struct irq_domain_ops imsic_base_domain_ops = {
	.alloc		= imsic_irq_domain_alloc,
	.free		= imsic_irq_domain_free,
#ifdef CONFIG_GENERIC_IRQ_DEBUGFS
	.debug_show	= imsic_irq_debug_show,
#endif
};

#ifdef CONFIG_RISCV_IMSIC_PCI

static void imsic_pci_mask_irq(struct irq_data *d)
{
	pci_msi_mask_irq(d);
	irq_chip_mask_parent(d);
}

static void imsic_pci_unmask_irq(struct irq_data *d)
{
	pci_msi_unmask_irq(d);
	irq_chip_unmask_parent(d);
}

static struct irq_chip imsic_pci_irq_chip = {
	.name			= "IMSIC-PCI",
	.irq_mask		= imsic_pci_mask_irq,
	.irq_unmask		= imsic_pci_unmask_irq,
#ifdef CONFIG_SMP
	.irq_set_affinity	= imsic_irq_set_affinity,
#endif
	.irq_eoi		= irq_chip_eoi_parent,
};

static struct msi_domain_ops imsic_pci_domain_ops = {
};

static struct msi_domain_info imsic_pci_domain_info = {
	.flags	= (MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS |
		   MSI_FLAG_PCI_MSIX),
	.ops	= &imsic_pci_domain_ops,
	.chip	= &imsic_pci_irq_chip,
};

#endif

static struct irq_chip imsic_plat_irq_chip = {
	.name			= "IMSIC-PLAT",
#ifdef CONFIG_SMP
	.irq_set_affinity	= imsic_irq_set_affinity,
#endif
};

static struct msi_domain_ops imsic_plat_domain_ops = {
};

static struct msi_domain_info imsic_plat_domain_info = {
	.flags	= (MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS),
	.ops	= &imsic_plat_domain_ops,
	.chip	= &imsic_plat_irq_chip,
};

static int imsic_irq_domains_init(struct fwnode_handle *fwnode)
{
	/* Create Base IRQ domain */
	imsic->base_domain = irq_domain_create_tree(fwnode,
					&imsic_base_domain_ops, imsic);
	if (!imsic->base_domain) {
		pr_err("%pfwP: failed to create IMSIC base domain\n",
			fwnode);
		return -ENOMEM;
	}
	irq_domain_update_bus_token(imsic->base_domain, DOMAIN_BUS_NEXUS);

#ifdef CONFIG_RISCV_IMSIC_PCI
	/* Create PCI MSI domain */
	imsic->pci_domain = pci_msi_create_irq_domain(fwnode,
						&imsic_pci_domain_info,
						imsic->base_domain);
	if (!imsic->pci_domain) {
		pr_err("%pfwP: failed to create IMSIC PCI domain\n", fwnode);
		irq_domain_remove(imsic->base_domain);
		return -ENOMEM;
	}
#endif

	/* Create Platform MSI domain */
	imsic->plat_domain = platform_msi_create_irq_domain(fwnode,
						&imsic_plat_domain_info,
						imsic->base_domain);
	if (!imsic->plat_domain) {
		pr_err("%pfwP: failed to create IMSIC platform domain\n",
			fwnode);
		if (imsic->pci_domain)
			irq_domain_remove(imsic->pci_domain);
		irq_domain_remove(imsic->base_domain);
		return -ENOMEM;
	}

	return 0;
}

static int imsic_platform_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct imsic_global_config *global;
	int rc;

	if (!imsic) {
		dev_err(dev, "early driver not probed\n");
		return -ENODEV;
	}

	if (imsic->base_domain) {
		dev_err(dev, "irq domain already created\n");
		return -ENODEV;
	}

	global = &imsic->global;

	/* Initialize IRQ and MSI domains */
	rc = imsic_irq_domains_init(dev->fwnode);
	if (rc) {
		dev_err(dev, "failed to initialize IRQ and MSI domains\n");
		return rc;
	}

	dev_info(dev, "  hart-index-bits: %d,  guest-index-bits: %d\n",
		 global->hart_index_bits, global->guest_index_bits);
	dev_info(dev, " group-index-bits: %d, group-index-shift: %d\n",
		 global->group_index_bits, global->group_index_shift);
	dev_info(dev, " per-CPU IDs %d at base PPN %pa\n",
		 global->nr_ids, &global->base_addr);
	dev_info(dev, " total %d interrupts available\n",
		 imsic->nr_hwirqs);

	return 0;
}

static const struct of_device_id imsic_platform_match[] = {
	{ .compatible = "riscv,imsics" },
	{}
};

static struct platform_driver imsic_platform_driver = {
	.driver = {
		.name		= "riscv-imsic",
		.of_match_table	= imsic_platform_match,
	},
	.probe = imsic_platform_probe,
};
builtin_platform_driver(imsic_platform_driver);

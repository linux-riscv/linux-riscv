// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Western Digital Corporation or its affiliates.
 * Copyright (C) 2022 Ventana Micro Systems Inc.
 */

#define pr_fmt(fmt) "riscv-imsic: " fmt
#include <linux/bitmap.h>
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/irqchip/riscv-imsic.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <asm/hwcap.h>

#define IMSIC_DISABLE_EIDELIVERY	0
#define IMSIC_ENABLE_EIDELIVERY		1
#define IMSIC_DISABLE_EITHRESHOLD	1
#define IMSIC_ENABLE_EITHRESHOLD	0

#define imsic_csr_write(__c, __v)	\
do {					\
	csr_write(CSR_ISELECT, __c);	\
	csr_write(CSR_IREG, __v);	\
} while (0)

#define imsic_csr_read(__c)		\
({					\
	unsigned long __v;		\
	csr_write(CSR_ISELECT, __c);	\
	__v = csr_read(CSR_IREG);	\
	__v;				\
})

#define imsic_csr_set(__c, __v)		\
do {					\
	csr_write(CSR_ISELECT, __c);	\
	csr_set(CSR_IREG, __v);		\
} while (0)

#define imsic_csr_clear(__c, __v)	\
do {					\
	csr_write(CSR_ISELECT, __c);	\
	csr_clear(CSR_IREG, __v);	\
} while (0)

struct imsic_mmio {
	phys_addr_t pa;
	void __iomem *va;
	unsigned long size;
};

struct imsic_priv {
	/* Global configuration common for all HARTs */
	struct imsic_global_config global;

	/* MMIO regions */
	u32 num_mmios;
	struct imsic_mmio *mmios;

	/* Global state of interrupt identities */
	raw_spinlock_t ids_lock;
	unsigned long *ids_used_bimap;
	unsigned long *ids_enabled_bimap;
	unsigned int *ids_target_cpu;

	/* Mask for connected CPUs */
	struct cpumask lmask;

	/* IPI interrupt identity */
	u32 ipi_id;
	u32 ipi_lsync_id;

	/* IRQ domains */
	struct irq_domain *base_domain;
	struct irq_domain *pci_domain;
	struct irq_domain *plat_domain;
};

struct imsic_handler {
	/* Local configuration for given HART */
	struct imsic_local_config local;

	/* Pointer to private context */
	struct imsic_priv *priv;
};

static bool imsic_init_done;

static int imsic_parent_irq;
static DEFINE_PER_CPU(struct imsic_handler, imsic_handlers);

const struct imsic_global_config *imsic_get_global_config(void)
{
	struct imsic_handler *handler = this_cpu_ptr(&imsic_handlers);

	if (!handler || !handler->priv)
		return NULL;

	return &handler->priv->global;
}
EXPORT_SYMBOL_GPL(imsic_get_global_config);

const struct imsic_local_config *imsic_get_local_config(unsigned int cpu)
{
	struct imsic_handler *handler = per_cpu_ptr(&imsic_handlers, cpu);

	if (!handler || !handler->priv)
		return NULL;

	return &handler->local;
}
EXPORT_SYMBOL_GPL(imsic_get_local_config);

static int imsic_cpu_page_phys(unsigned int cpu,
			       unsigned int guest_index,
			       phys_addr_t *out_msi_pa)
{
	struct imsic_handler *handler = per_cpu_ptr(&imsic_handlers, cpu);
	struct imsic_global_config *global;
	struct imsic_local_config *local;

	if (!handler || !handler->priv)
		return -ENODEV;
	local = &handler->local;
	global = &handler->priv->global;

	if (BIT(global->guest_index_bits) <= guest_index)
		return -EINVAL;

	if (out_msi_pa)
		*out_msi_pa = local->msi_pa +
			      (guest_index * IMSIC_MMIO_PAGE_SZ);

	return 0;
}

static int imsic_get_cpu(struct imsic_priv *priv,
			 const struct cpumask *mask_val, bool force,
			 unsigned int *out_target_cpu)
{
	struct cpumask amask;
	unsigned int cpu;

	cpumask_and(&amask, &priv->lmask, mask_val);

	if (force)
		cpu = cpumask_first(&amask);
	else
		cpu = cpumask_any_and(&amask, cpu_online_mask);

	if (cpu >= nr_cpu_ids)
		return -EINVAL;

	if (out_target_cpu)
		*out_target_cpu = cpu;

	return 0;
}

static int imsic_get_cpu_msi_msg(unsigned int cpu, unsigned int id,
				 struct msi_msg *msg)
{
	phys_addr_t msi_addr;
	int err;

	err = imsic_cpu_page_phys(cpu, 0, &msi_addr);
	if (err)
		return err;

	msg->address_hi = upper_32_bits(msi_addr);
	msg->address_lo = lower_32_bits(msi_addr);
	msg->data = id;

	return err;
}

static void imsic_id_set_target(struct imsic_priv *priv,
				 unsigned int id, unsigned int target_cpu)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&priv->ids_lock, flags);
	priv->ids_target_cpu[id] = target_cpu;
	raw_spin_unlock_irqrestore(&priv->ids_lock, flags);
}

static unsigned int imsic_id_get_target(struct imsic_priv *priv,
					unsigned int id)
{
	unsigned int ret;
	unsigned long flags;

	raw_spin_lock_irqsave(&priv->ids_lock, flags);
	ret = priv->ids_target_cpu[id];
	raw_spin_unlock_irqrestore(&priv->ids_lock, flags);

	return ret;
}

static void __imsic_eix_update(unsigned long base_id,
			       unsigned long num_id, bool pend, bool val)
{
	unsigned long i, isel, ireg, flags;
	unsigned long id = base_id, last_id = base_id + num_id;

	while (id < last_id) {
		isel = id / BITS_PER_LONG;
		isel *= BITS_PER_LONG / IMSIC_EIPx_BITS;
		isel += (pend) ? IMSIC_EIP0 : IMSIC_EIE0;

		ireg = 0;
		for (i = id & (__riscv_xlen - 1);
		     (id < last_id) && (i < __riscv_xlen); i++) {
			ireg |= BIT(i);
			id++;
		}

		/*
		 * The IMSIC EIEx and EIPx registers are indirectly
		 * accessed via using ISELECT and IREG CSRs so we
		 * save/restore local IRQ to ensure that we don't
		 * get preempted while accessing IMSIC registers.
		 */
		local_irq_save(flags);
		if (val)
			imsic_csr_set(isel, ireg);
		else
			imsic_csr_clear(isel, ireg);
		local_irq_restore(flags);
	}
}

#define __imsic_id_enable(__id)		\
	__imsic_eix_update((__id), 1, false, true)
#define __imsic_id_disable(__id)	\
	__imsic_eix_update((__id), 1, false, false)

#ifdef CONFIG_SMP
static void __imsic_id_smp_sync(struct imsic_priv *priv)
{
	struct imsic_handler *handler;
	struct cpumask amask;
	int cpu;

	cpumask_and(&amask, &priv->lmask, cpu_online_mask);
	for_each_cpu(cpu, &amask) {
		if (cpu == smp_processor_id())
			continue;

		handler = per_cpu_ptr(&imsic_handlers, cpu);
		if (!handler || !handler->priv || !handler->local.msi_va) {
			pr_warn("CPU%d: handler not initialized\n", cpu);
			continue;
		}

		writel(handler->priv->ipi_lsync_id, handler->local.msi_va);
	}
}
#else
#define __imsic_id_smp_sync(__priv)
#endif

static void imsic_id_enable(struct imsic_priv *priv, unsigned int id)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&priv->ids_lock, flags);
	bitmap_set(priv->ids_enabled_bimap, id, 1);
	__imsic_id_enable(id);
	raw_spin_unlock_irqrestore(&priv->ids_lock, flags);

	__imsic_id_smp_sync(priv);
}

static void imsic_id_disable(struct imsic_priv *priv, unsigned int id)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&priv->ids_lock, flags);
	bitmap_clear(priv->ids_enabled_bimap, id, 1);
	__imsic_id_disable(id);
	raw_spin_unlock_irqrestore(&priv->ids_lock, flags);

	__imsic_id_smp_sync(priv);
}

static void imsic_ids_local_sync(struct imsic_priv *priv)
{
	int i;
	unsigned long flags;

	raw_spin_lock_irqsave(&priv->ids_lock, flags);
	for (i = 1; i <= priv->global.nr_ids; i++) {
		if (priv->ipi_id == i || priv->ipi_lsync_id == i)
			continue;

		if (test_bit(i, priv->ids_enabled_bimap))
			__imsic_id_enable(i);
		else
			__imsic_id_disable(i);
	}
	raw_spin_unlock_irqrestore(&priv->ids_lock, flags);
}

static void imsic_ids_local_delivery(struct imsic_priv *priv, bool enable)
{
	if (enable) {
		imsic_csr_write(IMSIC_EITHRESHOLD, IMSIC_ENABLE_EITHRESHOLD);
		imsic_csr_write(IMSIC_EIDELIVERY, IMSIC_ENABLE_EIDELIVERY);
	} else {
		imsic_csr_write(IMSIC_EIDELIVERY, IMSIC_DISABLE_EIDELIVERY);
		imsic_csr_write(IMSIC_EITHRESHOLD, IMSIC_DISABLE_EITHRESHOLD);
	}
}

static int imsic_ids_alloc(struct imsic_priv *priv,
			   unsigned int max_id, unsigned int order)
{
	int ret;
	unsigned long flags;

	if ((priv->global.nr_ids < max_id) ||
	    (max_id < BIT(order)))
		return -EINVAL;

	raw_spin_lock_irqsave(&priv->ids_lock, flags);
	ret = bitmap_find_free_region(priv->ids_used_bimap,
				      max_id + 1, order);
	raw_spin_unlock_irqrestore(&priv->ids_lock, flags);

	return ret;
}

static void imsic_ids_free(struct imsic_priv *priv, unsigned int base_id,
			   unsigned int order)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&priv->ids_lock, flags);
	bitmap_release_region(priv->ids_used_bimap, base_id, order);
	raw_spin_unlock_irqrestore(&priv->ids_lock, flags);
}

static int __init imsic_ids_init(struct imsic_priv *priv)
{
	int i;
	struct imsic_global_config *global = &priv->global;

	raw_spin_lock_init(&priv->ids_lock);

	/* Allocate used bitmap */
	priv->ids_used_bimap = kcalloc(BITS_TO_LONGS(global->nr_ids + 1),
					sizeof(unsigned long), GFP_KERNEL);
	if (!priv->ids_used_bimap)
		return -ENOMEM;

	/* Allocate enabled bitmap */
	priv->ids_enabled_bimap = kcalloc(BITS_TO_LONGS(global->nr_ids + 1),
					   sizeof(unsigned long), GFP_KERNEL);
	if (!priv->ids_enabled_bimap) {
		kfree(priv->ids_used_bimap);
		return -ENOMEM;
	}

	/* Allocate target CPU array */
	priv->ids_target_cpu = kcalloc(global->nr_ids + 1,
				       sizeof(unsigned int), GFP_KERNEL);
	if (!priv->ids_target_cpu) {
		kfree(priv->ids_enabled_bimap);
		kfree(priv->ids_used_bimap);
		return -ENOMEM;
	}
	for (i = 0; i <= global->nr_ids; i++)
		priv->ids_target_cpu[i] = UINT_MAX;

	/* Reserve ID#0 because it is special and never implemented */
	bitmap_set(priv->ids_used_bimap, 0, 1);

	return 0;
}

static void __init imsic_ids_cleanup(struct imsic_priv *priv)
{
	kfree(priv->ids_target_cpu);
	kfree(priv->ids_enabled_bimap);
	kfree(priv->ids_used_bimap);
}

#ifdef CONFIG_SMP
static void imsic_ipi_send(unsigned int cpu)
{
	struct imsic_handler *handler = per_cpu_ptr(&imsic_handlers, cpu);

	if (!handler || !handler->priv || !handler->local.msi_va) {
		pr_warn("CPU%d: handler not initialized\n", cpu);
		return;
	}

	writel(handler->priv->ipi_id, handler->local.msi_va);
}

static void imsic_ipi_enable(struct imsic_priv *priv)
{
	__imsic_id_enable(priv->ipi_id);
	__imsic_id_enable(priv->ipi_lsync_id);
}

static int __init imsic_ipi_domain_init(struct imsic_priv *priv)
{
	int virq;

	/* Allocate interrupt identity for IPIs */
	virq = imsic_ids_alloc(priv, priv->global.nr_ids, get_count_order(1));
	if (virq < 0)
		return virq;
	priv->ipi_id = virq;

	/* Create IMSIC IPI multiplexing */
	virq = ipi_mux_create(BITS_PER_BYTE, imsic_ipi_send);
	if (virq <= 0) {
		imsic_ids_free(priv, priv->ipi_id, get_count_order(1));
		return (virq < 0) ? virq : -ENOMEM;
	}

	/* Set vIRQ range */
	riscv_ipi_set_virq_range(virq, BITS_PER_BYTE, true);

	/* Allocate interrupt identity for local enable/disable sync */
	virq = imsic_ids_alloc(priv, priv->global.nr_ids, get_count_order(1));
	if (virq < 0) {
		imsic_ids_free(priv, priv->ipi_id, get_count_order(1));
		return virq;
	}
	priv->ipi_lsync_id = virq;

	return 0;
}

static void __init imsic_ipi_domain_cleanup(struct imsic_priv *priv)
{
	imsic_ids_free(priv, priv->ipi_lsync_id, get_count_order(1));
	if (priv->ipi_id)
		imsic_ids_free(priv, priv->ipi_id, get_count_order(1));
}
#else
static void imsic_ipi_enable(struct imsic_priv *priv)
{
}

static int __init imsic_ipi_domain_init(struct imsic_priv *priv)
{
	/* Clear the IPI ids because we are not using IPIs */
	priv->ipi_id = 0;
	priv->ipi_lsync_id = 0;
	return 0;
}

static void __init imsic_ipi_domain_cleanup(struct imsic_priv *priv)
{
}
#endif

static void imsic_irq_mask(struct irq_data *d)
{
	imsic_id_disable(irq_data_get_irq_chip_data(d), d->hwirq);
}

static void imsic_irq_unmask(struct irq_data *d)
{
	imsic_id_enable(irq_data_get_irq_chip_data(d), d->hwirq);
}

static void imsic_irq_compose_msi_msg(struct irq_data *d,
				      struct msi_msg *msg)
{
	struct imsic_priv *priv = irq_data_get_irq_chip_data(d);
	unsigned int cpu;
	int err;

	cpu = imsic_id_get_target(priv, d->hwirq);
	WARN_ON(cpu == UINT_MAX);

	err = imsic_get_cpu_msi_msg(cpu, d->hwirq, msg);
	WARN_ON(err);

	iommu_dma_compose_msi_msg(irq_data_get_msi_desc(d), msg);
}

#ifdef CONFIG_SMP
static int imsic_irq_set_affinity(struct irq_data *d,
				  const struct cpumask *mask_val,
				  bool force)
{
	struct imsic_priv *priv = irq_data_get_irq_chip_data(d);
	unsigned int target_cpu;
	int rc;

	rc = imsic_get_cpu(priv, mask_val, force, &target_cpu);
	if (rc)
		return rc;

	imsic_id_set_target(priv, d->hwirq, target_cpu);
	irq_data_update_effective_affinity(d, cpumask_of(target_cpu));

	return IRQ_SET_MASK_OK;
}
#endif

static struct irq_chip imsic_irq_base_chip = {
	.name			= "RISC-V IMSIC-BASE",
	.irq_mask		= imsic_irq_mask,
	.irq_unmask		= imsic_irq_unmask,
#ifdef CONFIG_SMP
	.irq_set_affinity	= imsic_irq_set_affinity,
#endif
	.irq_compose_msi_msg	= imsic_irq_compose_msi_msg,
	.flags			= IRQCHIP_SKIP_SET_WAKE |
				  IRQCHIP_MASK_ON_SUSPEND,
};

static int imsic_irq_domain_alloc(struct irq_domain *domain,
				  unsigned int virq,
				  unsigned int nr_irqs,
				  void *args)
{
	struct imsic_priv *priv = domain->host_data;
	msi_alloc_info_t *info = args;
	phys_addr_t msi_addr;
	int i, hwirq, err = 0;
	unsigned int cpu;

	err = imsic_get_cpu(priv, &priv->lmask, false, &cpu);
	if (err)
		return err;

	err = imsic_cpu_page_phys(cpu, 0, &msi_addr);
	if (err)
		return err;

	hwirq = imsic_ids_alloc(priv, priv->global.nr_ids,
				get_count_order(nr_irqs));
	if (hwirq < 0)
		return hwirq;

	err = iommu_dma_prepare_msi(info->desc, msi_addr);
	if (err)
		goto fail;

	for (i = 0; i < nr_irqs; i++) {
		imsic_id_set_target(priv, hwirq + i, cpu);
		irq_domain_set_info(domain, virq + i, hwirq + i,
				    &imsic_irq_base_chip, priv,
				    handle_simple_irq, NULL, NULL);
		irq_set_noprobe(virq + i);
		irq_set_affinity(virq + i, &priv->lmask);
	}

	return 0;

fail:
	imsic_ids_free(priv, hwirq, get_count_order(nr_irqs));
	return err;
}

static void imsic_irq_domain_free(struct irq_domain *domain,
				  unsigned int virq,
				  unsigned int nr_irqs)
{
	struct irq_data *d = irq_domain_get_irq_data(domain, virq);
	struct imsic_priv *priv = domain->host_data;

	imsic_ids_free(priv, d->hwirq, get_count_order(nr_irqs));
	irq_domain_free_irqs_parent(domain, virq, nr_irqs);
}

static const struct irq_domain_ops imsic_base_domain_ops = {
	.alloc		= imsic_irq_domain_alloc,
	.free		= imsic_irq_domain_free,
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
	.name			= "RISC-V IMSIC-PCI",
	.irq_mask		= imsic_pci_mask_irq,
	.irq_unmask		= imsic_pci_unmask_irq,
	.irq_eoi		= irq_chip_eoi_parent,
};

static struct msi_domain_ops imsic_pci_domain_ops = {
};

static struct msi_domain_info imsic_pci_domain_info = {
	.flags	= (MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS |
		   MSI_FLAG_PCI_MSIX | MSI_FLAG_MULTI_PCI_MSI),
	.ops	= &imsic_pci_domain_ops,
	.chip	= &imsic_pci_irq_chip,
};

#endif

static struct irq_chip imsic_plat_irq_chip = {
	.name			= "RISC-V IMSIC-PLAT",
};

static struct msi_domain_ops imsic_plat_domain_ops = {
};

static struct msi_domain_info imsic_plat_domain_info = {
	.flags	= (MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS),
	.ops	= &imsic_plat_domain_ops,
	.chip	= &imsic_plat_irq_chip,
};

static int __init imsic_irq_domains_init(struct imsic_priv *priv,
					 struct fwnode_handle *fwnode)
{
	/* Create Base IRQ domain */
	priv->base_domain = irq_domain_create_tree(fwnode,
						&imsic_base_domain_ops, priv);
	if (!priv->base_domain) {
		pr_err("Failed to create IMSIC base domain\n");
		return -ENOMEM;
	}
	irq_domain_update_bus_token(priv->base_domain, DOMAIN_BUS_NEXUS);

#ifdef CONFIG_RISCV_IMSIC_PCI
	/* Create PCI MSI domain */
	priv->pci_domain = pci_msi_create_irq_domain(fwnode,
						&imsic_pci_domain_info,
						priv->base_domain);
	if (!priv->pci_domain) {
		pr_err("Failed to create IMSIC PCI domain\n");
		irq_domain_remove(priv->base_domain);
		return -ENOMEM;
	}
#endif

	/* Create Platform MSI domain */
	priv->plat_domain = platform_msi_create_irq_domain(fwnode,
						&imsic_plat_domain_info,
						priv->base_domain);
	if (!priv->plat_domain) {
		pr_err("Failed to create IMSIC platform domain\n");
		if (priv->pci_domain)
			irq_domain_remove(priv->pci_domain);
		irq_domain_remove(priv->base_domain);
		return -ENOMEM;
	}

	return 0;
}

/*
 * To handle an interrupt, we read the TOPEI CSR and write zero in one
 * instruction. If TOPEI CSR is non-zero then we translate TOPEI.ID to
 * Linux interrupt number and let Linux IRQ subsystem handle it.
 */
static void imsic_handle_irq(struct irq_desc *desc)
{
	struct imsic_handler *handler = this_cpu_ptr(&imsic_handlers);
	struct irq_chip *chip = irq_desc_get_chip(desc);
	struct imsic_priv *priv = handler->priv;
	irq_hw_number_t hwirq;
	int err;

	WARN_ON_ONCE(!handler->priv);

	chained_irq_enter(chip, desc);

	while ((hwirq = csr_swap(CSR_TOPEI, 0))) {
		hwirq = hwirq >> TOPEI_ID_SHIFT;

		if (hwirq == priv->ipi_id) {
#ifdef CONFIG_SMP
			ipi_mux_process();
#endif
			continue;
		} else if (hwirq == priv->ipi_lsync_id) {
			imsic_ids_local_sync(priv);
			continue;
		}

		err = generic_handle_domain_irq(priv->base_domain, hwirq);
		if (unlikely(err))
			pr_warn_ratelimited(
				"hwirq %lu mapping not found\n", hwirq);
	}

	chained_irq_exit(chip, desc);
}

static int imsic_starting_cpu(unsigned int cpu)
{
	struct imsic_handler *handler = this_cpu_ptr(&imsic_handlers);
	struct imsic_priv *priv = handler->priv;

	/* Enable per-CPU parent interrupt */
	if (imsic_parent_irq)
		enable_percpu_irq(imsic_parent_irq,
				  irq_get_trigger_type(imsic_parent_irq));
	else
		pr_warn("cpu%d: parent irq not available\n", cpu);

	/* Enable IPIs */
	imsic_ipi_enable(priv);

	/*
	 * Interrupts identities might have been enabled/disabled while
	 * this CPU was not running so sync-up local enable/disable state.
	 */
	imsic_ids_local_sync(priv);

	/* Locally enable interrupt delivery */
	imsic_ids_local_delivery(priv, true);

	return 0;
}

struct imsic_fwnode_ops {
	u32 (*nr_parent_irq)(struct fwnode_handle *fwnode,
			     void *fwopaque);
	int (*parent_hartid)(struct fwnode_handle *fwnode,
			     void *fwopaque, u32 index,
			     unsigned long *out_hartid);
	u32 (*nr_mmio)(struct fwnode_handle *fwnode, void *fwopaque);
	int (*mmio_to_resource)(struct fwnode_handle *fwnode,
				void *fwopaque, u32 index,
				struct resource *res);
	void __iomem *(*mmio_map)(struct fwnode_handle *fwnode,
				  void *fwopaque, u32 index);
	int (*read_u32)(struct fwnode_handle *fwnode,
			void *fwopaque, const char *prop, u32 *out_val);
	bool (*read_bool)(struct fwnode_handle *fwnode,
			  void *fwopaque, const char *prop);
};

static int __init imsic_init(struct imsic_fwnode_ops *fwops,
			     struct fwnode_handle *fwnode,
			     void *fwopaque)
{
	struct resource res;
	phys_addr_t base_addr;
	int rc, nr_parent_irqs;
	struct imsic_mmio *mmio;
	struct imsic_priv *priv;
	struct irq_domain *domain;
	struct imsic_handler *handler;
	struct imsic_global_config *global;
	u32 i, tmp, nr_handlers = 0;

	if (imsic_init_done) {
		pr_err("%pfwP: already initialized hence ignoring\n",
			fwnode);
		return -ENODEV;
	}

	if (!riscv_isa_extension_available(NULL, SxAIA)) {
		pr_err("%pfwP: AIA support not available\n", fwnode);
		return -ENODEV;
	}

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	global = &priv->global;

	/* Find number of parent interrupts */
	nr_parent_irqs = fwops->nr_parent_irq(fwnode, fwopaque);
	if (!nr_parent_irqs) {
		pr_err("%pfwP: no parent irqs available\n", fwnode);
		return -EINVAL;
	}

	/* Find number of guest index bits in MSI address */
	rc = fwops->read_u32(fwnode, fwopaque, "riscv,guest-index-bits",
			     &global->guest_index_bits);
	if (rc)
		global->guest_index_bits = 0;
	tmp = BITS_PER_LONG - IMSIC_MMIO_PAGE_SHIFT;
	if (tmp < global->guest_index_bits) {
		pr_err("%pfwP: guest index bits too big\n", fwnode);
		return -EINVAL;
	}

	/* Find number of HART index bits */
	rc = fwops->read_u32(fwnode, fwopaque, "riscv,hart-index-bits",
			     &global->hart_index_bits);
	if (rc) {
		/* Assume default value */
		global->hart_index_bits = __fls(nr_parent_irqs);
		if (BIT(global->hart_index_bits) < nr_parent_irqs)
			global->hart_index_bits++;
	}
	tmp = BITS_PER_LONG - IMSIC_MMIO_PAGE_SHIFT -
	      global->guest_index_bits;
	if (tmp < global->hart_index_bits) {
		pr_err("%pfwP: HART index bits too big\n", fwnode);
		return -EINVAL;
	}

	/* Find number of group index bits */
	rc = fwops->read_u32(fwnode, fwopaque, "riscv,group-index-bits",
			     &global->group_index_bits);
	if (rc)
		global->group_index_bits = 0;
	tmp = BITS_PER_LONG - IMSIC_MMIO_PAGE_SHIFT -
	      global->guest_index_bits - global->hart_index_bits;
	if (tmp < global->group_index_bits) {
		pr_err("%pfwP: group index bits too big\n", fwnode);
		return -EINVAL;
	}

	/*
	 * Find first bit position of group index.
	 * If not specified assumed the default APLIC-IMSIC configuration.
	 */
	rc = fwops->read_u32(fwnode, fwopaque, "riscv,group-index-shift",
			     &global->group_index_shift);
	if (rc)
		global->group_index_shift = IMSIC_MMIO_PAGE_SHIFT * 2;
	tmp = global->group_index_bits + global->group_index_shift - 1;
	if (tmp >= BITS_PER_LONG) {
		pr_err("%pfwP: group index shift too big\n", fwnode);
		return -EINVAL;
	}

	/* Find number of interrupt identities */
	rc = fwops->read_u32(fwnode, fwopaque, "riscv,num-ids",
			     &global->nr_ids);
	if (rc) {
		pr_err("%pfwP: number of interrupt identities not found\n",
			fwnode);
		return rc;
	}
	if ((global->nr_ids < IMSIC_MIN_ID) ||
	    (global->nr_ids >= IMSIC_MAX_ID) ||
	    ((global->nr_ids & IMSIC_MIN_ID) != IMSIC_MIN_ID)) {
		pr_err("%pfwP: invalid number of interrupt identities\n",
			fwnode);
		return -EINVAL;
	}

	/* Find number of guest interrupt identities */
	if (fwops->read_u32(fwnode, fwopaque, "riscv,num-guest-ids",
			    &global->nr_guest_ids))
		global->nr_guest_ids = global->nr_ids;
	if ((global->nr_guest_ids < IMSIC_MIN_ID) ||
	    (global->nr_guest_ids >= IMSIC_MAX_ID) ||
	    ((global->nr_guest_ids & IMSIC_MIN_ID) != IMSIC_MIN_ID)) {
		pr_err("%pfwP: invalid number of guest interrupt identities\n",
			fwnode);
		return -EINVAL;
	}

	/* Compute base address */
	rc = fwops->mmio_to_resource(fwnode, fwopaque, 0, &res);
	if (rc) {
		pr_err("%pfwP: first MMIO resource not found\n", fwnode);
		return -EINVAL;
	}
	global->base_addr = res.start;
	global->base_addr &= ~(BIT(global->guest_index_bits +
				   global->hart_index_bits +
				   IMSIC_MMIO_PAGE_SHIFT) - 1);
	global->base_addr &= ~((BIT(global->group_index_bits) - 1) <<
			       global->group_index_shift);

	/* Find number of MMIO register sets */
	priv->num_mmios = fwops->nr_mmio(fwnode, fwopaque);

	/* Allocate MMIO register sets */
	priv->mmios = kcalloc(priv->num_mmios, sizeof(*mmio), GFP_KERNEL);
	if (!priv->mmios) {
		rc = -ENOMEM;
		goto out_free_priv;
	}

	/* Parse and map MMIO register sets */
	for (i = 0; i < priv->num_mmios; i++) {
		mmio = &priv->mmios[i];
		rc = fwops->mmio_to_resource(fwnode, fwopaque, i, &res);
		if (rc) {
			pr_err("%pfwP: unable to parse MMIO regset %d\n",
				fwnode, i);
			goto out_iounmap;
		}
		mmio->pa = res.start;
		mmio->size = res.end - res.start + 1;

		base_addr = mmio->pa;
		base_addr &= ~(BIT(global->guest_index_bits +
				   global->hart_index_bits +
				   IMSIC_MMIO_PAGE_SHIFT) - 1);
		base_addr &= ~((BIT(global->group_index_bits) - 1) <<
			       global->group_index_shift);
		if (base_addr != global->base_addr) {
			rc = -EINVAL;
			pr_err("%pfwP: address mismatch for regset %d\n",
				fwnode, i);
			goto out_iounmap;
		}

		mmio->va = fwops->mmio_map(fwnode, fwopaque, i);
		if (!mmio->va) {
			rc = -EIO;
			pr_err("%pfwP: unable to map MMIO regset %d\n",
				fwnode, i);
			goto out_iounmap;
		}
	}

	/* Initialize interrupt identity management */
	rc = imsic_ids_init(priv);
	if (rc) {
		pr_err("%pfwP: failed to initialize interrupt management\n",
		       fwnode);
		goto out_iounmap;
	}

	/* Configure handlers for target CPUs */
	for (i = 0; i < nr_parent_irqs; i++) {
		unsigned long reloff, hartid;
		int j, cpu;

		rc = fwops->parent_hartid(fwnode, fwopaque, i, &hartid);
		if (rc) {
			pr_warn("%pfwP: hart ID for parent irq%d not found\n",
				fwnode, i);
			continue;
		}

		cpu = riscv_hartid_to_cpuid(hartid);
		if (cpu < 0) {
			pr_warn("%pfwP: invalid cpuid for parent irq%d\n",
				fwnode, i);
			continue;
		}

		/* Find MMIO location of MSI page */
		mmio = NULL;
		reloff = i * BIT(global->guest_index_bits) *
			 IMSIC_MMIO_PAGE_SZ;
		for (j = 0; priv->num_mmios; j++) {
			if (reloff < priv->mmios[j].size) {
				mmio = &priv->mmios[j];
				break;
			}

			/*
			 * MMIO region size may not be aligned to
			 * BIT(global->guest_index_bits) * IMSIC_MMIO_PAGE_SZ
			 * if holes are present.
			 */
			reloff -= ALIGN(priv->mmios[j].size,
			BIT(global->guest_index_bits) * IMSIC_MMIO_PAGE_SZ);
		}
		if (!mmio) {
			pr_warn("%pfwP: MMIO not found for parent irq%d\n",
				fwnode, i);
			continue;
		}

		handler = per_cpu_ptr(&imsic_handlers, cpu);
		if (handler->priv) {
			pr_warn("%pfwP: CPU%d handler already configured.\n",
				fwnode, cpu);
			goto done;
		}

		cpumask_set_cpu(cpu, &priv->lmask);
		handler->local.msi_pa = mmio->pa + reloff;
		handler->local.msi_va = mmio->va + reloff;
		handler->priv = priv;

done:
		nr_handlers++;
	}

	/* If no CPU handlers found then can't take interrupts */
	if (!nr_handlers) {
		pr_err("%pfwP: No CPU handlers found\n", fwnode);
		rc = -ENODEV;
		goto out_ids_cleanup;
	}

	/* Find parent domain and register chained handler */
	domain = irq_find_matching_fwnode(riscv_get_intc_hwnode(),
					  DOMAIN_BUS_ANY);
	if (!domain) {
		pr_err("%pfwP: Failed to find INTC domain\n", fwnode);
		rc = -ENOENT;
		goto out_ids_cleanup;
	}
	imsic_parent_irq = irq_create_mapping(domain, RV_IRQ_EXT);
	if (!imsic_parent_irq) {
		pr_err("%pfwP: Failed to create INTC mapping\n", fwnode);
		rc = -ENOENT;
		goto out_ids_cleanup;
	}
	irq_set_chained_handler(imsic_parent_irq, imsic_handle_irq);

	/* Initialize IPI domain */
	rc = imsic_ipi_domain_init(priv);
	if (rc) {
		pr_err("%pfwP: Failed to initialize IPI domain\n", fwnode);
		goto out_ids_cleanup;
	}

	/* Initialize IRQ and MSI domains */
	rc = imsic_irq_domains_init(priv, fwnode);
	if (rc) {
		pr_err("%pfwP: Failed to initialize IRQ and MSI domains\n",
		       fwnode);
		goto out_ipi_domain_cleanup;
	}

	/*
	 * Setup cpuhp state
	 *
	 * Don't disable per-CPU IMSIC file when CPU goes offline
	 * because this affects IPI and the masking/unmasking of
	 * virtual IPIs is done via generic IPI-Mux
	 */
	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
			  "irqchip/riscv/imsic:starting",
			  imsic_starting_cpu, NULL);

	/*
	 * Only one IMSIC instance allowed in a platform for clean
	 * implementation of SMP IRQ affinity and per-CPU IPIs.
	 *
	 * This means on a multi-socket (or multi-die) platform we
	 * will have multiple MMIO regions for one IMSIC instance.
	 */
	imsic_init_done = true;

	pr_info("%pfwP:  hart-index-bits: %d,  guest-index-bits: %d\n",
		fwnode, global->hart_index_bits, global->guest_index_bits);
	pr_info("%pfwP: group-index-bits: %d, group-index-shift: %d\n",
		fwnode, global->group_index_bits, global->group_index_shift);
	pr_info("%pfwP: mapped %d interrupts for %d CPUs at %pa\n",
		fwnode, global->nr_ids, nr_handlers, &global->base_addr);
	if (priv->ipi_lsync_id)
		pr_info("%pfwP: enable/disable sync using interrupt %d\n",
			fwnode, priv->ipi_lsync_id);
	if (priv->ipi_id)
		pr_info("%pfwP: providing IPIs using interrupt %d\n",
			fwnode, priv->ipi_id);

	return 0;

out_ipi_domain_cleanup:
	imsic_ipi_domain_cleanup(priv);
out_ids_cleanup:
	imsic_ids_cleanup(priv);
out_iounmap:
	for (i = 0; i < priv->num_mmios; i++) {
		if (priv->mmios[i].va)
			iounmap(priv->mmios[i].va);
	}
	kfree(priv->mmios);
out_free_priv:
	kfree(priv);
	return rc;
}

static u32 __init imsic_dt_nr_parent_irq(struct fwnode_handle *fwnode,
					 void *fwopaque)
{
	return of_irq_count(to_of_node(fwnode));
}

static int __init imsic_dt_parent_hartid(struct fwnode_handle *fwnode,
					 void *fwopaque, u32 index,
					 unsigned long *out_hartid)
{
	struct of_phandle_args parent;
	int rc;

	rc = of_irq_parse_one(to_of_node(fwnode), index, &parent);
	if (rc)
		return rc;

	/*
	 * Skip interrupts other than external interrupts for
	 * current privilege level.
	 */
	if (parent.args[0] != RV_IRQ_EXT)
		return -EINVAL;

	return riscv_of_parent_hartid(parent.np, out_hartid);
}

static u32 __init imsic_dt_nr_mmio(struct fwnode_handle *fwnode,
				   void *fwopaque)
{
	u32 ret = 0;
	struct resource res;

	while (!of_address_to_resource(to_of_node(fwnode), ret, &res))
		ret++;

	return ret;
}

static int __init imsic_mmio_to_resource(struct fwnode_handle *fwnode,
					 void *fwopaque, u32 index,
					 struct resource *res)
{
	return of_address_to_resource(to_of_node(fwnode), index, res);
}

static void __iomem __init *imsic_dt_mmio_map(struct fwnode_handle *fwnode,
					      void *fwopaque, u32 index)
{
	return of_iomap(to_of_node(fwnode), index);
}

static int __init imsic_dt_read_u32(struct fwnode_handle *fwnode,
				    void *fwopaque, const char *prop,
				    u32 *out_val)
{
	return of_property_read_u32(to_of_node(fwnode), prop, out_val);
}

static bool __init imsic_dt_read_bool(struct fwnode_handle *fwnode,
				      void *fwopaque, const char *prop)
{
	return of_property_read_bool(to_of_node(fwnode), prop);
}

static int __init imsic_dt_init(struct device_node *node,
				struct device_node *parent)
{
	struct imsic_fwnode_ops ops = {
		.nr_parent_irq = imsic_dt_nr_parent_irq,
		.parent_hartid = imsic_dt_parent_hartid,
		.nr_mmio = imsic_dt_nr_mmio,
		.mmio_to_resource = imsic_mmio_to_resource,
		.mmio_map = imsic_dt_mmio_map,
		.read_u32 = imsic_dt_read_u32,
		.read_bool = imsic_dt_read_bool,
	};

	return imsic_init(&ops, &node->fwnode, NULL);
}
IRQCHIP_DECLARE(riscv_imsic, "riscv,imsics", imsic_dt_init);

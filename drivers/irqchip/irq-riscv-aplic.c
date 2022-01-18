// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Western Digital Corporation or its affiliates.
 * Copyright (C) 2022 Ventana Micro Systems Inc.
 */

#include <linux/bitops.h>
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/irqchip/riscv-aplic.h>
#include <linux/irqchip/riscv-imsic.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/smp.h>

#define APLIC_DEFAULT_PRIORITY		1
#define APLIC_DISABLE_IDELIVERY		0
#define APLIC_ENABLE_IDELIVERY		1
#define APLIC_DISABLE_ITHRESHOLD	1
#define APLIC_ENABLE_ITHRESHOLD		0

struct aplic_msicfg {
	phys_addr_t		base_ppn;
	u32			hhxs;
	u32			hhxw;
	u32			lhxs;
	u32			lhxw;
};

struct aplic_idc {
	unsigned int		hart_index;
	void __iomem		*regs;
	struct aplic_priv	*priv;
};

struct aplic_priv {
	struct fwnode_handle	*fwnode;
	u32			nr_irqs;
	u32			nr_idcs;
	void __iomem		*regs;
	struct irq_domain	*irqdomain;
	struct aplic_msicfg	msicfg;
	struct cpumask		lmask;
};

struct aplic_fwnode_ops {
	int (*parent_hartid)(struct fwnode_handle *fwnode,
			     void *fwopaque, u32 index,
			     unsigned long *out_hartid);
	void __iomem *(*mmio_map)(struct fwnode_handle *fwnode,
				  void *fwopaque, u32 index);
	int (*read_nr_sources)(struct fwnode_handle *fwnode,
			       void *fwopaque, u32 *out_val);
	int (*read_nr_idcs)(struct fwnode_handle *fwnode,
			    void *fwopaque, u32 *out_val);
};

static unsigned int aplic_idc_parent_irq;
static DEFINE_PER_CPU(struct aplic_idc, aplic_idcs);

static void aplic_irq_unmask(struct irq_data *d)
{
	struct aplic_priv *priv = irq_data_get_irq_chip_data(d);

	writel(d->hwirq, priv->regs + APLIC_SETIENUM);

	if (!priv->nr_idcs)
		irq_chip_unmask_parent(d);
}

static void aplic_irq_mask(struct irq_data *d)
{
	struct aplic_priv *priv = irq_data_get_irq_chip_data(d);

	writel(d->hwirq, priv->regs + APLIC_CLRIENUM);

	if (!priv->nr_idcs)
		irq_chip_mask_parent(d);
}

static int aplic_set_type(struct irq_data *d, unsigned int type)
{
	u32 val = 0;
	void __iomem *sourcecfg;
	struct aplic_priv *priv = irq_data_get_irq_chip_data(d);

	switch (type) {
	case IRQ_TYPE_NONE:
		val = APLIC_SOURCECFG_SM_INACTIVE;
		break;
	case IRQ_TYPE_LEVEL_LOW:
		val = APLIC_SOURCECFG_SM_LEVEL_LOW;
		break;
	case IRQ_TYPE_LEVEL_HIGH:
		val = APLIC_SOURCECFG_SM_LEVEL_HIGH;
		break;
	case IRQ_TYPE_EDGE_FALLING:
		val = APLIC_SOURCECFG_SM_EDGE_FALL;
		break;
	case IRQ_TYPE_EDGE_RISING:
		val = APLIC_SOURCECFG_SM_EDGE_RISE;
		break;
	default:
		return -EINVAL;
	}

	sourcecfg = priv->regs + APLIC_SOURCECFG_BASE;
	sourcecfg += (d->hwirq - 1) * sizeof(u32);
	writel(val, sourcecfg);

	return 0;
}

static void aplic_irq_eoi(struct irq_data *d)
{
	struct aplic_priv *priv = irq_data_get_irq_chip_data(d);
	u32 reg_off, reg_mask;

	/*
	 * EOI handling only required only for level-triggered
	 * interrupts in APLIC MSI mode.
	 */

	if (priv->nr_idcs)
		return;

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

#ifdef CONFIG_SMP
static int aplic_set_affinity(struct irq_data *d,
			      const struct cpumask *mask_val, bool force)
{
	struct aplic_priv *priv = irq_data_get_irq_chip_data(d);
	struct aplic_idc *idc;
	unsigned int cpu, val;
	struct cpumask amask;
	void __iomem *target;

	if (!priv->nr_idcs)
		return irq_chip_set_affinity_parent(d, mask_val, force);

	cpumask_and(&amask, &priv->lmask, mask_val);

	if (force)
		cpu = cpumask_first(&amask);
	else
		cpu = cpumask_any_and(&amask, cpu_online_mask);

	if (cpu >= nr_cpu_ids)
		return -EINVAL;

	idc = per_cpu_ptr(&aplic_idcs, cpu);
	target = priv->regs + APLIC_TARGET_BASE;
	target += (d->hwirq - 1) * sizeof(u32);
	val = idc->hart_index & APLIC_TARGET_HART_IDX_MASK;
	val <<= APLIC_TARGET_HART_IDX_SHIFT;
	val |= APLIC_DEFAULT_PRIORITY;
	writel(val, target);

	irq_data_update_effective_affinity(d, cpumask_of(cpu));

	return IRQ_SET_MASK_OK_DONE;
}
#endif

static struct irq_chip aplic_chip = {
	.name		= "RISC-V APLIC",
	.irq_mask	= aplic_irq_mask,
	.irq_unmask	= aplic_irq_unmask,
	.irq_set_type	= aplic_set_type,
	.irq_eoi	= aplic_irq_eoi,
#ifdef CONFIG_SMP
	.irq_set_affinity = aplic_set_affinity,
#endif
	.flags		= IRQCHIP_SET_TYPE_MASKED |
			  IRQCHIP_SKIP_SET_WAKE |
			  IRQCHIP_MASK_ON_SUSPEND,
};

static int aplic_irqdomain_translate(struct irq_domain *d,
				     struct irq_fwspec *fwspec,
				     unsigned long *hwirq,
				     unsigned int *type)
{
	if (WARN_ON(fwspec->param_count < 2))
		return -EINVAL;
	if (WARN_ON(!fwspec->param[0]))
		return -EINVAL;

	*hwirq = fwspec->param[0];
	*type = fwspec->param[1] & IRQ_TYPE_SENSE_MASK;

	WARN_ON(*type == IRQ_TYPE_NONE);

	return 0;
}

static int aplic_irqdomain_msi_alloc(struct irq_domain *domain,
				     unsigned int virq, unsigned int nr_irqs,
				     void *arg)
{
	int i, ret;
	unsigned int type;
	irq_hw_number_t hwirq;
	struct irq_fwspec *fwspec = arg;
	struct aplic_priv *priv = platform_msi_get_host_data(domain);

	ret = aplic_irqdomain_translate(domain, fwspec, &hwirq, &type);
	if (ret)
		return ret;

	ret = platform_msi_device_domain_alloc(domain, virq, nr_irqs);
	if (ret)
		return ret;

	for (i = 0; i < nr_irqs; i++) {
		irq_domain_set_info(domain, virq + i, hwirq + i,
				    &aplic_chip, priv, handle_fasteoi_irq,
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

static const struct irq_domain_ops aplic_irqdomain_msi_ops = {
	.translate	= aplic_irqdomain_translate,
	.alloc		= aplic_irqdomain_msi_alloc,
	.free		= platform_msi_device_domain_free,
};

static int aplic_irqdomain_idc_alloc(struct irq_domain *domain,
				     unsigned int virq, unsigned int nr_irqs,
				     void *arg)
{
	int i, ret;
	unsigned int type;
	irq_hw_number_t hwirq;
	struct irq_fwspec *fwspec = arg;
	struct aplic_priv *priv = domain->host_data;

	ret = aplic_irqdomain_translate(domain, fwspec, &hwirq, &type);
	if (ret)
		return ret;

	for (i = 0; i < nr_irqs; i++) {
		irq_domain_set_info(domain, virq + i, hwirq + i,
				    &aplic_chip, priv, handle_fasteoi_irq,
				    NULL, NULL);
		irq_set_affinity(virq + i, &priv->lmask);
		/* See the reason described in aplic_irqdomain_msi_alloc() */
		irq_set_status_flags(virq + i, IRQ_DISABLE_UNLAZY);
	}

	return 0;
}

static const struct irq_domain_ops aplic_irqdomain_idc_ops = {
	.translate	= aplic_irqdomain_translate,
	.alloc		= aplic_irqdomain_idc_alloc,
	.free		= irq_domain_free_irqs_top,
};

static void aplic_init_hw_irqs(struct aplic_priv *priv)
{
	int i;

	/* Disable all interrupts */
	for (i = 0; i <= priv->nr_irqs; i += 32)
		writel(-1U, priv->regs + APLIC_CLRIE_BASE +
			    (i / 32) * sizeof(u32));

	/* Set interrupt type and default priority for all interrupts */
	for (i = 1; i <= priv->nr_irqs; i++) {
		writel(0, priv->regs + APLIC_SOURCECFG_BASE +
			  (i - 1) * sizeof(u32));
		writel(APLIC_DEFAULT_PRIORITY,
		       priv->regs + APLIC_TARGET_BASE +
		       (i - 1) * sizeof(u32));
	}

	/* Clear APLIC domaincfg */
	writel(0, priv->regs + APLIC_DOMAINCFG);
}

static void aplic_init_hw_global(struct aplic_priv *priv)
{
	u32 val;
#ifdef CONFIG_RISCV_M_MODE
	u32 valH;

	if (!priv->nr_idcs) {
		val = priv->msicfg.base_ppn;
		valH = (priv->msicfg.base_ppn >> 32) &
			APLIC_xMSICFGADDRH_BAPPN_MASK;
		valH |= (priv->msicfg.lhxw & APLIC_xMSICFGADDRH_LHXW_MASK)
			<< APLIC_xMSICFGADDRH_LHXW_SHIFT;
		valH |= (priv->msicfg.hhxw & APLIC_xMSICFGADDRH_HHXW_MASK)
			<< APLIC_xMSICFGADDRH_HHXW_SHIFT;
		valH |= (priv->msicfg.lhxs & APLIC_xMSICFGADDRH_LHXS_MASK)
			<< APLIC_xMSICFGADDRH_LHXS_SHIFT;
		valH |= (priv->msicfg.hhxs & APLIC_xMSICFGADDRH_HHXS_MASK)
			<< APLIC_xMSICFGADDRH_HHXS_SHIFT;
		writel(val, priv->regs + APLIC_xMSICFGADDR);
		writel(valH, priv->regs + APLIC_xMSICFGADDRH);
	}
#endif

	/* Setup APLIC domaincfg register */
	val = readl(priv->regs + APLIC_DOMAINCFG);
	val |= APLIC_DOMAINCFG_IE;
	if (!priv->nr_idcs)
		val |= APLIC_DOMAINCFG_DM;
	writel(val, priv->regs + APLIC_DOMAINCFG);
	if (readl(priv->regs + APLIC_DOMAINCFG) != val)
		pr_warn("%pfwP: unable to write 0x%x in domaincfg\n",
			priv->fwnode, val);
}

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

static int aplic_setup_msi(struct aplic_priv *priv,
			   struct aplic_fwnode_ops *fwops,
			   void *fwopaque)
{
	struct aplic_msicfg *mc = &priv->msicfg;
	const struct imsic_global_config *imsic_global;

	/*
	 * The APLIC outgoing MSI config registers assume target MSI
	 * controller to be RISC-V AIA IMSIC controller.
	 */
	imsic_global = imsic_get_global_config();
	if (!imsic_global) {
		pr_err("%pfwP: IMSIC global config not found\n",
			priv->fwnode);
		return -ENODEV;
	}

	/* Find number of guest index bits (LHXS) */
	mc->lhxs = imsic_global->guest_index_bits;
	if (APLIC_xMSICFGADDRH_LHXS_MASK < mc->lhxs) {
		pr_err("%pfwP: IMSIC guest index bits big for APLIC LHXS\n",
			priv->fwnode);
		return -EINVAL;
	}

	/* Find number of HART index bits (LHXW) */
	mc->lhxw = imsic_global->hart_index_bits;
	if (APLIC_xMSICFGADDRH_LHXW_MASK < mc->lhxw) {
		pr_err("%pfwP: IMSIC hart index bits big for APLIC LHXW\n",
			priv->fwnode);
		return -EINVAL;
	}

	/* Find number of group index bits (HHXW) */
	mc->hhxw = imsic_global->group_index_bits;
	if (APLIC_xMSICFGADDRH_HHXW_MASK < mc->hhxw) {
		pr_err("%pfwP: IMSIC group index bits big for APLIC HHXW\n",
			priv->fwnode);
		return -EINVAL;
	}

	/* Find first bit position of group index (HHXS) */
	mc->hhxs = imsic_global->group_index_shift;
	if (mc->hhxs < (2 * APLIC_xMSICFGADDR_PPN_SHIFT)) {
		pr_err("%pfwP: IMSIC group index shift should be >= %d\n",
			priv->fwnode, (2 * APLIC_xMSICFGADDR_PPN_SHIFT));
		return -EINVAL;
	}
	mc->hhxs -= (2 * APLIC_xMSICFGADDR_PPN_SHIFT);
	if (APLIC_xMSICFGADDRH_HHXS_MASK < mc->hhxs) {
		pr_err("%pfwP: IMSIC group index shift big for APLIC HHXS\n",
			priv->fwnode);
		return -EINVAL;
	}

	/* Compute PPN base */
	mc->base_ppn = imsic_global->base_addr >> APLIC_xMSICFGADDR_PPN_SHIFT;
	mc->base_ppn &= ~APLIC_xMSICFGADDR_PPN_HART(mc->lhxs);
	mc->base_ppn &= ~APLIC_xMSICFGADDR_PPN_LHX(mc->lhxw, mc->lhxs);
	mc->base_ppn &= ~APLIC_xMSICFGADDR_PPN_HHX(mc->hhxw, mc->hhxs);

	/* Use all possible CPUs as lmask */
	cpumask_copy(&priv->lmask, cpu_possible_mask);

	return 0;
}

/*
 * To handle an APLIC IDC interrupts, we just read the CLAIMI register
 * which will return highest priority pending interrupt and clear the
 * pending bit of the interrupt. This process is repeated until CLAIMI
 * register return zero value.
 */
static void aplic_idc_handle_irq(struct irq_desc *desc)
{
	struct aplic_idc *idc = this_cpu_ptr(&aplic_idcs);
	struct irq_chip *chip = irq_desc_get_chip(desc);
	irq_hw_number_t hw_irq;
	int irq;

	chained_irq_enter(chip, desc);

	while ((hw_irq = readl(idc->regs + APLIC_IDC_CLAIMI))) {
		hw_irq = hw_irq >> APLIC_IDC_TOPI_ID_SHIFT;
		irq = irq_find_mapping(idc->priv->irqdomain, hw_irq);

		if (unlikely(irq <= 0))
			pr_warn_ratelimited("hw_irq %lu mapping not found\n",
					    hw_irq);
		else
			generic_handle_irq(irq);
	}

	chained_irq_exit(chip, desc);
}

static void aplic_idc_set_delivery(struct aplic_idc *idc, bool en)
{
	u32 de = (en) ? APLIC_ENABLE_IDELIVERY : APLIC_DISABLE_IDELIVERY;
	u32 th = (en) ? APLIC_ENABLE_ITHRESHOLD : APLIC_DISABLE_ITHRESHOLD;

	/* Priority must be less than threshold for interrupt triggering */
	writel(th, idc->regs + APLIC_IDC_ITHRESHOLD);

	/* Delivery must be set to 1 for interrupt triggering */
	writel(de, idc->regs + APLIC_IDC_IDELIVERY);
}

static int aplic_idc_dying_cpu(unsigned int cpu)
{
	if (aplic_idc_parent_irq)
		disable_percpu_irq(aplic_idc_parent_irq);

	return 0;
}

static int aplic_idc_starting_cpu(unsigned int cpu)
{
	if (aplic_idc_parent_irq)
		enable_percpu_irq(aplic_idc_parent_irq,
				  irq_get_trigger_type(aplic_idc_parent_irq));

	return 0;
}

static int aplic_setup_idc(struct aplic_priv *priv,
			   struct aplic_fwnode_ops *fwops,
			   void *fwopaque)
{
	int i, j, rc, cpu, setup_count = 0;
	struct irq_domain *domain;
	unsigned long hartid;
	struct aplic_idc *idc;
	u32 val;

	/* Setup per-CPU IDC and target CPU mask */
	for (i = 0; i < priv->nr_idcs; i++) {
		rc = fwops->parent_hartid(priv->fwnode, fwopaque, i, &hartid);
		if (rc) {
			pr_warn("%pfwP: hart ID for parent irq%d not found\n",
				priv->fwnode, i);
			continue;
		}

		cpu = riscv_hartid_to_cpuid(hartid);
		if (cpu < 0) {
			pr_warn("%pfwP: invalid cpuid for IDC%d\n",
				priv->fwnode, i);
			continue;
		}

		cpumask_set_cpu(cpu, &priv->lmask);

		idc = per_cpu_ptr(&aplic_idcs, cpu);
		WARN_ON(idc->priv);

		idc->hart_index = i;
		idc->regs = priv->regs + APLIC_IDC_BASE + i * APLIC_IDC_SIZE;
		idc->priv = priv;

		aplic_idc_set_delivery(idc, true);

		/*
		 * Boot cpu might not have APLIC hart_index = 0 so check
		 * and update target registers of all interrupts.
		 */
		if (cpu == smp_processor_id() && idc->hart_index) {
			val = idc->hart_index & APLIC_TARGET_HART_IDX_MASK;
			val <<= APLIC_TARGET_HART_IDX_SHIFT;
			val |= APLIC_DEFAULT_PRIORITY;
			for (j = 1; j <= priv->nr_irqs; j++)
				writel(val, priv->regs + APLIC_TARGET_BASE +
					    (j - 1) * sizeof(u32));
		}

		setup_count++;
	}

	/* Find parent domain and register chained handler */
	domain = irq_find_matching_fwnode(riscv_get_intc_hwnode(),
					  DOMAIN_BUS_ANY);
	if (!aplic_idc_parent_irq && domain) {
		aplic_idc_parent_irq = irq_create_mapping(domain, RV_IRQ_EXT);
		if (aplic_idc_parent_irq) {
			irq_set_chained_handler(aplic_idc_parent_irq,
						aplic_idc_handle_irq);

			/*
			 * Setup CPUHP notifier to enable IDC parent
			 * interrupt on all CPUs
			 */
			cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
					  "irqchip/riscv/aplic:starting",
					  aplic_idc_starting_cpu,
					  aplic_idc_dying_cpu);
		}
	}

	/* Fail if we were not able to setup IDC for any CPU */
	return (setup_count) ? 0 : -ENODEV;
}

static int aplic_common_probe(struct aplic_fwnode_ops *fwops,
			      struct fwnode_handle *fwnode,
			      void *fwopaque,
			      struct device *dev)
{
	struct aplic_priv *priv;
	phys_addr_t pa;
	int rc;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	priv->fwnode = fwnode;

	/* Map the MMIO registers */
	priv->regs = fwops->mmio_map(fwnode, fwopaque, 0);
	if (!priv->regs) {
		pr_err("%pfwP: failed map MMIO registers\n", fwnode);
		kfree(priv);
		return -EIO;
	}

	/* Find out number of interrupt sources */
	rc = fwops->read_nr_sources(fwnode, fwopaque, &priv->nr_irqs);
	if (rc) {
		pr_err("%pfwP: failed to get number of interrupt sources\n",
			fwnode);
		iounmap(priv->regs);
		kfree(priv);
		return rc;
	}

	/* Setup initial state APLIC interrupts */
	aplic_init_hw_irqs(priv);

	/* Find out number of IDCs */
	rc = fwops->read_nr_idcs(fwnode, fwopaque, &priv->nr_idcs);
	if (rc) {
		pr_err("%pfwP: failed to get number of IDCs\n",
			fwnode);
		iounmap(priv->regs);
		kfree(priv);
		return rc;
	}

	/* Setup IDCs or MSIs based on number of IDCs */
	if (priv->nr_idcs)
		rc = aplic_setup_idc(priv, fwops, fwopaque);
	else
		rc = aplic_setup_msi(priv, fwops, fwopaque);
	if (rc) {
		pr_err("%pfwP: failed setup %s\n",
			fwnode, priv->nr_idcs ? "IDCs" : "MSIs");
		iounmap(priv->regs);
		kfree(priv);
		return rc;
	}

	/* Setup global config and interrupt delivery */
	aplic_init_hw_global(priv);

	/* Create irq domain instance for the APLIC */
	if (priv->nr_idcs)
		priv->irqdomain = irq_domain_create_linear(
						priv->fwnode,
						priv->nr_irqs + 1,
						&aplic_irqdomain_idc_ops,
						priv);
	else
		priv->irqdomain = platform_msi_create_device_domain(dev,
						priv->nr_irqs + 1,
						aplic_msi_write_msg,
						&aplic_irqdomain_msi_ops,
						priv);
	if (!priv->irqdomain) {
		pr_err("%pfwP: failed to add irq domain\n", priv->fwnode);
		iounmap(priv->regs);
		kfree(priv);
		return -ENOMEM;
	}

	/* Advertise the interrupt controller */
	if (priv->nr_idcs) {
		pr_info("%pfwP: %d interrupts directly connected to %d CPUs\n",
			priv->fwnode, priv->nr_irqs, priv->nr_idcs);
	} else {
		pa = priv->msicfg.base_ppn << APLIC_xMSICFGADDR_PPN_SHIFT;
		pr_info("%pfwP: %d interrupts forwared to MSI base %pa\n",
			priv->fwnode, priv->nr_irqs, &pa);
	}

	return 0;
}

static int aplic_dt_parent_hartid(struct fwnode_handle *fwnode,
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

static void __iomem *aplic_dt_mmio_map(struct fwnode_handle *fwnode,
					void *fwopaque, u32 index)
{
	return of_iomap(to_of_node(fwnode), index);
}

static int aplic_dt_read_nr_sources(struct fwnode_handle *fwnode,
				    void *fwopaque, u32 *out_val)
{
	return of_property_read_u32(to_of_node(fwnode),
				    "riscv,num-sources", out_val);
}

static int aplic_dt_read_nr_idcs(struct fwnode_handle *fwnode,
				 void *fwopaque, u32 *out_val)
{
	/*
	 * Setup number of IDCs based on parent interrupts
	 *
	 * If "msi-parent" DT property is present then we ignore the
	 * APLIC IDCs which forces the APLIC driver to use MSI mode.
	 */
	if (of_property_read_bool(to_of_node(fwnode), "msi-parent"))
		*out_val = 0;
	else
		*out_val = of_irq_count(to_of_node(fwnode));

	return 0;
}

static int aplic_probe(struct platform_device *pdev)
{
	struct device_node *node = pdev->dev.of_node;
	struct fwnode_handle *fwnode = of_node_to_fwnode(node);
	struct aplic_fwnode_ops ops = {
		.parent_hartid = aplic_dt_parent_hartid,
		.mmio_map = aplic_dt_mmio_map,
		.read_nr_sources = aplic_dt_read_nr_sources,
		.read_nr_idcs = aplic_dt_read_nr_idcs,
	};

	return aplic_common_probe(&ops, fwnode, NULL, &pdev->dev);
}

static const struct of_device_id aplic_match[] = {
	{ .compatible = "riscv,aplic" },
	{}
};

static struct platform_driver aplic_driver = {
	.driver = {
		.name		= "riscv-aplic",
		.of_match_table	= aplic_match,
	},
	.probe = aplic_probe,
};

static int __init aplic_init(void)
{
	return platform_driver_register(&aplic_driver);
}
core_initcall(aplic_init);

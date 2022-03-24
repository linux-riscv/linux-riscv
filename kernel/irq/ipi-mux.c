// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Multiplex several virtual IPIs over a single HW IPI.
 *
 * Copyright The Asahi Linux Contributors
 * Copyright (c) 2022 Ventana Micro Systems Inc.
 */

#define pr_fmt(fmt) "ipi-mux: " fmt
#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/irqdomain.h>
#include <linux/jump_label.h>
#include <linux/percpu.h>
#include <linux/smp.h>

struct ipi_mux_cpu {
	atomic_t			enable;
	atomic_t			bits;
	struct cpumask			send_mask;
};

struct ipi_mux_control {
	void				*data;
	unsigned int			nr;
	unsigned int			parent_virq;
	struct irq_domain		*domain;
	const struct ipi_mux_ops	*ops;
	struct ipi_mux_cpu __percpu	*cpu;
};

static struct ipi_mux_control *imux;
static DEFINE_STATIC_KEY_FALSE(imux_pre_handle);
static DEFINE_STATIC_KEY_FALSE(imux_post_handle);

static void ipi_mux_mask(struct irq_data *d)
{
	struct ipi_mux_cpu *icpu = this_cpu_ptr(imux->cpu);

	atomic_andnot(BIT(irqd_to_hwirq(d)), &icpu->enable);
}

static void ipi_mux_unmask(struct irq_data *d)
{
	u32 ibit = BIT(irqd_to_hwirq(d));
	struct ipi_mux_cpu *icpu = this_cpu_ptr(imux->cpu);

	atomic_or(ibit, &icpu->enable);

	/*
	 * The atomic_or() above must complete before the atomic_read()
	 * below to avoid racing ipi_mux_send_mask().
	 */
	smp_mb__after_atomic();

	/* If a pending IPI was unmasked, raise a parent IPI immediately. */
	if (atomic_read(&icpu->bits) & ibit)
		imux->ops->ipi_mux_send(imux->parent_virq, imux->data,
					cpumask_of(smp_processor_id()));
}

static void ipi_mux_send_mask(struct irq_data *d, const struct cpumask *mask)
{
	u32 ibit = BIT(irqd_to_hwirq(d));
	struct ipi_mux_cpu *icpu = this_cpu_ptr(imux->cpu);
	struct cpumask *send_mask = &icpu->send_mask;
	unsigned long pending;
	int cpu;

	cpumask_clear(send_mask);

	for_each_cpu(cpu, mask) {
		icpu = per_cpu_ptr(imux->cpu, cpu);
		pending = atomic_fetch_or_release(ibit, &icpu->bits);

		/*
		 * The atomic_fetch_or_release() above must complete before
		 * the atomic_read() below to avoid racing ipi_mux_unmask().
		 */
		smp_mb__after_atomic();

		if (!(pending & ibit) &&
		    (atomic_read(&icpu->enable) & ibit))
			cpumask_set_cpu(cpu, send_mask);
	}

	/* Trigger the parent IPI */
	imux->ops->ipi_mux_send(imux->parent_virq, imux->data, send_mask);
}

static const struct irq_chip ipi_mux_chip = {
	.name		= "IPI Mux",
	.irq_mask	= ipi_mux_mask,
	.irq_unmask	= ipi_mux_unmask,
	.ipi_send_mask	= ipi_mux_send_mask,
};

static int ipi_mux_domain_alloc(struct irq_domain *d, unsigned int virq,
				unsigned int nr_irqs, void *arg)
{
	int i;

	for (i = 0; i < nr_irqs; i++) {
		irq_set_percpu_devid(virq + i);
		irq_domain_set_info(d, virq + i, i,
				    &ipi_mux_chip, d->host_data,
				    handle_percpu_devid_irq, NULL, NULL);
	}

	return 0;
}

static const struct irq_domain_ops ipi_mux_domain_ops = {
	.alloc		= ipi_mux_domain_alloc,
	.free		= irq_domain_free_irqs_top,
};

/**
 * ipi_mux_process - Process multiplexed virtual IPIs
 */
void ipi_mux_process(void)
{
	struct ipi_mux_cpu *icpu = this_cpu_ptr(imux->cpu);
	irq_hw_number_t hwirq;
	unsigned long ipis;
	int en;

	if (static_branch_unlikely(&imux_pre_handle))
		imux->ops->ipi_mux_pre_handle(imux->parent_virq, imux->data);

	/*
	 * Reading enable mask does not need to be ordered as long as
	 * this function called from interrupt handler because only
	 * the CPU itself can change it's own enable mask.
	 */
	en = atomic_read(&icpu->enable);

	/*
	 * Clear the IPIs we are about to handle. This pairs with the
	 * atomic_fetch_or_release() in ipi_mux_send_mask().
	 */
	ipis = atomic_fetch_andnot(en, &icpu->bits) & en;

	for_each_set_bit(hwirq, &ipis, imux->nr)
		generic_handle_domain_irq(imux->domain, hwirq);

	if (static_branch_unlikely(&imux_post_handle))
		imux->ops->ipi_mux_post_handle(imux->parent_virq, imux->data);
}

static void ipi_mux_handler(struct irq_desc *desc)
{
	struct irq_chip *chip = irq_desc_get_chip(desc);

	chained_irq_enter(chip, desc);
	ipi_mux_process();
	chained_irq_exit(chip, desc);
}

/**
 * ipi_mux_create - Create virtual IPIs multiplexed on top of a single
 * parent IPI.
 * @parent_virq:	virq of the parent per-CPU IRQ
 * @nr_ipi:		number of virtual IPIs to create. This should
 *			be <= BITS_PER_TYPE(int)
 * @ops:		multiplexing operations for the parent IPI
 * @data:		opaque data used by the multiplexing operations
 *
 * If the parent IPI > 0 then ipi_mux_process() will be automatically
 * called via chained handler.
 *
 * If the parent IPI <= 0 then it is responsibility of irqchip drivers
 * to explicitly call ipi_mux_process() for processing muxed IPIs.
 *
 * Returns first virq of the newly created virtual IPIs upon success
 * or <=0 upon failure
 */
int ipi_mux_create(unsigned int parent_virq, unsigned int nr_ipi,
		   const struct ipi_mux_ops *ops, void *data)
{
	struct fwnode_handle *fwnode;
	struct irq_domain *domain;
	int rc;

	if (imux)
		return -EEXIST;

	if (BITS_PER_TYPE(int) < nr_ipi || !ops || !ops->ipi_mux_send)
		return -EINVAL;

	if (parent_virq &&
	    !irqd_is_per_cpu(irq_desc_get_irq_data(irq_to_desc(parent_virq))))
		return -EINVAL;

	imux = kzalloc(sizeof(*imux), GFP_KERNEL);
	if (!imux)
		return -ENOMEM;

	imux->cpu = alloc_percpu(typeof(*imux->cpu));
	if (!imux->cpu) {
		rc = -ENOMEM;
		goto fail_free_mux;
	}

	fwnode = irq_domain_alloc_named_fwnode("IPI-Mux");
	if (!fwnode) {
		pr_err("unable to create IPI Mux fwnode\n");
		rc = -ENOMEM;
		goto fail_free_cpu;
	}

	domain = irq_domain_create_simple(fwnode, nr_ipi, 0,
					  &ipi_mux_domain_ops, NULL);
	if (!domain) {
		pr_err("unable to add IPI Mux domain\n");
		rc = -ENOMEM;
		goto fail_free_fwnode;
	}

	domain->flags |= IRQ_DOMAIN_FLAG_IPI_SINGLE;
	irq_domain_update_bus_token(domain, DOMAIN_BUS_IPI);

	rc = __irq_domain_alloc_irqs(domain, -1, nr_ipi,
				     NUMA_NO_NODE, NULL, false, NULL);
	if (rc <= 0) {
		pr_err("unable to alloc IRQs from IPI Mux domain\n");
		goto fail_free_domain;
	}

	imux->domain = domain;
	imux->data = data;
	imux->nr = nr_ipi;
	imux->parent_virq = parent_virq;
	imux->ops = ops;

	if (imux->ops->ipi_mux_pre_handle)
		static_branch_enable(&imux_pre_handle);

	if (imux->ops->ipi_mux_post_handle)
		static_branch_enable(&imux_post_handle);

	if (parent_virq > 0)
		irq_set_chained_handler(parent_virq, ipi_mux_handler);

	return rc;

fail_free_domain:
	irq_domain_remove(domain);
fail_free_fwnode:
	irq_domain_free_fwnode(fwnode);
fail_free_cpu:
	free_percpu(imux->cpu);
fail_free_mux:
	kfree(imux);
	imux = NULL;
	return rc;
}

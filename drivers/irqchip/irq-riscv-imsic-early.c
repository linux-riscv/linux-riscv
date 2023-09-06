// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Western Digital Corporation or its affiliates.
 * Copyright (C) 2022 Ventana Micro Systems Inc.
 */

#define pr_fmt(fmt) "riscv-imsic: " fmt
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/smp.h>

#include "irq-riscv-imsic-state.h"

/*
 * The IMSIC driver uses 1 IPI for ID synchronization and
 * arch/riscv/kernel/smp.c require 6 IPIs so we fix the
 * total number of IPIs to 8.
 */
#define IMSIC_NR_IPI				8

static int imsic_parent_irq;

#ifdef CONFIG_SMP
static irqreturn_t imsic_ids_sync_handler(int irq, void *data)
{
	imsic_ids_local_sync();
	return IRQ_HANDLED;
}

void imsic_ids_remote_sync(void)
{
	struct cpumask amask;

	/*
	 * We simply inject ID synchronization IPI to all target CPUs
	 * except current CPU. The ipi_send_mask() implementation of
	 * IPI mux will inject ID synchronization IPI only for CPUs
	 * that have enabled it so offline CPUs won't receive IPI.
	 * An offline CPU will unconditionally synchronize IDs through
	 * imsic_starting_cpu() when the CPU is brought up.
	 */
	cpumask_andnot(&amask, cpu_online_mask, cpumask_of(smp_processor_id()));
	__ipi_send_mask(imsic->ipi_lsync_desc, &amask);
}

static void imsic_ipi_send(unsigned int cpu)
{
	struct imsic_local_config *local =
				per_cpu_ptr(imsic->global.local, cpu);

	writel(imsic->ipi_id, local->msi_va);
}

static void imsic_ipi_starting_cpu(void)
{
	/* Enable IPIs for current CPU. */
	__imsic_id_enable(imsic->ipi_id);

	/* Enable virtual IPI used for IMSIC ID synchronization */
	enable_percpu_irq(imsic->ipi_virq, 0);
}

static void imsic_ipi_dying_cpu(void)
{
	/*
	 * Disable virtual IPI used for IMSIC ID synchronization so
	 * that we don't receive ID synchronization requests.
	 */
	disable_percpu_irq(imsic->ipi_virq);
}

static int __init imsic_ipi_domain_init(void)
{
	int virq;

	/* Allocate interrupt identity for IPIs */
	virq = imsic_ids_alloc(get_count_order(1));
	if (virq < 0)
		return virq;
	imsic->ipi_id = virq;

	/* Create IMSIC IPI multiplexing */
	virq = ipi_mux_create(IMSIC_NR_IPI, imsic_ipi_send);
	if (virq <= 0) {
		imsic_ids_free(imsic->ipi_id, get_count_order(1));
		return (virq < 0) ? virq : -ENOMEM;
	}
	imsic->ipi_virq = virq;

	/* First vIRQ is used for IMSIC ID synchronization */
	virq = request_percpu_irq(imsic->ipi_virq, imsic_ids_sync_handler,
				  "riscv-imsic-lsync", imsic->global.local);
	if (virq) {
		imsic_ids_free(imsic->ipi_id, get_count_order(1));
		return virq;
	}
	irq_set_status_flags(imsic->ipi_virq, IRQ_HIDDEN);
	imsic->ipi_lsync_desc = irq_to_desc(imsic->ipi_virq);

	/* Set vIRQ range */
	riscv_ipi_set_virq_range(imsic->ipi_virq + 1, IMSIC_NR_IPI - 1, true);

	/* Announce that IMSIC is providing IPIs */
	pr_info("%pfwP: providing IPIs using interrupt %d\n",
		imsic->fwnode, imsic->ipi_id);

	return 0;
}
#else
static void imsic_ipi_starting_cpu(void)
{
}

static void imsic_ipi_dying_cpu(void)
{
}

static int __init imsic_ipi_domain_init(void)
{
	/* Clear the IPI id because we are not using IPIs */
	imsic->ipi_id = 0;
	return 0;
}
#endif

/*
 * To handle an interrupt, we read the TOPEI CSR and write zero in one
 * instruction. If TOPEI CSR is non-zero then we translate TOPEI.ID to
 * Linux interrupt number and let Linux IRQ subsystem handle it.
 */
static void imsic_handle_irq(struct irq_desc *desc)
{
	struct irq_chip *chip = irq_desc_get_chip(desc);
	irq_hw_number_t hwirq;
	int err;

	chained_irq_enter(chip, desc);

	while ((hwirq = csr_swap(CSR_TOPEI, 0))) {
		hwirq = hwirq >> TOPEI_ID_SHIFT;

		if (hwirq == imsic->ipi_id) {
#ifdef CONFIG_SMP
			ipi_mux_process();
#endif
			continue;
		}

		if (unlikely(!imsic->base_domain))
			continue;

		err = generic_handle_domain_irq(imsic->base_domain, hwirq);
		if (unlikely(err))
			pr_warn_ratelimited(
				"hwirq %lu mapping not found\n", hwirq);
	}

	chained_irq_exit(chip, desc);
}

static int imsic_starting_cpu(unsigned int cpu)
{
	/* Enable per-CPU parent interrupt */
	enable_percpu_irq(imsic_parent_irq,
			  irq_get_trigger_type(imsic_parent_irq));

	/* Setup IPIs */
	imsic_ipi_starting_cpu();

	/*
	 * Interrupts identities might have been enabled/disabled while
	 * this CPU was not running so sync-up local enable/disable state.
	 */
	imsic_ids_local_sync();

	/* Enable local interrupt delivery */
	imsic_ids_local_delivery(true);

	return 0;
}

static int imsic_dying_cpu(unsigned int cpu)
{
	/* Cleanup IPIs */
	imsic_ipi_dying_cpu();

	return 0;
}

static int __init imsic_early_probe(struct fwnode_handle *fwnode)
{
	int rc;
	struct irq_domain *domain;

	/* Setup IMSIC state */
	rc = imsic_setup_state(fwnode);
	if (rc) {
		pr_err("%pfwP: failed to setup state (error %d)\n",
			fwnode, rc);
		return rc;
	}

	/* Find parent domain and register chained handler */
	domain = irq_find_matching_fwnode(riscv_get_intc_hwnode(),
					  DOMAIN_BUS_ANY);
	if (!domain) {
		pr_err("%pfwP: Failed to find INTC domain\n", fwnode);
		return -ENOENT;
	}
	imsic_parent_irq = irq_create_mapping(domain, RV_IRQ_EXT);
	if (!imsic_parent_irq) {
		pr_err("%pfwP: Failed to create INTC mapping\n", fwnode);
		return -ENOENT;
	}
	irq_set_chained_handler(imsic_parent_irq, imsic_handle_irq);

	/* Initialize IPI domain */
	rc = imsic_ipi_domain_init();
	if (rc) {
		pr_err("%pfwP: Failed to initialize IPI domain\n", fwnode);
		return rc;
	}

	/*
	 * Setup cpuhp state (must be done after setting imsic_parent_irq)
	 *
	 * Don't disable per-CPU IMSIC file when CPU goes offline
	 * because this affects IPI and the masking/unmasking of
	 * virtual IPIs is done via generic IPI-Mux
	 */
	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
			  "irqchip/riscv/imsic:starting",
			  imsic_starting_cpu, imsic_dying_cpu);

	return 0;
}

static int __init imsic_early_dt_init(struct device_node *node,
				      struct device_node *parent)
{
	int rc;

	/* Do early setup of IMSIC state and IPIs */
	rc = imsic_early_probe(&node->fwnode);
	if (rc)
		return rc;

	/* Ensure that OF platform device gets probed */
	of_node_clear_flag(node, OF_POPULATED);
	return 0;
}
IRQCHIP_DECLARE(riscv_imsic, "riscv,imsics", imsic_early_dt_init);

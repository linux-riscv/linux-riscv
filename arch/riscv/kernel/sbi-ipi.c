// SPDX-License-Identifier: GPL-2.0-only
/*
 * Multiplex several IPIs over a single HW IPI.
 *
 * Copyright (c) 2022 Ventana Micro Systems Inc.
 */

#define pr_fmt(fmt) "riscv: " fmt
#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <asm/sbi.h>

static int sbi_ipi_virq;

static void sbi_send_cpumask_ipi(unsigned int parent_virq, void *data,
				 const struct cpumask *target)
{
	sbi_send_ipi(target);
}

static void sbi_ipi_clear(unsigned int parent_virq, void *data)
{
	csr_clear(CSR_IP, IE_SIE);
}

static struct ipi_mux_ops sbi_ipi_ops = {
	.ipi_mux_pre_handle = sbi_ipi_clear,
	.ipi_mux_send = sbi_send_cpumask_ipi,
};

static int sbi_ipi_dying_cpu(unsigned int cpu)
{
	disable_percpu_irq(sbi_ipi_virq);
	return 0;
}

static int sbi_ipi_starting_cpu(unsigned int cpu)
{
	enable_percpu_irq(sbi_ipi_virq, irq_get_trigger_type(sbi_ipi_virq));
	return 0;
}

void __init sbi_ipi_init(void)
{
	int virq;
	struct irq_domain *domain;

	if (riscv_ipi_have_virq_range())
		return;

	domain = irq_find_matching_fwnode(riscv_get_intc_hwnode(),
					  DOMAIN_BUS_ANY);
	if (!domain) {
		pr_err("unable to find INTC IRQ domain\n");
		return;
	}

	sbi_ipi_virq = irq_create_mapping(domain, RV_IRQ_SOFT);
	if (!sbi_ipi_virq) {
		pr_err("unable to create INTC IRQ mapping\n");
		return;
	}

	virq = ipi_mux_create(sbi_ipi_virq, BITS_PER_BYTE,
			      &sbi_ipi_ops, NULL);
	if (virq <= 0) {
		pr_err("unable to create muxed IPIs\n");
		irq_dispose_mapping(sbi_ipi_virq);
		return;
	}

	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
			  "irqchip/sbi-ipi:starting",
			  sbi_ipi_starting_cpu, sbi_ipi_dying_cpu);

	riscv_ipi_set_virq_range(virq, BITS_PER_BYTE);
	pr_info("providing IPIs using SBI IPI extension\n");
}

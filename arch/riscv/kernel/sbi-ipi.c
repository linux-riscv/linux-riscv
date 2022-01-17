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
#include <linux/percpu.h>
#include <asm/sbi.h>

static int sbi_ipi_virq;
static DEFINE_PER_CPU_READ_MOSTLY(int, sbi_ipi_dummy_dev);

static irqreturn_t sbi_ipi_handle(int irq, void *dev_id)
{
	csr_clear(CSR_IP, IE_SIE);
	ipi_mux_process();
	return IRQ_HANDLED;
}

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
	int virq, rc;
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

	rc = request_percpu_irq(sbi_ipi_virq, sbi_ipi_handle,
				"riscv-sbi-ipi", &sbi_ipi_dummy_dev);
	if (rc) {
		pr_err("registering percpu irq failed (error %d)\n", rc);
		irq_dispose_mapping(sbi_ipi_virq);
		return;
	}

	virq = ipi_mux_create(BITS_PER_BYTE, sbi_send_ipi);
	if (virq <= 0) {
		pr_err("unable to create muxed IPIs\n");
		free_percpu_irq(sbi_ipi_virq, &sbi_ipi_dummy_dev);
		irq_dispose_mapping(sbi_ipi_virq);
		return;
	}

	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
			  "irqchip/sbi-ipi:starting",
			  sbi_ipi_starting_cpu, sbi_ipi_dying_cpu);

	riscv_ipi_set_virq_range(virq, BITS_PER_BYTE);
	pr_info("providing IPIs using SBI IPI extension\n");
}

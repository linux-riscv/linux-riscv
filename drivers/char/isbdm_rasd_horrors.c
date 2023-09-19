/*
 * ISBDM Sentinel glue needed to make RASD work.
 *
 * SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * 2023-Aug-11 Evan Green <evan@rivosinc.com>
 */

#include <linux/irqchip/riscv-imsic.h>
#include <linux/irqdomain.h>
#include <linux/pci.h>
#include <linux/rasd.h>
#include <asm/csr.h>
#include <asm/sbi.h>

#include "isbdmex.h"
#include "isbdm_rasd_horrors.h"

struct rasd_hgei_control {
	struct isbdm *ii;
	int cpu;
};

static DEFINE_PER_CPU(struct rasd_hgei_control, rasd_hgei);
static int hgei_parent_irq;

/* Find the physical address of a virtual interrupt file for a given CPU. */
static phys_addr_t get_imsic_guest_interrupt_file(int cpu, int guest_file)
{
	const struct imsic_global_config *imsic = imsic_get_global_config();
	struct imsic_local_config *local;

	if (!imsic) {
		pr_warn("%s: Failed to get IMSIC\n", __func__);
		return 0;
	}

	if (guest_file >= BIT(imsic->guest_index_bits)) {
		pr_warn("%s: Requested guest file %d, out of range %lu",
			__func__, guest_file, BIT(imsic->guest_index_bits));

		return 0;
	}

	local = per_cpu_ptr(imsic->local, cpu);
	/* The extra 1 skips over the physical supervisor page. */
	return local->msi_pa + ((guest_file + 1) << IMSIC_MMIO_PAGE_SHIFT);
}

/*
 * The initial version of RASD needs to give the host a way to send interrupts
 * to Sentinel, ideally with minimal hardware changes. Since virtualization is
 * not in the mix, steal IMSIC guest interrupt files and map the doorbell pages'
 * IOVAs to those guest interrupt files.
 */
static int rasd_map_imsic_pages(struct isbdm *ii)
{
	struct iommu_domain *domain = iommu_get_domain_for_dev(&ii->pdev->dev);
	int cpu;
	int i;
	int ifile;
	unsigned long iova;
	phys_addr_t imsic_page;
	int ret;

	ii->cpu_count = num_online_cpus();
	ii->ifiles_per_cpu = RASD_APP_DOORBELL_PAGES / ii->cpu_count;
	if (ii->cpu_count * ii->ifiles_per_cpu != RASD_APP_DOORBELL_PAGES)
		ii->ifiles_per_cpu++;

	/*
	 * Map the 16 doorbell pages in the control BAR, plus the admin queue.
	 */
	WARN_ON(RASD_AWQ_DRBL_PAGE(RASD_APP_DOORBELL_PAGES) != RASD_ADM_Q_DRBL);

	iova = RASD_CONTROL_BAR_IOVA + RASD_AWQ_DRBL_0_PAGE;
	cpu = 0;
	ifile = 0;
	for (i = 0; i < RASD_APP_DOORBELL_PAGES + 1; i++) {
		imsic_page = get_imsic_guest_interrupt_file(cpu, ifile);
		if (imsic_page == 0) {
			dev_err(&ii->pdev->dev,
				"Failed to get IMSIC guest interrupt file %d for CPU %d\n",
				ifile,
				cpu);

			goto unmap_pages;
		}

		ret = iommu_map(domain, iova, imsic_page,
				RASD_DRBL_PAGE_SIZE,
				IOMMU_READ | IOMMU_WRITE | IOMMU_MMIO,
				GFP_KERNEL);

		if (ret) {
			dev_err_probe(&ii->pdev->dev, ret,
					"Failed to map doorbell page at %llx",
					(unsigned long long)iova);

			goto unmap_pages;
		}

		iova += RASD_DRBL_PAGE_SIZE;
		ifile++;
		if (ifile == ii->ifiles_per_cpu) {
			ifile = 0;
			cpu++;
		}
	}

	return 0;

unmap_pages:
	iommu_unmap(domain,
		    RASD_CONTROL_BAR_IOVA + RASD_AWQ_DRBL_0_PAGE,
		    iova - RASD_CONTROL_BAR_IOVA + RASD_AWQ_DRBL_0_PAGE);

	return ret;
}

/* Change VGEIN to the given value, and return the old value. */
static unsigned long select_vgein(unsigned long ifile)
{
	unsigned long old_hstatus = csr_read(CSR_HSTATUS);
	unsigned long new_hstatus = old_hstatus & ~HSTATUS_VGEIN;

	new_hstatus |= ifile << HSTATUS_VGEIN_SHIFT;
	csr_write(CSR_HSTATUS, new_hstatus);
	return old_hstatus;
}

/* Interrupt handler for Guest External interrupts. */
static irqreturn_t rasd_hgei_interrupt(int irq, void *dev_id)
{
	int i;
	unsigned long hgei_mask;
	unsigned long old_hstatus;
	unsigned long topi;
	struct rasd_hgei_control *hgctrl = dev_id;
	struct isbdm *ii = hgctrl->ii;
	uint32_t q_num;

	hgei_mask = csr_read(CSR_HGEIP) & csr_read(CSR_HGEIE);
	old_hstatus = csr_read(CSR_HSTATUS);
	for (i = 1; (i < 6) && hgei_mask; i++) {
		if (!(hgei_mask & BIT(i)))
			continue;

		hgei_mask &= ~BIT(i);
		select_vgein(i);
		while ((topi = csr_swap(CSR_VSTOPEI, 0))) {
			topi >>= TOPI_IID_SHIFT;

			/*
			 * There are 64 interrupts per ifile (numbered 64-127),
			 * N interrupt files per cpu (numbered 1 to N), and M
			 * cpus.
			 */
			q_num = ((hgctrl->cpu * ii->ifiles_per_cpu) +
				 (i - 1)) * 64 + (topi - 64);

			dev_info(&ii->pdev->dev,
				 "Incoming host interrupt %d (irq %lx, cpu %d, ifile %d)\n",
				 q_num, topi, hgctrl->cpu, i);
		}
	}

	csr_write(CSR_HSTATUS, old_hstatus);
	return IRQ_HANDLED;
}

/* Function that runs on each CPU to set up guest interrupt files. */
static void rasd_enable_guest_interrupts(struct isbdm *ii)
{
	int cpu = smp_processor_id();
	unsigned long old_hstatus;
	unsigned long mie, hgeie;
	int ifile;
	int ifile_count = ii->ifiles_per_cpu;
	int ret;

	/* Weird discontiguous configurations are not expected. */
	if (WARN_ON(cpu >= ii->cpu_count))
		return;

	/* Account for the admin queue as well on the last CPU */
	if (cpu == ii->cpu_count - 1)
		ifile_count++;

	old_hstatus = csr_read(CSR_HSTATUS);
	hgeie = csr_read(CSR_HGEIE);

	/* Enable interrupts 64-127 on each guest interrupt file in use. */
	for (ifile = 0; ifile < ifile_count; ifile++) {
		/* Select the guest interrupt file. */
		select_vgein(ifile + 1);

		/*
		 * Enable a cool 64 interrupts. Use the second qword for
		 * convenience (as we need 64 and irq 0 is never valid).
		 */
		vimsic_csr_write(IMSIC_EIP0 + 2, 0);
		vimsic_csr_write(IMSIC_EIE0 + 2, 0xFFFFFFFFFFFFFFFF);

		/* Enable this virtual guest. */
		vimsic_csr_write(IMSIC_EITHRESHOLD, IMSIC_ENABLE_EITHRESHOLD);
		vimsic_csr_write(IMSIC_EIDELIVERY, IMSIC_ENABLE_EIDELIVERY);
		hgeie |= 1 << (ifile + 1);
	}

	csr_write(CSR_HSTATUS, old_hstatus);
	/* Enable guest interrupts in HS mode. */
	csr_write(CSR_HGEIE, hgeie);

	/* Enable per-CPU SGEI interrupt */
	enable_percpu_irq(ii->hgei_irq, irq_get_trigger_type(ii->hgei_irq));
	csr_set(CSR_HIE, BIT(IRQ_S_GEXT));
}

/*
 * Enable interrupts on all the guest interrupt files in use, and enable virtual
 * guest interrupts in general.
 */
static int rasd_setup_guest_interrupts(struct isbdm *ii)
{
	int cpu, rc;
	struct irq_domain *domain;
	struct rasd_hgei_control *hgctrl;

	/* Initialize per-CPU guest external interrupt line management */
	for_each_possible_cpu(cpu) {
		hgctrl = per_cpu_ptr(&rasd_hgei, cpu);
		hgctrl->ii = ii;
		hgctrl->cpu = cpu;
	}

	/* Find INTC irq domain */
	domain = irq_find_matching_fwnode(riscv_get_intc_hwnode(),
					  DOMAIN_BUS_ANY);
	if (!domain) {
		dev_err_probe(&ii->pdev->dev, -ENOENT,
			      "unable to find INTC domain\n");

		return -ENOENT;
	}

	/* Map per-CPU SGEI interrupt from INTC domain */
	ii->hgei_irq = irq_create_mapping(domain, IRQ_S_GEXT);
	if (!ii->hgei_irq) {
		dev_err_probe(&ii->pdev->dev, -ENOMEM,
			      "unable to map SGEI IRQ\n");

		return -ENOMEM;
	}

	hgei_parent_irq = ii->hgei_irq;
	rc = request_percpu_irq(ii->hgei_irq, rasd_hgei_interrupt,
				"isbdm-rasd-gei", &rasd_hgei);

	if (rc) {
		dev_err_probe(&ii->pdev->dev, rc,
			      "failed to request SGEI IRQ. Is KVM enabled?\n");

		return rc;
	}

	on_each_cpu((smp_call_func_t)rasd_enable_guest_interrupts, ii, 1);
	return 0;
}

static int rasd_setup_control_bar(struct isbdm *ii)
{
	struct iommu_domain *domain = iommu_get_domain_for_dev(&ii->pdev->dev);
	int ret;

	/* Create the control BAR page and map it for the device. */
	ii->rasd_control = (void *)get_zeroed_page(GFP_KERNEL);
	if (!ii->rasd_control) {
		dev_err(&ii->pdev->dev, "Failed to get RASD control page");
		return -ENOMEM;
	}

	ret = iommu_map(domain, RASD_CONTROL_BAR_IOVA,
			virt_to_phys((unsigned long *)ii->rasd_control),
			PAGE_SIZE, IOMMU_READ | IOMMU_WRITE | IOMMU_MMIO,
			GFP_KERNEL);

	if (ret) {
		dev_err_probe(&ii->pdev->dev, ret,
			      "Failed to map RASD control BAR");

		goto free_control_page;
	}

	ret = rasd_map_imsic_pages(ii);
	if (ret)
		goto unmap_control_page;

	ret = rasd_setup_guest_interrupts(ii);
	if (ret)
		goto unmap_imsic_pages;

	return 0;

unmap_imsic_pages:
	iommu_unmap(domain, RASD_CONTROL_BAR_IOVA + RASD_AWQ_DRBL_0_PAGE,
		    RASD_DRBL_PAGE_SIZE * (RASD_APP_DOORBELL_PAGES + 1));

unmap_control_page:
	iommu_unmap(domain, RASD_CONTROL_BAR_IOVA, PAGE_SIZE);

free_control_page:
	free_page((unsigned long)ii->rasd_control);
	ii->rasd_control = NULL;
	return ret;
}

/*
 * Set up translations for the known IOVAs that ISBDM produces when ferrying
 * RASD host BAR accesses across.
 */
int isbdm_map_rasd_regions(struct isbdm *ii)
{
	struct iommu_domain *domain = iommu_get_domain_for_dev(&ii->pdev->dev);
	int ret;

	if (!domain) {
		dev_err(&ii->pdev->dev, "Cannot get IOMMU domain");
		return -ENODEV;
	}

	ret = rasd_setup_control_bar(ii);
	if (ret)
		return ret;

	/* Map the DDR BAR. */
	/* TODO: Get the base and size of memory. */
	ret = iommu_map(domain, RASD_DDR_BAR_IOVA, 0x80000000,
			RASD_DDR_BAR_SIZE, IOMMU_READ | IOMMU_WRITE,
			GFP_KERNEL);

	if (ret) {
		dev_err_probe(&ii->pdev->dev, ret,
			      "Failed to map RASD control BAR");

		goto teardown_control_bar;
	}

	/* Map the HBM BAR. */
	/* TODO: Get the base and size of HBM. */
	ret = iommu_map(domain, RASD_HBM_BAR_IOVA, 0x80000000,
			RASD_HBM_BAR_SIZE, IOMMU_READ | IOMMU_WRITE,
			GFP_KERNEL);

	if (ret) {
		dev_err_probe(&ii->pdev->dev, ret,
			      "Failed to map RASD control BAR");

		goto unmap_ddr_bar;
	}

	return 0;

unmap_ddr_bar:
	iommu_unmap(domain, RASD_DDR_BAR_IOVA, RASD_DDR_BAR_SIZE);

teardown_control_bar:
	isbdm_free_rasd_control(ii);
	return ret;
}

void isbdm_free_rasd_control(struct isbdm *ii)
{
	struct iommu_domain *domain = iommu_get_domain_for_dev(&ii->pdev->dev);

	/* Unmap the app doorbells. */
	iommu_unmap(domain, RASD_CONTROL_BAR_IOVA + RASD_AWQ_DRBL_0_PAGE,
		    RASD_DRBL_PAGE_SIZE * (RASD_APP_DOORBELL_PAGES + 1));

	/* Unmap the regular memory */
	iommu_unmap(domain, RASD_CONTROL_BAR_IOVA, PAGE_SIZE);
	if (ii->rasd_control) {
		free_page((unsigned long)ii->rasd_control);
		ii->rasd_control = NULL;
	}
}

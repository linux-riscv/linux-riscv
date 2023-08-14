/*
 * ISBDM Sentinel glue needed to make RASD work.
 *
 * SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * 2023-Aug-11 Evan Green <evan@rivosinc.com>
 */

#include <linux/pci.h>
#include <linux/rasd.h>
#include <linux/irqchip/riscv-imsic.h>

#include "isbdmex.h"
#include "isbdm_rasd_horrors.h"

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

printk("EVAN mapped imsic pages!!!");
	return 0;

unmap_pages:
	iommu_unmap(domain,
		    RASD_CONTROL_BAR_IOVA + RASD_AWQ_DRBL_0_PAGE,
		    iova - RASD_CONTROL_BAR_IOVA + RASD_AWQ_DRBL_0_PAGE);

	return ret;
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

	return 0;

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

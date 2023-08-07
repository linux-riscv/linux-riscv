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

#include "isbdmex.h"
#include "isbdm_rasd_horrors.h"

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

	/* Map the DDR BAR. */
	/* TODO: Get the base and size of memory. */
	ret = iommu_map(domain, RASD_DDR_BAR_IOVA, 0x80000000,
			RASD_DDR_BAR_SIZE, IOMMU_READ | IOMMU_WRITE,
			GFP_KERNEL);

	if (ret) {
		dev_err_probe(&ii->pdev->dev, ret,
			      "Failed to map RASD control BAR");

		goto unmap_control_bar;
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

unmap_control_bar:
	iommu_unmap(domain, RASD_CONTROL_BAR_IOVA, PAGE_SIZE);

free_control_page:
	isbdm_free_rasd_control(ii);
	return ret;
}

void isbdm_free_rasd_control(struct isbdm *ii)
{
	if (ii->rasd_control) {
		free_page((unsigned long)ii->rasd_control);
		ii->rasd_control = NULL;
	}
}

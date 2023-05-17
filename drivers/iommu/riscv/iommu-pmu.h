// SPDX-License-Identifier: GPL-2.0-only
/*
 * IOMMU API for RISC-V architected Ziommu implementations.
 *
 * Copyright © 2023 Rivos Inc.
 *
 * Authors
 *  Pranoy Dutta <prydt@rivosinc.com>
 */
#ifndef RIVOS_IOMMU_PMU_H
#define RIVOS_IOMMU_PMU_H
#include <linux/perf_event.h>

struct riscv_iommu_pmu {
	struct pmu pmu;
	struct riscv_iommu_device *iommu_dev;
};

int iommu_pmu_register(struct riscv_iommu_pmu *iommu_pmu);
void iommu_pmu_unregister(struct riscv_iommu_pmu *iommu_pmu);

#endif

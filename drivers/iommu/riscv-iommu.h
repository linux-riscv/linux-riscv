/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright © 2021-2022, Rivos Inc.
 *
 * RISC-V Ziommu - IOMMU Interface Specification.
 *
 * Authors: Tomasz Jeznach <tjeznach@rivosinc.com>
 *
 */

#ifndef _RISCV_IOMMU_H_
#define _RISCV_IOMMU_H_

#include <linux/types.h>
#include <linux/iova.h>
#include <linux/io.h>
#include <linux/idr.h>
#include <linux/mmu_notifier.h>
#include <linux/list.h>
#include <linux/iommu.h>

#include "riscv-iommu-bits.h"

struct riscv_iommu {
	void __iomem *reg;	/* virtual address of IOMMU hardware register set */
	u64 reg_phys;		/* physical address of hardware register set */
	u64 reg_size;		/* register set length */
	u64 cap;		/* supported and enabled hardware capabilities */

	unsigned long zero;	/* shared zeroed page */
	unsigned long ddtp;	/* device directory root pointer */
	unsigned long sync;	/* Notification page */
	int ddt_mode;
	bool dc_format32;	/* device context entry format */

	/* instruction queue */
	spinlock_t cq_lock;
	struct riscv_iommu_command *cq;
	unsigned cq_mask;
	unsigned cq_tail;
	int cq_irq;


	/* fault queue */
	struct riscv_iommu_event *fq;
	unsigned fq_mask;
	int fq_irq;

	/* page request queue */
	struct riscv_iommu_page_request *pq;
	struct iopf_queue *pq_work;
	unsigned pq_mask;
	int pq_irq;

	/* general global lock */
	struct mutex lock;

	/* core iommu interface and system device */
	struct iommu_device iommu;
	struct device *dev;
};

struct riscv_iommu_domain {
	struct iommu_domain domain;
	struct mutex lock;
	struct list_head endpoints;
	struct riscv_iommu_msipte *msi_root;
	pgd_t *pgd_root;
	unsigned gscid;
	bool g_stage;
};

/* translation context devid:pasid */
struct riscv_iommu_endpoint {
	struct device *dev;
	struct riscv_iommu *iommu;
	struct list_head g_list;
	struct list_head s_list;
	struct riscv_iommu_dc *dc;
	struct riscv_iommu_pc *pc;
	struct list_head regions;	// msi list
	struct list_head bindings;	// sva list
	unsigned device_id;		// shall
	unsigned pasid_bits;	/* 0: pasid disabled */
	unsigned pasid_feat;
	ioasid_t pscid;
	bool sva_enabled;
};

#endif

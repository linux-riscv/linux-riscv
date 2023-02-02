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

#include "iommu-bits.h"

struct riscv_iommu_queue {
	dma_addr_t base_dma;
	void *base;
	u32 len;		/* single item length */
	u32 cnt;		/* items count */
	u32 lui;		/* last used index, consumer/producer share */
	u32 qbr;		/* queue base register offset */
	u32 qcr;		/* queue control and status register offset */
	int irq;		/* registered interrupt number */
};

struct riscv_iommu_device {
	void __iomem *reg;	/* virtual address of IOMMU hardware register set */
	u64 reg_phys;		/* physical address of hardware register set */
	u64 reg_size;		/* register set length */
	u64 cap;		/* supported and enabled hardware capabilities */

	unsigned long zero;	/* shared zeroed page */
	unsigned long ddtp;	/* device directory root pointer */
	unsigned long sync;	/* Notification page */
	int ddt_mode;
	bool dc_format32;	/* device context entry format */

	/* page request queue */
	struct iopf_queue *pq_work;

	/* instruction queue */
	spinlock_t cq_lock;

	/* hardware ring buffers */
	struct riscv_iommu_queue cmdq;
	struct riscv_iommu_queue fltq;
	struct riscv_iommu_queue priq;

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
	struct riscv_iommu_device *iommu;
	struct list_head g_list;
	struct list_head s_list;
	struct riscv_iommu_dc *dc;
	struct riscv_iommu_pc *pc;
	struct list_head regions;
	struct list_head bindings;
	unsigned device_id;
	unsigned pasid_bits;	/* 0: pasid disabled */
	unsigned pasid_feat;
	ioasid_t pscid;
	bool sva_enabled;
};

/* Helper functions and macros */

static inline u32 riscv_iommu_readl(struct riscv_iommu_device *iommu,
				    unsigned offset)
{
	return readl_relaxed(iommu->reg + offset);
}

static inline void riscv_iommu_writel(struct riscv_iommu_device *iommu,
				      unsigned offset, u32 val)
{
	writel_relaxed(val, iommu->reg + offset);
}

static inline u64 riscv_iommu_readq(struct riscv_iommu_device *iommu,
				    unsigned offset)
{
	return readq_relaxed(iommu->reg + offset);
}

static inline void riscv_iommu_writeq(struct riscv_iommu_device *iommu,
				      unsigned offset, u64 val)
{
	writeq_relaxed(val, iommu->reg + offset);
}

#endif

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright © 2022-2023 Rivos Inc.
 * Copyright © 2023 FORTH-ICS/CARV
 *
 * RISC-V IOMMU Interface Specification.
 *
 * Authors
 *	Tomasz Jeznach <tjeznach@rivosinc.com>
 *	Nick Kossifidis <mick@ics.forth.gr>
 */

#ifndef _RISCV_IOMMU_H_
#define _RISCV_IOMMU_H_

#include <linux/types.h>
#include <linux/iova.h>
#include <linux/io.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/iommu.h>
#include <linux/io-pgtable.h>

#include "iommu-bits.h"

struct riscv_iommu_device {
	struct iommu_device iommu;	/* iommu core interface */
	struct device *dev;		/* iommu hardware */

	/* hardware control register space */
	void __iomem *reg;
	resource_size_t reg_phys;

	/* IRQs for the various queues */
	int irq_cmdq;
	int irq_fltq;
	int irq_pm;
	int irq_priq;

	/* supported and enabled hardware capabilities */
	u64 cap;

	/* global lock, to be removed */
	spinlock_t cq_lock;

	/* device directory table root pointer and mode */
	unsigned long ddtp;
	unsigned int ddt_mode;
	bool ddtp_in_iomem;

	/* Connected end-points */
	struct rb_root eps;
	struct mutex eps_mutex;	/* protects eps access */

#ifdef CONFIG_RISCV_IOMMU_DEBUGFS
	/* DebugFS Info */
	struct dentry *debugfs;
#endif
};

struct riscv_iommu_domain {
	struct iommu_domain domain;

	struct list_head endpoints;
	struct mutex lock;	/* protects domain attach/detach */
	struct riscv_iommu_device *iommu;

	unsigned int mode;	/* RIO_ATP_MODE_* enum */
	unsigned int pscid;	/* RISC-V IOMMU PSCID */

	pgd_t *pgd_root;	/* page table root pointer */
};

/* Private dev_iommu_priv object, device-domain relationship. */
struct riscv_iommu_endpoint {
	struct device *dev;			/* platform or PCI endpoint device */
	unsigned int devid;			/* PCI bus:device:function number */
	unsigned int domid;			/* PCI domain number, segment */
	struct rb_node node;			/* device tracking node (lookup by devid) */
	struct riscv_iommu_device *iommu;	/* parent iommu device */

	struct mutex lock;			/* protects domain attach/detach */
	struct list_head domain;		/* endpoint attached managed domain */
};

/* Helper functions and macros */

static inline u32 riscv_iommu_readl(struct riscv_iommu_device *iommu,
				    unsigned int offset)
{
	return readl_relaxed(iommu->reg + offset);
}

static inline void riscv_iommu_writel(struct riscv_iommu_device *iommu,
				      unsigned int offset, u32 val)
{
	writel_relaxed(val, iommu->reg + offset);
}

static inline u64 riscv_iommu_readq(struct riscv_iommu_device *iommu,
				    unsigned int offset)
{
#ifdef CONFIG_64BIT
	return readq_relaxed(iommu->reg + offset);
#else
	u32 low, high;

	low = readl_relaxed(iommu->reg + offset);
	high = readl_relaxed(iommu->reg + offset + sizeof(u32));
	return low | ((u64)high << 32);
#endif
}

static inline void riscv_iommu_writeq(struct riscv_iommu_device *iommu,
				      unsigned int offset, u64 val)
{
#ifdef CONFIG_64BIT
	writeq_relaxed(val, iommu->reg + offset);
#else
	/* IOMMU 64-bit register access updates high-half first */
	writel_relaxed(val >> 32, iommu->reg + offset + sizeof(u32));
	writel_relaxed(val, iommu->reg + offset);
#endif
}

int riscv_iommu_init(struct riscv_iommu_device *iommu);
void riscv_iommu_remove(struct riscv_iommu_device *iommu);

#ifdef CONFIG_RISCV_IOMMU_DEBUGFS
void riscv_iommu_debugfs_setup(struct riscv_iommu_device *iommu);
#endif

#endif

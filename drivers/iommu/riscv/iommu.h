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
#include <linux/mmu_notifier.h>
#include <linux/list.h>
#include <linux/iommu.h>
#include <linux/io-pgtable.h>
#include <linux/mmu_notifier.h>
#include <linux/perf_event.h>

#include "iommu-bits.h"
#include "../iommu-sva.h"

enum riscv_iommu_queue_type {
	RISCV_IOMMU_FAULT_QUEUE,
	RISCV_IOMMU_COMMAND_QUEUE,
	RISCV_IOMMU_PAGE_REQUEST_QUEUE,
};

#define IOMMU_PAGE_SIZE_4K     BIT_ULL(12)
#define IOMMU_PAGE_SIZE_2M     BIT_ULL(21)
#define IOMMU_PAGE_SIZE_1G     BIT_ULL(30)
#define IOMMU_PAGE_SIZE_512G   BIT_ULL(39)

struct riscv_iommu_queue {
	dma_addr_t base_dma;	/* ring buffer bus address */
	void *base;		/* ring buffer pointer */
	unsigned int qbr;	/* queue base register offset */
	unsigned int qcr;	/* queue control and status register offset */
	size_t len;		/* single item length */
	u32 cnt;		/* items count */
	u32 lui;		/* last used index, consumer/producer share */
	int irq;		/* registered interrupt number */
	bool in_iomem;		/* indicates queue data are in I/O memory  */
};

struct riscv_iommu_device {
	struct iommu_device iommu;	/* iommu core interface */
	struct device *dev;		/* iommu hardware */

	/* hardware control register space */
	void __iomem *reg;
	resource_size_t reg_phys;

	/* IRQs for the various queues */
	int irqs[RISCV_IOMMU_INTR_COUNT];
	int irqs_count;

	/* hardware queues */
	struct riscv_iommu_queue fltq;
	struct riscv_iommu_queue cmdq;
	struct riscv_iommu_queue priq;

	/* supported and enabled hardware capabilities */
	u64 cap;

	/* global lock, to be removed */
	spinlock_t cq_lock;

	/* device directory table root pointer and mode */
	unsigned long ddtp;
	unsigned int ddt_mode;
	bool ddtp_in_iomem;

	/* I/O page fault queue */
	struct iopf_queue *pq_work;

	/* Connected end-points */
	struct rb_root eps;
	struct mutex eps_mutex;	/* protects eps access */

#ifdef CONFIG_RISCV_IOMMU_DEBUGFS
	/* DebugFS Info */
	struct dentry *debugfs;
#endif

	/* Performance Monitoring */
	struct pmu pmu;
	unsigned long counters_used;
};

struct riscv_iommu_domain {
	struct iommu_domain domain;
	struct io_pgtable pgtbl;

	struct list_head endpoints;
	struct list_head notifiers;
	struct mutex lock;	/* protects domain attach/detach */
	struct mmu_notifier mn;
	struct riscv_iommu_device *iommu;

	bool is_32bit;		/* SXL/GXL 32-bit modes enabled */
	unsigned int mode;	/* RIO_ATP_MODE_* enum */
	unsigned int pscid;	/* RISC-V IOMMU PSCID / GSCID */
	ioasid_t pasid;		/* IOMMU_DOMAIN_SVA: Cached PASID */
	bool g_stage;		/* 2nd stage translation domain */

	pgd_t *pgd_root;	/* page table root pointer */
};

/* Private dev_iommu_priv object, device-domain relationship. */
struct riscv_iommu_endpoint {
	struct device *dev;			/* platform or PCI endpoint device */
	unsigned int devid;			/* PCI bus:device:function number */
	unsigned int domid;			/* PCI domain number, segment */
	struct rb_node node;			/* device tracking node (lookup by devid) */
	struct riscv_iommu_dc *dc;		/* device context pointer */
	struct riscv_iommu_pc *pc;		/* process context root, valid if pasid_enabled is true */
	struct riscv_iommu_device *iommu;	/* parent iommu device */
	struct riscv_iommu_msi_pte *msi_root;	/* interrupt re-mapping */

	struct mutex lock;			/* protects domain attach/detach */
	struct list_head domain;		/* endpoint attached managed domain */
	struct list_head regions;		/* reserved regions, interrupt remapping window */

	/* end point info bits */
	unsigned int pasid_bits;
	unsigned int pasid_feat;
	bool pasid_enabled;
	bool ir_enabled;
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

int riscv_iommu_pmu_register(struct riscv_iommu_device *iommu);
void riscv_iommu_pmu_unregister(struct riscv_iommu_device *iommu);

#endif

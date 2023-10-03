/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Rivos DPA device driver
 *
 * Copyright (C) 2022-2023 Rivos Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _DPA_DRM_H_
#define _DPA_DRM_H_

#include <linux/completion.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/wait.h>

#include <drm/drm.h>
#include <drm/drm_device.h>
#include <drm/drm_dpa.h>

#include "dpa_daffy.h"

#define PCI_VENDOR_ID_RIVOS         0x1efd
#define PCI_DEVICE_ID_RIVOS_DPA     0x0012

#define DPA_DB_PAGES_BASE	0x0
#define DPA_FWQ_BASE		0x11000
#define DPA_PERF_MON_BASE	0x12000
#define DPA_MSIX_CAUSE_BASE	0x13000
#define DPA_MMIO_SIZE		0x100000

#define DPA_NUM_DB_PAGES	16
#define DPA_DB_PAGE_SIZE	4096

#define DPA_FWQ_VERSION_ID		0x0
#define DPA_FWQ_QUEUE_DESCRIPTOR	0x8
#define DPA_FWQ_QUEUE_DOORBELL		0x10
#define DPA_FWQ_QUEUE_CTRL		0x18
#define DPA_FWQ_QUEUE_CTRL_ENABLE	BIT(0)
#define DPA_FWQ_QUEUE_CTRL_BUSY		BIT(1)
#define DPA_FWQ_ERROR_CODE		0x20

#define DPA_NUM_MSIX		8

struct dpa_device {
	/* big lock for device data structures */
	struct mutex lock;

	/* list of processes using device */
	//struct list *plist;
	struct device *dev;
	struct pci_dev			*pdev;
	struct drm_device		ddev;

	void __iomem *regs;

	int base_irq;

	/* List of active DPA processes */
	struct mutex dpa_processes_lock;
	struct list_head dpa_processes;
	unsigned int dpa_process_count;

	struct dpa_daffy daffy;
};

// keep track of all allocated aql queues
struct dpa_aql_queue {
	struct list_head list;
	u32 id;
	u32 mmap_offset;
};

struct dpa_process {
	// list_head for list of processes using dpa
	struct list_head dpa_process_list;

	/* the DPA instance associated with this process */
	struct dpa_device *dev;

	struct mutex lock;

	// use this for multiple opens by same process
	struct kref ref;

	/* IOMMU Shared Virtual Address unit */
	struct iommu_sva *sva;

	/* pasid allocated to this process */
	u32 pasid;

	// aql queues
	struct list_head queue_list;

	struct page *signal_pages[DPA_DRM_MAX_SIGNAL_PAGES];
	unsigned int num_signal_pages;
	unsigned int num_signal_waiters;
	spinlock_t signal_lock;
#define SIGNAL_WQ_HASH_BITS	3
	struct wait_queue_head signal_wqs[1 << SIGNAL_WQ_HASH_BITS];

	// Start of doorbell registers in DUC MMIO
	phys_addr_t doorbell_base;
	u32 doorbell_offset;
	u32 doorbell_size;

	struct completion kill_done;
};

static inline struct dpa_device *drm_to_dpa_dev(struct drm_device *ddev)
{
	return container_of(ddev, struct dpa_device, ddev);
}

static inline u64 dpa_fwq_read(struct dpa_device *dpa, u64 offset)
{
	return readq(dpa->regs + DPA_FWQ_BASE + offset);
}

static inline void dpa_fwq_write(struct dpa_device *dpa, u64 val, u64 offset)
{
	writeq(val, dpa->regs + DPA_FWQ_BASE + offset);
}

int dpa_signal_wake(struct dpa_device *dpa, u32 pasid, u64 signal_idx);
int dpa_kill_done(struct dpa_device *dpa, u32 pasid, u32 cause);

#endif /* _DPA_DRM_H_ */

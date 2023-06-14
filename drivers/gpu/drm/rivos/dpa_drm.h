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

#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/wait.h>
#include <linux/completion.h>
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
#define DPA_FWQ_ERROR_CODE		0x20

#define DPA_NUM_MSIX		8

#define DPA_PROCESS_MAX		DPA_NUM_DB_PAGES

#define DRM_IOCTL(name)						        \
static int dpa_drm_ioctl_##name(struct drm_device *dev,			\
	void *data, struct drm_file *file)				\
{									\
	struct dpa_process *p = file->driver_priv;			\
	struct dpa_device *dpa = drm_to_dpa_dev(dev);			\
	if (!p)								\
		return -EINVAL;						\
	return dpa_ioctl_##name(p, dpa, data);				\
}									\

struct dpa_fwq {
	struct dpa_fw_queue_desc desc;
	struct dpa_fw_queue_pkt h_ring[DPA_FW_QUEUE_SIZE];
	struct dpa_fw_queue_pkt d_ring[DPA_FW_QUEUE_SIZE];
};

struct dpa_daffy {
	struct mutex lock;
	wait_queue_head_t wq;

	struct dpa_fwq *fwq;
	dma_addr_t fwq_dma_addr;
};

struct dpa_device {
	/* big lock for device data structures */
	struct mutex lock;

	/* list of processes using device */
	//struct list *plist;
	struct device *dev;
	struct pci_dev			*pdev;
	struct drm_device		ddev;

	int drm_minor;

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

	/* XXX Do these belong here? */
	struct file *drm_file;
	void *drm_priv;

	struct mutex lock;

	// use this for multiple opens by same process
	struct kref ref;

	/* mm struct of the process */
	void *mm;

	/* IOMMU Shared Virtual Address unit */
	struct iommu_sva *sva;

	/* pasid allocated to this process */
	u32 pasid;

	unsigned int alloc_count;

	// aql queues
	struct list_head queue_list;

	/* signal related */
	u64 signal_pages_va;
	struct page *signal_pages[DPA_DRM_MAX_SIGNAL_PAGES];
	unsigned int signal_pages_count;

	/* Signal waiters */
	spinlock_t signal_waiters_lock;
	struct list_head signal_waiters;

	// Start of doorbell registers in DUC MMIO
	phys_addr_t doorbell_base;
};

struct dpa_signal_waiter {
	struct list_head list;

	u64 signal_idx;
	int error;
	struct completion signal_done;
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

/* some random number for now */
#define DPA_GPU_ID (1234)

/* userspace is expecting version (10, 9, 9) for RIG64 ISA */
#define DPA_HSA_GFX_VERSION (0x100909)

/* For now let userspace allocate anything within a 47-bit address space */
#define DPA_GPUVM_ADDR_LIMIT ((1ULL << 47) - 1)

struct dpa_process *dpa_get_process_by_mm(const struct mm_struct *mm);
struct dpa_process *dpa_get_process_by_pasid(u32 pasid);
irqreturn_t daffy_handle_irq(int irq, void *dpa_dev);
irqreturn_t daffy_process_device_queue(int irq, void *dpa_dev);
void dpa_release_process(struct kref *ref);

/* offsets to MMAP calls for different things */
#define DRM_MMAP_TYPE_SHIFT (60)
#define DRM_MMAP_TYPE_DOORBELL (0x1ULL)

#endif /* _DPA_DRM_H_ */

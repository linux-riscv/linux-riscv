#ifndef _DPA_KFD_H_
#define _DPA_KFD_H_

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/iommu.h>
#include <drm/drm_gem.h>
#include <drm/drm_device.h>
#include <drm/drm_dpa.h>

#define PCI_VENDOR_ID_RIVOS         0x1efd
#define PCI_DEVICE_ID_RIVOS_DPA     0x0012

// DUC-SS register regions
#define DUC_REGS_DISPATCH			0x0000
#define DUC_REGS_INTERNAL_VF		0x0ec0
#define DUC_REGS_INTERNAL_PF		0x0f18
#define DUC_REGS_FW					0x1368
#define DUC_REGS_CTN				0x1390
#define DUC_REGS_DMA				0x13a0
#define DUC_REGS_DOORBELLS			0x2000

// Individual regs within DUC_REGS_FW region
#define DUC_REGS_FW_VER				0x1368
#define DUC_REGS_FW_PASID			0x1370
#define DUC_REGS_FW_DESC			0x1378
#define DUC_REGS_FW_DOORBELL		0x1380
#define DUC_REGS_FW_TIMESTAMP		0x1388

#define DUC_MMIO_SIZE				0x80000

#define DPA_PROCESS_MAX (16)

#define DRM_KFD_IOCTL(name)						        \
static int dpa_drm_ioctl_##name(struct drm_device *dev, 	        \
	void *data, struct drm_file *file)				\
{									\
	struct dpa_kfd_process *p = file->driver_priv;			\
	if (!p)								\
		return -EINVAL;						\
	struct dpa_device* dpa = drm_to_dpa_dev(dev);			\
	return dpa_ioctl_##name(p, dpa, data);				\
}									\
static int dpa_kfd_ioctl_##name(struct file *filep,			\
                                struct dpa_kfd_process *p, void *data)	\
{									\
	struct dpa_device* dpa = p->dev;				\
	return dpa_ioctl_##name(p, dpa, data);				\
}									\

// contains info about the queue to fw
struct dpa_fwq_info {

	// one page allocated for queue to fw
	struct dpa_fw_queue_desc *fw_queue;

	// convinience pointers to the rings
	struct dpa_fw_queue_pkt *h_ring;
	struct dpa_fw_queue_pkt *d_ring;

	// dma address of the q
	dma_addr_t fw_queue_dma_addr;
	// XXX lock? use big lock?
	// XXX need to add wait event if q is full
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

	volatile char *regs;

	struct dpa_fwq_info qinfo;
};

// keep track of all allocated aql queues
struct dpa_aql_queue {
	struct list_head list;
	u32 id;
	u32 mmap_offset;
};

struct dpa_kfd_process {
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

	unsigned alloc_count;

	// maintain a list of allocations in vram
	struct list_head buffers;

	// event stuff
	u64 *event_page;
	struct idr event_idr;
	struct list_head event_list;

	// aql queues
	struct list_head queue_list;

	// Start of doorbell registers in DUC MMIO
	phys_addr_t doorbell_base;
};

// tracks buffers -- especially vram allocations
struct dpa_kfd_buffer {
	struct list_head process_alloc_list;

	struct drm_gem_object gobj;

	unsigned int id;
	unsigned int type;

	u64 size;
	unsigned page_count;
	struct page **pages;

	struct dpa_kfd_process *p;
};

#define gem_to_dpa_buf(gobj) container_of((gobj), struct dpa_kfd_buffer, gobj)

static inline struct dpa_device *drm_to_dpa_dev(struct drm_device *ddev)
{
	return container_of(ddev, struct dpa_device, ddev);
}

typedef int kfd_ioctl_t(struct file *filep, struct dpa_kfd_process *process,
			void *data);

struct kfd_ioctl_desc {
	unsigned int cmd;
	int flags;
	kfd_ioctl_t *func;
	unsigned int cmd_drv;
	const char *name;
};

/* some random number for now */
#define DPA_GPU_ID (1234)

/* userspace is expecting version (10, 9, 9) for RIG64 ISA */
#define DPA_HSA_GFX_VERSION (0x10909)

/* For now let userspace allocate anything within a 47-bit address space */
#define DPA_GPUVM_ADDR_LIMIT ((1ULL << 47) - 1)

/* Size of a doorbell page */
#define DPA_DOORBELL_PAGE_SIZE (PAGE_SIZE)

/* just one page max for signals right now */
#define DPA_MAX_EVENT_PAGE_SIZE (PAGE_SIZE)

/* per process max on signals based on a page */
#define DPA_MAX_SIGNAL_EVENTS (PAGE_SIZE / sizeof(u64))

#define KFD_EVENT_TIMEOUT_IMMEDIATE 0
#define KFD_EVENT_TIMEOUT_INFINITE 0xFFFFFFFFu

/* HSA Event types */
#define KFD_EVENT_TYPE_SIGNAL (0)
#define KFD_EVENT_TYPE_HW_EXCEPTION (3)
#define KFD_EVENT_TYPE_DEBUG (5)
#define KFD_EVENT_TYPE_MEMORY (8)

/* mostly a copy of what's in amdgpu struct kfd_event */
struct dpa_kfd_event {
	unsigned id;
	int type;
	spinlock_t lock;
	wait_queue_head_t wq;
	bool auto_reset;
	bool signaled;

	struct list_head events;
};

/* copy from kfd_event */
struct dpa_kfd_event_waiter {
	wait_queue_entry_t wait;
	struct dpa_kfd_event *event; /* Event to wait for */
	bool activated;		 /* Becomes true when event is signaled */
};

/* offsets to MMAP calls for different things */
#define KFD_MMAP_TYPE_SHIFT (60)
#define KFD_MMAP_TYPE_DOORBELL (0x1ULL)
#define KFD_MMAP_TYPE_EVENTS (0x2ULL)

// temporary until DRM/GEM
#define KFD_MMAP_TYPE_VRAM (0x0ULL)

#define KFD_GPU_ID_HASH_WIDTH (4)
#define KFD_MMAP_GPU_ID_SHIFT (48)
#define KFD_MMAP_GPU_ID_MASK ((1ULL << KFD_GPU_ID_HASH_WIDTH) - 1) \
				<< KFD_MMAP_GPU_ID_SHIFT)

#define KFD_MMAP_GET_GPU_ID(offset) (((offset) >> KFD_MMAP_GPU_ID_SHIFT) & \
				     (KFD_GPU_ID_HASH_WIDTH - 1))

#endif /* _DPA_KFD_H_ */

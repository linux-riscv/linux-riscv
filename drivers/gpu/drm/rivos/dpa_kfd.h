#ifndef _DPA_KFD_H_
#define _DPA_KFD_H_

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/iommu.h>
#include <linux/wait.h>
#include <drm/drm.h>
#include <drm/drm_gem.h>
#include <drm/drm_device.h>
#include <drm/drm_dpa.h>
#include <drm/drm_buddy.h>

#define PCI_VENDOR_ID_RIVOS         0x1efd
#define PCI_DEVICE_ID_RIVOS_DPA     0x0012

// DUC-SS register regions
#define DUC_REGS_DISPATCH			0x0000
#define DUC_REGS_INTERNAL_VF		0x0940
#define DUC_REGS_QL_SYNC			0x0980
#define DUC_REGS_INTERNAL_PF		0x0b80
#define DUC_REGS_FW					0x0fd0
#define DUC_REGS_CTN				0x1008
#define DUC_REGS_DMA				0x1018
#define DUC_REGS_DOORBELLS			0x2000

// Individual regs within DUC_REGS_FW region
#define DUC_REGS_FW_VER				0x0fd0
#define DUC_REGS_FW_PASID			0x0fd8
#define DUC_REGS_FW_DESC			0x0fe0
#define DUC_REGS_FW_DOORBELL		0x0fe8
#define DUC_REGS_FW_TIMESTAMP		0x1000

#define DUC_PAGE_SIZE           (1 << 12)
#define DUC_NUM_MSIX_INTERRUPTS	8

#define DUC_REGS_MSIX_CAUSE_START       (18 * DUC_PAGE_SIZE)
#define DUC_REGS_MSIX_CAUSE_END			\
	(DUC_REGS_MSIX_CAUSE_START + DUC_NUM_MSIX_INTERRUPTS)
#define DUC_REGS_MSIX                   (19 * DUC_PAGE_SIZE)

#define DUC_MMIO_SIZE				0x80000

#define DPA_PROCESS_MAX (16)

#define DRM_IOCTL(name)						        \
static int dpa_drm_ioctl_##name(struct drm_device *dev,			\
	void *data, struct drm_file *file)				\
{									\
	struct dpa_kfd_process *p = file->driver_priv;			\
	struct dpa_device* dpa = drm_to_dpa_dev(dev);			\
	if (!p)								\
		return -EINVAL;						\
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

	u64 hbm_size;
	u64 hbm_base;
	void *hbm_va;
	/* list of processes using device */
	//struct list *plist;
	struct device *dev;
	struct pci_dev			*pdev;
	struct drm_device		ddev;

	struct drm_buddy mm;
	struct mutex mm_lock;

	int drm_minor;

	void __iomem *regs;

	int base_irq;
	wait_queue_head_t wq;

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

	// aql queues
	struct list_head queue_list;

	/* signal related */
	u64 signal_pages_va;
	struct page *signal_pages[DPA_DRM_MAX_SIGNAL_PAGES];
	unsigned signal_pages_count;

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

	struct list_head blocks;

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
#define DPA_HSA_GFX_VERSION (0x100909)

/* For now let userspace allocate anything within a 47-bit address space */
#define DPA_GPUVM_ADDR_LIMIT ((1ULL << 47) - 1)

/* Size of a doorbell page */
#define DPA_DOORBELL_PAGE_SIZE (PAGE_SIZE)

irqreturn_t handle_daffy(int irq, void *dpa_dev);

/* offsets to MMAP calls for different things */
#define KFD_MMAP_TYPE_SHIFT (60)
#define KFD_MMAP_TYPE_DOORBELL (0x1ULL)

// temporary until DRM/GEM
#define KFD_MMAP_TYPE_VRAM (0x0ULL)

#define KFD_GPU_ID_HASH_WIDTH (4)
#define KFD_MMAP_GPU_ID_SHIFT (48)
#define KFD_MMAP_GPU_ID_MASK ((1ULL << KFD_GPU_ID_HASH_WIDTH) - 1) \
				<< KFD_MMAP_GPU_ID_SHIFT)

#define KFD_MMAP_GET_GPU_ID(offset) (((offset) >> KFD_MMAP_GPU_ID_SHIFT) & \
				     (KFD_GPU_ID_HASH_WIDTH - 1))

#endif /* _DPA_KFD_H_ */

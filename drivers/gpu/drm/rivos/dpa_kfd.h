#ifndef _DPA_KFD_H_
#define _DPA_KFD_H_

#include <linux/kernel.h>
#include <linux/iommu.h>

#include "dpa_daffy.h"

#define DPA_REGS_MIN_SIZE 0x1000

#define DUC_PCI_STATUS_REG 0x0000

#define DUC_PCI_DMA_SRC_ADDR 0x0001
#define DUC_PCI_DMA_DST_ADDR 0x0021
#define DUC_PCI_DMA_SIZES 0x0041
#define DUC_PCI_DMA_OP_CODES 0x0061
#define DUC_PCI_DMA_PASIDS 0x0081
#define DUC_PCI_DMA_GO 0x00A1
#define DUC_PCI_DMA_OP_DONE 0x00A9
#define DUC_PCI_DMA_INTERRUPT_ENABLE 0x00B1

#define DUC_PCI_QUEUE_INFO_ADDRESS 0x00B9
#define DUC_PCI_QUEUE_INFO_SIZE 0x00C1

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

	int drm_minor;

	// XXX use explicit 4k
#define DPA_MMIO_SIZE (PAGE_SIZE)
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
	// list_head for list of processes using device

	/* the DPA instance associated with this process */
	struct dpa_device *dev;

	struct mutex lock;

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
	void *fake_doorbell_page;
};

// tracks buffers -- especially vram allocations
struct dpa_kfd_buffer {
	struct list_head process_alloc_list;

	unsigned int id;
	unsigned int type;

	u64 size;
	unsigned page_count;
	struct page **pages;

	struct dpa_kfd_process *p;
};


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

/* For now let userspace allocate anything within a 48-bit address space */
#define DPA_GPUVM_ADDR_LIMIT ((1ULL << 48) - 1)

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
#define KFD_MMAP_TYPE_EVENTS (0x2ULL)
#define KFD_MMAP_TYPE_DOORBELL (0x1ULL)

#define KFD_GPU_ID_HASH_WIDTH (4)
#define KFD_MMAP_GPU_ID_SHIFT (48)
#define KFD_MMAP_GPU_ID_MASK ((1ULL << KFD_GPU_ID_HASH_WIDTH) - 1) \
				<< KFD_MMAP_GPU_ID_SHIFT)

#define KFD_MMAP_GET_GPU_ID(offset) (((offset) >> KFD_MMAP_GPU_ID_SHIFT) & \
				     (KFD_GPU_ID_HASH_WIDTH - 1))

#endif /* _DPA_KFD_H_ */

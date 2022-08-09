#ifndef _DPA_KFD_H_
#define _DPA_KFD_H_

#include <linux/kernel.h>
#include <linux/virtio.h>

#define DPA_FW_QUEUE_MAGIC (0xF00FADE5)
#define DPA_FW_QUEUE_PAGE_SIZE (4 * 1024)
struct dpa_fw_queue {
	u32 magic;
	u32 size;
	u32 read_ptr;
	u32 write_ptr;
	u64 ring_base_ptr;
};

struct dpa_fw_queue_pkt {
	u8 buf[64];
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

	// just keep it per process for now
	//struct list_head buffers;

	// one page allocated for queue to fw
	struct dpa_fw_queue *fw_queue;
	dma_addr_t fw_queue_dma_addr;

	// for virtio demo
	struct virtio_pci_common_cfg __iomem *common;
};

struct dpa_kfd_process {
	// list_head for list of processes using device

	/* the DPA instance associated with this process */
	struct dpa_device *dev;

	struct mutex lock;

	/* mm struct of the process */
	void *mm;

	// struct mmu_notifier *mmu_notifier;

	/* pasid allocated to this process */
	u32 pasid;

	unsigned alloc_count;
	// hack for now -- just maintain a list of allocations in vram
	struct list_head buffers;
};

// tracks buffers -- especially vram allocations
struct dpa_kfd_buffer {
	struct list_head process_alloc_list;
	//struct list_head dev_alloc_list;

	unsigned int id;
	unsigned int type;

	// only contiguous pages for now
	void *buf;

	u64 size;
	struct page *page;
	dma_addr_t dma_addr;

	//unsigned num_pages;
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
#define DPA_HSA_GFX_VERSION (10909)

/* For now let userspace allocate anything within a 48-bit address space */
#define DPA_GPUVM_ADDR_LIMIT ((1ULL << 48) - 1)

#endif /* _DPA_KFD_H_ */

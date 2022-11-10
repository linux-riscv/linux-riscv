#ifndef DCE_H
#define DCE_H

#include "linux/mutex.h"
#include "linux/eventfd.h"
#include <linux/workqueue.h>

#define DCE_CTRL 0

#define DCE_STATUS 8

#define DCE_INTERRUPT_CONFIG_DESCRIPTOR_COMPLETION 48
#define DCE_INTERRUPT_CONFIG_TIMEOUT               56
#define DCE_INTERRUPT_CONFIG_ERROR_CONDITION       64
#define DCE_INTERRUPT_STATUS                       72
#define DCE_INTERRUPT_MASK                         80

/* TODO: fix offset */
#define DCE_REG_WQITBA      0x0
#define DCE_REG_WQRUNSTS    0x10
#define DCE_REG_WQENABLE    0x18
#define DCE_REG_WQIRQSTS    0x20
#define DCE_REG_WQCR        0x0


#define DCE_OPCODE_CLFLUSH            0
#define DCE_OPCODE_MEMCPY             1
#define DCE_OPCODE_MEMSET             2
#define DCE_OPCODE_MEMCMP             3
// #define DCE_OPCODE_COMPRESS           4
// #define DCE_OPCODE_DECOMPRESS         5
#define DCE_OPCODE_LOAD_KEY           6
#define DCE_OPCODE_CLEAR_KEY          7
#define DCE_OPCODE_ENCRYPT            8
#define DCE_OPCODE_DECRYPT            9
// #define DCE_OPCODE_DECRYPT_DECOMPRESS 10
// #define DCE_OPCODE_COMPRESS_ENCRYPT   11
/* CRC Opcodes */
#define DCE_OPCODE_CRC_GEN            12
#define DCE_OPCODE_MEMCPY_CRC_GEN     13
/* PI Opcodes */
#define DCE_OPCODE_DIF_CHK            14
#define DCE_OPCODE_DIF_GEN            15
#define DCE_OPCODE_DIF_UPD            16
#define DCE_OPCODE_DIF_STRP           17
#define DCE_OPCODE_DIX_CHK            18
#define DCE_OPCODE_DIX_GEN            19

#define SRC_IS_LIST                 (1 << 1)
#define SRC2_IS_LIST                (1 << 2)
#define DEST_IS_LIST                (1 << 3)
#define PASID_VALID                 (1 << 4)


#define DEVICE_NAME "dce"
#define DEVICE_VF_NAME "dcevf"
#define VENDOR_ID 0x1EFD
#define DEVICE_ID 0x0010
#define DEVICE_VF_ID 0x0011
#define DCE_MINOR 0x0
#define DCE_NR_DEVS  2
#define DCE_NR_VIRTFN 7

/* TRANSCTL fields */
#define TRANSCTL_SUPV		BIT(31)
#define TRANSCTL_PASID_V	BIT(30)
#define TRANSCTL_PASID		GENMASK(19, 0)

/* JOB_CONTROL fields */
#define JOB_CTRL_SIZE		GENMASK(47, 0)

/* PI_CTL fields */
#define PI_CTL_NUM_LBA_8_0	GENMASK(45, 37)
#define PI_CTL_NUM_LBA_15_9	GENMASK(47, 41)

/* FMT_INFO fields */
#define FMT_INFO_LBAS		GENMASK(15, 14)
#define FMT_INFO_PIF		GENMASK(13, 12)

enum {
	DEST,
	SRC,
	SRC2,
	IV,
	AAD,
	COMP,
	NUM_SG_TBLS /*each of the above kind needs a SG list, potentially */
};

typedef enum {
    _16GB = 0,
    _32GB = 1,
    _64GB = 2,
    PIF_RESERVED = 3,
} PIF_encoding;

/* WQ type based on ownership */
typedef enum {
	DISABLED=0,
	KERNEL_WQ,
	USER_OWNED_WQ,
	SHARED_KERNEL_WQ,
	RESERVED_WQ,
} wq_type;

typedef struct AccessInfoRead {
	uint64_t* value;
	uint64_t  offset;
} AccessInfoRead;

typedef struct AccessInfoWrite {
	uint64_t value;
	uint64_t offset;
} AccessInfoWrite;

typedef struct DataAddrNode {
       uint64_t ptr;
       uint64_t size;
} DataAddrNode;

#define NUM_WQ      64
#define DEFAULT_NUM_DSC_PER_WQ 64

typedef struct __attribute__((packed)) WQITE {
    uint64_t DSCBA;
    uint8_t  DSCSZ;
    uint64_t DSCPTA;
    uint32_t TRANSCTL;
    uint64_t WQ_CTX_SAVE_BA;
    // TBA: key slot management
} WQITE;

/* shared with HW which expects both head and tail
 * to be 64B aligned and 64B apart */
typedef struct __attribute__((packed, aligned(64))) HeadTailIndex {
	/* init by driver, read by driver/SW, written by HW */
	volatile u64 head;
	u64 padding1[7];
	/* init by driver, read by HW, written by SW/Driver */
	/* TODO: Remove _Atomic and use kernel atomic stuff */
	_Atomic u64 tail;
	u64 padding2[7];
} HeadTailIndex;

/*struct shared with HW, expects exact layout */
typedef struct __attribute__((packed, aligned(64))) DCEDescriptor {
	uint8_t  opcode;
	uint8_t  ctrl;
	uint16_t operand0;
	uint32_t pasid;
	uint64_t source;
	uint64_t destination;
	uint64_t completion;
	uint64_t operand1;
	uint64_t operand2;
	uint64_t operand3;
	uint64_t operand4;
} DCEDescriptor;

/* representation of a WQ, holds both HW shared regions and managmement */
typedef struct DescriptorRing {
	/* Data structures shared with HW*/
	DCEDescriptor* descriptors;
	HeadTailIndex* hti;

	/* Local cached copy of WQITE.DSCSZ
	 * TODO: Change to mask? */
	size_t length;

	/* Sequence num of the last job where clean up was performed
	 * written by clean_up_worker, read by dce_push_descriptor */
	uint32_t clean_up_index;

	/* IOVA for configuration of the data strucs shared with HW
	 * Kept for cleanup*/
	dma_addr_t desc_dma;
	dma_addr_t hti_dma;

} DescriptorRing;

typedef struct UserArea {
	u64 hti;
	u64 descriptors;
	u64 numDescs;
} UserArea;

typedef struct KernelQueueReq {
    u32 DSCSZ;
    u32 eventfd_vld;
    u32 eventfd;
} KernelQueueReq;

#define RAW_READ          _IOR(0xAA, 0, struct AccessInfo*)
#define RAW_WRITE         _IOW(0xAA, 1, struct AccessInfo*)
#define SUBMIT_DESCRIPTOR _IOW(0xAA, 2, struct DescriptorInput*)
#define SETUP_USER_WQ 	  _IOW(0xAA, 3, UserArea *)
#define REQUEST_KERNEL_WQ _IOW(0xAA, 4, KernelQueueReq *)

#define MIN(a, b) \
	({ __typeof__ (a) _a = (a); \
	   __typeof__ (b) _b = (b); \
	   _a < _b ? _a : _b; })


static const struct pci_device_id pci_use_msi[] = {

	{ PCI_DEVICE_SUB(VENDOR_ID, DEVICE_ID,
			 PCI_ANY_ID, PCI_ANY_ID) },
	{ PCI_DEVICE_SUB(VENDOR_ID, DEVICE_VF_ID,
			 PCI_ANY_ID, PCI_ANY_ID) },
	{ }
};

typedef struct work_queue {
	wq_type type;

	// eventfd structure
	bool efd_ctx_valid;
	struct eventfd_ctx * efd_ctx;

	/* The actual ring */
	DescriptorRing descriptor_ring;

	struct mutex wq_tail_lock;
	/* Locks around modifications in the per WQ loop of clean_up_work
	 * Probably unecessary if using atomic set of clean_up_index and
	 * a single threaded kernel workqueue */
	struct mutex wq_clean_lock;
} work_queue;

struct dce_driver_priv
{
	struct work_struct clean_up_worker;

	/* probe time assigned information*/
	struct pci_dev *pdev;
	struct device * pci_dev;
	struct device dev;
	dev_t dev_num;
	struct cdev cdev;
	int vf_number;/* VF only */
	bool sva_enabled;/* PASID / SVA */
	uint64_t mmio_start;
	uint64_t mmio_start_phys;

	/* protect against concurrent access to this struct */
	struct mutex lock;
	/* protect against concurrent access to the IO space */
	struct mutex dce_reg_lock;

	/* Kernel space memory area, read by HW */
	WQITE * WQIT;
	dma_addr_t WQIT_dma;

	/* DCE workqueue configuration space*/
	work_queue wq[NUM_WQ];

};

void clean_up_work(struct work_struct *work);
void free_resources(struct device * dev, struct dce_driver_priv *priv);

uint64_t dce_reg_read(struct dce_driver_priv *priv, int reg);
void dce_reg_write(struct dce_driver_priv *priv, int reg, uint64_t value);
int dce_ops_open(struct inode *inode, struct file *file);
int dce_ops_release(struct inode *inode, struct file *file);
ssize_t dce_ops_write(struct file *fp, const char __user *buf, size_t count, loff_t *ppos);
ssize_t dce_ops_read(struct file *fp, char __user *buf, size_t count, loff_t *ppos);
long dce_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int dce_mmap(struct file *file, struct vm_area_struct *vma);
irqreturn_t handle_dce(int irq, void *dce_priv_p);

int setup_memory_regions(struct dce_driver_priv * drv_priv);

int setup_kernel_wq(
		struct dce_driver_priv * dce_priv, int wq_num, KernelQueueReq * kqr);

#endif

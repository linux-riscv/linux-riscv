/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Rivos DCE device driver
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

#ifndef RIVOS_DCE_H
#define RIVOS_DCE_H

#include "linux/mutex.h"
#include "linux/spinlock.h"
#include "linux/eventfd.h"
#include <linux/workqueue.h>

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

#define DCE_GCS                 (127 * 4096)
#define DCE_GCS_KEYOWN_BASE     0x10
#define DCE_GCS_KEYOWN_STRIDE   8
#define DCE_GCS_KEYOWN(fn) \
	(DCE_GCS + DCE_GCS_KEYOWN_BASE + fn * DCE_GCS_KEYOWN_STRIDE)

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

#define DEVICE_NAME "dce"
#define DEVICE_VF_NAME "dcevf"
#define VENDOR_ID 0x1EFD
#define DEVICE_ID 0x0010
#define DEVICE_VF_ID 0x0011
#define DCE_NR_DEVS  2
#define DCE_NR_VIRTFN 7
#define DCE_NR_FN (DCE_NR_VIRTFN + 1)

/* TRANSCTL fields */
#define TRANSCTL_SUPV       BIT(31)
#define TRANSCTL_PASID_V    BIT(30)
#define TRANSCTL_PASID      GENMASK(19, 0)

/* JOB_CONTROL fields */
#define JOB_CTRL_SIZE       GENMASK(47, 0)

/* PI_CTL fields */
#define PI_CTL_NUM_LBA_8_0  GENMASK(45, 37)
#define PI_CTL_NUM_LBA_15_9 GENMASK(47, 41)

/* FMT_INFO fields */
#define FMT_INFO_LBAS       GENMASK(15, 14)
#define FMT_INFO_PIF        GENMASK(13, 12)

enum {
	DEST,
	SRC,
	SRC2,
	IV,
	AAD,
	COMP,
	NUM_SG_TBLS /*each of the above kind needs a SG list, potentially */
};

enum {
	_16GB = 0,
	_32GB = 1,
	_64GB = 2,
	PIF_RESERVED = 3,
};

/* WQ type based on ownership */
enum wq_type {
	DISABLED = 0,
	KERNEL_WQ,
	KERNEL_FLUSHING_WQ,
	USER_OWNED_WQ,
	SHARED_KERNEL_WQ,
	RESERVED_WQ,
};


/* TODO: Used only in deprecated read*/
struct AccessInfoRead {
	uint64_t *value;
	uint64_t  offset;
};

/* TODO: Used only in deprecated write*/
struct AccessInfoWrite {
	uint64_t value;
	uint64_t offset;
};

/* TODO: Unsused ?*/
struct DataAddrNode {
	uint64_t ptr;
	uint64_t size;
};

#define NUM_WQ      64
#define DEFAULT_NUM_DSC_PER_WQ 64

#define DCE_NR_KEYS 64
#define DCE_KEYS_PER_QUEUE 2
#define DCE_KEY_VALID 0x80
/* TODO: checking sl < DCE_NR_KEYS would be good */
#define DCE_KEY_VALID_ENTRY(sl) (DCE_KEY_VALID | (sl&0x3F))

struct __packed __aligned(64) WQITE {
	uint64_t DSCBA;
	uint64_t DSCPTA;
	uint8_t  DSCSZ;
	uint8_t padding[3];
	uint32_t TRANSCTL;
	uint64_t WQ_CTX_SAVE_BA;
	uint8_t  keys[DCE_KEYS_PER_QUEUE];
};

/*
 * shared with HW which expects both head and tail
 * to be 64B aligned and 64B apart
 * head updated by HW
 * tail updated by SW (driver for kernel queues, userspce for user queues)
 */
struct __packed __aligned(64) HeadTailIndex {
	/* init by driver, read by driver/SW, written by HW, expect LE repr */
	/* Valid usecase? Documentation/process/volatile-considered-harmful.rst*/
	volatile u64 head;
	u64 padding1[7];
	/* init by driver, read by HW, written by SW/Driver */
	u64 tail;
	u64 padding2[7];
};

/*struct shared with HW, expects exact layout and LE repr */
struct __packed __aligned(64) DCEDescriptor {
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
};

/* representation of a WQ, holds both HW shared regions and managmement */
struct DescriptorRing {
	/* Data structures shared with HW*/
	struct DCEDescriptor *descriptors;
	struct HeadTailIndex *hti;

	/* Local cached copy of WQITE.DSCSZ*/
	/* TODO: Change to mask? */
	size_t length;

	/*
	 * Sequence num of the last job where clean up was performed
	 * written by clean_up_worker, read by dce_push_descriptor
	 */
	uint64_t clean_up_index;

	/* IOVA of the data strucs shared with HW, kept for cleanup*/
	dma_addr_t desc_dma;
	dma_addr_t hti_dma;
};

struct UserArea {
	u64 hti;
	u64 descriptors;
	u64 numDescs;
};

struct KernelQueueReq {
	u32 DSCSZ;
	u32 eventfd_vld;
	u32 eventfd;
};

#define RAW_READ          _IOR(0xAA, 0, struct AccessInfo*)
#define RAW_WRITE         _IOW(0xAA, 1, struct AccessInfo*)
#define SUBMIT_DESCRIPTOR _IOW(0xAA, 2, struct DescriptorInput*)
#define SETUP_USER_WQ     _IOW(0xAA, 3, struct UserArea *)
#define REQUEST_KERNEL_WQ _IOW(0xAA, 4, struct KernelQueueReq *)

#define MIN(a, b) \
	({	__typeof__(a) _a = (a); \
		__typeof__(b) _b = (b); \
		_a < _b ? _a : _b; })

static const struct pci_device_id pci_use_msi[] = {
	{ PCI_DEVICE_SUB(VENDOR_ID, DEVICE_ID,
			 PCI_ANY_ID, PCI_ANY_ID) },
	{ PCI_DEVICE_SUB(VENDOR_ID, DEVICE_VF_ID,
			 PCI_ANY_ID, PCI_ANY_ID) },
	{ }
};

struct work_queue {
	enum wq_type type;
	struct WQITE *wqite;

	// eventfd structure
	bool efd_ctx_valid;
	struct eventfd_ctx *efd_ctx;

	/* The actual ring, used for kernel queues*/
	struct DescriptorRing descriptor_ring;

	spinlock_t lock;
	/* Wait queue to wait on space being available for job submission */
	wait_queue_head_t full_waiter;
} work_queue;

struct dce_driver_priv {
	struct work_struct clean_up_worker;

	/* probe time assigned information*/
	struct pci_dev *pdev;
	struct device dev;
	struct cdev cdev;
	int id; /* cdev unique id, also dce_driver minor, by chance */
	bool sva_enabled;/* PASID / SVA */
	uint64_t mmio_start;
	uint64_t mmio_start_phys;

	/* protect against concurrent access to this struct */
	struct mutex lock;
	/* protect against concurrent access to the IO space */
	spinlock_t reg_lock;

	/* Kernel space memory area, read by HW */
	struct WQITE *WQIT;
	dma_addr_t WQIT_dma;

	/* DCE workqueue configuration space*/
	struct work_queue wq[NUM_WQ];
};

void clean_up_work(struct work_struct *work);
void free_resources(struct device *dev, struct dce_driver_priv *priv);

uint64_t dce_reg_read(struct dce_driver_priv *priv, int reg);
void dce_reg_write(struct dce_driver_priv *priv, int reg, uint64_t value);
int dce_ops_open(struct inode *inode, struct file *file);
int dce_ops_release(struct inode *inode, struct file *file);
ssize_t dce_ops_write(struct file *fp, const char __user *buf, size_t count, loff_t *ppos);
ssize_t dce_ops_read(struct file *fp, char __user *buf, size_t count, loff_t *ppos);
long dce_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int dce_mmap(struct file *file, struct vm_area_struct *vma);
irqreturn_t handle_dce(int irq, void *dce_priv_p);

int setup_memory_regions(struct dce_driver_priv *drv_priv);

int setup_default_kernel_queue(struct dce_driver_priv *dce_priv);

#endif

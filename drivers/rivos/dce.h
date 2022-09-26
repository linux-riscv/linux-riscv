#ifndef DCE_H
#define DCE_H

#include "linux/mutex.h"

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
#define DCE_OPCODE_COMPRESS           4
#define DCE_OPCODE_DECOMPRESS         5
#define DCE_OPCODE_LOAD_KEY           6
#define DCE_OPCODE_CLEAR_KEY          7
#define DCE_OPCODE_ENCRYPT            8
#define DCE_OPCODE_DECRYPT            9
#define DCE_OPCODE_DECRYPT_DECOMPRESS 10
#define DCE_OPCODE_COMPRESS_ENCRYPT   11

#define SRC_IS_LIST                 (1 << 1)
#define SRC2_IS_LIST                (1 << 2)
#define DEST_IS_LIST                (1 << 3)
#define PASID_VALID                 (1 << 4)


#define DEVICE_NAME "dce"
#define DEVICE_VF_NAME "dcevf"
#define VENDOR_ID 0x1EFD
#define DEVICE_ID 0x0001
#define DEVICE_VF_ID 0x0002
#define DCE_MINOR 0x0
#define DCE_NR_DEVS  2
#define DCE_NR_VIRTFN 7

/* TRANSCTL fields */
#define TRANSCTL_SUPV		BIT(31)
#define TRANSCTL_PASID_V	BIT(30)
#define TRANSCTL_PASID		GENMASK(19, 0)

enum {
	DEST,
	SRC,
	SRC2,
	IV,
	AAD,
	COMP,
	NUM_SG_TBLS
};

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
#define NUM_DSC_PER_WQ 64
typedef struct __attribute__((packed)) WQITE {
    uint64_t DSCBA;
    uint8_t  DSCSZ;
    uint64_t DSCPTA;
    uint32_t TRANSCTL;
    uint64_t WQ_CTX_SAVE_BA;
    // TBA: key slot management
} __attribute__((packed)) WQITE;

typedef struct HeadTailIndex {
	uint64_t head;
	uint64_t tail;
} HeadTailIndex;

typedef struct __attribute__((packed)) DCEDescriptor {
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
} __attribute__((packed)) DCEDescriptor;

typedef struct DescriptorRing {
	size_t length;

	DCEDescriptor* descriptors;
	HeadTailIndex* hti;

	uint32_t clean_up_index;

	dma_addr_t desc_dma;
	dma_addr_t hti_dma;

	int * dma_direction[NUM_SG_TBLS];
	struct sg_table * sg_tables[NUM_SG_TBLS];
	DataAddrNode ** hw_addr[NUM_SG_TBLS];
} DescriptorRing;

typedef struct UserArea {
	HeadTailIndex * hti;
	DCEDescriptor * descriptors;
	int numDescs;
} UserArea;

#define RAW_READ          _IOR(0xAA, 0, struct AccessInfo*)
#define RAW_WRITE         _IOW(0xAA, 1, struct AccessInfo*)
#define SUBMIT_DESCRIPTOR _IOW(0xAA, 2, struct DescriptorInput*)
#define INITIALIZE_USER_MEM _IOW(0xAA, 3, struct UserArea*)

#define MIN(a, b) \
	({ __typeof__ (a) _a = (a); \
	   __typeof__ (b) _b = (b); \
	   _a < _b ? _a : _b; })


static const struct pci_device_id pci_use_msi[] = {

	{ PCI_DEVICE_SUB(VENDOR_ID, DEVICE_ID,
			 PCI_ANY_ID, PCI_ANY_ID) },
	{ }
};

typedef struct work_queue {
	bool enable;
	struct file * owner;

	/* The actual ring */
	DescriptorRing descriptor_ring;
} work_queue;

struct dce_driver_priv
{
	struct work_struct clean_up_worker;

	struct pci_dev *pdev;
	struct device * pci_dev;
	struct device dev;
	dev_t dev_num;
	struct cdev cdev;

	u32* in;
	u32* out;
	u32* temp;

	struct mutex lock;

	uint64_t mmio_start;
	uint64_t mmio_start_phys;


    WQITE * WQIT;
    dma_addr_t WQIT_dma;

	work_queue wq[NUM_WQ];

	/* VF only */
	int vf_number;

	/* PASID / SVA */
	bool sva_enabled;
};


uint64_t dce_reg_read(struct dce_driver_priv *priv, int reg);
void dce_reg_write(struct dce_driver_priv *priv, int reg, uint64_t value);
int dce_ops_open(struct inode *inode, struct file *file);
int dce_ops_release(struct inode *inode, struct file *file);
ssize_t dce_ops_write(struct file *fp, const char __user *buf, size_t count, loff_t *ppos);
ssize_t dce_ops_read(struct file *fp, char __user *buf, size_t count, loff_t *ppos);
long dce_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

void setup_memory_regions(struct dce_driver_priv * drv_priv);

#endif
#ifndef DCE_H
#define DCE_H

#define DCE_CTRL 0

#define DCE_STATUS 8

#define DCE_INTERRUPT_CONFIG_DESCRIPTOR_COMPLETION 48
#define DCE_INTERRUPT_CONFIG_TIMEOUT               56
#define DCE_INTERRUPT_CONFIG_ERROR_CONDITION       64
#define DCE_INTERRUPT_STATUS                       72
#define DCE_INTERRUPT_MASK                         80

/* TODO: fix offset */
#define DCE_WQITBA	88
#define DCE_WQCR	96


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

#define DEVICE_NAME "dce"
#define VENDOR_ID 0x1FED
#define DEVICE_ID 0x0001

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
    uint32_t Descriptor_transctl;
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
	DCEDescriptor* descriptors;
	dma_addr_t dma;
	size_t length;
	int enabled;
} DescriptorRing;

#define RAW_READ          _IOR(0xAA, 0, struct AccessInfo*)
#define RAW_WRITE         _IOW(0xAA, 1, struct AccessInfo*)
#define SUBMIT_DESCRIPTOR _IOW(0xAA, 2, struct DescriptorInput*)

#define MIN(a, b) \
	({ __typeof__ (a) _a = (a); \
	   __typeof__ (b) _b = (b); \
	   _a < _b ? _a : _b; })

enum {
	DEST,
	SRC,
	SRC2,
	COMP,
	NUM_SG_TBLS
};

static const struct pci_device_id pci_use_msi[] = {

	{ PCI_DEVICE_SUB(VENDOR_ID, DEVICE_ID,
			 PCI_ANY_ID, PCI_ANY_ID) },
	{ }
};

struct dce_driver_priv
{
	struct device* dev;
	dev_t dev_num;
	struct cdev cdev;

	u32* in;
	u32* out;
	u32* temp;

	uint64_t mmio_start;

    WQITE * WQIT;
    dma_addr_t WQIT_dma;

	HeadTailIndex * hti;
	dma_addr_t hti_dma;

	DescriptorRing descriptor_ring;
	struct sg_table sg_tables[NUM_SG_TBLS];
	DataAddrNode * hw_addr[NUM_SG_TBLS];
};

#endif
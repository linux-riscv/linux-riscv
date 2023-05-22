/*
 * SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __ISBDMEX_H
#define __ISBDMEX_H

#include <linux/iommu.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/wait.h>

#include <rdma/isbdm-abi.h>
#include "isbdm-ib.h"

/* The current arbitrarily hardcoded ring size. */
#define ISBDMEX_RING_SIZE 1024
#define ISBDMEX_RMB_TABLE_SIZE ISBDMEX_RING_SIZE

/*
 * The art of picking a RX refill threshold. Ideally it would be as close to
 * empty as you can wait without underflowing, to minimize "trips to the gas
 * station".
 */
#define ISBDMEX_RX_THRESHOLD (ISBDMEX_RING_SIZE / 4)

/* The hardcoded buffer size */
#define ISBDMEX_BUF_SIZE 4096

/* Registers are mostly 64-bits, except for the head/tail regs. */
#define ISBDM_CMD_RING_BASE	0
#define ISBDM_CMD_RING_HEAD	8
#define ISBDM_CMD_RING_TAIL	16
#define ISBDM_CMD_RING_CTRL	24
#define ISBDM_RX_RING_BASE	32
#define ISBDM_RX_RING_HEAD	40
#define ISBDM_RX_RING_TAIL	48
#define ISBDM_RX_RING_CTRL	56
#define ISBDM_TX_RING_BASE	64
#define ISBDM_TX_RING_HEAD	72
#define ISBDM_TX_RING_TAIL	80
#define ISBDM_TX_RING_CTRL	88
#define ISBDM_RMBA_BASE		96
#define ISBDM_RMBA_CTRL		104
#define ISBDM_IPSR		112
#define ISBDM_IPMR		120
#define ISBDM_IRCR		128
#define ISBDM_ADMIN		136
#define ISBDM_RX_TLP_DROP_CNT	160

#define ISBDM_WRITEQ(isbdm, reg, val) writeq(cpu_to_le64(val), (isbdm)->base + (reg))
#define ISBDM_READQ(isbdm, reg) le64_to_cpu(readq((isbdm)->base + (reg)))

/* Ring base register fields, which apply to CMD, TX, and RX rings. */
/* The number of entries in the ring will be 2^(LOG2SZM1 + 1) */
#define ISBDM_RING_BASE_LOG2SZM1_MASK 0x1F

/* Macro to convert from a size to a register value. */
#define ISBDM_SIZE_TO_LOG2SZM1(size) \
	(__builtin_ctzll(size) - 1)

/* The ring tables must be 4k aligned. */
#define ISBDM_RING_BASE_ADDR_MASK 0xFFFFFFFFFFFFF000

/* The ENABLE bit is common to all rings (TX, RX, CMD) */
#define ISBDM_RING_CTRL_ENABLE 0x1
/*
 * The ring's BUSY flag goes down to indicate it has finished operating on
 * buffers within the ring.
 */
#define ISBDM_RING_CTRL_BUSY BIT(63)

/* RX ring control buffer size: 2^(BUFSIZ+9). */
#define ISBDM_RX_RING_CTRL_BUFSIZ_SHIFT 1
#define ISBDM_RX_RING_CTRL_BUFSIZ_MASK \
	(0x7 << ISBDM_RX_RING_CTRL_BUFSIZ_SHIFT)

/*
 * If the number of free descriptors drops below this specified threshold, an
 * RXRTHR interrupt fires.
 */
#define ISBDM_RX_RING_CTRL_RXRTHR_MAX 0xFFFFFFFF
#define ISBDM_RX_RING_CTRL_RXRTHR_SHIFT 16
#define ISBDM_RX_RING_CTRL_RXRTHR_MASK \
	(ISBDM_RX_RING_CTRL_RXRTHR_MAX << \
	 ISBDM_RX_RING_CTRL_RXRTHR_SHIFT)

/* Convert from a buffer size into the BUFSIZ register field value. */
#define ISBDM_RX_BUFFER_SIZE_TO_REG(size) \
	(__builtin_ctzll(size) - 9)

/*
 * The success code from an RDMA command, written to the physical address
 * designated in notify_iova if the NV flag is set. All others are failures.
 */
#define ISBDM_STATUS_SUCCESS 0

/*
 * Illegal command, non-zero reserved, PASID not enabled, privileged PASID not
 * enabled
 */
#define ISBDM_STATUS_MALFORMED_COMMAND 0x80000001

/* UR/CA response to RMBA read */
#define ISBDM_STATUS_RMBA_ACCESS_FAULT 0x80000002

/* RMBA data entry was poisoned */
#define ISBDM_STATUS_RMBA_DATA_CORRUPTION 0x80000003

/*
 * UR/CA response to translation request, RF/Invalid response to page request,
 * or ATS disabled
 */
#define ISBDM_STATUS_RMB_TRANSLATION_FAULT 0x80000004

/*
 * UR/CA response received, security key mismatch, write attempt to RO buffer,
 * or accessing bytes beyond the buffer
 */
#define ISBDM_STATUS_RMB_ACCESS_FAULT 0x80000005

/* RMB data was poisoned */
#define ISBDM_STATUS_RMB_DATA_CORRUPTION 0x80000006

/*
 * UR/CA response to translation request, RF/Invalid response to page target,
 * ATS disabled, PRI disabled and page not present, or requested permission not
 * granted
 */
#define ISBDM_STATUS_LMB_TRANSLATION_FAULT 0x80000007

/* UR/CA response received for local buffer access */
#define ISBDM_STATUS_LMB_ACCESS_FAULT 0x80000008

/* Local memory buffer data was poisoned */
#define ISBDM_STATUS_LMB_DATA_CORRUPTION 0x80000009

/*
 * Command aborted due to command ring being disabled, or BME being turned off
 */
#define ISBDM_STATUS_ABORTED 0x8000000A

/* Interrupt bits (both mask and status) */
#define ISBDM_LNKSTS_IRQ (1 << 0)
/* Transmit descriptor with ND=1 transmitted */
#define ISBDM_TXDONE_IRQ (1 << 1)
/* Transmit ring memory fault */
#define ISBDM_TXMF_IRQ (1 << 2)
/* Message with LS=1 was received */
#define ISBDM_RXDONE_IRQ (1 << 3)
/* Receive ring overflow */
#define ISBDM_RXOVF_IRQ (1 << 4)
/* Free receive descriptors below threshold */
#define ISBDM_RXRTHR_IRQ (1 << 5)
/* Receive ring memory fault detected */
#define ISBDM_RXMF_IRQ (1 << 6)
/* Command with LI=1 was completed */
#define ISBDM_CMDDONE_IRQ (1 << 7)
/* Command ring memory fault*/
#define ISBDM_CMDMF_IRQ (1 << 8)
/* UR received for an ATS request leading to ATS being disabled */
#define ISBDM_ATS_UR_IRQ (1 << 9)
/* RF response caused PRI to be disabled */
#define ISBDM_PRI_RF_IRQ (1 << 10)
/* Interrupt summary bit, clear to ask HW to re-evaluate interrupts. */
#define ISBDM_IPSR_IIP (1ULL << 63)

/* The mask of all known interrupts. */
#define ISBDM_ALL_IRQ_MASK \
	(ISBDM_LNKSTS_IRQ | ISBDM_TXDONE_IRQ | ISBDM_TXMF_IRQ | \
	 ISBDM_RXDONE_IRQ | ISBDM_RXOVF_IRQ | ISBDM_RXRTHR_IRQ | \
	 ISBDM_RXMF_IRQ | ISBDM_CMDDONE_IRQ | ISBDM_CMDMF_IRQ | \
	 ISBDM_ATS_UR_IRQ | ISBDM_PRI_RF_IRQ)

#define ISBDM_RX_TLP_DROP_CTR_SIZE (1ULL << 40)
#define ISBDM_RX_TLP_DROP_CTR_MASK (ISBDM_RX_TLP_DROP_CTR_SIZE - 1)
#define ISBDM_RX_TLP_DROP_CTR_HIGH_BIT (ISBDM_RX_TLP_DROP_CTR_SIZE >> 1)

/* Size mask for TX and RX descriptors, though the max size is 64KB. */
#define ISBDM_DESC_SIZE_MASK 0x0001FFFF
#define ISBDM_DESC_SIZE_MAX 0x00010000

/* Generate an interrupt on completion, in TX descriptor */
#define ISBDM_DESC_TX_ND 0x20000000

/* Last Segment */
#define ISBDM_DESC_LS 0x40000000
/* First Segment */
#define ISBDM_DESC_FS 0x80000000

/* RX and TX hardware descriptor format */
struct isbdm_descriptor {
	__le64 iova;
	__le32 length;
	__le32 flags;
};

/* PASID the iova corresponds to */
#define ISBDM_REMOTE_BUF_PASID_MASK 0xfffff
/* Access with privileged mode if 1, or user/unprivileged if 0 or PV==0 */
#define ISBDM_REMOTE_BUF_PP BIT(30)
/* PASID is valid*/
#define ISBDM_REMOTE_BUF_PV BIT(31)
/* Can be written by remote agents */
#define ISBDM_REMOTE_BUF_W BIT(63)

#define ISBDM_REMOTE_BUF_SIZE_MASK 0xffffffffffff

/* The hardware structure used for remote buffers. */
struct isbdm_remote_buffer {
    /* The address of the buffer */
    __le64 iova;
    /* The PASID and some flags */
    __le64 pasid_flags;
    /* Size of the buffer in bytes */
    __le64 size;
    /* Value that must match during remote requests. */
    __le64 security_key;
    __le64 reserved1;
    __le64 reserved2;
    __le64 reserved3;
    /* Available for software use, untouched by hardware */
    __le64 sw_avail;
};

/* Fields within the third qword of the command descriptor */
#define ISBDM_RDMA_SIZE_MASK 0xffffffffff
/* PASID to use for local access if PV==1 */
#define ISBDM_RDMA_PASID_MASK 0xfffff
#define ISBDM_RDMA_PASID_SHIFT 40
/* Generate MSI upon completion */
#define ISBDM_RDMA_LI BIT(60)
/* Write 4-byte status to notify_iova */
#define ISBDM_RDMA_NV BIT(61)
/* Access with supervisor privilege (0 or PV==0 is unprivileged) */
#define ISBDM_RDMA_PP BIT(62)
/* PASID is valid */
#define ISBDM_RDMA_PV BIT(63)

/* Fields within the fourth qword of the command descriptor */
/* Remote memory buffer index */
#define ISBDM_RDMA_RMBI_MASK 0xffffffff
/* RDMA command */
#define ISBDM_RDMA_RMBI_RESERVED_MASK (0x7ffffULL << 19)
#define ISBDM_RDMA_COMMAND_MASK 0x1f
#define ISBDM_RDMA_COMMAND_SHIFT 59

/* Command field values to do all the things. */

#define ISBDM_COMMAND_RESERVED 0ull
/* Read from remote into local buffer */
#define ISBDM_COMMAND_READ 1ull
/* Write from local buffer to remote */
#define ISBDM_COMMAND_WRITE 2ull
/* Compare and swap */
#define ISBDM_COMMAND_CAS 3ull
/* Fetch and add */
#define ISBDM_COMMAND_FETCH_ADD 4ull

/* Fields within the fifth qword of the command descriptor */
/* Offset within the remote memory buffer */
#define ISBDM_RDMA_RMB_OFFSET_MASK 0xffffffffffffULL
#define ISBDM_RDMA_RMB_OFFSET_RESERVED 0x3fff000000000000ULL

/* Non-cached hint */
#define ISBDM_RDMA_RMB_OFFSET_NCH (1ULL << 62)
/* Relaxed ordering */
#define ISBDM_RDMA_RMB_OFFSET_RO (1ULL << 63)

/* Command descriptor used by hardware */
struct isbdm_rdma_command {
    /* Local virtual address */
    __le64 iova;
    /* Optional notify virtual address */
    __le64 notify_iova;
    /* Size, PASID, and flags */
    __le64 size_pasid_flags;
    /* Remote buffer index, command, and a couple flags */
    __le64 rmbi_command;
    /* Remote virtual address */
    __le64 riova;
    /* Value that much match what's in the remote buffer entry */
    __le64 security_key;
    /* Compare value for CAS, amount to add for FetchNAdd */
    __le64 amo_value1;
    /* Exchange value for CAS */
    __le64 amo_value2;
};

/* The magic that goes at the start of the packet. */
#define ISBDM_PACKET_MAGIC 0x15BD
/* Raw I/O from directly reading/writing the ISBDM device. */
#define ISBDM_PACKET_RAW 0x01
/* Infiniband send op. */
#define ISBDM_PACKET_IB_SEND 0x02

/* Protocol structure defined by software for send/recv packets. */
struct isbdm_packet_header {
	/* Set this to cpu_to_le16(ISBDM_PACKET_MAGIC). */
	__le16 magic;
	/* See ISBDM_PACKET_TYPE_* definitions. */
	u8 type;
	/* Padding */
	u8 reserved;
	/* Source LID for IB UD sends. */
	__le16 src_lid;
	/* Source Queue Pair number for IB UD sends. */
	__le32 src_qp;
	/* Destination Queue Pair number for IB sends. */
	__le32 dest_qp;
};

/*
 * Use this bit in software to poison a descriptor of a partially cut off
 * packet. Hardware should never "see" a descriptor with this bit set, as it's
 * only set when software own the descriptor.
 */
#define ISBDM_DESC_SW_POISON 0x10000000

/* Offsets within the DVSEC */
#define ISBDM_DVSEC_VENLENREV_OFFSET 0x4
#define ISBDM_DVSEC_ID_OFFSET 0x8
#define ISBDM_DVSEC_LINK_CTRLSTS2_OFFSET 0x94

/* DVSEC Vendor ID, length, and revision fields. */
#define ISBDM_DVSEC_LENGTH 0x1A4
#define ISBDM_DVSEC_REV 1
#define ISBDM_DVSEC_VENDOR 0x1EFD

/* DVSEC Identifier */
#define ISBDM_DVSEC_ID 0x7

/* PCI Link Control 2 and Link Status 2 offset */
#define ISBDM_DVSEC_LINK_CONTROL_STATUS2 \
    (ISBDM_DVSEC_OFFSET + ISBDM_DVSEC_LINK_CTRLSTS2_OFFSET)

/* Define the PCIe control/status 2 register bits, proxied through via DVSEC. */
/* Crosslink Resolution */
#define PCIE_CTRL_STS2_CROSSLINK_MASK (0x3 << 24)
#define PCIE_CTRL_STS2_CROSSLINK_UPSTREAM (0x1 << 24)
#define PCIE_CTRL_STS2_CROSSLINK_DOWNSTREAM (0x2 << 24)
#define PCIE_CTRL_STS2_CROSSLINK_NOT_COMPLETED (0x3 << 24)

/* Downstream Component Presence */
#define PCIE_CTRL_STS2_DWNSTRM_PRS_MASK (0x7 << 28)
#define PCIE_CTRL_STS2_DWNSTRM_DOWN_UNDETERMINED (0x0 << 28)
#define PCIE_CTRL_STS2_DWNSTRM_DOWN_NOT_PRESENT (0x1 << 28)
#define PCIE_CTRL_STS2_DWNSTRM_DOWN_PRESENT (0x2 << 28)
#define PCIE_CTRL_STS2_DWNSTRM_UP_PRESENT (0x4 << 28)
#define PCIE_CTRL_STS2_DWNSTRM_UP_PRESENT_DRS (0x5 << 28)

/* ioctls for the isbdmex device */
#define IOCTL_SET_IPMR		_IO('3', 1)	/* ORs in IPMR bits. */
#define IOCTL_CLEAR_IPMR	_IO('3', 2)	/* ANDs out IPMR bits. */
#define IOCTL_GET_IPSR		_IO('3', 3)	/* Get the IPSR register. */
#define IOCTL_RX_REFILL		_IO('3', 4)	/* Refill RX descriptors. */
#define IOCTL_ALLOC_RMB		_IO('3', 5)	/* Create remote memory buf. */
#define IOCTL_FREE_RMB		_IO('3', 6)	/* Destroy remote memory buf. */
#define IOCTL_RDMA_CMD		_IO('3', 7)	/* Send RDMA command. */
#define IOCTL_GET_LAST_ERROR	_IO('3', 8)	/* Get error status. */
#define IOCTL_GET_RX_DROP_CNT	_IO('3', 9)	/* Get RX drop count. */
#define IOCTL_LINK_STATUS_OP	_IO('3', 10)	/* Link status operations */

#define IOCTL_LINK_STATUS_OP_DISCONNECT 1
#define IOCTL_LINK_STATUS_OP_RECONNECT 2

/* Info about a hardware ring (tx, rx, or cmd). */
struct isbdm_ring {
	/* The virtual address of the hardware's table of entries. */
	union {
		struct isbdm_descriptor *descs;
		struct isbdm_rdma_command *cmds;
		struct isbdm_remote_buffer *rmbs;
	};

	/* The index where the producer puts the next descriptor. */
	u32 prod_idx;
	/* The index the consumer should examine next. */
	u32 cons_idx;
	/* The size of an element in the ring. */
	size_t element_size;
	/* The number of entries in the ring. */
	u64 size;
	/* The physical address of the table. */
	dma_addr_t physical;
	/*
	 * The list of buffers waiting to get on the hardware queue for TX, or
	 * waiting to be dispatched for RX.
	 */
	struct list_head wait_list;
	/* The set of buffers actually in flight in a hardware descriptor. */
	struct list_head inflight_list;
	/* The set of buffers hanging around waiting for use. */
	struct list_head free_list;
	/* The mutex serializing access to the ring. */
	struct mutex lock;
};

/* A cute little struct that tracks the actual buffers ISBDM uses. */
struct isbdm_buf {
	struct list_head node;
	void *buf;
	dma_addr_t physical;
	/* The valid size. */
	size_t size;
	/* The buffer size. */
	size_t capacity;
	/* Contains info on the first/last segment bits. */
	uint32_t flags;
	/* The descriptor index, to detect driver descriptor handling bugs. */
	uint32_t desc_idx;
};

/* Last error reporting */
struct isbdm_last_error {
	/* Number of submitted commands that have yet to complete. */
	size_t inflight_commands;
	/*
	 * Error code from the hardware for the first error to have occurred
	 * since the last status check. Cleared when read.
	 */
	uint32_t error;
};

struct isbdm_user_ctx {
	/* Reference since this pointer gets saved in the command queue. */
	struct kref ref;
	/* The device associated with this open file. */
	struct isbdm *isbdm;
	/* The SVA context ensuring this process has a PASID. */
	struct iommu_sva *sva;
	/* Last error accounting */
	struct isbdm_last_error last_error;
};

struct isbdm_qp;

/* Another struct for tracking RDMA commands. */
struct isbdm_command {
	struct list_head node;
	/* The command entry itself. */
	struct isbdm_rdma_command cmd;
	/* The descriptor index, to detect driver descriptor handling bugs. */
	uint32_t desc_idx;
	/* The usermode file context, for returning the status code. */
	struct isbdm_user_ctx *user_ctx;
	/* The queue pair this command was sent from. */
	struct isbdm_qp *qp;
	/* A copy of the work queue entry associated with this command. */
	struct isbdm_wqe wqe;
	/*
	 * The address of a DMA pool buffer, used for RDMA ops with inline data.
	 */
	dma_addr_t inline_dma_addr;
};

struct isbdm_device;

enum isbdm_link_status {
	ISBDM_LINK_DOWN,
	ISBDM_LINK_UPSTREAM,
	ISBDM_LINK_DOWNSTREAM
};

/* Per-instance hardware info */
struct isbdm {
	struct pci_dev 		*pdev;
	void __iomem		*base;

	/* Pending interrupt bits to be serviced by the bottom half. */
	atomic64_t pending_irqs;

	/*
	 * Shadow copy of the interrupt mask register, to avoid reaching out to
	 * the hardware unnecessarily.
	 */
	u64 irq_mask;

	struct isbdm_ring rx_ring;
	struct isbdm_ring tx_ring;
	struct isbdm_ring cmd_ring;
	/* Remembers the most recent descriptor with the FIRST_SEGMENT bit. */
	struct isbdm_buf *packet_start;
	struct isbdm_remote_buffer *rmb_table;
	dma_addr_t rmb_table_physical;
	struct mutex rmb_table_lock;
	/*
	 * Pool of DMA coherent buffers that gets used when ibverbs sends an
	 * RDMA operation with inline data.
	 */
	struct dma_pool *inline_pool;
	/*
	 * Keep an array parallel to the cmd_ring for notify writes from the
	 * hardware. A fancier version of this driver would support notify
	 * writes directly to usermode.
	 */
	uint32_t *notify_area;
	dma_addr_t notify_area_physical;

	/* Wait queue head blocking reads. */
	struct wait_queue_head read_wait_queue;

	int			irq;
	int			instance;
	struct miscdevice	misc;
	/* Node on the isbdmex_list. */
	struct list_head	node;
	/* Shadow copy of the dropped RX TLP count that manages upper bits. */
	u64 dropped_rx_tlps;

	/* Pointer to the device structure tracking all the rdma entries. */
	struct isbdm_device *ib_device;

	/* Offset of the ISBDM DVSEC capability. */
	u16 dvsec_cap;
	enum isbdm_link_status link_status;
	/* Some random bits created to give the device a unique GID. */
	u32 rand_id;
};

/* Drivers support routines */
void isbdmex_user_ctx_release(struct kref *ref);

/* Hardware-poking routines */
struct isbdm_buf *get_buf(struct isbdm *ii, struct isbdm_ring *ring);
void put_buf(struct isbdm *ii, struct isbdm_ring *ring, struct isbdm_buf *buf);
struct isbdm_command *get_cmd(struct isbdm *ii, struct isbdm_ring *ring);
void put_cmd(struct isbdm *ii, struct isbdm_ring *ring,
	     struct isbdm_command *cmd);

void isbdm_tx_enqueue(struct isbdm *ii);
void isbdm_cmd_enqueue(struct isbdm *ii);
void isbdm_reap_tx(struct isbdm *ii);
void isbdm_reap_cmds(struct isbdm *ii);
int isbdm_init_hw(struct isbdm *ii);
void isbdm_deinit_hw(struct isbdm *ii);
void isbdm_disable(struct isbdm *ii);
void isbdm_hw_reset(struct isbdm *ii);
ssize_t isbdmex_raw_send(struct isbdm *ii, const void __user *va, size_t size);
int isbdmex_send_command(struct isbdm *ii, struct isbdm_user_ctx *user_ctx,
			 const void __user *user_cmd);

int isbdmex_alloc_rmb(struct isbdm *ii, struct file *file,
		      const void __user *user_rmb);

int isbdm_alloc_rmb(struct isbdm *ii, struct isbdm_remote_buffer *rmb);
void isbdm_set_rmb_key(struct isbdm *ii, int rmbi, u64 key);
int isbdmex_free_rmb(struct isbdm *ii, struct file *file, int rmbi);
void isbdm_free_rmb(struct isbdm *ii, int rmbi);
void isbdm_free_all_rmbs(struct isbdm *ii, struct file *file);
void isbdm_process_rx_done(struct isbdm *ii);
void isbdm_rx_overflow(struct isbdm *ii);
ssize_t isbdmex_read_one(struct isbdm *ii, void __user *va, size_t size);
void isbdm_rx_threshold(struct isbdm *ii);
void isbdm_start(struct isbdm *ii);
void isbdm_process_link_status_change(struct isbdm *ii);

/* Hardware routines for test. */
u64 isbdmex_ioctl_set_ipmr(struct isbdm *ii, u64 mask);
u64 isbdmex_ioctl_clear_ipmr(struct isbdm *ii, u64 mask);
u64 isbdmex_ioctl_get_ipsr(struct isbdm *ii);
u64 isbdmex_get_dropped_rx_count(struct isbdm *ii);
int isbdmex_link_status_op(struct isbdm *ii, void __user *argp);

void isbdm_complete_rdma_cmd(struct isbdm *ii, struct isbdm_command *command,
			     uint32_t status);

void isbdm_process_rx_packet(struct isbdm *ii, struct isbdm_buf *start,
			     struct isbdm_buf *end);

static inline u64 isbdm_gid(struct isbdm *ii)
{
	return ((u64)ii->rand_id << 8) | (ii->instance + 0x10);
}

#endif

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
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/wait.h>

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
#define ISBDM_CMD_RING_TAIL	12
#define ISBDM_CMD_RING_CTRL	16
#define ISBDM_RX_RING_BASE	24
#define ISBDM_RX_RING_HEAD	32
#define ISBDM_RX_RING_TAIL	36
#define ISBDM_RX_RING_CTRL	40
#define ISBDM_TX_RING_BASE	48
#define ISBDM_TX_RING_HEAD	56
#define ISBDM_TX_RING_TAIL	60
#define ISBDM_TX_RING_CTRL	64
#define ISBDM_RMBA_BASE		72
#define ISBDM_RMBA_CTRL		80
#define ISBDM_IPSR		88
#define ISBDM_IPMR		96
#define ISBDM_IRCR		104
#define ISBDM_ADMIN		112

#define ISBDM_WRITEQ(isbdm, reg, val) writeq(cpu_to_le64(val), (isbdm)->base + (reg))
#define ISBDM_WRITEL(isbdm, reg, val) writel(cpu_to_le32(val), (isbdm)->base + (reg))
#define ISBDM_READQ(isbdm, reg) le64_to_cpu(readq((isbdm)->base + (reg)))
#define ISBDM_READL(isbdm, reg) le32_to_cpu(readl((isbdm)->base + (reg)))

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

/* The success code from an RDMA command. All others are failures. */
#define ISBDM_STATUS_SUCCESS 0

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

/* Generate an interrupt on completion, in TX descriptor */
#define ISBDM_DESC_TX_ND 0x20000000

/* Last Segment */
#define ISBDM_DESC_LS 0x40000000
/* First Segment */
#define ISBDM_DESC_FS 0x80000000

/* RX and TX hardware descriptor format */
struct isbdm_descriptor {
	__le64 iova;
	__le16 length;
	__le16 reserved;
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
#define ISBDM_RDMA_RMBI_MASK 0xffffffffff
/* RDMA command */
#define ISBDM_RDMA_RMBI_RESERVED_MASK (0x7ffffULL << 19)
#define ISBDM_RDMA_COMMAND_MASK 0x1f
#define ISBDM_RDMA_COMMAND_SHIFT 59

/* Fields within the fifth qword of the command descriptor */
/* Offset within the remote memory buffer */
#define ISBDM_RDMA_RMB_OFFSET_MASK 0xffffffffffff

/* Command descriptor used by hardware */
struct isbdm_rdma_command {
    /* Local virtual address */
    __le64 iova;
    /* Optional notify virtual address */
    __le64 notify_iova;
    /* Size, PASID, and flags */
    __le64 size_pasid_flags;
    /* Remote buffer index and command */
    __le64 rmbi_command;
    /* Offset within the remote memory buffer */
    __le64 rmb_offset;
    /* Value that much match what's in the remote buffer entry */
    __le64 security_key;
    /* Compare value for CAS, amount to add for FetchNAdd */
    __le64 amo_value1;
    /* Exchange value for CAS */
    __le64 amo_value2;
};

/*
 * Use this bit in software to poison a descriptor of a partially cut off
 * packet. Hardware should never "see" a descriptor with this bit set, as it's
 * only set when software own the descriptor.
 */
#define ISBDM_DESC_SW_POISON 0x10000000

/* ioctls for the isbdmex device */
#define IOCTL_SET_IPMR		_IO('3', 1)	/* ORs in IPMR bits. */
#define IOCTL_CLEAR_IPMR	_IO('3', 2)	/* ANDs out IPMR bits. */
#define IOCTL_GET_IPSR		_IO('3', 3)	/* Get the IPSR register. */
#define IOCTL_RX_REFILL		_IO('3', 4)	/* Refill RX descriptors. */
#define IOCTL_ALLOC_RMB		_IO('3', 5)	/* Create remote memory buf. */
#define IOCTL_FREE_RMB		_IO('3', 6)	/* Destroy remote memory buf. */
#define IOCTL_RDMA_CMD		_IO('3', 7)	/* Send RDMA command. */
#define IOCTL_GET_LAST_ERROR	_IO('3', 8)	/* Get error status. */

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

/* Another struct for tracking RDMA commands. */
struct isbdm_command {
	struct list_head node;
	/* The command entry itself. */
	struct isbdm_rdma_command cmd;
	/* The descriptor index, to detect driver descriptor handling bugs. */
	uint32_t desc_idx;
	/* The usermode file context, for returning the status code. */
	struct isbdm_user_ctx *user_ctx;
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
	struct isbdm_remote_buffer *rmb_table;
	dma_addr_t rmb_table_physical;
	struct mutex rmb_table_lock;
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
};

/* Drivers support routines */
void isbdmex_user_ctx_release(struct kref *ref);

/* Hardware-poking routines */
void isbdm_reap_tx(struct isbdm *ii);
void isbdm_reap_cmds(struct isbdm *ii);
int isbdm_init_hw(struct isbdm *ii);
void isbdm_deinit_hw(struct isbdm *ii);
void isbdm_enable(struct isbdm *ii);
void isbdm_disable(struct isbdm *ii);
void isbdm_hw_reset(struct isbdm *ii);
ssize_t isbdmex_send(struct isbdm *ii, const char __user *va, size_t size);
int isbdmex_send_command(struct isbdm *ii, struct isbdm_user_ctx *user_ctx,
			 const char __user *user_cmd);

int isbdmex_alloc_rmb(struct isbdm *ii, struct file *file,
		      const char __user *user_rmb);

int isbdmex_free_rmb(struct isbdm *ii, struct file *file, int rmbi);
void isbdm_free_all_rmbs(struct isbdm *ii, struct file *file);
void isbdm_process_rx_done(struct isbdm *ii);
void isbdm_rx_overflow(struct isbdm *ii);
ssize_t isbdmex_read_one(struct isbdm *ii, char __user *va, size_t size);
void isbdm_rx_threshold(struct isbdm *ii);

/* Hardware routines for test. */
u64 isbdmex_ioctl_set_ipmr(struct isbdm *ii, u64 mask);
u64 isbdmex_ioctl_clear_ipmr(struct isbdm *ii, u64 mask);
u64 isbdmex_ioctl_get_ipsr(struct isbdm *ii);

#endif

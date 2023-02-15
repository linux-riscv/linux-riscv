/*
 * SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __ISBDMEX_H
#define __ISBDMEX_H

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>

/* The current arbitrarily hardcoded ring size. */
#define ISBDMEX_RING_SIZE 1024

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

/* The mask of all known interrupts. */
#define ISBDM_ALL_IRQ_MASK \
	(ISBDM_LNKSTS_IRQ | ISBDM_TXDONE_IRQ | ISBDM_TXMF_IRQ | \
	 ISBDM_RXDONE_IRQ | ISBDM_RXOVF_IRQ | ISBDM_RXRTHR_IRQ | \
	 ISBDM_RXMF_IRQ | ISBDM_CMDDONE_IRQ | ISBDM_CMDMF_IRQ | \
	 ISBDM_ATS_UR_IRQ | ISBDM_PRI_RF_IRQ)

/* Error flag, in RX descriptor */
#define ISBDM_DESC_RX_ERR 0x20000000
/* Generate an interrupt on completion, in TX descriptor */
#define ISBDM_DESC_TX_ND 0x20000000

/* Last Segment */
#define ISBDM_DESC_LS 0x40000000
/* First Segment */
#define ISBDM_DESC_FS 0x80000000

/* Info about a hardware ring (tx, rx, or cmd). */
struct isbdm_ring {
	/* The virtual address of the hardware's table of entries. */
	struct isbdm_descriptor *entries;
	/* The index where the producer puts the next descriptor. */
	u32 prod_idx;
	/* The index the consumer should examine next. */
	u32 cons_idx;
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
};

/* Per-instance hardware info */
struct isbdm {
	struct pci_dev 		*pdev;
	void __iomem		*base;

	/* Pending interrupt bits to be serviced by the bottom half. */
	atomic_t pending_irqs;

	/*
	 * Shadow copy of the interrupt mask register, to avoid reaching out to
	 * the hardware unnecessarily.
	 */
	u64 irq_mask;

	struct isbdm_ring rx_ring;
	struct isbdm_ring tx_ring;
	struct isbdm_ring cmd_ring;

	int			irq;
	int			instance;
	struct miscdevice	misc;
	/* Node on the isbdmex_list. */
	struct list_head	node;
};

/* RX and TX hardware descriptor format */
struct isbdm_descriptor {
	__le64 iova;
	__le16 length;
	__le16 reserved;
	__le32 flags;
};

/* Hardware-poking routines */
void isbdm_reap_tx(struct isbdm *ii);
int isbdm_init_hw(struct isbdm *ii);
void isbdm_deinit_hw(struct isbdm *ii);
void isbdm_enable(struct isbdm *ii);
void isbdm_disable(struct isbdm *ii);
void isbdm_hw_reset(struct isbdm *ii);
ssize_t isbdmex_send(struct isbdm *ii, const char __user *va, size_t size);

#endif

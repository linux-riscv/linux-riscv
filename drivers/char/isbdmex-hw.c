/* isbdmex-hw
 *
 * ISBDM exerciser driver, hardware interface
 *
 * SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * 3 Feb 2023 mev
 */

#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/pci.h>

#include "isbdmex.h"

static struct isbdm_buf *alloc_buf(struct isbdm *ii)
{
	struct isbdm_buf *buf = kzalloc(sizeof(struct isbdm_buf), GFP_KERNEL);

	if (!buf)
		return NULL;

	buf->buf = dma_alloc_coherent(&ii->pdev->dev, ISBDMEX_BUF_SIZE,
				      &buf->physical, GFP_KERNEL);

	if (!buf->buf) {
		kfree(buf);
		return NULL;
	}

	buf->capacity = ISBDMEX_BUF_SIZE;
	return buf;
}

static void free_buf(struct isbdm *ii, struct isbdm_buf *buf) {
	dma_free_coherent(&ii->pdev->dev, buf->size, buf->buf, buf->physical);
	kfree(buf);
	return;
}

static void free_buf_list(struct isbdm *ii, struct list_head *head) {
	struct isbdm_buf *cur, *tmp;

	list_for_each_entry_safe(cur, tmp, head, node) {
		free_buf(ii, cur);
	}

	return;
}

/*
 * Grab a buffer and remove it from the free list, or allocate a new one.
 * Assumes the ring's lock is already held.
 */
static struct isbdm_buf *get_buf(struct isbdm *ii, struct isbdm_ring *ring)
{

	struct isbdm_buf *buf;

	WARN_ON_ONCE(!mutex_is_locked(&ring->lock));

	if (!list_empty(&ring->free_list)) {
		buf = list_first_entry(&ring->free_list, struct isbdm_buf,
				       node);

		list_del(&buf->node);
		buf->size = 0;
		return buf;
	}

	return alloc_buf(ii);
}

/* Put a buffer onto the free list. Assumes the ring's lock is held. */
static void put_buf(struct isbdm *ii, struct isbdm_ring *ring,
		    struct isbdm_buf *buf)
{

	WARN_ON_ONCE(!mutex_is_locked(&ring->lock));

	list_add(&buf->node, &ring->free_list);
}

/* Returns non-zero if the ring is completely stuffed. */
static int ring_is_full(struct isbdm_ring *ring)
{
	u64 mask = ring->size - 1;

	return ((ring->prod_idx + 1) & mask) == (ring->cons_idx & mask);
}

/* Fill out descriptors for as many packets as possible on the waitlist. */
static void isbdm_tx_enqueue(struct isbdm *ii)
{
	struct isbdm_buf *buf;
	u32 flags;
	struct isbdm_descriptor *desc;
	struct isbdm_ring *ring = &ii->tx_ring;
	u32 mask = ring->size - 1;

	if (list_empty(&ring->wait_list))
		return;

	/* Add as many to the descriptor ring as possible. */
	while (!list_empty(&ring->wait_list) &&
	       !ring_is_full(ring)) {

		buf = list_first_entry(&ring->wait_list,
				       struct isbdm_buf, node);

		list_del(&buf->node);
		list_add_tail(&buf->node, &ring->inflight_list);
		desc = &ring->entries[ring->prod_idx];
		desc->iova = cpu_to_le64(buf->physical);
		desc->reserved = cpu_to_le16(0);
		flags = buf->flags;
		if (flags & ISBDM_DESC_LS)
			flags |= ISBDM_DESC_TX_ND;

		desc->flags = cpu_to_le32(flags);
		desc->length = cpu_to_le16(buf->size);
		ring->prod_idx = (ring->prod_idx + 1) & mask;
		break;
	}

	ISBDM_WRITEL(ii, ISBDM_TX_RING_TAIL, ring->prod_idx);
	return;
}

static int alloc_ring(struct isbdm *ii, struct isbdm_ring *ring, u64 *base_reg)
{
	size_t table_size;

	INIT_LIST_HEAD(&ring->wait_list);
	INIT_LIST_HEAD(&ring->inflight_list);
	INIT_LIST_HEAD(&ring->free_list);
	mutex_init(&ring->lock);
	ring->size = ISBDMEX_RING_SIZE;
	table_size = ring->size * sizeof(struct isbdm_descriptor);
	ring->entries = dma_alloc_coherent(&ii->pdev->dev, table_size,
					   &ring->physical, GFP_KERNEL);
	if (!ring->entries)
		return -ENOMEM;

	WARN_ON(ii->tx_ring.physical & ~ISBDM_RING_BASE_ADDR_MASK);

	memset(ring->entries, 0, table_size);
	*base_reg = ii->tx_ring.physical | ISBDM_SIZE_TO_LOG2SZM1(ii->tx_ring.size);
	return 0;
}

static void free_ring(struct isbdm *ii, struct isbdm_ring *ring)
{
	if (ring->entries) {
		size_t table_size;

		table_size = ring->size * sizeof(struct isbdm_descriptor);
		dma_free_coherent(&ii->pdev->dev, table_size, ring->entries,
				  ring->physical);

		ring->entries = NULL;
	}

	free_buf_list(ii, &ring->wait_list);
	free_buf_list(ii, &ring->inflight_list);
	free_buf_list(ii, &ring->free_list);
	return;
}

static int init_tx_ring(struct isbdm *ii)
{
	u64 base;
	int rc;

	rc = alloc_ring(ii, &ii->tx_ring, &base);
	if (rc)
		return rc;

	ISBDM_WRITEQ(ii, ISBDM_TX_RING_BASE, base);
	return 0;
}

static void deinit_tx_ring(struct isbdm *ii)
{
	ISBDM_WRITEQ(ii, ISBDM_TX_RING_BASE, 0);
	free_ring(ii, &ii->tx_ring);
	return;
}

static void enable_tx_ring(struct isbdm *ii)
{
	u64 ctrl = ISBDM_READQ(ii, ISBDM_TX_RING_CTRL);

	ctrl |= ISBDM_RING_CTRL_ENABLE;
	ISBDM_WRITEQ(ii, ISBDM_TX_RING_CTRL, ctrl);
	return;
}

static void disable_tx_ring(struct isbdm *ii)
{
	u64 ctrl = ISBDM_READQ(ii, ISBDM_TX_RING_CTRL);

	ctrl &= ~ISBDM_RING_CTRL_ENABLE;
	ISBDM_WRITEQ(ii, ISBDM_TX_RING_CTRL, ctrl);
	return;
}

static void enable_interrupt(struct isbdm *ii, u64 mask)
{
	ii->irq_mask &= ~mask;
	ISBDM_WRITEQ(ii, ISBDM_IPMR, ii->irq_mask);
	return;
}

static void disable_interrupt(struct isbdm *ii, u64 mask)
{
	ii->irq_mask |= mask;
	ISBDM_WRITEQ(ii, ISBDM_IPMR, ii->irq_mask);
	return;
}

void isbdm_reap_tx(struct isbdm *ii)
{
	struct isbdm_ring *ring = &ii->tx_ring;
	u32 mask = ring->size - 1;
	u32 hw_next = ISBDM_READL(ii, ISBDM_TX_RING_HEAD) & mask;

	mutex_lock(&ring->lock);
	while (ring->cons_idx != hw_next) {
		struct isbdm_buf *buf;

		if (list_empty(&ring->inflight_list)) {
			dev_err(&ii->pdev->dev, "TX inflight underflow");
			break;
		}

		buf = list_first_entry(&ring->inflight_list,
				       struct isbdm_buf, node);

		list_del(&buf->node);
		list_add(&buf->node, &ring->free_list);
		ring->cons_idx = (ring->cons_idx + 1) & mask;
	}

	mutex_unlock(&ring->lock);
	return;
}

int isbdm_init_hw(struct isbdm *ii)
{
	int rc;

	rc = init_tx_ring(ii);
	if (rc)
		return rc;

	return 0;
}

void isbdm_deinit_hw(struct isbdm *ii)
{
	deinit_tx_ring(ii);
	return;
}

void isbdm_enable(struct isbdm *ii)
{
	enable_interrupt(ii, ISBDM_LNKSTS_IRQ);
	enable_tx_ring(ii);
	enable_interrupt(ii, ISBDM_TXDONE_IRQ | ISBDM_TXMF_IRQ);
	return;
}

void isbdm_disable(struct isbdm *ii)
{
	disable_interrupt(ii, ISBDM_TXDONE_IRQ | ISBDM_TXMF_IRQ);
	disable_tx_ring(ii);
	return;
}

void isbdm_hw_reset(struct isbdm *ii)
{
	/* Clear queue and RDMA enables: */
	ISBDM_WRITEQ(ii, ISBDM_CMD_RING_CTRL, 0);
	ISBDM_WRITEQ(ii, ISBDM_TX_RING_CTRL, 0);
	ISBDM_WRITEQ(ii, ISBDM_RX_RING_CTRL, 0);
	ISBDM_WRITEQ(ii, ISBDM_RMBA_CTRL, 0);
	/* Disable all IRQs */
	ISBDM_WRITEQ(ii, ISBDM_IPMR, -1ULL);
}

ssize_t isbdmex_send(struct isbdm *ii, const char __user *va, size_t size)
{
	struct isbdm_buf *buf, *tmp;
	int first = ISBDM_DESC_FS;
	LIST_HEAD(local_list);
	int not_done;
	ssize_t rc;
	size_t remaining = size;

	mutex_lock(&ii->tx_ring.lock);
	/* Loop creating packets and queueing them on to our local list. */
	do {
		buf = get_buf(ii, &ii->tx_ring);
		if (!buf) {
			rc = -ENOMEM;
			goto out;
		}

		if (remaining < buf->capacity) {
			buf->size = remaining;

		} else {
			buf->size = buf->capacity;
		}

		buf->flags = first;
		first = 0;
		if (remaining != 0) {
			not_done = copy_from_user(buf->buf, va, buf->size);
			if (not_done != 0) {
				rc = -EFAULT;
				goto out;
			}

			va += buf->size;
			remaining -= buf->size;
		}

		if (remaining == 0) {
			buf->flags |= ISBDM_DESC_LS;
		}

		list_add_tail(&buf->node, &local_list);
	} while (remaining != 0);

	/*
	 * Now that all the buffers are set up, enqueue them onto the waitlist,
	 * then stick as many as possible into the hardware.
	 */

	list_splice_tail_init(&local_list, &ii->tx_ring.wait_list);
	isbdm_tx_enqueue(ii);
	rc = size;

out:
	/* On failure, clean up any buffers on the local list. */
	list_for_each_entry_safe(buf, tmp, &local_list, node) {
		put_buf(ii, &ii->tx_ring, buf);
	}

	mutex_unlock(&ii->tx_ring.lock);
	return rc;
}
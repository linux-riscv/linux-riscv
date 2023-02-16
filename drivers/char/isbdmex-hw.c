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

	WARN_ON_ONCE(!mutex_is_locked(&ring->lock));

	if (list_empty(&ring->wait_list))
		return;

	/* Add as many to the descriptor ring as possible. */
	while (!list_empty(&ring->wait_list) &&
	       !ring_is_full(ring)) {

		buf = list_first_entry(&ring->wait_list,
				       struct isbdm_buf, node);

		list_del(&buf->node);
		list_add_tail(&buf->node, &ring->inflight_list);
		buf->desc_idx = ring->prod_idx;
		desc = &ring->entries[ring->prod_idx];
		desc->iova = cpu_to_le64(buf->physical);
		desc->reserved = cpu_to_le16(0);
		flags = buf->flags;
		if (flags & ISBDM_DESC_LS)
			flags |= ISBDM_DESC_TX_ND;

		desc->flags = cpu_to_le32(flags);

		WARN_ON_ONCE(!buf->size);

		desc->length = cpu_to_le16(buf->size - 1);
		ring->prod_idx = (ring->prod_idx + 1) & mask;
	}

	ISBDM_WRITEL(ii, ISBDM_TX_RING_TAIL, ring->prod_idx);
	return;
}

/* Fill the receive ring with fresh descriptors for it to scribble on. */
static void isbdm_rx_refill(struct isbdm *ii)
{
	struct isbdm_ring *ring = &ii->rx_ring;
	u32 mask = ring->size - 1;

	WARN_ON_ONCE(!mutex_is_locked(&ring->lock));
	WARN_ON_ONCE(ring->cons_idx & ~mask);

	/* Fill the whole table. */
	while (((ring->prod_idx + 1) & mask) != ring->cons_idx) {
		struct isbdm_buf *buf = get_buf(ii, ring);
		struct isbdm_descriptor *desc = &ring->entries[ring->prod_idx];

		if (!buf) {
			dev_err(&ii->pdev->dev, "Alloc failure refilling RX");
			break;
		}

		buf->desc_idx = ring->prod_idx;
		desc->iova = cpu_to_le64(buf->physical);
		desc->flags = 0;
		desc->reserved = 0;
		desc->length = 0;
		list_add_tail(&buf->node, &ring->inflight_list);
		ring->prod_idx = (ring->prod_idx + 1) & mask;
	}

	/* Let hardware know about all the yummy buffers. */
	ISBDM_WRITEL(ii, ISBDM_RX_RING_TAIL, ring->prod_idx);
	return;
}

/* Allocate resources associated with a ring, and initialize the struct. */
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

	WARN_ON(ring->physical & ~ISBDM_RING_BASE_ADDR_MASK);

	memset(ring->entries, 0, table_size);
	*base_reg = ring->physical | ISBDM_SIZE_TO_LOG2SZM1(ring->size);
	return 0;
}

/* Free resources associated with a ring. */
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

static int init_rx_ring(struct isbdm *ii)
{
	u64 base;
	u64 ctrl;
	int rc;
	int threshold;

	rc = alloc_ring(ii, &ii->rx_ring, &base);
	if (rc)
		return rc;

	mutex_lock(&ii->rx_ring.lock);
	isbdm_rx_refill(ii);
	mutex_unlock(&ii->rx_ring.lock);
	/* Set up the size of all RX buffers. */
	ISBDM_WRITEQ(ii, ISBDM_RX_RING_BASE, base);
	ctrl = ISBDM_READQ(ii, ISBDM_RX_RING_CTRL);
	ctrl &= ~(ISBDM_RX_RING_CTRL_BUFSIZ_MASK |
		  ISBDM_RX_RING_CTRL_RXRTHR_MASK);

	ctrl |= ISBDM_RX_BUFFER_SIZE_TO_REG(ISBDMEX_BUF_SIZE) <<
		ISBDM_RX_RING_CTRL_BUFSIZ_SHIFT;

	threshold = ISBDMEX_RX_THRESHOLD;
	if (threshold > ISBDM_RX_RING_CTRL_RXRTHR_MAX)
		threshold = ISBDM_RX_RING_CTRL_RXRTHR_MAX;

	ctrl |= threshold << ISBDM_RX_RING_CTRL_RXRTHR_SHIFT;
	ISBDM_WRITEQ(ii, ISBDM_RX_RING_CTRL, ctrl);
	return 0;
}

static void deinit_tx_ring(struct isbdm *ii)
{
	ISBDM_WRITEQ(ii, ISBDM_TX_RING_BASE, 0);
	free_ring(ii, &ii->tx_ring);
	return;
}

static void deinit_rx_ring(struct isbdm *ii)
{
	ISBDM_WRITEQ(ii, ISBDM_RX_RING_BASE, 0);
	free_ring(ii, &ii->rx_ring);
	return;
}

static void enable_tx_ring(struct isbdm *ii)
{
	u64 ctrl = ISBDM_READQ(ii, ISBDM_TX_RING_CTRL);

	ctrl |= ISBDM_RING_CTRL_ENABLE;
	ISBDM_WRITEQ(ii, ISBDM_TX_RING_CTRL, ctrl);
	return;
}

static void enable_rx_ring(struct isbdm *ii)
{
	u64 ctrl = ISBDM_READQ(ii, ISBDM_RX_RING_CTRL);

	ctrl |= ISBDM_RING_CTRL_ENABLE;
	ISBDM_WRITEQ(ii, ISBDM_RX_RING_CTRL, ctrl);
	return;
}

static void disable_tx_ring(struct isbdm *ii)
{
	u64 ctrl = ISBDM_READQ(ii, ISBDM_TX_RING_CTRL);

	ctrl &= ~ISBDM_RING_CTRL_ENABLE;
	ISBDM_WRITEQ(ii, ISBDM_TX_RING_CTRL, ctrl);
	return;
}

static void disable_rx_ring(struct isbdm *ii)
{
	u64 ctrl = ISBDM_READQ(ii, ISBDM_RX_RING_CTRL);

	ctrl &= ~ISBDM_RING_CTRL_ENABLE;
	ISBDM_WRITEQ(ii, ISBDM_RX_RING_CTRL, ctrl);
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

/* Attempt to pull one complete packet off the wait list, if available. */
static int isbdmex_dequeue_one(struct isbdm *ii, struct list_head *head)
{
	struct isbdm_buf *buf = NULL;
	struct list_head *list = &ii->rx_ring.wait_list;

	INIT_LIST_HEAD(head);

	/*
	 * Skip any packets that don't have FS set. In the common case this
	 * should break right away.
	 */
	while (!list_empty(list)) {
		buf = list_first_entry(list, struct isbdm_buf, node);
		if ((buf->flags & ISBDM_DESC_FS) &&
		    !(buf->flags & ISBDM_DESC_SW_POISON))
			break;

		list_del(&buf->node);
		dev_info(&ii->pdev->dev,
			 "Discarding RX fragment flags %x size %zx data %x",
			 buf->flags,
			 buf->size,
			 *(int *)buf->buf);

		put_buf(ii, &ii->rx_ring, buf);
		buf = NULL;
	}

	/* If the list turned out to be empty, return empty handed. */
	if (!buf)
		return 0;

	/* Stick the start on the list to return. */
	list_del(&buf->node);
	list_add_tail(&buf->node, head);

	/* Grab packets until an LS is seen. */
	while (!list_empty(list) && !(buf->flags & ISBDM_DESC_LS)) {
		buf = list_first_entry(list, struct isbdm_buf, node);
		list_del(&buf->node);
		list_add_tail(&buf->node, head);
	}

	/*
	 * If the list drained without finding a last descriptor, then only a
	 * partial packet is availble. Put everything back and wait.
	 */
	if (!(buf->flags & ISBDM_DESC_LS)) {
		list_splice_init(head, list);
		return 0;
	}

	return 1;
}

/* Process and release buffers that the hardware has completed sending. */
void isbdm_reap_tx(struct isbdm *ii)
{
	struct isbdm_ring *ring = &ii->tx_ring;
	u32 mask = ring->size - 1;
	u32 hw_next = ISBDM_READL(ii, ISBDM_TX_RING_HEAD) & mask;

	mutex_lock(&ring->lock);

	WARN_ON_ONCE((ring->cons_idx | ring->prod_idx) & ~mask);

	if ((hw_next > ring->prod_idx) && (ring->cons_idx <= ring->prod_idx)) {
		dev_err(&ii->pdev->dev,
			"TX consumer zoomed %x->%x, through producer %x",
			ring->cons_idx,
			hw_next,
			ring->prod_idx);
	}

	while (ring->cons_idx != hw_next) {
		struct isbdm_buf *buf;

		if (list_empty(&ring->inflight_list)) {
			dev_err(&ii->pdev->dev, "TX inflight underflow");
			break;
		}

		buf = list_first_entry(&ring->inflight_list,
				       struct isbdm_buf, node);

		if (buf->desc_idx != ring->cons_idx) {
			dev_err(&ii->pdev->dev,
				"Reaping wrong TX descriptor: %u != list %u\n",
				ring->cons_idx,
				buf->desc_idx);

			/* TODO: Do something about this, reset tx ring? */
		}

		list_del(&buf->node);
		list_add(&buf->node, &ring->free_list);
		ring->cons_idx = (ring->cons_idx + 1) & mask;
	}

	/* Hopefully more space was made, so jam more in now. */
	isbdm_tx_enqueue(ii);
	mutex_unlock(&ring->lock);
	return;
}

int isbdm_init_hw(struct isbdm *ii)
{
	int rc;

	rc = init_tx_ring(ii);
	if (rc)
		return rc;

	rc = init_rx_ring(ii);
	if (rc)
		return rc;

	return 0;
}

void isbdm_deinit_hw(struct isbdm *ii)
{
	deinit_tx_ring(ii);
	deinit_rx_ring(ii);
	return;
}

void isbdm_enable(struct isbdm *ii)
{
	u64 mask = ISBDM_TXDONE_IRQ | ISBDM_TXMF_IRQ | ISBDM_RXDONE_IRQ |
		   ISBDM_RXOVF_IRQ | ISBDM_RXRTHR_IRQ | ISBDM_RXMF_IRQ;

	enable_interrupt(ii, ISBDM_LNKSTS_IRQ);
	enable_tx_ring(ii);
	enable_rx_ring(ii);
	enable_interrupt(ii, mask);
	return;
}

void isbdm_disable(struct isbdm *ii)
{
	u64 mask = ISBDM_TXDONE_IRQ | ISBDM_TXMF_IRQ | ISBDM_RXDONE_IRQ |
		   ISBDM_RXMF_IRQ | ISBDM_RXOVF_IRQ;

	disable_interrupt(ii, mask);
	disable_rx_ring(ii);
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

/*
 * Turn a transmit request into a set of buffers, and enqueue it onto the
 * hardware or a software waiting list.
 */
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
	while (remaining != 0) {
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
		not_done = copy_from_user(buf->buf, va, buf->size);
		if (not_done != 0) {
			rc = -EFAULT;
			goto out;
		}

		va += buf->size;
		remaining -= buf->size;
		if (remaining == 0) {
			buf->flags |= ISBDM_DESC_LS;
		}

		list_add_tail(&buf->node, &local_list);
	}

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

/* Reap any completed RX descriptors. */
void isbdm_process_rx_done(struct isbdm *ii)
{
	struct isbdm_ring *ring = &ii->rx_ring;
	u32 mask = ring->size - 1;
	u32 hw_next = ISBDM_READL(ii, ISBDM_RX_RING_HEAD) & mask;

	mutex_lock(&ring->lock);

	WARN_ON_ONCE((ring->cons_idx | ring->prod_idx) & ~mask);

	while (ring->cons_idx != hw_next) {
		struct isbdm_buf *buf;
		struct isbdm_descriptor *desc = &ring->entries[ring->cons_idx];

		if (list_empty(&ring->inflight_list)) {
			dev_err(&ii->pdev->dev, "RX inflight underflow");
			break;
		}

		buf = list_first_entry(&ring->inflight_list,
				       struct isbdm_buf, node);

		if ((buf->desc_idx != ring->cons_idx) ||
		    (buf->physical != le64_to_cpu(desc->iova))) {
			dev_err(&ii->pdev->dev,
				"Reaping wrong RX descriptor: %u %llx != list %u %llx\n",
				ring->cons_idx,
				le64_to_cpu(desc->iova),
				buf->desc_idx,
				buf->physical);

			/* TODO: Do something about this, reset rx ring? */
		}

		buf->flags = le32_to_cpu(desc->flags);
		buf->size = le16_to_cpu(desc->length) + 1;
		if (buf->size > buf->capacity) {
			dev_err(&ii->pdev->dev,
				"RX size %zu exceeds capacity %zu\n",
				buf->size,
				buf->capacity);
		}

		list_del(&buf->node);
		list_add_tail(&buf->node, &ring->wait_list);
		ring->cons_idx = (ring->cons_idx + 1) & mask;
	}

	/* If the RX threshold interrupt is not in use, refill now */
	if (!ISBDMEX_RX_THRESHOLD)
		isbdm_rx_refill(ii);

	mutex_unlock(&ring->lock);

	/* Let anybody blocked know there's something to get. */
	wake_up(&ii->read_wait_queue);
	return;
}

void isbdm_rx_overflow(struct isbdm *ii)
{
	struct isbdm_ring *ring = &ii->rx_ring;
	u32 mask = ring->size - 1;
	u32 i;

	/* TODO: Attempt to recover from an overflow. */
	dev_err(&ii->pdev->dev, "RX overflow!");
	mutex_lock(&ring->lock);
	/*
	 * Go backwards from the end and poison any descriptors that are part of
	 * the last packet that got cut off.
	 */
	i = (ISBDM_READL(ii, ISBDM_RX_RING_HEAD) - 1) & mask;
	while ((i != ring->prod_idx) &&
	       (!(ring->entries[i].flags & ISBDM_DESC_LS))) {

		ring->entries[i].flags |= ISBDM_DESC_SW_POISON;
		i = (i - 1) & mask;
	}

	mutex_unlock(&ring->lock);
	return;
}

/* Handle an RX threshold interrupt. */
void isbdm_rx_threshold(struct isbdm *ii)
{
	mutex_lock(&ii->rx_ring.lock);
	isbdm_rx_refill(ii);
	mutex_unlock(&ii->rx_ring.lock);
}

/* Read one message from the wait list and into user mode. */
ssize_t isbdmex_read_one(struct isbdm *ii, char __user *va, size_t size)
{
	struct isbdm_buf *buf, *tmp;
	ssize_t completed = 0;
	LIST_HEAD(packet_list);
	struct isbdm_ring *ring = &ii->rx_ring;

	mutex_lock(&ring->lock);
	if (!isbdmex_dequeue_one(ii, &packet_list)) {
		goto out;
	}

	list_for_each_entry(buf, &packet_list, node) {
		size_t size_to_copy = buf->size;
		int not_done;

		if (size_to_copy > (size - completed))
			size_to_copy = size - completed;

		if (size_to_copy == 0)
			break;

		not_done = copy_to_user(va + completed,
					buf->buf,
					size_to_copy);

		if (not_done != 0) {
			completed = -EFAULT;
			goto out;
		}

		completed += size_to_copy;
	}

out:
	/*
	 * Release all buffers in this packet, regardless of how much the user
	 * actually read. You only get one shot!
	 */
	list_for_each_entry_safe(buf, tmp, &packet_list, node) {
		put_buf(ii, ring, buf);
	}

	mutex_unlock(&ring->lock);
	return completed;
}

/* ioctl for testing that allows usermode to alter the interrupt mask. */
u64 isbdmex_ioctl_set_ipmr(struct isbdm *ii, u64 mask)
{
	u64 old_value = ISBDM_READQ(ii, ISBDM_IPMR);

	ISBDM_WRITEQ(ii, ISBDM_IPMR, old_value | mask);
	return old_value;
}

u64 isbdmex_ioctl_clear_ipmr(struct isbdm *ii, u64 mask)
{
	u64 old_value = ISBDM_READQ(ii, ISBDM_IPMR);

	ISBDM_WRITEQ(ii, ISBDM_IPMR, old_value & ~mask);
	return old_value;
}

u64 isbdmex_ioctl_get_ipsr(struct isbdm *ii)
{
	return ISBDM_READQ(ii, ISBDM_IPSR);
}

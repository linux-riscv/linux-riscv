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
#include <linux/ioasid.h>
#include <linux/iopoll.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/pci.h>
#include <linux/sched.h>

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

static struct isbdm_command *alloc_cmd(struct isbdm *ii)
{
	struct isbdm_command *cmd = kzalloc(sizeof(struct isbdm_command),
					    GFP_KERNEL);

	if (!cmd)
		return NULL;

	return cmd;
}

static void free_cmd(struct isbdm *ii, struct isbdm_command *cmd)
{
	kfree(cmd);
}

static void free_cmd_list(struct isbdm *ii, struct list_head *head)
{
	struct isbdm_command *cur, *tmp;

	list_for_each_entry_safe(cur, tmp, head, node) {
		free_cmd(ii, cur);
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

static struct isbdm_command *get_cmd(struct isbdm *ii, struct isbdm_ring *ring)
{
	struct isbdm_command *command;

	WARN_ON_ONCE(!mutex_is_locked(&ring->lock));

	if (!list_empty(&ring->free_list)) {
		command = list_first_entry(&ring->free_list,
					   struct isbdm_command, node);

		list_del(&command->node);
		return command;
	}

	return alloc_cmd(ii);
}

/* Put a command onto the free list. Assumes the ring's lock is held. */
static void put_cmd(struct isbdm *ii, struct isbdm_ring *ring,
		    struct isbdm_command *cmd)
{

	WARN_ON_ONCE(!mutex_is_locked(&ring->lock));

	list_add(&cmd->node, &ring->free_list);
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
		desc = &ring->descs[ring->prod_idx];
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

/* Start as many commands as fit in the hardware table. */
static void isbdm_cmd_enqueue(struct isbdm *ii)
{
	struct isbdm_command *cmd;
	struct isbdm_rdma_command *cmd_desc;
	struct isbdm_ring *ring = &ii->cmd_ring;
	u32 mask = ring->size - 1;

	WARN_ON_ONCE(!mutex_is_locked(&ring->lock));

	if (list_empty(&ring->wait_list))
		return;

	/* Add as many to the cmd ring as possible. */
	while (!list_empty(&ring->wait_list) &&
	       !ring_is_full(ring)) {

		cmd = list_first_entry(&ring->wait_list,
				       struct isbdm_command, node);

		list_del(&cmd->node);
		list_add_tail(&cmd->node, &ring->inflight_list);
		cmd->cmd.notify_iova = ii->notify_area_physical +
				       (ring->prod_idx * sizeof(u32));

		cmd->desc_idx = ring->prod_idx;
		cmd_desc = &ring->cmds[ring->prod_idx];
		/* Assumed to already be valid since it made it in the queue */
		memcpy(cmd_desc, &cmd->cmd, sizeof(*cmd_desc));
		ring->prod_idx = (ring->prod_idx + 1) & mask;
	}

	ISBDM_WRITEL(ii, ISBDM_CMD_RING_TAIL, ring->prod_idx);
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
		struct isbdm_descriptor *desc = &ring->descs[ring->prod_idx];

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
static int alloc_ring(struct isbdm *ii, struct isbdm_ring *ring,
		      size_t element_size, u64 *base_reg)
{
	size_t table_size;

	INIT_LIST_HEAD(&ring->wait_list);
	INIT_LIST_HEAD(&ring->inflight_list);
	INIT_LIST_HEAD(&ring->free_list);
	mutex_init(&ring->lock);
	ring->size = ISBDMEX_RING_SIZE;
	ring->element_size = element_size;
	table_size = ring->size * element_size;
	ring->descs = dma_alloc_coherent(&ii->pdev->dev, table_size,
					 &ring->physical, GFP_KERNEL);
	if (!ring->descs)
		return -ENOMEM;

	WARN_ON(ring->physical & ~ISBDM_RING_BASE_ADDR_MASK);

	memset(ring->descs, 0, table_size);
	*base_reg = ring->physical | ISBDM_SIZE_TO_LOG2SZM1(ring->size);
	return 0;
}

/* Free resources associated with a ring. */
static void free_ring(struct isbdm *ii, struct isbdm_ring *ring)
{
	if (ring->descs) {
		size_t table_size;

		table_size = ring->size * ring->element_size;
		dma_free_coherent(&ii->pdev->dev, table_size, ring->descs,
				  ring->physical);

		ring->descs = NULL;
	}

	if (ring->element_size == sizeof(struct isbdm_rdma_command)) {
		free_cmd_list(ii, &ring->wait_list);
		free_cmd_list(ii, &ring->inflight_list);
		free_cmd_list(ii, &ring->free_list);

	} else {
		free_buf_list(ii, &ring->wait_list);
		free_buf_list(ii, &ring->inflight_list);
		free_buf_list(ii, &ring->free_list);
	}

	return;
}

static int init_tx_ring(struct isbdm *ii)
{
	u64 base;
	int rc;

	rc = alloc_ring(ii, &ii->tx_ring, sizeof(struct isbdm_descriptor),
			&base);
	if (rc)
		return rc;

	ISBDM_WRITEQ(ii, ISBDM_TX_RING_BASE, base);
	return 0;
}

static int init_cmd_ring(struct isbdm *ii)
{
	u64 base;
	int rc;

	rc = alloc_ring(ii, &ii->cmd_ring, sizeof(struct isbdm_rdma_command),
			&base);
	if (rc)
		return rc;

	ISBDM_WRITEQ(ii, ISBDM_CMD_RING_BASE, base);
	return 0;
}

static int init_rmb_table(struct isbdm *ii)
{
	size_t alloc_size;
	size_t table_size;
	u64 base;

	/*
	 * In addition to allocating the remote memory buffer array here, also
	 * allocate an array running parallel to the command ring that contains
	 * space for the notify result from the hardware for each command
	 * descriptor. This result is written untranslated, but not using the
	 * PASID of the command itself. So it's a physical address. We can
	 * either dedicate some space in the kernel for the notify write, or
	 * enforce that some region of memory handed to us by usermode will not
	 * go away until the command is complete. For now we've opted for the
	 * simpler option of just dedicating space here and forwarding the write
	 * onto usermode when the command descriptor is reaped.
	 */
	table_size = sizeof(struct isbdm_remote_buffer) *
		     ISBDMEX_RMB_TABLE_SIZE;

	alloc_size = table_size + (sizeof(u32) * ISBDMEX_RING_SIZE);
	ii->rmb_table = dma_alloc_coherent(&ii->pdev->dev, alloc_size,
					   &ii->rmb_table_physical, GFP_KERNEL);

	if (!ii->rmb_table)
		return -ENOMEM;

	base = ii->rmb_table_physical |
	       ISBDM_SIZE_TO_LOG2SZM1(ISBDMEX_RMB_TABLE_SIZE);

	ISBDM_WRITEQ(ii, ISBDM_RMBA_BASE, base);
	mutex_init(&ii->rmb_table_lock);
	ii->notify_area = (u32 *)(ii->rmb_table + ISBDMEX_RMB_TABLE_SIZE);
	ii->notify_area_physical = ii->rmb_table_physical + table_size;
	return 0;
}

static int init_rx_ring(struct isbdm *ii)
{
	u64 base;
	u64 ctrl;
	int rc;
	int threshold;

	rc = alloc_ring(ii, &ii->rx_ring, sizeof(struct isbdm_descriptor),
			&base);
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

static void deinit_cmd_ring(struct isbdm *ii)
{
	ISBDM_WRITEQ(ii, ISBDM_CMD_RING_BASE, 0);
	free_ring(ii, &ii->cmd_ring);
	return;
}

static void deinit_rmb_table(struct isbdm *ii)
{
	ISBDM_WRITEQ(ii, ISBDM_RMBA_BASE, 0);
	if (ii->rmb_table) {
		size_t table_size;

		table_size = sizeof(struct isbdm_remote_buffer) *
			     ISBDMEX_RMB_TABLE_SIZE;

		dma_free_coherent(&ii->pdev->dev, table_size, ii->rmb_table,
				  ii->rmb_table_physical);

		ii->rmb_table = NULL;
		ii->notify_area = NULL;
	}

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

static void enable_cmd_ring(struct isbdm *ii)
{
	u64 ctrl = ISBDM_READQ(ii, ISBDM_CMD_RING_CTRL);

	ctrl |= ISBDM_RING_CTRL_ENABLE;
	ISBDM_WRITEQ(ii, ISBDM_CMD_RING_CTRL, ctrl);
	ctrl = ISBDM_READQ(ii, ISBDM_RMBA_CTRL);
	ctrl |= ISBDM_RING_CTRL_ENABLE;
	ISBDM_WRITEQ(ii, ISBDM_RMBA_CTRL, ctrl);
	return;
}

static void disable_ring(struct isbdm *ii, size_t ctrl_reg)
{
	u64 ctrl = ISBDM_READQ(ii, ctrl_reg);
	int rc;

	if (!(ctrl & ISBDM_RING_CTRL_ENABLE))
		return;

	ctrl &= ~ISBDM_RING_CTRL_ENABLE;
	ISBDM_WRITEQ(ii, ctrl_reg, ctrl);
	rc = readq_poll_timeout(ii->base + ctrl_reg, ctrl,
				!(le64_to_cpu(ctrl) & ISBDM_RING_CTRL_BUSY),
				100, 50000);

	if (rc)
		dev_err(&ii->pdev->dev, "Failed to gracefully stop ring");
}

static void disable_tx_ring(struct isbdm *ii)
{
	disable_ring(ii, ISBDM_TX_RING_CTRL);
	return;
}

static void disable_rx_ring(struct isbdm *ii)
{
	disable_ring(ii, ISBDM_RX_RING_CTRL);
	return;
}

static void disable_cmd_ring(struct isbdm *ii)
{
	disable_ring(ii, ISBDM_CMD_RING_CTRL);
	disable_ring(ii, ISBDM_RMBA_CTRL);
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

/* Process and release commands that the hardware has completed. */
void isbdm_reap_cmds(struct isbdm *ii)
{
	struct isbdm_ring *ring = &ii->cmd_ring;
	u32 mask = ring->size - 1;
	u32 hw_next = ISBDM_READL(ii, ISBDM_CMD_RING_HEAD) & mask;

	mutex_lock(&ring->lock);

	WARN_ON_ONCE((ring->cons_idx | ring->prod_idx) & ~mask);

	if ((hw_next > ring->prod_idx) && (ring->cons_idx <= ring->prod_idx)) {
		dev_err(&ii->pdev->dev,
			"command consumer zoomed %x->%x, through producer %x",
			ring->cons_idx,
			hw_next,
			ring->prod_idx);
	}

	while (ring->cons_idx != hw_next) {
		struct isbdm_command *command;

		if (list_empty(&ring->inflight_list)) {
			dev_err(&ii->pdev->dev, "command inflight underflow");
			break;
		}

		command = list_first_entry(&ring->inflight_list,
					   struct isbdm_command, node);

		if (command->desc_idx != ring->cons_idx) {
			dev_err(&ii->pdev->dev,
				"Reaping wrong cmd descriptor: %u != list %u\n",
				ring->cons_idx,
				command->desc_idx);

			/* TODO: Do something about this, reset command ring? */
		}

		list_del(&command->node);
		/* Shuttle the notify result back to the file context. */
		if (le64_to_cpu(command->cmd.size_pasid_flags) &
		    ISBDM_RDMA_NV) {

			uint32_t status = ii->notify_area[command->desc_idx];

			/* Write the error back if it was the first. */
			if ((status != ISBDM_STATUS_SUCCESS) &&
			    (command->user_ctx->last_error.error ==
			     ISBDM_STATUS_SUCCESS)) {

				command->user_ctx->last_error.error =
					le32_to_cpu(status);

				/*
				 * Ensure the error gets out before decrementing
				 * inflight command count.
				 */
				smp_wmb();
			}
		}

		WARN_ON_ONCE(!command->user_ctx->last_error.inflight_commands);

		command->user_ctx->last_error.inflight_commands--;
		kref_put(&command->user_ctx->ref, isbdmex_user_ctx_release);
		command->user_ctx = NULL;
		list_add(&command->node, &ring->free_list);
		ring->cons_idx = (ring->cons_idx + 1) & mask;
	}

	/* Hopefully more space was made, so jam more in now. */
	isbdm_cmd_enqueue(ii);
	mutex_unlock(&ring->lock);
	return;
}

int isbdm_init_hw(struct isbdm *ii)
{
	int rc;

	rc = init_tx_ring(ii);
	if (rc)
		return rc;

	rc = init_cmd_ring(ii);
	if (rc)
		return rc;

	rc = init_rmb_table(ii);
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
	deinit_cmd_ring(ii);
	deinit_rmb_table(ii);
	deinit_rx_ring(ii);
	return;
}

void isbdm_enable(struct isbdm *ii)
{
	u64 mask = ISBDM_TXDONE_IRQ | ISBDM_TXMF_IRQ | ISBDM_RXDONE_IRQ |
		   ISBDM_RXOVF_IRQ | ISBDM_RXRTHR_IRQ | ISBDM_RXMF_IRQ |
		   ISBDM_CMDDONE_IRQ | ISBDM_CMDMF_IRQ;

	enable_interrupt(ii, ISBDM_LNKSTS_IRQ);
	enable_tx_ring(ii);
	enable_cmd_ring(ii);
	enable_rx_ring(ii);
	enable_interrupt(ii, mask);
	return;
}

void isbdm_disable(struct isbdm *ii)
{
	disable_interrupt(ii, ISBDM_ALL_IRQ_MASK);
	disable_rx_ring(ii);
	disable_cmd_ring(ii);
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

/* Submit an RDMA command from userspace */
int isbdmex_send_command(struct isbdm *ii, struct isbdm_user_ctx *user_ctx,
			 const char __user *user_cmd)
{
	struct isbdm_command *command;
	struct task_struct *task = get_current();
	int not_done;
	uint64_t pasid = task->mm->pasid;
	int rc;
	uint64_t value;

	if (pasid == INVALID_IOASID) {
		dev_err(&ii->pdev->dev, "Current process doesn't have PASID\n");
		return -EAGAIN;
	}

	mutex_lock(&ii->cmd_ring.lock);
	command = get_cmd(ii, &ii->cmd_ring);
	if (!command) {
		rc = -ENOMEM;
		goto out;
	}

	not_done = copy_from_user(&command->cmd, user_cmd,
				  sizeof(command->cmd));

	if (not_done != 0) {
		rc = -EFAULT;
		goto out;
	}

	value = le64_to_cpu(command->cmd.size_pasid_flags);
	/* Take the size and notify flag from usermode, leave everything else */
	value &= ISBDM_RDMA_SIZE_MASK | ISBDM_RDMA_NV;
	value |= ISBDM_RDMA_PV;
	if (pasid > ISBDM_RDMA_PASID_MASK) {
		dev_err(&ii->pdev->dev, "PASID out of range\n");
		rc = -ERANGE;
		goto out;
	}

	value |= pasid << ISBDM_RDMA_PASID_SHIFT;
	command->cmd.size_pasid_flags = cpu_to_le64(value);

	/* Make sure sure usermode isn't trying to set reserved bits. */
	value = le64_to_cpu(command->cmd.rmb_offset);
	if (value > ISBDM_RDMA_RMB_OFFSET_MASK) {
		dev_err(&ii->pdev->dev, "RMB offset out of range\n");
		rc = -ERANGE;
		goto out;
	}

	value = le64_to_cpu(command->cmd.rmbi_command);
	if (value & ISBDM_RDMA_RMBI_RESERVED_MASK) {
		dev_err(&ii->pdev->dev, "RMBI/command reserved bits set\n");
		rc = -ERANGE;
		goto out;
	}

	/*
	 * Save the file context along with the command so the status can be
	 * returned.
	 */
	user_ctx->last_error.inflight_commands++;
	command->user_ctx = user_ctx;
	kref_get(&user_ctx->ref);
	command->cmd.notify_iova = 0;
	list_add_tail(&command->node, &ii->cmd_ring.wait_list);
	isbdm_cmd_enqueue(ii);
	rc = 0;

out:
	if (rc && command)
		put_cmd(ii, &ii->cmd_ring, command);

	mutex_unlock(&ii->cmd_ring.lock);
	return rc;
}

/*
 * Create a new remote memory buffer for potential use by ISBDM. Returns the RMB
 * index on success.
 */
int isbdmex_alloc_rmb(struct isbdm *ii, struct file *file,
		      const char __user *user_rmb)
{
	struct task_struct *task = get_current();
	int idx;
	int not_done;
	uint64_t pasid = task->mm->pasid;
	struct isbdm_remote_buffer rbcopy;
	uint64_t value;

	if (pasid == INVALID_IOASID) {
		dev_err(&ii->pdev->dev, "Current process doesn't have PASID\n");
		return -EAGAIN;
	}

	if (pasid > ISBDM_REMOTE_BUF_PASID_MASK) {
		dev_err(&ii->pdev->dev, "PASID out of range\n");
		return -ERANGE;
	}

	not_done = copy_from_user(&rbcopy, user_rmb, sizeof(rbcopy));
	if (not_done != 0)
		return -EFAULT;

	/* Let usermode control only the W bit in pasid_flags. */
	value = le64_to_cpu(rbcopy.pasid_flags);
	value &= ISBDM_REMOTE_BUF_W;
	value |= ISBDM_REMOTE_BUF_PV | pasid;
	rbcopy.pasid_flags = cpu_to_le64(value);
	/* Stick the file in to know which entries to clean up on close. */
	rbcopy.sw_avail = cpu_to_le64((unsigned long)file);

	/* Hunt for a free entry in the hardware. */
	mutex_lock(&ii->rmb_table_lock);
	for (idx = 0; idx < ISBDMEX_RMB_TABLE_SIZE; idx++) {
		if (ii->rmb_table[idx].sw_avail == 0) {
			memcpy(&ii->rmb_table[idx], &rbcopy, sizeof(rbcopy));
			break;
		}
	}

	mutex_unlock(&ii->rmb_table_lock);
	if (idx == ISBDMEX_RMB_TABLE_SIZE)
		return -ENOSPC;

	return idx;
}

/* Free a previously allocated remote memory buffer */
int isbdmex_free_rmb(struct isbdm *ii, struct file *file, int rmbi)
{
	int rc = -ENOENT;
	__le64 token = cpu_to_le64((unsigned long)file);

	if (rmbi > ISBDMEX_RMB_TABLE_SIZE) {
		dev_err(&ii->pdev->dev, "RMB index %u out of range\n", rmbi);
		return -ERANGE;
	}

	mutex_lock(&ii->rmb_table_lock);
	if (ii->rmb_table[rmbi].sw_avail == token) {
		/* Invert the security key first to prevent torn reads */
		ii->rmb_table[rmbi].security_key =
			~ii->rmb_table[rmbi].security_key;

		wmb();
		memset(&ii->rmb_table[rmbi], 0, sizeof(ii->rmb_table[rmbi]));
		rc = 0;
	}

	mutex_unlock(&ii->rmb_table_lock);
	return rc;
}

/* Free all remote memory buffers associated with this file. */
void isbdm_free_all_rmbs(struct isbdm *ii, struct file *file)
{
	int idx;

	__le64 token = cpu_to_le64((unsigned long)file);
	mutex_lock(&ii->rmb_table_lock);
	for (idx = 0; idx < ISBDMEX_RMB_TABLE_SIZE; idx++) {
		if (ii->rmb_table[idx].sw_avail == token) {
			/*
			 * Invert the security key first to prevent torn reads
			 */
			ii->rmb_table[idx].security_key =
				~ii->rmb_table[idx].security_key;
			wmb();

			memset(&ii->rmb_table[idx], 0,
			       sizeof(ii->rmb_table[idx]));
		}
	}

	mutex_unlock(&ii->rmb_table_lock);
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
		struct isbdm_descriptor *desc = &ring->descs[ring->cons_idx];

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
	       (!(ring->descs[i].flags & ISBDM_DESC_LS))) {

		ring->descs[i].flags |= ISBDM_DESC_SW_POISON;
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

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
struct isbdm_buf *get_buf(struct isbdm *ii, struct isbdm_ring *ring)
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
void put_buf(struct isbdm *ii, struct isbdm_ring *ring, struct isbdm_buf *buf)
{

	WARN_ON_ONCE(!mutex_is_locked(&ring->lock));

	list_add(&buf->node, &ring->free_list);
}

struct isbdm_command *get_cmd(struct isbdm *ii, struct isbdm_ring *ring)
{
	struct isbdm_command *command;

	WARN_ON_ONCE(!mutex_is_locked(&ring->lock));

	if (!list_empty(&ring->free_list)) {
		command = list_first_entry(&ring->free_list,
					   struct isbdm_command, node);

		list_del(&command->node);
		command->user_ctx = NULL;
		command->qp = NULL;
		command->inline_dma_addr = 0;
		return command;
	}

	return alloc_cmd(ii);
}

/* Put a command onto the free list. Assumes the ring's lock is held. */
void put_cmd(struct isbdm *ii, struct isbdm_ring *ring,
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
void isbdm_tx_enqueue(struct isbdm *ii)
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
		flags = buf->flags;
		if (flags & ISBDM_DESC_LS)
			flags |= ISBDM_DESC_TX_ND;

		desc->flags = cpu_to_le32(flags);

		WARN_ON_ONCE(!buf->size);

		desc->length = cpu_to_le32(buf->size & ISBDM_DESC_SIZE_MASK);
		ring->prod_idx = (ring->prod_idx + 1) & mask;
	}

	ISBDM_WRITEL(ii, ISBDM_TX_RING_TAIL, ring->prod_idx);
	return;
}

/* Start as many commands as fit in the hardware table. */
void isbdm_cmd_enqueue(struct isbdm *ii)
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
	u32 count = 0;

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
		desc->length = 0;
		list_add_tail(&buf->node, &ring->inflight_list);
		ring->prod_idx = (ring->prod_idx + 1) & mask;
		count++;
	}

	dev_dbg(&ii->pdev->dev, "%s: Added %u descriptors\n", __func__, count);
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

	/* HW only does a head/tail reset on a rising edge of ENABLE. */
	WARN_ON_ONCE(ctrl & ISBDM_RING_CTRL_ENABLE);

	ctrl |= ISBDM_RING_CTRL_ENABLE;
	ii->tx_ring.prod_idx = 0;
	ii->tx_ring.cons_idx = 0;
	ISBDM_WRITEQ(ii, ISBDM_TX_RING_CTRL, ctrl);
	return;
}

static void enable_rx_ring(struct isbdm *ii)
{
	u64 ctrl = ISBDM_READQ(ii, ISBDM_RX_RING_CTRL);

	/* HW only does a head/tail reset on a rising edge of ENABLE. */
	WARN_ON_ONCE(ctrl & ISBDM_RING_CTRL_ENABLE);

	ctrl |= ISBDM_RING_CTRL_ENABLE;
	ii->rx_ring.cons_idx = 0;
	ii->rx_ring.prod_idx = 0;
	ISBDM_WRITEQ(ii, ISBDM_RX_RING_CTRL, ctrl);
	return;
}

static void enable_cmd_ring(struct isbdm *ii)
{
	u64 ctrl = ISBDM_READQ(ii, ISBDM_CMD_RING_CTRL);

	/* HW only does a head/tail reset on a rising edge of ENABLE. */
	WARN_ON_ONCE(ctrl & ISBDM_RING_CTRL_ENABLE);

	ctrl |= ISBDM_RING_CTRL_ENABLE;
	ii->cmd_ring.cons_idx = 0;
	ii->cmd_ring.prod_idx = 0;
	ISBDM_WRITEQ(ii, ISBDM_CMD_RING_CTRL, ctrl);
	ctrl = ISBDM_READQ(ii, ISBDM_RMBA_CTRL);

	WARN_ON_ONCE(ctrl & ISBDM_RING_CTRL_ENABLE);

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
	u64 new_mask = ii->irq_mask & ~mask;

	if (ii->irq_mask != new_mask) {
		ii->irq_mask &= ~mask;
		ISBDM_WRITEQ(ii, ISBDM_IPMR, ii->irq_mask);
	}

	return;
}

static void disable_interrupt(struct isbdm *ii, u64 mask)
{
	u64 new_mask = ii->irq_mask | mask;

	if (ii->irq_mask != new_mask) {
		ii->irq_mask |= mask;
		ISBDM_WRITEQ(ii, ISBDM_IPMR, ii->irq_mask);
	}

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

/*
 * Get the dropped packet count, maintaining higher bits in software. Assumes
 * the RX ring's lock is already held.
 */
static u64 get_dropped_rx_count(struct isbdm *ii)
{
	u64 hw_count = ISBDM_READQ(ii, ISBDM_RX_TLP_DROP_CNT);

	/* If the high bit has changed, update the software bits. */
	if ((hw_count ^ ii->dropped_rx_tlps) & ISBDM_RX_TLP_DROP_CTR_HIGH_BIT) {
		ii->dropped_rx_tlps += ISBDM_RX_TLP_DROP_CTR_HIGH_BIT;

	/*
	 * If we didn't observe a high bit change but the value went down,
	 * either we missed an update or the hardware counter did something
	 * unexpected.
	 */
	} else if (hw_count < ii->dropped_rx_tlps) {
		dev_warn(&ii->pdev->dev,
			 "RX drop counter went backwards from %llx -> %llx\n",
			 ii->dropped_rx_tlps & ISBDM_RX_TLP_DROP_CTR_MASK,
			 hw_count);
	}

	ii->dropped_rx_tlps =
		(ii->dropped_rx_tlps & ~ISBDM_RX_TLP_DROP_CTR_MASK) | hw_count;

	return ii->dropped_rx_tlps;
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

/* Handle a single completed command. */
static void isbdm_complete_cmd(struct isbdm *ii, struct isbdm_command *command,
			       u32 status)
{
	struct isbdm_user_ctx *user_ctx = command->user_ctx;

	if (user_ctx) {
		/* Shuttle the notify result back to the file context. */
		if ((status != ISBDM_STATUS_SUCCESS) &&
		    (user_ctx->last_error.error == ISBDM_STATUS_SUCCESS)) {

			user_ctx->last_error.error = status;

			/*
			 * Ensure the error gets out before decrementing
			 * inflight command count.
			 */
			smp_wmb();
		}

		WARN_ON_ONCE(!user_ctx->last_error.inflight_commands);

		user_ctx->last_error.inflight_commands--;
		kref_put(&user_ctx->ref, isbdmex_user_ctx_release);
		command->user_ctx = NULL;

	} else {
		isbdm_complete_rdma_cmd(ii, command, status);
	}

	list_add(&command->node, &ii->cmd_ring.free_list);
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
		u64 size_pasid_flags;
		u32 status = ISBDM_STATUS_SUCCESS;

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
		size_pasid_flags = le64_to_cpu(command->cmd.size_pasid_flags);
		if (size_pasid_flags & ISBDM_RDMA_NV)
			status = ii->notify_area[command->desc_idx];

		isbdm_complete_cmd(ii, command, status);
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

static void isbdm_enable(struct isbdm *ii)
{
	u64 mask = ISBDM_TXDONE_IRQ | ISBDM_TXMF_IRQ | ISBDM_RXDONE_IRQ |
		   ISBDM_RXOVF_IRQ | ISBDM_RXRTHR_IRQ | ISBDM_RXMF_IRQ |
		   ISBDM_CMDDONE_IRQ | ISBDM_CMDMF_IRQ;

	/* Clear out any old interrupts (except LNKSTS, we want that). */
	ISBDM_WRITEQ(ii, ISBDM_IPSR, mask);
	enable_tx_ring(ii);
	enable_cmd_ring(ii);
	enable_rx_ring(ii);
	enable_interrupt(ii, mask | ISBDM_LNKSTS_IRQ);
	return;
}

void isbdm_disable(struct isbdm *ii)
{
	/* Disable all interrupts except LNKSTS. */
	disable_interrupt(ii, (ISBDM_ALL_IRQ_MASK & ~ISBDM_LNKSTS_IRQ));
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

/* Submit an RDMA command from userspace */
int isbdmex_send_command(struct isbdm *ii, struct isbdm_user_ctx *user_ctx,
			 const void __user *user_cmd)
{
	struct isbdm_command *command;
	struct task_struct *task = get_current();
	int not_done;
	uint64_t pasid = task->mm->pasid;
	int rc;
	uint64_t value;

	if (pasid == IOMMU_PASID_INVALID) {
		dev_err(&ii->pdev->dev, "Current process doesn't have PASID\n");
		return -EAGAIN;
	}

	mutex_lock(&ii->cmd_ring.lock);
	if (ii->link_status == ISBDM_LINK_DOWN) {
		rc = -ENOTCONN;
		goto out;
	}

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
	if (value & ISBDM_RDMA_RMB_OFFSET_RESERVED) {
		dev_err(&ii->pdev->dev, "RMB offset reserved bits set\n");
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
		      const void __user *user_rmb)
{
	struct task_struct *task = get_current();
	int not_done;
	uint64_t pasid = task->mm->pasid;
	struct isbdm_remote_buffer rbcopy;
	uint64_t value;

	if (pasid == IOMMU_PASID_INVALID) {
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
	return isbdm_alloc_rmb(ii, &rbcopy);
}

/*
 * Create a new remote memory buffer for potential use by ISBDM. Returns the RMB
 * index on success.
 */
int isbdm_alloc_rmb(struct isbdm *ii, struct isbdm_remote_buffer *rmb)
{
	int idx;

	/* This member being zero is representative of a free slot. */
	WARN_ON_ONCE(rmb->sw_avail == 0);

	/* Hunt for a free entry in the hardware. */
	mutex_lock(&ii->rmb_table_lock);
	for (idx = 0; idx < ISBDMEX_RMB_TABLE_SIZE; idx++) {
		if (ii->rmb_table[idx].sw_avail == 0) {
			memcpy(&ii->rmb_table[idx], rmb, sizeof(*rmb));
			break;
		}
	}

	mutex_unlock(&ii->rmb_table_lock);
	if (idx == ISBDMEX_RMB_TABLE_SIZE)
		return -ENOSPC;

	return idx;
}

void isbdm_set_rmb_key(struct isbdm *ii, int rmbi, u64 key)
{
	if (WARN_ON_ONCE(rmbi >= ISBDMEX_RMB_TABLE_SIZE))
		return;

	WRITE_ONCE(ii->rmb_table[rmbi].security_key, cpu_to_le64(key));
	smp_wmb();
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

	if (ii->rmb_table[rmbi].sw_avail == token) {
		isbdm_free_rmb(ii, rmbi);
		rc = 0;
	}

	return rc;
}

/* Unconditionally free the RMB at the given index. */
void isbdm_free_rmb(struct isbdm *ii, int rmbi)
{
	mutex_lock(&ii->rmb_table_lock);

	/*
	 * Invert the security key first to prevent the remote reading a
	 * half-zeroed value
	 */
	ii->rmb_table[rmbi].security_key =
		~ii->rmb_table[rmbi].security_key;

	wmb();
	memset(&ii->rmb_table[rmbi], 0, sizeof(ii->rmb_table[rmbi]));
	mutex_unlock(&ii->rmb_table_lock);
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
		buf->size = le32_to_cpu(desc->length) & ISBDM_DESC_SIZE_MASK;
		if (buf->size > buf->capacity) {
			dev_err(&ii->pdev->dev,
				"RX size %zu exceeds capacity %zu\n",
				buf->size,
				buf->capacity);
		}

		list_del(&buf->node);
		list_add_tail(&buf->node, &ring->wait_list);
		ring->cons_idx = (ring->cons_idx + 1) & mask;
		if (buf->flags & ISBDM_DESC_FS) {
			ii->packet_start = buf;
		}

		if (buf->flags & ISBDM_DESC_LS) {
			isbdm_process_rx_packet(ii, ii->packet_start, buf);
			ii->packet_start = NULL;
		}
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

	/*
	 * The dropped RX TLP counter just went up for sure. read it to avoid
	 * missing a rollover of the high bit and losing rollovers.
	 */
	get_dropped_rx_count(ii);
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

/* Attempt to bring up the ISBDM link. */
static void isbdm_connect(struct isbdm *ii)
{
	isbdm_enable(ii);
	/* Refill RX since it was drained on disconnect. */
	isbdm_rx_threshold(ii);
}

/* Cancel and flush all pending TX transfers. */
static void isbdm_abort_tx(struct isbdm *ii)
{
	struct isbdm_ring *ring = &ii->tx_ring;
	u32 mask = ring->size - 1;
	struct isbdm_buf *buf, *tmp;
	u32 end_idx;
	u32 count = 0;

	mutex_lock(&ring->lock);
	end_idx = ring->prod_idx;

	WARN_ON_ONCE((ring->cons_idx | ring->prod_idx) & ~mask);

	while (ring->cons_idx != end_idx) {
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
		}

		list_del(&buf->node);
		list_add(&buf->node, &ring->free_list);
		ring->cons_idx = (ring->cons_idx + 1) & mask;
		count++;
	}

	if (!list_empty(&ring->inflight_list)) {
		dev_err(&ii->pdev->dev,
			"Reaped %u TX descriptors, but inflight list leaked.\n",
			count);

		INIT_LIST_HEAD(&ring->inflight_list);
	}

	/* Also discard any TX packets that didn't make it into hardware. */
	list_for_each_entry_safe(buf, tmp, &ring->wait_list, node) {
		put_buf(ii, ring, buf);
		count++;
	}

	if (count)
		dev_info(&ii->pdev->dev, "Dropped %u TX packets\n", count);

	mutex_unlock(&ring->lock);
	return;
}

/* Remove all RX descriptors from the ring */
static void isbdm_abort_rx(struct isbdm *ii)
{
	struct isbdm_ring *ring = &ii->rx_ring;
	struct isbdm_buf *buf, *tmp;
	u32 end_idx;
	u32 count = 0;
	u32 mask = ring->size - 1;

	mutex_lock(&ring->lock);
	end_idx = ring->prod_idx;

	WARN_ON_ONCE((ring->cons_idx | ring->prod_idx) & ~mask);

	while (ring->cons_idx != end_idx) {
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
		}

		list_del(&buf->node);
		put_buf(ii, ring, buf);
		ring->cons_idx = (ring->cons_idx + 1) & mask;
		count++;
	}

	ii->packet_start = NULL;
	if (!list_empty(&ring->inflight_list)) {
		dev_err(&ii->pdev->dev,
			"Reaped %u RX descriptors, but inflight list leaked.\n",
			count);

		INIT_LIST_HEAD(&ring->inflight_list);
	}

	/* Also discard any completed RX packets waiting to be read. */
	list_for_each_entry_safe(buf, tmp, &ring->wait_list, node) {
		put_buf(ii, ring, buf);
		count++;
	}

	dev_dbg(&ii->pdev->dev, "Reaped %u RX descriptors\n", count);
	mutex_unlock(&ring->lock);

	/* Let anybody blocked know there's now nothing to get. */
	wake_up(&ii->read_wait_queue);
	return;
}

/* Abort and completing any in-flight or queued RDMA commands. */
static void isbdm_abort_cmds(struct isbdm *ii)
{
	struct isbdm_ring *ring = &ii->cmd_ring;
	struct isbdm_command *command, *tmp;
	u32 mask = ring->size - 1;
	u32 count = 0;
	u32 end_idx;

	mutex_lock(&ring->lock);
	end_idx = ring->prod_idx;

	WARN_ON_ONCE((ring->cons_idx | ring->prod_idx) & ~mask);

	while (ring->cons_idx != end_idx) {
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
		}

		list_del(&command->node);
		isbdm_complete_cmd(ii, command, ISBDM_STATUS_ABORTED);
		ring->cons_idx = (ring->cons_idx + 1) & mask;
		count++;
	}

	if (!list_empty(&ring->inflight_list)) {
		dev_err(&ii->pdev->dev,
			"Reaped %u RDMA commands, but inflight list leaked.\n",
			count);

		INIT_LIST_HEAD(&ring->inflight_list);
	}

	/* Also discard any commands waiting to make it into the hardware. */
	list_for_each_entry_safe(command, tmp, &ring->wait_list, node) {
		isbdm_complete_cmd(ii, command, ISBDM_STATUS_ABORTED);
		count++;
	}

	if (count)
		dev_info(&ii->pdev->dev, "Dropped %u RDMA commands\n", count);

	mutex_unlock(&ring->lock);
	return;
}

/*
 * Tear down the ISBDM communcation channel. Must result in link_status being
 * set to ISBDM_LINK_DOWN.
 */
static void isbdm_disconnect(struct isbdm *ii)
{
	if (ii->link_status == ISBDM_LINK_DOWN)
		return;

	/* Set link down first to keep new things from piling in. */
	ii->link_status = ISBDM_LINK_DOWN;

	/* Stop the hardware. */
	isbdm_disable(ii);

	/* Clean up resources for all the in-flight and pending I/O. */
	isbdm_abort_tx(ii);
	isbdm_abort_rx(ii);
	isbdm_abort_cmds(ii);
}

/* Query the status of the physical link. */
static enum isbdm_link_status isbdm_query_link(struct isbdm *ii)
{
	u32 crosslink;
	u32 presence;
	u32 ctrlsts2;
	int rc;

	rc = pci_read_config_dword(ii->pdev,
		ii->dvsec_cap + ISBDM_DVSEC_LINK_CTRLSTS2_OFFSET,
		&ctrlsts2);

	if (rc) {
		dev_err(&ii->pdev->dev, "Failed to read link status: %d\n", rc);
		return ISBDM_LINK_DOWN;
	}

	crosslink = ctrlsts2 & PCIE_CTRL_STS2_CROSSLINK_MASK;
	if (crosslink == PCIE_CTRL_STS2_CROSSLINK_DOWNSTREAM) {
		return ISBDM_LINK_DOWNSTREAM;

	} else if (crosslink == PCIE_CTRL_STS2_CROSSLINK_UPSTREAM) {
		presence = ctrlsts2 & PCIE_CTRL_STS2_DWNSTRM_PRS_MASK;
		if ((presence == PCIE_CTRL_STS2_DWNSTRM_UP_PRESENT) ||
		    (presence == PCIE_CTRL_STS2_DWNSTRM_UP_PRESENT_DRS)) {

			return ISBDM_LINK_UPSTREAM;
		}
	}

	return ISBDM_LINK_DOWN;
}

/* Query the status of the physical link and do setup/teardown. */
static void isbdm_check_link(struct isbdm *ii)
{
	enum isbdm_link_status link_status = isbdm_query_link(ii);

	if (ii->link_status == link_status)
		return;

	WARN_ON_ONCE(link_status == ISBDM_LINK_DOWN);

	ii->link_status = link_status;
	isbdm_connect(ii);
}

void isbdm_start(struct isbdm *ii)
{
	/* Clear out old interrupts, including LNKSTS. */
	ISBDM_WRITEQ(ii, ISBDM_IPSR, ISBDM_ALL_IRQ_MASK | ISBDM_IPSR_IIP);
	/* Enable LNKSTS for connect/disconnects in the future. */
	enable_interrupt(ii, ISBDM_LNKSTS_IRQ);
	/* Explicitly check the link now to maybe bring it up. */
	isbdm_check_link(ii);
}

/* Handle a link status change interrupt. */
void isbdm_process_link_status_change(struct isbdm *ii)
{
	/*
	 * Always disconnect things on a LNKSTS change, as even
	 * connected->connected is treated as a brief disconnect.
	 */
	isbdm_disconnect(ii);
	isbdm_check_link(ii);
}

/* Read one message from the wait list and into user mode. */
ssize_t isbdmex_read_one(struct isbdm *ii, void __user *va, size_t size)
{
	struct isbdm_buf *buf, *tmp;
	ssize_t completed = 0;
	LIST_HEAD(packet_list);
	struct isbdm_ring *ring = &ii->rx_ring;
	size_t buf_off = sizeof(struct isbdm_packet_header);

	mutex_lock(&ring->lock);
	if (ii->link_status == ISBDM_LINK_DOWN) {
		completed = -ENOTCONN;
		goto out;
	}

	if (!isbdmex_dequeue_one(ii, &packet_list)) {
		goto out;
	}

	list_for_each_entry(buf, &packet_list, node) {
		size_t size_to_copy = buf->size - buf_off;
		int not_done;

		WARN_ON_ONCE(buf->size < buf_off);

		if (size_to_copy > (size - completed))
			size_to_copy = size - completed;

		if (size_to_copy == 0)
			break;

		not_done = copy_to_user(va + completed,
					buf->buf + buf_off,
					size_to_copy);

		if (not_done != 0) {
			completed = -EFAULT;
			goto out;
		}

		completed += size_to_copy;

		/*
		 * The first descriptor had to skip the packet header, all
		 * others are data straight up.
		 */
		buf_off = 0;
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

u64 isbdmex_get_dropped_rx_count(struct isbdm *ii)
{
	u64 value;

	mutex_lock(&ii->rx_ring.lock);
	value = get_dropped_rx_count(ii);
	mutex_unlock(&ii->rx_ring.lock);
	return value;
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Rivos DPA device driver
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

#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/completion.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

#include "dpa_drm.h"
#include "dpa_daffy.h"
#include "duc_structs.h"

#define DAFFY_ENABLE_TIMEOUT_US	500000

int daffy_init(struct dpa_device *dpa)
{
	struct dpa_daffy *daffy = &dpa->daffy;
	u64 version, ctrl;
	ktime_t timeout;
	int i;

	version = dpa_fwq_read(dpa, DPA_FWQ_VERSION_ID);
	dev_info(dpa->dev, "Daffy queue version %llu\n", version);

	daffy->fwq = dma_alloc_coherent(dpa->dev, sizeof(*daffy->fwq),
					&daffy->fwq_dma_addr, GFP_KERNEL);
	if (!daffy->fwq)
		return -ENOMEM;

	daffy->fwq->desc.magic = DAFFY_QUEUE_MAGIC;
	daffy->fwq->desc.version = DAFFY_QUEUE_DESC_VERSION;
	daffy->fwq->desc.h_qsize = DPA_FW_QUEUE_SIZE;
	daffy->fwq->desc.d_qsize = DPA_FW_QUEUE_SIZE;
	daffy->fwq->desc.h_read_index = 0;
	daffy->fwq->desc.h_write_index = 0;
	daffy->fwq->desc.d_read_index = 0;
	daffy->fwq->desc.d_write_index = 0;
	daffy->fwq->desc.h_ring_base_ptr =
		daffy->fwq_dma_addr + offsetof(struct dpa_fwq, h_ring);
	daffy->fwq->desc.d_ring_base_ptr =
		daffy->fwq_dma_addr + offsetof(struct dpa_fwq, d_ring);

	dev_dbg(dpa->dev, "fw queue at %pad\n", &daffy->fwq_dma_addr);

	/* Invalidate all packet headers. */
	for (i = 0; i < DPA_FW_QUEUE_SIZE; i++) {
		daffy->fwq->h_ring[i].hdr.command = DAFFY_CMD_INVALID;
		daffy->fwq->d_ring[i].hdr.command = DAFFY_CMD_INVALID;
	}

	spin_lock_init(&daffy->h_lock);
	init_waitqueue_head(&daffy->h_full_wq);
	INIT_LIST_HEAD(&daffy->h_waiters);

	dpa_fwq_write(dpa, daffy->fwq_dma_addr, DPA_FWQ_QUEUE_DESCRIPTOR);

	dpa_fwq_write(dpa, DPA_FWQ_QUEUE_CTRL_ENABLE | DPA_FWQ_QUEUE_CTRL_BUSY,
		      DPA_FWQ_QUEUE_CTRL);
	timeout = ktime_add_us(ktime_get(), DAFFY_ENABLE_TIMEOUT_US);
	for (;;) {
		ctrl = dpa_fwq_read(dpa, DPA_FWQ_QUEUE_CTRL);
		if (!(ctrl & DPA_FWQ_QUEUE_CTRL_BUSY))
			break;
		if (ktime_compare(ktime_get(), timeout) > 0)
			break;
		usleep_range(1000, 5000);
	}
	if (ctrl & DPA_FWQ_QUEUE_CTRL_BUSY)
		return -ETIMEDOUT;
	if (!(ctrl & DPA_FWQ_QUEUE_CTRL_ENABLE))
		return -EIO;

	return 0;
}

void daffy_free(struct dpa_device *dpa)
{
	struct dpa_daffy *daffy = &dpa->daffy;
	ktime_t timeout;
	u64 ctrl;

	dpa_fwq_write(dpa, DPA_FWQ_QUEUE_CTRL_BUSY, DPA_FWQ_QUEUE_CTRL);
	timeout = ktime_add_us(ktime_get(), DAFFY_ENABLE_TIMEOUT_US);
	for (;;) {
		ctrl = dpa_fwq_read(dpa, DPA_FWQ_QUEUE_CTRL);
		if (!(ctrl & DPA_FWQ_QUEUE_CTRL_BUSY))
			break;
		if (ktime_compare(ktime_get(), timeout) > 0)
			break;
		usleep_range(1000, 5000);
	}
	WARN_ON((ctrl & (DPA_FWQ_QUEUE_CTRL_BUSY | DPA_FWQ_QUEUE_CTRL_ENABLE)));

	dpa_fwq_write(dpa, 0, DPA_FWQ_QUEUE_DESCRIPTOR);
	dma_free_coherent(dpa->dev, sizeof(*daffy->fwq), daffy->fwq,
			  daffy->fwq_dma_addr);
}

static void daffy_process_host_queue(struct dpa_device *dpa)
{
	struct dpa_daffy *daffy = &dpa->daffy;
	struct dpa_fwq *fwq = daffy->fwq;
	struct dpa_fwq_waiter *waiter, *tmp;
	unsigned long flags;
	u64 read_index;

	read_index = fwq->desc.h_read_index;
	spin_lock_irqsave(&daffy->h_lock, flags);
	list_for_each_entry_safe(waiter, tmp, &daffy->h_waiters, node) {
		unsigned int index;

		if (waiter->pkt->hdr.id >= read_index)
			break;

		index = waiter->pkt->hdr.id & (fwq->desc.h_qsize - 1);
		*waiter->pkt = fwq->h_ring[index];
		list_del_init(&waiter->node);
		complete(&waiter->done);
	}
	daffy->h_retire_index = read_index;
	spin_unlock_irqrestore(&daffy->h_lock, flags);

	wake_up_interruptible(&daffy->h_full_wq);
}

static void daffy_process_device_queue(struct dpa_device *dpa)
{
	struct dpa_daffy *daffy = &dpa->daffy;
	struct dpa_fwq *fwq = daffy->fwq;
	u64 read_index, write_index;

	read_index = fwq->desc.d_read_index;
	write_index = fwq->desc.d_write_index;

	dma_rmb();

	while (read_index != write_index) {
		unsigned int index = read_index & (fwq->desc.d_qsize - 1);
		struct daffy_queue_pkt *pkt = &fwq->d_ring[index];

		dev_dbg(dpa->dev, "%s: Daffy d_read_index: %#llx, write_index: %#llx\n",
			__func__, read_index, write_index);

		if (pkt->hdr.id != read_index) {
			dev_warn(dpa->dev, "%s: Daffy packet has ID %#llx, expected %#llx\n",
				__func__, pkt->hdr.id, read_index);
			break;
		}

		switch (pkt->hdr.command) {
		case DAFFY_CMD_INVALID:
			dev_warn(dpa->dev, "%s: Processing invalid Daffy packet\n",
				__func__);
			break;
		case DAFFY_CMD_UPDATE_SIGNAL: {
			u64 signal_idx = pkt->u.update_signal.signal_idx;
			u32 pasid = pkt->u.update_signal.pasid;

			dev_dbg(dpa->dev, "%s: Processing update_signal Daffy packet\n",
				__func__);
			dpa_signal_wake(dpa, pasid, signal_idx);
			break;
		}
		default:
			dev_warn(dpa->dev, "%s: Received unexpected Daffy command %x\n",
				__func__, pkt->hdr.command);
			break;
		}

		pkt->hdr.command = DAFFY_CMD_INVALID;
		read_index++;

		dma_wmb();
		fwq->desc.d_read_index = read_index;
	}
	dev_dbg(dpa->dev, "%s: Daffy final d_read_index: %#llx, d_write_index: %#llx\n",
		__func__, read_index, write_index);
}

irqreturn_t daffy_handle_irq(int irq, void *data)
{
	struct dpa_device *dpa = data;
	void __iomem *cause_addr;
	int vec = irq - dpa->base_irq;
	u64 cause;

	cause_addr = dpa->regs + DPA_MSIX_CAUSE_BASE + vec * sizeof(u64);
	cause = readq(cause_addr);
	writeq(cause, cause_addr);
	dev_info(dpa->dev, "%s: Received MSI interrupt %d with cause %llu\n",
		__func__, vec, cause);

	/*
	 * Handle the MSI-X vector, only FW_QUEUE_H2D and FW_QUEUE_D2H
	 * are supported for now.
	 * TODO: Add handling for causes that indicate an error.
	 */
	switch (vec) {
	case DPA_MSI_FW_QUEUE_H2D:
		daffy_process_host_queue(dpa);
		return IRQ_HANDLED;
	case DPA_MSI_FW_QUEUE_D2H:
		daffy_process_device_queue(dpa);
		return IRQ_HANDLED;
	default:
		dev_warn(dpa->dev, "%s: MSI vector %d received but not handled",
			__func__, vec);
		return IRQ_NONE;
	}
}

static inline bool daffy_host_queue_full(struct dpa_daffy *daffy)
{
	return (daffy->fwq->desc.h_write_index - daffy->h_retire_index) >=
		DPA_FW_QUEUE_SIZE;
}

static int daffy_submit_sync(struct dpa_device *dpa,
			     struct daffy_queue_pkt *pkt)
{
	struct dpa_daffy *daffy = &dpa->daffy;
	struct dpa_fwq *fwq = daffy->fwq;
	struct dpa_fwq_waiter waiter;
	struct daffy_queue_pkt *head;
	unsigned int index;
	int ret;

	INIT_LIST_HEAD(&waiter.node);
	init_completion(&waiter.done);
	waiter.pkt = pkt;

	spin_lock_irq(&daffy->h_lock);
	ret = wait_event_interruptible_lock_irq(daffy->h_full_wq,
						!daffy_host_queue_full(daffy),
						daffy->h_lock);
	if (ret < 0)
		goto out;

	index = fwq->desc.h_write_index & (fwq->desc.h_qsize - 1);
	head = &fwq->h_ring[index];
	if (head->hdr.command != DAFFY_CMD_INVALID) {
		dev_warn(dpa->dev, "%s: head packet not invalid 0x%x\n",
			 __func__, head->hdr.command);
		ret = -EIO;
		goto out;
	}
	pkt->hdr.id = fwq->desc.h_write_index;

	dev_dbg(dpa->dev, "submitting pkt id %llu, cmd: %#x\n", pkt->hdr.id,
		pkt->hdr.command);
	*head = *pkt;
	dma_wmb();
	fwq->desc.h_write_index++;

	list_add_tail(&waiter.node, &daffy->h_waiters);
	spin_unlock_irq(&daffy->h_lock);

	dpa_fwq_write(dpa, 1, DPA_FWQ_QUEUE_DOORBELL);

	ret = wait_for_completion_interruptible(&waiter.done);
	if (ret < 0) {
		spin_lock_irq(&daffy->h_lock);
		list_del(&waiter.node);
		spin_unlock_irq(&daffy->h_lock);
		return ret;
	}
	dev_dbg(dpa->dev, "pkt id %llu completed, cmd: %#x, resp: %#x\n",
		pkt->hdr.id, pkt->hdr.command, pkt->hdr.response);
	if (pkt->hdr.response != DAFFY_RESP_SUCCESS)
		return -EIO;
	return 0;

out:
	spin_unlock_irq(&daffy->h_lock);
	return ret;
}

int daffy_get_info_cmd(struct dpa_device *dpa,
		       struct drm_dpa_get_info *args)
{
	struct daffy_queue_pkt pkt;
	int ret;

	memset(&pkt, 0, sizeof(pkt));
	pkt.hdr.command = DAFFY_CMD_GET_INFO;
	ret = daffy_submit_sync(dpa, &pkt);
	if (ret < 0)
		return ret;

	memcpy(&args->pe_enable_mask, &pkt.u.get_info.pe_enable_mask,
	       sizeof(args->pe_enable_mask));
	return 0;
}

int daffy_register_pasid_cmd(struct dpa_device *dpa, u32 pasid,
			     u32 *db_offset, u32 *db_size)
{
	struct daffy_queue_pkt pkt;
	struct daffy_register_pasid_cmd *cmd;
	int ret;

	memset(&pkt, 0, sizeof(pkt));
	pkt.hdr.command = DAFFY_CMD_REGISTER_PASID;
	cmd = &pkt.u.register_pasid;
	cmd->pasid = pasid;

	ret = daffy_submit_sync(dpa, &pkt);
	if (ret)
		return ret;

	*db_offset = cmd->doorbell_offset;
	*db_size = cmd->doorbell_size;

	return 0;
}

int daffy_unregister_pasid_cmd(struct dpa_device *dpa, u32 pasid)
{
	struct daffy_queue_pkt pkt;
	struct daffy_unregister_pasid_cmd *cmd;

	memset(&pkt, 0, sizeof(pkt));
	pkt.hdr.command = DAFFY_CMD_UNREGISTER_PASID;
	cmd = &pkt.u.unregister_pasid;
	cmd->pasid = pasid;

	return daffy_submit_sync(dpa, &pkt);
}

int daffy_destroy_queue_cmd(struct dpa_device *dpa, u32 queue_id)
{
	struct daffy_queue_pkt pkt;

	memset(&pkt, 0, sizeof(pkt));
	pkt.hdr.command = DAFFY_CMD_DESTROY_QUEUE;
	pkt.u.destroy_queue.queue_id = queue_id;

	return daffy_submit_sync(dpa, &pkt);
}

int daffy_create_queue_cmd(struct dpa_device *dpa,
			   struct dpa_process *p,
			   struct drm_dpa_create_queue *args)
{
	struct daffy_queue_pkt pkt;
	struct daffy_create_queue_cmd *cmd;
	int ret;

	memset(&pkt, 0, sizeof(pkt));
	pkt.hdr.command = DAFFY_CMD_CREATE_QUEUE;
	cmd = &pkt.u.create_queue;
	cmd->pasid = p->pasid;
	cmd->ring_base_address = args->ring_base_address;
	cmd->ring_size = args->ring_size;

	if (args->flags & DPA_DRM_CREATE_QUEUE_DEBUG)
		cmd->flags |= DAFFY_CREATE_QUEUE_DEBUG;
	ret = daffy_submit_sync(dpa, &pkt);
	if (ret < 0)
		return ret;

	args->queue_id = cmd->queue_id;
	// fw gives us the offset into the entire 16 page region
	// user process should get offset into the mmaped doorbell region
	args->doorbell_offset = cmd->doorbell_offset - p->doorbell_offset;

	return 0;
}

int daffy_set_signal_pages_cmd(struct dpa_device *dpa, struct dpa_process *p,
			       struct drm_dpa_set_signal_pages *args,
			       u32 num_pages)
{
	struct daffy_queue_pkt pkt;
	struct daffy_set_signal_pages_cmd *cmd;

	memset(&pkt, 0, sizeof(pkt));
	pkt.hdr.command = DAFFY_CMD_SET_SIGNAL_PAGES;
	cmd = &pkt.u.set_signal_pages;
	cmd->base_address = args->va;
	cmd->num_pages = num_pages;
	cmd->pasid = p->pasid;

	return daffy_submit_sync(dpa, &pkt);
}

int daffy_set_notification_queue_cmd(struct dpa_device *dpa,
				     struct dpa_process *p,
				     struct drm_dpa_set_notification_queue *args)
{
	struct daffy_queue_pkt pkt;
	struct daffy_set_notification_queue_cmd *cmd;

	memset(&pkt, 0, sizeof(pkt));
	pkt.hdr.command = DAFFY_CMD_SET_NOTIFICATION_QUEUE;
	cmd = &pkt.u.set_notification_queue;
	cmd->base_address = args->base_address;
	cmd->ring_size = args->ring_size;
	cmd->pasid = p->pasid;
	cmd->signal_id = args->signal_id;

	return daffy_submit_sync(dpa, &pkt);
}

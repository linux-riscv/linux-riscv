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
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

#include "dpa_drm.h"
#include "dpa_daffy.h"

static int daffy_queue_has_space(struct dpa_daffy *daffy)
{
	return 1;
//	return (qinfo->fw_queue->h_read_index !=
//		qinfo->fw_queue->h_write_index);
}

// return the index of the command
// user of this must mark it invalid after a response shows up
// XXX this interface is insufficient for multiple users...
// need to copy packet responses somewhere, maybe need pkt id
static unsigned int daffy_add_to_queue(struct dpa_device *dpa,
			 struct dpa_fw_queue_pkt *pkt)
{
	struct dpa_daffy *daffy = &dpa->daffy;
	struct dpa_fwq *fwq = daffy->fwq;
	struct dpa_fw_queue_pkt *head;
	unsigned int index;

	mutex_lock(&daffy->lock);

	index = fwq->desc.h_write_index & (fwq->desc.h_qsize - 1);
	head = &fwq->h_ring[index];

	if (head->hdr.command != INVALID) {
		dev_warn(dpa->dev, "%s: head packet not invalid 0x%x\n",
			 __func__, head->hdr.command);
		mutex_unlock(&daffy->lock);
		return -1;
	}
	pkt->hdr.id = fwq->desc.h_write_index;
	memcpy(head, pkt, sizeof(*pkt));
	dma_wmb();
	fwq->desc.h_write_index++;

	mutex_unlock(&daffy->lock);

	dpa_fwq_write(dpa, 1, DPA_FWQ_QUEUE_DOORBELL);

	return index;
}

int daffy_init(struct dpa_device *dpa)
{
	struct dpa_daffy *daffy = &dpa->daffy;
	u64 version;
	int i;

	version = dpa_fwq_read(dpa, DPA_FWQ_VERSION_ID);
	dev_info(dpa->dev, "Daffy queue version %llu\n", version);

	daffy->fwq = dma_alloc_coherent(dpa->dev, sizeof(*daffy->fwq),
					&daffy->fwq_dma_addr, GFP_KERNEL);
	if (!daffy->fwq)
		return -ENOMEM;

	daffy->fwq->desc.magic = DPA_FW_QUEUE_MAGIC;
	daffy->fwq->desc.version = DPA_FW_QUEUE_DESC_VERSION;
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
		daffy->fwq->h_ring[i].hdr.command = INVALID;
		daffy->fwq->d_ring[i].hdr.command = INVALID;
	}

	mutex_init(&daffy->lock);
	init_waitqueue_head(&daffy->wq);

	dpa_fwq_write(dpa, daffy->fwq_dma_addr, DPA_FWQ_QUEUE_DESCRIPTOR);

	return 0;
}

void daffy_free(struct dpa_device *dpa)
{
	struct dpa_daffy *daffy = &dpa->daffy;

	dpa_fwq_write(dpa, 0, DPA_FWQ_QUEUE_DESCRIPTOR);
	/* TODO: Add proper fw queue disable sequence. */
	dma_free_coherent(dpa->dev, sizeof(*daffy->fwq), daffy->fwq,
			  daffy->fwq_dma_addr);
}

irqreturn_t daffy_process_device_queue(int irq, void *data)
{
	struct dpa_device *dpa = data;
	struct dpa_daffy *daffy = &dpa->daffy;
	struct dpa_fwq *fwq = daffy->fwq;
	u64 read_index, write_index;

	mutex_lock(&daffy->lock);

	read_index = fwq->desc.d_read_index;
	write_index = fwq->desc.d_write_index;

	dma_rmb();

	while (read_index != write_index) {
		unsigned int index = read_index & (fwq->desc.d_qsize - 1);
		struct dpa_fw_queue_pkt *pkt = &fwq->d_ring[index];

		dev_dbg(dpa->dev, "%s: Daffy d_read_index: %#llx, write_index: %#llx\n",
			__func__, read_index, write_index);

		if (pkt->hdr.id != read_index) {
			dev_warn(dpa->dev, "%s: Daffy packet has ID %#llx, expected %#llx\n",
				__func__, pkt->hdr.id, read_index);
			break;
		}

		switch (pkt->hdr.command) {
		case INVALID:
			dev_warn(dpa->dev, "%s: Processing invalid Daffy packet\n",
				__func__);
			pkt->hdr.response = ERROR;
			break;
		case UPDATE_SIGNAL: {
			u64 signal_idx = pkt->u.dusc.signal_idx;
			u32 pasid = pkt->u.dusc.pasid;
			struct dpa_process *p;
			struct dpa_signal_waiter *waiter;
			unsigned long flags;
			
			dev_dbg(dpa->dev, "%s: Processing update_signal Daffy packet\n",
				__func__);

			p = dpa_get_process_by_pasid(dpa, pasid);
			if (!p) {
				dev_warn(dpa->dev, "%s: DPA process not found for PASID %d\n",
					__func__, pasid);
				pkt->hdr.response = ERROR;
				break;
			}

			spin_lock_irqsave(&p->signal_waiters_lock, flags);
			list_for_each_entry(waiter, &p->signal_waiters, list) {
				if (waiter->signal_idx == signal_idx) {
					complete(&waiter->signal_done);
					break;
				}
			}
			spin_unlock_irqrestore(&p->signal_waiters_lock, flags);
			kref_put(&p->ref, dpa_release_process);
			pkt->hdr.response = SUCCESS;
			break;
		}
		default:
			dev_warn(dpa->dev, "%s: Received unexpected Daffy command %x\n",
				__func__, pkt->hdr.command);
			pkt->hdr.response = ERROR;
			break;
		}

		pkt->hdr.command = INVALID;
		read_index++;

		dma_wmb();
		fwq->desc.d_read_index = read_index;
	}
	dev_dbg(dpa->dev, "%s: Daffy final d_read_index: %#llx, d_write_index: %#llx\n",
		__func__, read_index, write_index);

	mutex_unlock(&daffy->lock);
	return IRQ_HANDLED;
}

irqreturn_t daffy_handle_irq(int irq, void *data)
{
	struct dpa_device *dpa = data;
	void __iomem *cause_addr;
	int vec = irq - dpa->base_irq;
	u64 cause;
	irqreturn_t irq_ret = IRQ_HANDLED;

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
	case FW_QUEUE_H2D:
		wake_up_interruptible(&dpa->daffy.wq);
		break;

	case FW_QUEUE_D2H:
		irq_ret = IRQ_WAKE_THREAD;
		break;

	default:
		dev_warn(dpa->dev, "%s: MSI vector %d received but not handled",
			__func__, vec);
	}

	return irq_ret;
}

int daffy_get_info_cmd(struct dpa_device *dev,
					struct dpa_process *p,
					struct drm_dpa_get_info *args)
{
	struct dpa_daffy *daffy = &dev->daffy;
	struct dpa_fw_queue_pkt pkt;
	struct dpa_fw_queue_pkt *qpkt;
	unsigned int index;
	int ret = 0;

	if (!daffy_queue_has_space(daffy)) {
		// XXX wait on wait queue
		dev_warn(dev->dev, "%s: queue is full\n", __func__);
		return -EBUSY;
	}
	memset(&pkt, 0, sizeof(pkt));
	pkt.hdr.command = GET_INFO;

	index = daffy_add_to_queue(dev, &pkt);
	dev_warn(dev->dev, "%s: added to queue index %u cmd = %u\n",
		 __func__, index, pkt.hdr.command);
	if (index == -1)
		return -EINVAL;

	qpkt = &daffy->fwq->h_ring[index];
	ret = wait_event_interruptible(daffy->wq, qpkt->hdr.response > 0);
	if (ret)
		goto out;

	if (qpkt->hdr.response != SUCCESS) {
		dev_warn(dev->dev, "%s: DUC did not succeed processing packet type %d at index 0x%x, got response %d",
			__func__, qpkt->hdr.command, index, qpkt->hdr.response);
		ret = -EINVAL;
		goto out;
	}

	args->pe_grid_dim_x = qpkt->u.dgic.pe_grid_dim_x;
	args->pe_grid_dim_y = qpkt->u.dgic.pe_grid_dim_y;
out:
	return ret;
}

int daffy_destroy_queue_cmd(struct dpa_device *dev,
			    struct dpa_process *p, u32 queue_id)
{
	struct dpa_daffy *daffy = &dev->daffy;
	struct dpa_fw_queue_pkt pkt, *qpkt;
	struct daffy_destroy_queue_cmd *cmd;
	unsigned int index;
	int ret = 0;

	memset(&pkt, 0, sizeof(pkt));
	pkt.hdr.command = DESTROY_QUEUE;
	cmd = &pkt.u.ddqc;

	cmd->queue_id = queue_id;

	index = daffy_add_to_queue(dev, &pkt);
	dev_warn(dev->dev, "%s: added to queue index %u cmd = %u qid = %u\n",
		 __func__, index, pkt.hdr.command, queue_id);
	if (index == -1) {
		dev_warn(dev->dev, "%s: got invalid queue index -1\n", __func__);
		ret = -EINVAL;
		goto out;
	}
	qpkt = &daffy->fwq->h_ring[index];
	ret = wait_event_interruptible(daffy->wq, qpkt->hdr.response > 0);
	if (ret)
		goto out;

	if (qpkt->hdr.response != SUCCESS) {
		dev_warn(dev->dev, "%s: DUC did not succeed processing packet type %d at index 0x%x, got response %d",
			__func__, qpkt->hdr.command, index, qpkt->hdr.response);
		ret = -EINVAL;
	}

out:
	return ret;
}


int daffy_create_queue_cmd(struct dpa_device *dev,
			   struct dpa_process *p,
			   struct drm_dpa_create_queue *args)
{
	struct dpa_daffy *daffy = &dev->daffy;
	struct dpa_fw_queue_pkt pkt, *qpkt;
	struct daffy_create_queue_cmd *cmd;
	u64 wr_ptr = args->write_pointer_address;
	u64 rd_ptr = args->read_pointer_address;
	u64 ring_ptr = args->ring_base_address;
	unsigned int index;
	int ret = 0;

	if (!daffy_queue_has_space(daffy)) {
		// XXX wait on wait queue
		dev_warn(dev->dev, "%s: queue is full\n", __func__);
		return -EBUSY;
	}

	memset(&pkt, 0, sizeof(pkt));
	pkt.hdr.command = CREATE_QUEUE;
	cmd = &pkt.u.dcqc;

	cmd->pasid = p->pasid;
	cmd->ring_base_address = ring_ptr;
	cmd->write_pointer_address = wr_ptr;
	cmd->read_pointer_address = rd_ptr;
	cmd->ring_size = args->ring_size;

	index = daffy_add_to_queue(dev, &pkt);
	dev_warn(dev->dev, "%s: added to queue index %u cmd = %u ring = 0x%llx wr 0x%llx rd 0x%llx\n",
		__func__, index, pkt.hdr.command,
		cmd->ring_base_address, cmd->write_pointer_address,
		cmd->read_pointer_address);
	if (index == -1) {
		dev_warn(dev->dev, "%s: got invalid queue index -1\n", __func__);
		ret = -EINVAL;
		// goto out_unmap_rwptr;
	}
	qpkt = &daffy->fwq->h_ring[index];
	ret = wait_event_interruptible(daffy->wq, qpkt->hdr.response > 0);
	if (ret)
		goto out;

	if (qpkt->hdr.response != SUCCESS) {
		dev_warn(dev->dev, "%s: DUC did not succeed processing packet type %d at index 0x%x, got response %d",
			__func__, qpkt->hdr.command, index, qpkt->hdr.response);
		ret = -EINVAL;
		goto out;
	}

	args->queue_id = qpkt->u.dcqc.queue_id;
	// doorbell_offset will get converted from page offset to something else by caller
	args->doorbell_offset = qpkt->u.dcqc.doorbell_offset;
out:
	return ret;
}

int daffy_register_signal_pages_cmd(struct dpa_device *dpa_dev,
				struct dpa_process *p,
				struct drm_dpa_create_signal_pages *args,
				u32 num_pages)
{
	struct dpa_daffy *daffy = &dpa_dev->daffy;
	struct dpa_fw_queue_pkt pkt, *qpkt;
	struct daffy_register_signal_pages_cmd *cmd;
	unsigned int index;
	int ret = 0;

	if (!daffy_queue_has_space(daffy)) {
		dev_warn(dpa_dev->dev, "%s: queue is full\n", __func__);
		return -EBUSY;
	}

	memset(&pkt, 0, sizeof(pkt));
	pkt.hdr.command = REGISTER_SIGNAL_PAGES;

	cmd = &pkt.u.drspc;
	cmd->base_address = args->va;
	cmd->num_pages = num_pages;
	cmd->type = SIGNAL;	// Only support default signal type for now
	cmd->pasid = p->pasid;

	index = daffy_add_to_queue(dpa_dev, &pkt);
	dev_warn(dpa_dev->dev, "%s: added to queue index %u cmd = %u\n",
		 __func__, index, pkt.hdr.command);
	if (index == -1) {
		dev_warn(dpa_dev->dev, "%s: got invalid queue index -1\n", __func__);
		ret = -EINVAL;
	}
	qpkt = &daffy->fwq->h_ring[index];
	ret = wait_event_interruptible(daffy->wq, qpkt->hdr.response > 0);

	if (qpkt->hdr.response != SUCCESS) {
		dev_warn(dpa_dev->dev, "%s: DUC did not succeed processing packet type %d at index 0x%x, got response %d",
			__func__, qpkt->hdr.command, index, qpkt->hdr.response);
		ret = -EINVAL;
	}

	return ret;
}

int daffy_unregister_signal_pages_cmd(struct dpa_device *dpa_dev,
				struct dpa_process *p)
{
	struct dpa_daffy *daffy = &dpa_dev->daffy;
	struct dpa_fw_queue_pkt pkt, *qpkt;
	struct daffy_unregister_signal_pages_cmd *cmd;
	unsigned int index;
	int ret = 0;

	if (!daffy_queue_has_space(daffy)) {
		dev_warn(dpa_dev->dev, "%s: queue is full\n", __func__);
		return -EBUSY;
	}

	memset(&pkt, 0, sizeof(pkt));
	pkt.hdr.command = UNREGISTER_SIGNAL_PAGES;

	cmd = &pkt.u.durspc;
	cmd->pasid = p->pasid;

	index = daffy_add_to_queue(dpa_dev, &pkt);
	dev_warn(dpa_dev->dev, "%s: added to queue index %u cmd = %u\n",
		 __func__, index, pkt.hdr.command);
	if (index == -1) {
		dev_warn(dpa_dev->dev, "%s: got invalid queue index -1\n", __func__);
		ret = -EINVAL;
	}
	qpkt = &daffy->fwq->h_ring[index];
	ret = wait_event_interruptible(daffy->wq, qpkt->hdr.response > 0);

	if (qpkt->hdr.response != SUCCESS) {
		dev_warn(dpa_dev->dev, "%s: DUC did not succeed processing packet type %d at index 0x%x, got response %d",
			__func__, qpkt->hdr.command, index, qpkt->hdr.response);
		ret = -EINVAL;
	}

	return ret;
}

int daffy_subscribe_signal_cmd(struct dpa_device *dpa_dev,
				struct dpa_process *p, u64 signal_idx)
{
	struct dpa_daffy *daffy = &dpa_dev->daffy;
	struct dpa_fw_queue_pkt pkt, *qpkt;
	struct daffy_subscribe_signal_cmd *cmd;
	unsigned int index;
	int ret = 0;

	if (!daffy_queue_has_space(daffy)) {
		dev_warn(dpa_dev->dev, "%s: queue is full\n", __func__);
		return -EBUSY;
	}

	memset(&pkt, 0, sizeof(pkt));
	pkt.hdr.command = SUBSCRIBE_SIGNAL;

	cmd = &pkt.u.dssc;
	cmd->signal_idx = signal_idx;
	cmd->pasid = p->pasid;

	index = daffy_add_to_queue(dpa_dev, &pkt);
	dev_warn(dpa_dev->dev, "%s: added to queue index %u cmd = %u\n",
		 __func__, index, pkt.hdr.command);
	if (index == -1) {
		dev_warn(dpa_dev->dev, "%s: got invalid queue index -1\n", __func__);
		ret = -EINVAL;
	}
	qpkt = &daffy->fwq->h_ring[index];
	ret = wait_event_interruptible(daffy->wq, qpkt->hdr.response > 0);

	if (qpkt->hdr.response == ERROR) {
		dev_warn(dpa_dev->dev, "%s: DUC did not succeed processing packet type %d at index 0x%x, got response %d",
			__func__, qpkt->hdr.command, index, qpkt->hdr.response);
		ret = -EINVAL;
	} else if (qpkt->hdr.response == ALREADY_SIGNALED) {
		dev_warn(dpa_dev->dev, "%s: DUC did not process the subscription, signal is already complete\n",
			__func__);
		ret = 1;
	}

	return ret;
}

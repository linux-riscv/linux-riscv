#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <uapi/linux/kfd_ioctl.h>

#include "dpa_daffy.h"

static int queue_has_space(struct dpa_fwq_info *qinfo)
{
	return 1;
//	return (qinfo->fw_queue->h_read_index !=
//		qinfo->fw_queue->h_write_index);
}

// return the index of the command
// user of this must mark it invalid after a response shows up
// XXX this interface is insufficient for multiple users...
// need to copy packet responses somewhere, maybe need pkt id
static unsigned add_to_queue(struct dpa_device *dev,
			 struct dpa_fw_queue_pkt *pkt)
{
	struct dpa_fwq_info *qinfo = &dev->qinfo;
	struct dpa_fw_queue_pkt *head = qinfo->h_ring;
	unsigned index = (qinfo->fw_queue->h_write_index) &
		(qinfo->fw_queue->h_qsize - 1);

	head += index;

	if (head->hdr.command != INVALID) {
		dev_warn(dev->dev, "%s: head packet not invalid 0x%x\n",
			 __func__, head->hdr.command);
		return -1;
	}
	pkt->hdr.id = qinfo->fw_queue->h_write_index;
	memcpy(head, pkt, sizeof(*pkt));
	smp_wmb();
	qinfo->fw_queue->h_write_index++; // XXX atomic or locking?

	// XXX hit doorbell maybe higher level?

	return index;
}

int daffy_alloc_fw_queue(struct dpa_device *dpa_dev)
{
	int i;
	struct dpa_fwq_info *q = &dpa_dev->qinfo;
	q->fw_queue = kzalloc(DPA_FW_QUEUE_PAGE_SIZE, GFP_KERNEL);
	if (!q->fw_queue)
		return -ENOMEM;

	q->fw_queue_dma_addr = dma_map_single(dpa_dev->dev,
					      q->fw_queue,
					      DPA_FW_QUEUE_PAGE_SIZE,
					      DMA_BIDIRECTIONAL);
	if (q->fw_queue_dma_addr == DMA_MAPPING_ERROR) {
		kfree(q->fw_queue);
		return -EIO;
	}

	q->fw_queue->magic = DPA_FW_QUEUE_MAGIC;
	q->fw_queue->version = DPA_FW_QUEUE_DESC_VERSION;
	q->fw_queue->h_qsize  = DPA_FW_QUEUE_SIZE;
	q->fw_queue->d_qsize  = DPA_FW_QUEUE_SIZE;
	q->fw_queue->h_read_index = 0;
	q->fw_queue->h_write_index = 0;
	q->fw_queue->d_read_index = 0;
	q->fw_queue->d_write_index = 0;

	// start at +64b to give space for descriptor
	q->fw_queue->h_ring_base_ptr =
		(u64)(q->fw_queue_dma_addr) +
		DPA_FWQ_PKT_SIZE;

	q->fw_queue->d_ring_base_ptr =
		q->fw_queue->h_ring_base_ptr +
		(q->fw_queue->h_qsize * DPA_FWQ_PKT_SIZE);

	q->h_ring = (void *)q->fw_queue + DPA_FWQ_PKT_SIZE;
	q->d_ring = q->h_ring + (DPA_FW_QUEUE_SIZE * DPA_FWQ_PKT_SIZE);
	dev_warn(dpa_dev->dev, "%s: fw_queue at %llx ring at %llx\n",
		 __func__, (u64)q->fw_queue, (u64)q->h_ring);
	dev_warn(dpa_dev->dev, "%s: pkt size is %lu\n",
		 __func__, sizeof(struct dpa_fw_queue_pkt));

	// init all packets to invalid
	for (i = 0; i < DPA_FW_QUEUE_SIZE; i++) {
		struct dpa_fw_queue_pkt *h_pkt = q->h_ring + i;
		struct dpa_fw_queue_pkt *d_pkt = q->d_ring + i;
		h_pkt->hdr.command = INVALID;
		d_pkt->hdr.command = INVALID;
	}

	return 0;
}

void daffy_free_fw_queue(struct dpa_device *dpa_dev)
{
	struct dpa_fwq_info *q = &dpa_dev->qinfo;
	dma_unmap_single(dpa_dev->dev,
			 q->fw_queue_dma_addr,
			 DPA_FW_QUEUE_PAGE_SIZE,
			 DMA_BIDIRECTIONAL);
	kfree(q->fw_queue);
}

int daffy_get_version_cmd(struct dpa_device *dev, u32 *version)
{
	struct dpa_fw_queue_pkt pkt;
	volatile struct dpa_fw_queue_pkt *qpkt;
	struct daffy_get_version_cmd *cmd = &pkt.u.dgvc;
	unsigned index;

	if (!queue_has_space(&dev->qinfo)) {
		// XXX wait on wait queue
		dev_warn(dev->dev, "%s: queue is full\n", __func__);
		return -EBUSY;
	}
	memset(&pkt, 0, sizeof(pkt));
	pkt.hdr.command = GET_VERSION;
	pkt.u.dgvc.version = 0x22222222;

	index = add_to_queue(dev, &pkt);
	dev_warn(dev->dev, "%s: added to queue index %u cmd = %u ver = %u\n",
		 __func__, index, pkt.hdr.command, cmd->version);
	if (index == -1) {
		return -EINVAL;
	}
	qpkt = dev->qinfo.h_ring + index;
	// XXX wait for response?
	usleep_range(100000, 200000);
	dev_warn(dev->dev, "%s: after sleep: rsp = %u ver = 0x%x ridx = %llu\n",
		 __func__, qpkt->hdr.response, qpkt->u.dgvc.version,
		dev->qinfo.fw_queue->h_read_index);
	*version = qpkt->u.dgvc.version;

	return 0;
}

int daffy_destroy_queue_cmd(struct dpa_device *dev,
			    struct dpa_kfd_process *p, u32 queue_id)
{
	struct dpa_fw_queue_pkt pkt, *qpkt;
	struct daffy_destroy_queue_cmd *cmd;
	unsigned index;
	int ret = 0;

	memset(&pkt, 0, sizeof(pkt));
	pkt.hdr.command = DESTROY_QUEUE;
	cmd = &pkt.u.ddqc;

	cmd->queue_id = queue_id;

	index = add_to_queue(dev, &pkt);
	dev_warn(dev->dev, "%s: added to queue index %u cmd = %u qid = %u\n",
		 __func__, index, pkt.hdr.command, queue_id);
	if (index == -1) {
		dev_warn(dev->dev, "%s: got invalid queue index -1\n", __func__);
		ret = -EINVAL;
		goto out;
	}
	qpkt = dev->qinfo.h_ring + index;
	// XXX wait for response
	usleep_range(100000, 200000);
	dev_warn(dev->dev, "%s: after sleep: rsp = %u ridx = %llu\n",
		 __func__, qpkt->hdr.response, dev->qinfo.fw_queue->h_read_index);

out:
	return ret;
}


int daffy_create_queue_cmd(struct dpa_device *dev,
			   struct dpa_kfd_process *p,
			   struct drm_dpa_create_queue *args)
{
	struct dpa_fw_queue_pkt pkt, *qpkt;
	struct daffy_create_queue_cmd *cmd;

	u64 wr_ptr = args->write_pointer_address;
	u64 rd_ptr = args->read_pointer_address;
	u64 ring_ptr = args->ring_base_address;
	// struct page *ring_page, *rwptr_page;
	// int ring_offset, rd_offset, wr_offset;
	// dma_addr_t ring_dma_addr = 0;
	// dma_addr_t rwptr_dma_addr = 0;
	unsigned index;
	int ret = 0;

	if (!queue_has_space(&dev->qinfo)) {
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

	index = add_to_queue(dev, &pkt);
	dev_warn(dev->dev, "%s: added to queue index %u cmd = %u ring = 0x%llx wr 0x%llx rd 0x%llx\n",
		 __func__, index, pkt.hdr.command,
		 cmd->ring_base_address, cmd->write_pointer_address, cmd->read_pointer_address);
	if (index == -1) {
		dev_warn(dev->dev, "%s: got invalid queue index -1\n", __func__);
		ret = -EINVAL;
		// goto out_unmap_rwptr;
	}
	qpkt = dev->qinfo.h_ring + index;
	// XXX wait for response
	usleep_range(100000, 200000);
	dev_warn(dev->dev, "%s: after sleep: rsp = %u queue id = 0x%x ridx = %llu\n",
		 __func__, qpkt->hdr.response, qpkt->u.dcqc.queue_id,
		dev->qinfo.fw_queue->h_read_index);
	args->queue_id = qpkt->u.dcqc.queue_id;
	// doorbell_offset will get converted from page offset to something else by caller
	args->doorbell_offset = qpkt->u.dcqc.doorbell_offset;

	return ret;
}

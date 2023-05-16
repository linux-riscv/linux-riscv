// SPDX-License-Identifier: GPL-2.0-only
/*
 * Rivos DCE device driver
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

#include <asm-generic/int-ll64.h>
#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/iommu.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/wait.h>
#include <linux/mutex.h>

#include "dce.h"

#define MAX_DCE_DEVICES 16

static dev_t dev_num;
static dev_t dev_vf_num;

static DEFINE_IDA(dce_minor_ida);
static DEFINE_IDA(dcevf_minor_ida);

uint64_t dce_reg_read(struct dce_driver_priv *priv, int reg)
{
	uint64_t result = ioread64((void __iomem *)(priv->mmio_start + reg));
	// printk(KERN_INFO "Read 0x%llx from address 0x%llx\n", result, priv->mmio_start + reg);
	return result;
}

void dce_reg_write(struct dce_driver_priv *priv, int reg, uint64_t value)
{
	// printk(KERN_INFO "Writing 0x%llx to address 0x%llx\n", value, priv->mmio_start + reg);
	iowrite64(value, (void __iomem *)(priv->mmio_start + reg));
}

void clean_up_work(struct work_struct *work)
{
	struct dce_driver_priv *dce_priv =
		container_of(work, struct dce_driver_priv, clean_up_worker);
	/* getting per queue interrupt status */
	uint64_t irq_sts = dce_reg_read(dce_priv, DCE_REG_WQIRQSTS);
	/* clear irq status */
	dce_reg_write(dce_priv, DCE_REG_WQIRQSTS, irq_sts);

	dev_dbg(&dce_priv->dev, "Cleanup start\n");

	for (int wq_num = 0; wq_num < NUM_WQ; wq_num++) {
		struct work_queue *wq = dce_priv->wq + wq_num;
		bool irqbit = irq_sts & BIT_ULL(wq_num);
		bool flush;

		spin_lock(&wq->lock);
		flush = (wq->type == KERNEL_FLUSHING_WQ);
		irq_sts &= ~BIT_ULL(wq_num);

		if (!flush && wq->type != KERNEL_WQ) {
			spin_unlock(&wq->lock);
			continue;
		}

		if (flush || irqbit) {
			struct DescriptorRing *ring = &wq->descriptor_ring;
			uint64_t head, curr;

			if (!ring->hti) {
				dev_err(&dce_priv->dev, "Invalid ring for wq %d", wq_num);
				spin_unlock(&wq->lock);
				continue;
			}

			head = ring->hti->head;
			curr = ring->clean_up_index;
			spin_unlock(&wq->lock);

			/* Do the actual cleaning up, right now just eventfd */
			dev_dbg(&dce_priv->dev,
				"Cleanup on %d, %llu->%llu", wq_num, curr, head);

			while (curr < head) {
				/* Position in queue int qi = (curr % ring->length); */
				/* for every clean up, notify user via eventfd when applicable*/
				/* TODO: Find out an optimal policy for eventfd */
				if (wq->efd_ctx_valid) {
					if (eventfd_signal(wq->efd_ctx, 1) < 1)
						dev_warn_ratelimited(&dce_priv->dev,
							"wq: %d, overflow on eventfd\n",
							wq_num);
				}
				curr++;
			}

			dev_dbg(&dce_priv->dev,
				"Cleanup done on %d updating clean index\n",
				wq_num);
			spin_lock(&wq->lock);
			ring->clean_up_index = curr;
			spin_unlock(&wq->lock);
			dev_dbg(&dce_priv->dev, "Cleanup really done\n");
			wake_up_interruptible(&wq->full_waiter);
		} else {
			spin_unlock(&wq->lock);
		}
	}

	/*
	 * Eagerly recheck for interrupt status, might not generate IRQ if
	 * another queue asserted its status bit between read and clear
	 * Could also eagerly check for head updates, but this would potentially
	 * hide driver/IRQ bugs so leave as it is for now
	 */
	irq_sts = dce_reg_read(dce_priv, DCE_REG_WQIRQSTS);
	if (irq_sts) {
		dev_dbg(&dce_priv->dev, "Rescheduling worker!");
		schedule_work(&dce_priv->clean_up_worker);
	}
}

struct dce_submitter_ctx {
	struct dce_driver_priv *priv;
	struct iommu_sva *sva;
	int wq_num;
	unsigned int pasid;
};

static void set_queue_enable(struct dce_driver_priv *dev_ctx, int wq_num, bool enable);
int dce_ops_open(struct inode *inode, struct file *file)
{
	struct dce_driver_priv *priv =
		container_of(inode->i_cdev, struct dce_driver_priv, cdev);
	struct dce_submitter_ctx *ctx;
	int err = 0;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->priv = priv;
	ctx->sva = NULL;
	ctx->pasid = 0;
	ctx->wq_num = -1;

	if (priv->sva_enabled) {
		ctx->sva = iommu_sva_bind_device(&priv->pdev->dev, current->mm);
		if (IS_ERR(ctx->sva)) {
			err = PTR_ERR(ctx->sva);
			dev_err(&priv->dev, "open: sva_bind_device fail:%d!\n", err);
			goto error;
		} else {
			dev_dbg(&priv->dev, "open: sva_bind_device success!\n");
		}
		ctx->pasid = iommu_sva_get_pasid(ctx->sva);
		if (ctx->pasid == IOMMU_PASID_INVALID) {
			dev_err(&priv->dev, "open: sva_get_pasid fail!\n");
			iommu_sva_unbind_device(ctx->sva);
			err =  -ENODEV;
			goto error;
		} else {
			dev_dbg(&priv->dev, "open: sva_get_pasid success!\n");
		}
	} else {
		dev_err(&priv->dev, "open: PASID support required, fail!\n");
		err = -EFAULT;
		goto error;
	}
	/* keep sva context linked to the file */
	file->private_data = ctx;
	return 0;
error:
	kfree(ctx);
	return err;
}

/* /!\ Function expect wq->lock locked on entry and returns it unlocked */
static int release_kernel_queue(struct dce_driver_priv *priv, int wq_num)
{
	/* Policy: wait for jobs to execute */
	struct work_queue *wq = priv->wq+wq_num;
	struct DescriptorRing *ring = &(wq->descriptor_ring);
	/* Make queue unsuitable for submission */
	wq->type = KERNEL_FLUSHING_WQ;
	/* Wait for jobs to execute*/
	/* TODO: Add timeout ? */
	while (true) {
		uint64_t head = ring->hti->head;
		uint64_t tail = ring->hti->tail; /* We hold the lock, this is not moving...*/
		uint64_t clean = ring->clean_up_index;

		if (wq->type != KERNEL_FLUSHING_WQ)
			dev_err(&priv->dev, "Flushing a queue that is not in flush\n");
		spin_unlock(&wq->lock);

		if (clean >= tail)
			break;

		dev_dbg(&priv->dev,
			"Waiting for queue %d flush - tail:%llu head:%llu, clean:%llu\n",
			wq_num, tail, head, clean);
		/* TODO: Change to event */
		/* Give some time for HW to actually do some work */
		usleep_range(10000, 100000);
		schedule_work(&priv->clean_up_worker);
		/* Wait some for the worker to have time to process descriptors */
		usleep_range(10000, 100000);
		spin_lock(&wq->lock);
	}
	/* Disable queue in HW */
	/* TODO: Need to poll for completion? */
	set_queue_enable(priv, wq_num, false);

	/* Deal with context*/
	if (ring->desc_dma) {
		dma_free_coherent(&priv->pdev->dev,
			(ring->length * sizeof(struct DCEDescriptor)),
			ring->descriptors, ring->desc_dma);
	}
	if (ring->hti_dma) {
		dma_free_coherent(&priv->pdev->dev, sizeof(struct HeadTailIndex),
			ring->hti, ring->hti_dma);
	}
	/* Clean up the eventfd ctx */
	if (wq->efd_ctx_valid) {
		eventfd_ctx_put(wq->efd_ctx);
		wq->efd_ctx_valid = false;
		wq->efd_ctx = 0;
	}

	wq->type = DISABLED;
	/* TODO: Describe barrier */
	wmb();
	memset(&(wq->descriptor_ring), 0, sizeof(struct DescriptorRing));
	memset(&priv->WQIT[wq_num], 0, sizeof(struct WQITE));
	return 0;
}

/* /!\ Function expect wq->lock locked on entry and returns it unlocked */
static int release_shared_kernel_queue(struct dce_driver_priv *priv, int wq_num)
{
	/* Policy, wait for jobs for this context to execute */
	/* TODO: Probably not always what we want */
	struct work_queue *wq = priv->wq + wq_num;

	spin_unlock(&wq->lock);
	return 0;
}

/* /!\ Function expect wq->lock locked on entry and returns it unlocked */
static int release_user_queue(struct dce_driver_priv *priv, int wq_num)
{
	// TODO: Policy, abort jobs in queue
	// Let user deal with the flush as the
	// head/tail and associated indices are in userspace
	struct work_queue *wq = priv->wq + wq_num;
	/* Disable queue in HW */
	/* TODO: Need to poll for completion? Should we use abort ? */
	set_queue_enable(priv, wq_num, false);

	memset(&priv->WQIT[wq_num], 0, sizeof(struct WQITE));
	wq->type = DISABLED;
	spin_unlock(&wq->lock);
	return 0;
}

/*
 * Release gets called when all references to the file are dropped
 * There should not be multiple calls to release if the fd was cloned on fork
 * as a result, for user and owned kernel queues, we can always tear down
 * relevant data structures on call to release
 */
int dce_ops_release(struct inode *inode, struct file *file)
{
	struct dce_submitter_ctx *ctx = file->private_data;
	struct dce_driver_priv *priv = ctx->priv;
	int wq_num = ctx->wq_num;
	int err = 0;
	struct work_queue *wq;

	if (wq_num < 0) {
		/* clearing an unused ctx */
		goto opencleanup;
	}
	wq = priv->wq + wq_num;
	dev_dbg(&priv->dev, "Releasing fd for queue %d\n", wq_num);
	/*
	 * Lock the queue, this should make sure that not other operation happens on it
	 * before it is marked as disabled. The release function should unlock it.
	 */
	spin_lock(&wq->lock);
	switch (wq->type) {
	case KERNEL_WQ:
		err = release_kernel_queue(priv, wq_num);
		break;
	case SHARED_KERNEL_WQ:
		err = release_shared_kernel_queue(priv, wq_num);
		break;
	case USER_OWNED_WQ:
		err = release_user_queue(priv, wq_num);
		break;
	/* Unexpected cases*/
	case DISABLED:
	case RESERVED_WQ:
	case KERNEL_FLUSHING_WQ:
	default:
		err = -EFAULT;
		dev_err(&priv->dev, "Release on queue in unexpected state\n");
		spin_unlock(&wq->lock);
		break;
	}

opencleanup:
	if (ctx->sva)
		iommu_sva_unbind_device(ctx->sva);
	kfree(ctx);
	dev_info(&priv->dev, "Released fd for queue %d\n", wq_num);
	return err;
}

/*TODO: cleanup*/
#if 0
ssize_t dce_ops_write(struct file *fp, const char __user *buf, size_t count, loff_t *ppos)
{
	return 0;
}

ssize_t dce_ops_read(struct file *fp, char __user *buf, size_t count, loff_t *ppos)
{
	return 0;
}
#endif

/*
 * compute number of descriptors in a WQ using DSCSZ
 * should probably replace by a shift at some point
 * and also used the driver copy rather than fetch from HW...
 * TODO: remove
 */
static int get_num_desc_for_wq(struct dce_driver_priv *priv, int wq_num)
{
	int DSCSZ = priv->WQIT[wq_num].DSCSZ;
	int num_desc = DEFAULT_NUM_DSC_PER_WQ;

	while (DSCSZ--)
		num_desc *= 2;
	return num_desc;
}

static inline uint64_t dce_wq_size(struct work_queue *wq)
{
	return DEFAULT_NUM_DSC_PER_WQ << wq->wqite->DSCSZ;
}

static void notify_queue_update(struct dce_driver_priv *dev_ctx, int wq_num);

static bool dce_wq_full(struct work_queue *wq)
{
	uint64_t wq_size = dce_wq_size(wq);
	uint64_t tail  = wq->descriptor_ring.hti->tail;
	uint64_t clean = wq->descriptor_ring.clean_up_index;
	/* TODO: Should only be for kernel queues, check ?*/
	/* always leave one slot free */
	return tail == (clean + wq_size - 1);
}

static bool dce_wq_full_locked(struct work_queue *wq)
{
	bool ret;

	spin_lock(&wq->lock);
	ret = dce_wq_full(wq);
	spin_unlock(&wq->lock);
	return ret;
}

/* Push descriptor to kernel queue */
static int dce_push_descriptor(struct dce_driver_priv *priv,
		struct DCEDescriptor *descriptor, int wq_num, bool nonblock)
{
	struct DescriptorRing *ring;
	u64 tail_idx;
	int ret = 0;
	struct work_queue *wq = &priv->wq[wq_num];
	struct DCEDescriptor *dest;
	int queue_size;

	/* Serializing push_descriptor, queue type update, clean index update */
try_push:
	spin_lock(&wq->lock); /* Guarantees tail and type do not change */
	if (wq->type != KERNEL_WQ) {
		/* FIXME: Actually, this path is also used on flush */
		dev_warn(&priv->dev, "Pushing to invalid queue %d ?!?\n", wq_num);
		spin_unlock(&wq->lock);
		return -EFAULT;
	}
	queue_size = get_num_desc_for_wq(priv, wq_num);
	ring = &wq->descriptor_ring;
	tail_idx = ring->hti->tail;
	dev_dbg(&priv->dev,
		"Trying to push job %llu to wq %d (head=%llu, clean=%llu)\n",
		tail_idx, wq_num, ring->hti->head, ring->clean_up_index);

	if (dce_wq_full(wq)) {
		spin_unlock(&wq->lock);
		if (nonblock) {
			dev_dbg(&priv->dev, "Queue %d full, try again\n", wq_num);
			return -EAGAIN;
		}
		/* Wait for event*/
		dev_dbg(&priv->dev, "Queue %d full, waiting\n", wq_num);
		ret = wait_event_interruptible(wq->full_waiter,
					!dce_wq_full_locked(wq));
		if (ret) {
			dev_dbg(&priv->dev, "Queue %d was full, waiting interrupted\n", wq_num);
			return ret;
		}
		dev_dbg(&priv->dev, "Queue %d was full, retrying\n", wq_num);
		goto try_push;
	}
	/* If we got here, we can push!*/
	dest = ring->descriptors + (tail_idx % queue_size);
	/*copy descriptor to queue and make it observable */
	*dest = *descriptor;
	dma_wmb();
	/*
	 * increment tail index, but make sure the job is observable first
	 * the previous write should be observable to device before the write
	 * to tail is, otherwise corrupted job data might be considered
	 * /!\ may not wait for notify to check tail!
	 */
	ring->hti->tail++;
	spin_unlock(&wq->lock);
	/* Contains a wmb to make tail update observable before kicking the device */
	notify_queue_update(priv, wq_num);
	return 0; /* success */
}

static int parse_descriptor_based_on_opcode(
		struct DCEDescriptor *desc, struct DCEDescriptor *input, u32 pasid)
{
	desc->opcode = input->opcode;
	desc->ctrl = input->ctrl | 1; /* Always generate interrupt*/
	desc->operand0 = input->operand0;
	desc->pasid = 0;

	/* Default handling of operands */
	desc->source = input->source;
	desc->destination = input->destination;
	desc->completion = input->completion;
	desc->operand1 = input->operand1;
	desc->operand2 = input->operand2;
	desc->operand3 = input->operand3;
	desc->operand4 = input->operand4;

	// Set the pasid and valid bits
	desc->pasid = pasid;
	desc->pasid |= TRANSCTL_PASID_V; /* Always use SVA for job mem accesses*/
	return 0;
}

void dce_reset_descriptor_ring(struct dce_driver_priv *drv_priv, int wq_num)
{
	/*TODO: repurpose this function */
}

/* return an unused workqueue number or -1*/
static int reserve_unused_wq(struct dce_driver_priv *priv)
{
	int ret = -1;

	mutex_lock(&(priv->lock));
	for (int i = 0; i < NUM_WQ; ++i) {
		struct work_queue *wq = priv->wq + i;

		if (wq->type == DISABLED) {
			ret = i;
			wq->type = RESERVED_WQ;
			break;
		}
	}
	mutex_unlock(&(priv->lock));
	return ret;
}

/* set the enable bit for queue in dce HW */
static void set_queue_enable(struct dce_driver_priv *dev_ctx, int wq_num, bool enable)
{
	u64 wq_enable;

	if (enable)
	/* Ensure that writes to the updated mem structures are observable by
	 * device before actually enabling the queue
	 */
		wmb();
	/*
	 * TODO: This is the best we can do for now before HW offers a solution
	 * for atomic clear/set of enable bits.
	 */
	spin_lock(&dev_ctx->reg_lock);
	wq_enable = dce_reg_read(dev_ctx, DCE_REG_WQENABLE);
	if (enable)
		wq_enable |= BIT_ULL(wq_num);
	else
		wq_enable &= (~BIT_ULL(wq_num));
	dce_reg_write(dev_ctx, DCE_REG_WQENABLE, wq_enable);
	spin_unlock(&dev_ctx->reg_lock);
}

static void notify_queue_update(struct dce_driver_priv *dev_ctx, int wq_num)
{
	uint64_t WQCR_REG = ((wq_num + 1) * PAGE_SIZE) + DCE_REG_WQCR;
	/*
	 * We want all previous writes to be observable before
	 * the dce_reg_write which is an io_write
	 * The device should observe the updated tail index or jobs may be missed
	 */
	wmb();
	dce_reg_write(dev_ctx, WQCR_REG, 1);
}

static int setup_user_wq(struct dce_submitter_ctx *ctx,
					  int wq_num, struct UserArea *ua)
{
	struct dce_driver_priv *dce_priv = ctx->priv;
	size_t length = ua->numDescs;
	struct work_queue *wq = dce_priv->wq+wq_num;
	struct DescriptorRing *ring = &wq->descriptor_ring;
	int size = length * sizeof(struct DCEDescriptor);
	int DSCSZ;

	if (wq->type != RESERVED_WQ) {
		dev_dbg(&dce_priv->dev,
			"User queue setup on reserved queue only, clean/reserve first");
		return -EFAULT;
	}
	/* make sure size is multiple of 4K */
	/* TODO: Check alignement as per spec, i.e. naturally aligned to full queue size*/
	if ((size < 0x1000) || (__arch_hweight64(size) != 1)) {
		dev_warn(&dce_priv->dev, "Invalid size requested for User queue:%d", size);
		return -EBADR;
	}
	DSCSZ = fls(size) - fls(0x1000);

	// printk(KERN_INFO"%s: DSCSZ is 0x%x\n",__func__, DSCSZ);

	ring->length = length;
	/* TODO: Check alignment for both*/
	ring->descriptors = (struct DCEDescriptor *)ua->descriptors;
	ring->hti = (struct HeadTailIndex *)ua->hti;

	/*Setup WQITE */
	dce_priv->WQIT[wq_num].DSCBA  = (u64) ring->descriptors;
	dce_priv->WQIT[wq_num].DSCSZ  = DSCSZ;
	dce_priv->WQIT[wq_num].DSCPTA = (u64) ring->hti;
	/* set the PASID fields in TRANSCTL */
	dce_priv->WQIT[wq_num].TRANSCTL = FIELD_PREP(TRANSCTL_SUPV, 0) |
					  FIELD_PREP(TRANSCTL_PASID_V, 1) |
					  FIELD_PREP(TRANSCTL_PASID, ctx->pasid);
	dce_priv->WQIT[wq_num].keys[0]  = DCE_KEY_VALID_ENTRY(6);
	dce_priv->WQIT[wq_num].keys[1]  = DCE_KEY_VALID_ENTRY(18);

	/* enable queue in HW, does its own wmb()*/
	set_queue_enable(dce_priv, wq_num, true);

	/* enabled queue in driver */
	dce_priv->wq[wq_num].type = USER_OWNED_WQ;
	dev_info(&dce_priv->dev, "wq %d as USER_OWNED_WQ\n", wq_num);
	return 0;
}

static int request_user_wq(struct dce_submitter_ctx *ctx, struct UserArea *ua)
{
	struct dce_driver_priv *priv = ctx->priv;
	/*TODO: Could make sense to do UserArea validation here */
	int wqnum = reserve_unused_wq(priv);

	if (wqnum < 0) /* no more free queues */
		return -ENOBUFS;

	ctx->wq_num = wqnum;
	/*
	 * TODO: Refactor, pass only &wq to setup_memory
	 * return WQ as DISABLED on error
	 */
	return setup_user_wq(ctx, ctx->wq_num, ua);
}

int setup_kernel_wq(struct dce_driver_priv *dce_priv, int wq_num,
		struct KernelQueueReq *kqr)
{
	struct work_queue *wq = dce_priv->wq + wq_num;
	struct DescriptorRing *ring = &wq->descriptor_ring;
	int DSCSZ = 0;
	size_t length;
	int err = 0;

	memset(ring, 0, sizeof(struct DescriptorRing));
	/* Only setup reserved queues */
	if (dce_priv->wq[wq_num].type != RESERVED_WQ) {
		pr_err("Queue setup only possible on reserved queue, clean/reserve first\n");
		err = -EFAULT;
		goto type_error;
	}

	// Parse KernelQueueReq if provided
	if (kqr) {
		DSCSZ = kqr->DSCSZ;
		if (kqr->eventfd_vld) {
			struct eventfd_ctx *efdctx = eventfd_ctx_fdget(kqr->eventfd);

			if (IS_ERR(efdctx)) {
				err = PTR_ERR(efdctx);
				dev_warn(&dce_priv->dev, "Unable to get eventfd\n");
				goto efd_error;
			}
			wq->efd_ctx = efdctx;
			wq->efd_ctx_valid = true;
		}
	}

	/* TODO: Some commonality with user queue code, regroup in the same place*/
	/* Supervisor memory setup */

	/* per DCE spec: Actual ring size is computed by: 2^(DSCSZ + 12) */
	length = 0x1000 * (1 << DSCSZ) / sizeof(struct DCEDescriptor);
	ring->length = length;

	// Allcate the descriptors as coherent DMA memory
	// TODO: Error handling, alloc DMA can fail
	ring->descriptors =
		dma_alloc_coherent(&dce_priv->pdev->dev, length * sizeof(struct DCEDescriptor),
			&ring->desc_dma, GFP_KERNEL);
	if (!ring->descriptors) {
		dev_err(&dce_priv->dev, "Failed to allocate job storage\n");
		err = -ENOMEM;
		goto descriptor_alloc_error;
	}

	//printk(KERN_INFO "Allocated wq %u descriptors at 0x%llx\n", wq_num,
	//	(uint64_t)ring->descriptors);

	ring->hti = dma_alloc_coherent(&dce_priv->pdev->dev,
		sizeof(struct HeadTailIndex), &ring->hti_dma, GFP_KERNEL);
	if (!ring->hti) {
		err = -ENOMEM;
		goto hti_alloc_error;
	}
	ring->hti->head = 0;
	ring->hti->tail = 0;

	/* populate WQITE */
	dce_priv->WQIT[wq_num].DSCBA = ring->desc_dma;
	dce_priv->WQIT[wq_num].DSCSZ = DSCSZ;
	dce_priv->WQIT[wq_num].DSCPTA = ring->hti_dma;
	dce_priv->WQIT[wq_num].TRANSCTL = FIELD_PREP(TRANSCTL_SUPV, 1);
	/* TODO: get from user */
	dce_priv->WQIT[wq_num].keys[0]  = DCE_KEY_VALID_ENTRY(6);
	dce_priv->WQIT[wq_num].keys[1]  = DCE_KEY_VALID_ENTRY(18);
	/* enable the queue in HW, does its own wmb() */
	set_queue_enable(dce_priv, wq_num, true);

	/* mark the WQ as enabled in driver */
	dce_priv->wq[wq_num].type = KERNEL_WQ;
	dev_info(&dce_priv->dev, "wq %d as KERNEL_WQ\n", wq_num);
	return 0;

efd_error:
hti_alloc_error:
	dma_free_coherent(&dce_priv->pdev->dev, length * sizeof(struct DCEDescriptor),
		ring->descriptors, ring->desc_dma);
descriptor_alloc_error:
	if (wq->efd_ctx_valid) {
		eventfd_ctx_put(wq->efd_ctx);
		wq->efd_ctx_valid = false;
	}
type_error:
	return err;
}

/*
 * set up default shared kernel submission queue 0
 * type of queue is set late, but it is ok because this is done
 * before device is exposed, so no need for normal locking
 */
int setup_default_kernel_queue(struct dce_driver_priv *dce_priv)
{
	struct work_queue *wq = &(dce_priv->wq[0]);
	/* Reserve WQ 0 */
	mutex_lock(&dce_priv->lock);
	if (wq->type != DISABLED) {
		pr_err("Default queue already used\n");
		mutex_unlock(&dce_priv->lock);
		return -EFAULT;
	}
	wq->type = RESERVED_WQ;
	mutex_unlock(&dce_priv->lock);
	if (setup_kernel_wq(dce_priv, 0, NULL) < 0) {
		pr_err("Error setting up default queue\n");
		/* TODO: return queue to unused */
		return -EFAULT;
	}
	wq->type = SHARED_KERNEL_WQ;
	return 0;
}

static int request_kernel_wq(
					struct dce_submitter_ctx *ctx, struct KernelQueueReq *kqr)
{
	/* WQ shouldn't have been assigned at this point */
	if (ctx->wq_num != -1)
		return -EFAULT;

	dev_info(&ctx->priv->dev, "Requesting kernel WQ\n");
	/* allocate a queue to context or fallback to wq 0*/
	{
		int wqnum = reserve_unused_wq(ctx->priv);

		if (wqnum < 0) { /* no more free queues */
			ctx->wq_num = 0; /* Fallback to shared queue */
			/* TODO: Would it make more sense to just fault here*/
			dev_info(&ctx->priv->dev, "Out of wq, falling back to default!\n");
		} else {
			ctx->wq_num = wqnum;
			/*
			 * TODO: Refactor, pass only &wq to setup_memory
			 * requires a separate activation function for the queue
			 */
			if (setup_kernel_wq(ctx->priv, wqnum, kqr) < 0) {
				dev_err(&ctx->priv->dev,
					"Failure to setup wq %d as kernel WQ\n",
					wqnum);
				return -EFAULT;
			}
		}
	}
	return 0;
}


static void init_wq(struct work_queue *wq)
{
	wq->type = DISABLED;
	spin_lock_init(&wq->lock);
	init_waitqueue_head(&wq->full_waiter);
}

void free_resources(struct device *dev, struct dce_driver_priv *priv)
{
	/* TODO: Free each WQ as well? */
	/* also take the HW down properly, waiting for it to be unpluggable?*/
	if (priv->WQIT)
		dma_free_coherent(&priv->pdev->dev, 0x1000, priv->WQIT, priv->WQIT_dma);
}

long dce_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct DCEDescriptor descriptor;
	struct dce_submitter_ctx *ctx = file->private_data;
	struct dce_driver_priv *priv = ctx->priv;

#ifdef CONFIG_IOMMU_SVA
	/* prevent all ioctl from succeeding if the fd is from a parent process*/
	if (ctx->pasid != current->mm->pasid)
		return -EBADFD;
#endif
	switch (cmd) {
/*TODO: cleanup*/
#if 0
		case RAW_READ: {
			struct AccessInfoRead __user *__access_info;
			struct AccessInfoRead access_info;

			__access_info = (struct AccessInfoRead __user *) arg;
			if (copy_from_user(&access_info, __access_info, sizeof(access_info)))
				return -EFAULT;

			val = ioread64((void __iomem *)(priv->mmio_start + access_info.offset));
			if (copy_to_user(access_info.value, &val, 8))
				dev_info(&priv->dev, "error during iread ioctl!\n");

			break;
		}

		case RAW_WRITE: {
			struct AccessInfoWrite __user *__access_info;
			struct AccessInfoWrite access_info;

			__access_info =	(struct AccessInfoWrite __user *) arg;
			if (copy_from_user(&access_info, __access_info, sizeof(access_info)))
				return -EFAULT;

			iowrite64(access_info.value, (void __iomem *)(priv->mmio_start + access_info.offset));

			break;
		}
#endif
	case REQUEST_KERNEL_WQ:
		{
			struct KernelQueueReq __user *__kqr_input;
			struct KernelQueueReq kqr = {
				.DSCSZ = 0, .eventfd_vld = false, .eventfd = 0};

			/* Check if PASID is enabled */
			if (!priv->sva_enabled)
				return -EFAULT;

			__kqr_input = (struct KernelQueueReq __user *) arg;
			if (__kqr_input) /* TODO: What if NULL ?, should it be -EFAULT as well?*/
				if (copy_from_user(&kqr, __kqr_input, sizeof(struct KernelQueueReq)))
					return -EFAULT;

			return request_kernel_wq(ctx, &kqr);
		}
		break;

	case SETUP_USER_WQ:
		{
			struct UserArea __user *__UserArea_input;
			struct UserArea ua;

			/* Check if PASID is enabled */
			if (!priv->sva_enabled)
				return -EFAULT;

			__UserArea_input = (struct UserArea __user *) arg;
			if (copy_from_user(&ua, __UserArea_input, sizeof(struct UserArea)))
				return -EFAULT;

			/* WQ shouldn't havve been assigned at this point */
			if (ctx->wq_num != -1)
				return -EFAULT;
			return request_user_wq(ctx, &ua);
		}
		break;

		case SUBMIT_DESCRIPTOR: {
			struct DCEDescriptor __user *__descriptor_input;
			struct DCEDescriptor descriptor_input;
			bool nonblock = file->f_flags & O_NONBLOCK;

			__descriptor_input = (struct DCEDescriptor __user *) arg;
			if (copy_from_user(&descriptor_input, __descriptor_input, sizeof(descriptor_input)))
				return -EFAULT;

			/* Default to WQ 0 (Shared kernel) if not assigned */
			if (ctx->wq_num == -1) {
				pr_info("Falling back to default queue\n");
				ctx->wq_num = 0;
			}

			if (parse_descriptor_based_on_opcode(&descriptor,
				&descriptor_input, ctx->pasid) < 0) {
				pr_warn("Failed to parse descriptor for submission\n");
				return -EFAULT;
			}
			return dce_push_descriptor(priv, &descriptor, ctx->wq_num, nonblock);
		}
	}

	return 0;
}

int dce_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct dce_submitter_ctx *ctx = file->private_data;
	struct dce_driver_priv *priv = ctx->priv;
	unsigned long pfn;

	if (ctx->wq_num == -1)
		return -EFAULT;
	if (priv->wq[ctx->wq_num].type != USER_OWNED_WQ)
		return -EACCES;

	/* WQCR are in a page each, page offset wq_num+1 */
	pfn = phys_to_pfn(priv->mmio_start_phys);
	pfn += (ctx->wq_num + 1);

	/* Make sure the door bell does not work with fork() */
	vm_flags_set(vma, VM_IO | VM_DONTEXPAND | VM_DONTDUMP | VM_DONTCOPY);
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	// printk(KERN_INFO "Mappping wq %d from 0x%lx to 0x%lx\n", wq_num, vma->vm_start,pfn);

	if (io_remap_pfn_range(vma, vma->vm_start, pfn, PAGE_SIZE,
			vma->vm_page_prot)) {
		dev_warn(&priv->dev, "Mapping failed!\n");
		return -EAGAIN;
	}
	return 0;
}

static const struct file_operations dce_ops = {
	.owner          = THIS_MODULE,
	.open           = dce_ops_open,
	.release        = dce_ops_release,
/*TODO: cleanup*/
#if 0
	.read           = dce_ops_read,
	.write          = dce_ops_write,
#endif
	.mmap           = dce_mmap,
	.unlocked_ioctl = dce_ioctl
};

irqreturn_t handle_dce(int irq, void *dce_priv_p)
{
	struct dce_driver_priv *dce_priv = dce_priv_p;

	/* FIXME: multiple thread running this? schedule_work reentrant safe?*/
	dev_dbg(&dce_priv->dev, "Got interrupt %d, work scheduled!\n", irq);
	schedule_work(&dce_priv->clean_up_worker);
	return IRQ_HANDLED;
}

int setup_memory_regions(struct dce_driver_priv *drv_priv)
{
	struct device *dev = &drv_priv->pdev->dev;
	int err = 0;

	err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	/* TODO: Actually handle error !? */
	if (err)
		dev_info(&drv_priv->pdev->dev, "DMA set mask failed: %d\n", err);
	/* WQIT is 4KiB */
	/* TODO: Error handling, dma_alloc can fail*/
	/* TODO: check alignement, the idea is to have a page aligned alloc */
	drv_priv->WQIT =
		dma_alloc_coherent(dev, 0x1000, &drv_priv->WQIT_dma, GFP_KERNEL);
	if ((drv_priv->WQIT_dma & GENMASK(11, 0)) != 0) {
		dev_err(&drv_priv->dev, "DCE: WQITBA[11:0]:0x%pad is not all zero!\n",
			&drv_priv->WQIT_dma);
		dma_free_coherent(dev, 0x1000, drv_priv->WQIT, drv_priv->WQIT_dma);
		return -EFAULT;
	}
	for (int w = 0; w < NUM_WQ; w++)
		drv_priv->wq[w].wqite = drv_priv->WQIT + w;

	dce_reg_write(drv_priv, DCE_REG_WQITBA, (uint64_t) drv_priv->WQIT_dma);
	return 0;
}

/* Probing, registering and device name management below */

static struct pci_driver dce_driver;

static int dce_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int err = 0;
	struct dce_driver_priv *drv_priv;
	struct device *dev = &pdev->dev;
	struct cdev *cdev;
	bool isPF = pdev->is_physfn;
	int minor;

	dev_info(dev, "Probing DCE: vendor:%x device:%x\n",
			(int)pdev->vendor, (int)pdev->device);

	if (!isPF && pdev->device != DEVICE_VF_ID) {
		dev_err(dev, "Unhandled device type!\n");
		return -ENOTDIR;
	}

	err = pci_enable_device_mem(pdev);
	if (err) {
		dev_err(dev, "pci_enable_device_mem fail\n");
		return err;
	}

	err = pci_request_mem_regions(pdev, DEVICE_NAME);
	if (err) {
		dev_err(dev, "pci_request_mem_regions fail\n");
		goto disable_device_and_fail;
	}

	pci_set_master(pdev);

	drv_priv = kzalloc_node(sizeof(*drv_priv), GFP_KERNEL,
			     dev_to_node(dev));
	if (!drv_priv) {
		err = -ENOMEM;
		goto disable_device_and_fail;
	}

	drv_priv->pdev = pdev;

	drv_priv->mmio_start_phys = pci_resource_start(pdev, 0);

	if (iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_SVA)) {
		drv_priv->sva_enabled = false;
		dev_err(dev, "DCE:Unable to turn on user SVA feature. Device disabled\n");
		goto disable_device_and_fail;
	} else {
		dev_info(dev, "DCE:SVA feature enabled.\n");
		drv_priv->sva_enabled = true;
	}

	// initialize the child device
	dev = &drv_priv->dev;

	device_initialize(dev);
	if (isPF) {
		minor = ida_alloc(&dce_minor_ida, GFP_KERNEL);
		if (minor < 0) {
			dev_err(dev, "Failure to get minor\n");
			goto free_resources_and_fail;
		}
		drv_priv->id = minor;
		dev->devt = MKDEV(MAJOR(dev_num), minor);
		err = dev_set_name(dev, "dce%dfn0", minor);
	} else {
		int vf_num = pci_iov_vf_id(pdev);
		int pf_id;
		struct dce_driver_priv *pfdrv = pci_iov_get_pf_drvdata(pdev, &dce_driver);

		if (IS_ERR_OR_NULL(pfdrv)) {
			dev_err(dev, "Failed to get PF driver data\n");
			goto free_resources_and_fail;
		}
		pf_id = pfdrv->id;
		if (vf_num < 0) {
			dev_err(dev, "Failed to identify PF\n");
			goto free_resources_and_fail;
		}
		minor = ida_alloc(&dcevf_minor_ida,  GFP_KERNEL);
		if (minor < 0) {
			dev_err(dev, "Failure to get minor\n");
			goto free_resources_and_fail;
		}
		dev->devt = MKDEV(MAJOR(dev_vf_num), minor);
		err = dev_set_name(dev, "dce%dfn%d", pf_id, vf_num+1);
	}

	dev->parent = &pdev->dev;

	cdev = &drv_priv->cdev;
	cdev_init(cdev, &dce_ops);
	cdev->owner = THIS_MODULE;

	drv_priv->mmio_start = (uint64_t)pci_iomap(pdev, 0, 0);

	pci_set_drvdata(pdev, drv_priv);

	/* priv mem regions setup */
	err = setup_memory_regions(drv_priv);
	if (err)
		goto disable_device_and_fail;

	/* MSI setup */
	/*TODO: Check. pci_match_id is marked as deprecated in kernel doc */
	if (pci_match_id(pci_use_msi, pdev)) {
		int vec;

		pci_set_master(pdev);
		err = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_ALL_TYPES);
		if (err < 0)
			dev_err(dev, "Failed setting up IRQ\n");

		dev_info(&pdev->dev,
				"Using MSI(-X) interrupts: msi_enabled:%d, msix_enabled: %d\n",
				pdev->msi_enabled,
				pdev->msix_enabled);

		vec = pci_irq_vector(pdev, 0);
		dev_info(&pdev->dev, "irqcount: %d, IRQ vector is %d\n", err, vec);

		/* auto frees on device detach, nice */
		err = devm_request_threaded_irq(dev, vec, handle_dce, NULL,
							IRQF_ONESHOT, DEVICE_NAME, drv_priv);
		if (err < 0)
			dev_err(&pdev->dev, "Failed setting up IRQ\n");
	} else {
		dev_warn(&pdev->dev, "DCE: MSI enable failed\n");
	}

	if (isPF) {
		err = pci_enable_sriov(pdev, DCE_NR_VIRTFN);
		if (err < 0) {
			dev_err(&pdev->dev, "pci_enable_sriov fail\n");
			goto disable_device_and_fail;
		}
	}


	/* work queue setup */
	INIT_WORK(&drv_priv->clean_up_worker, clean_up_work);

	/* init mutex */
	mutex_init(&drv_priv->lock);
	spin_lock_init(&drv_priv->reg_lock);

	for (int i = 0; i < NUM_WQ; i++)
		init_wq(drv_priv->wq+i);

	/* Simple setup for key ownership, all for all for now*/
	for (int fn = 0; fn < DCE_NR_FN; fn++)
		dce_reg_write(drv_priv, DCE_GCS_KEYOWN(fn), ~(u64)0);

	/* setup WQ 0 for SHARED_KERNEL usage */
	err = setup_default_kernel_queue(drv_priv);
	if (err < 0)
		goto free_resources_and_fail;

	/* Finally expose the device */
	err = cdev_device_add(&drv_priv->cdev, &drv_priv->dev);
	if (err) {
		dev_err(&pdev->dev, "cdev add failed\n");
		goto free_resources_and_fail;
	} else {
		dev_info(&pdev->dev, "Exposing as %s", dev_name(dev));
	}
	return 0;

free_resources_and_fail:
	free_resources(dev, drv_priv);

disable_device_and_fail:
	pci_disable_device(pdev);
	return err;
}

static int dev_sriov_configure(struct pci_dev *dev, int numvfs)
{
	if (numvfs > 0) {
		pci_enable_sriov(dev, numvfs);
		return numvfs;
	}
	if (numvfs == 0) {
		pci_disable_sriov(dev);
		return 0;
	}
	return 0;
}

static void dce_remove(struct pci_dev *pdev)
{
	free_resources(&pdev->dev, pci_get_drvdata(pdev));
}

static SIMPLE_DEV_PM_OPS(vmd_dev_pm_ops, vmd_suspend, vmd_resume);

static const struct pci_device_id dce_id_table[] = {
	{PCI_DEVICE(VENDOR_ID, DEVICE_ID)},
	{0, },
};
MODULE_DEVICE_TABLE(pci, dce_id_table);

static struct pci_driver dce_driver = {
	.name     = DEVICE_NAME,
	.id_table = dce_id_table,
	.probe    = dce_probe,
	.remove   = dce_remove,
	.sriov_configure = dev_sriov_configure,
	.driver	= {
		.pm = &vmd_dev_pm_ops,
	},
};

static const struct pci_device_id dcevf_id_table[] = {
	{PCI_DEVICE(VENDOR_ID, DEVICE_VF_ID)},
	{0, },
};

static struct pci_driver dcevf_driver = {
	.name     = DEVICE_VF_NAME,
	.id_table = dcevf_id_table,
	.probe    = dce_probe,
	.remove   = dce_remove,
	.driver	= {
		.pm = &vmd_dev_pm_ops,
	},
};

static int __init dce_driver_init(void)
{
	int err;
	/* PF driver init */
	err = alloc_chrdev_region(&dev_num, 0, MAX_DCE_DEVICES, DEVICE_NAME);
	if (err)
		return err;

	err = pci_register_driver(&dce_driver);
	/* VF driver init */
	err = alloc_chrdev_region(&dev_vf_num, 0, MAX_DCE_DEVICES*DCE_NR_VIRTFN, DEVICE_VF_NAME);
	if (err)
		return err;

	err = pci_register_driver(&dcevf_driver);
	return err;
}

static void __exit dce_driver_exit(void)
{
	pci_unregister_driver(&dce_driver);
	pci_unregister_driver(&dcevf_driver);
}

MODULE_LICENSE("GPL");

module_init(dce_driver_init);
module_exit(dce_driver_exit);

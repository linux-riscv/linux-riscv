/* isbdmex
 *
 * ISBDM exerciser driver
 *
 * SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * 3 Feb 2023 mev
 */

#include <linux/bitmap.h>
#include <linux/device.h>
#include <linux/dmapool.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pci-epf.h>
#include <linux/pci_ids.h>
#include <linux/random.h>
#include <linux/rivos-rot.h>
#include <linux/uaccess.h>

#include "isbdmex.h"

/******************************************************************************/
/* Multiple device/instance management */

/* Driver'll be instantiated several times, probed in order of discovery in PCI.
 * This bitmap holds which indices have been probed/are live:
 */
#define ISBDM_MAX_INSTANCES	64			/* In reality, 32! */

static DEFINE_MUTEX(isbdmex_mutex);
static unsigned long		isbdm_instance_bmap = 0;

/*
 * Keep a global list of devices so at open time they can be looked up by minor
 * number, also protected by the mutex.
 */
static LIST_HEAD(isbdmex_list);

/* Finds an available instance index, or returns -1 if full: */
static int isbdmex_new_instance(struct isbdm *ii)
{
	mutex_lock(&isbdmex_mutex);
	ii->instance = bitmap_find_free_region(&isbdm_instance_bmap,
					       ISBDM_MAX_INSTANCES, 0);

	if (ii->instance >= 0)
		list_add_tail(&ii->node, &isbdmex_list);

	mutex_unlock(&isbdmex_mutex);
	return ii->instance;
}

static void isbdmex_del_instance(struct isbdm *ii)
{
	mutex_lock(&isbdmex_mutex);
	if (ii->instance >= 0)
		bitmap_release_region(&isbdm_instance_bmap, ii->instance, 0);

	list_del(&ii->node);
	mutex_unlock(&isbdmex_mutex);
}

static struct isbdm *isbdmex_locate(int minor)
{
	struct isbdm *found = NULL;
	struct isbdm *ii;

	mutex_lock(&isbdmex_mutex);
	list_for_each_entry(ii, &isbdmex_list, node) {
		if (ii->misc.minor == minor) {
			found = ii;
			break;
		}
	}

	mutex_unlock(&isbdmex_mutex);
	return found;
}

/******************************************************************************/
/* IRQ handling */

static irqreturn_t isbdmex_irq_handler(int irq, void *data)
{
	struct isbdm *ii = data;
	u64 ipsr = ISBDM_READQ(ii, ISBDM_IPSR) & ~ii->irq_mask;

	if (ipsr) {
		/* TODO: I don't need an exchange, just a write. How to do? */
		atomic64_xchg(&ii->pending_irqs, ipsr);
		return IRQ_WAKE_THREAD;
	}

	return IRQ_NONE;
}

static irqreturn_t isbdmex_irq_thread(int irq, void *data)
{
	struct isbdm *ii = data;
	u64 pending = atomic64_xchg(&ii->pending_irqs, 0);
	u64 handled = ISBDM_TXMF_IRQ | ISBDM_RXMF_IRQ | ISBDM_TXDONE_IRQ |
		      ISBDM_RXOVF_IRQ | ISBDM_RXRTHR_IRQ | ISBDM_RXDONE_IRQ |
		      ISBDM_IPSR_IIP | ISBDM_CMDDONE_IRQ | ISBDM_CMDMF_IRQ |
		      ISBDM_LNKSTS_IRQ;

	if (pending & (ISBDM_TXMF_IRQ | ISBDM_RXMF_IRQ)) {
		dev_err(&ii->pdev->dev, "memory fault %llx\n", pending);
		/* TODO: Actually do something about TXMF (flush ring?) */
	}

	if (pending & ISBDM_LNKSTS_IRQ)
		isbdm_process_link_status_change(ii);

	if (pending & ISBDM_RXOVF_IRQ)
		isbdm_rx_overflow(ii);

	/* The summary bit should indicate a pending interrupt. */
	WARN_ON_ONCE(!(pending & ISBDM_IPSR_IIP));

	/*
	 * Disable the RX threshold interrupt to avoid it immediately refiring
	 * until further in this function.
	 */
	if (pending & ISBDM_RXRTHR_IRQ)
		isbdm_disable_interrupt(ii, ISBDM_RXRTHR_IRQ);

	/* Write 1 to clear the handled interrupts. */
	ISBDM_WRITEQ(ii, ISBDM_IPSR, handled & pending);

	/*
	 * Only process completed entries after clearing the interrupt.
	 * Otherwise another packet could complete after we've read HEAD but
	 * before completing the interrupt, and we'd never get notified again.
	 */
	if (pending & ISBDM_RXDONE_IRQ)
		isbdm_process_rx_done(ii);

	if (pending & ISBDM_RXRTHR_IRQ)
		isbdm_rx_threshold(ii);

	if (pending & ISBDM_TXDONE_IRQ)
		isbdm_reap_tx(ii);

	if (pending & ISBDM_CMDDONE_IRQ)
		isbdm_reap_cmds(ii);

	return IRQ_HANDLED;
}

static int isbdmex_request_irq(struct pci_dev *pdev)
{
	int ret, irq;
	struct device *dev = &pdev->dev;
	struct isbdm *ii = (struct isbdm *)pci_get_drvdata(pdev);

	/* FIXME: Can this leak/does devm sweep this? */
	ret = pci_alloc_irq_vectors(pdev,
				    /* Just the one? */ 1, 1,
				    PCI_IRQ_MSI | PCI_IRQ_MSIX);
	if (ret < 0) {
		dev_err(dev, "Failed to allocate MSI (%d)\n", ret);
		return ret;
	}

	/* Get Linux IRQ number from the MSI vector #0: */
	irq = pci_irq_vector(pdev, 0);
	if (irq < 0) {
		dev_err(dev, "IRQ vector invalid (%d)\n", irq);
		return irq;
	}
	ii->irq = irq;

	ret = devm_request_threaded_irq(dev, irq,
					isbdmex_irq_handler, isbdmex_irq_thread,
					IRQF_ONESHOT, dev_name(dev), ii);
	if (ret < 0) {
		dev_err(dev, "Request for IRQ%d failed (%d)\n", irq, ret);
		return ret;
	}

	return ret;
}

void isbdmex_user_ctx_release(struct kref *ref)
{
	struct isbdm_user_ctx *ctx;

	ctx = container_of(ref, struct isbdm_user_ctx, ref);

	WARN_ON_ONCE(ctx->last_error.inflight_commands);

	kfree(ctx);
}

/******************************************************************************/
/* fops/user handling */

static int isbdmex_open(struct inode *inode, struct file *file)
{

	struct isbdm_user_ctx *ctx;
	struct isbdm *ii;
	int rc;

	ii = isbdmex_locate(iminor(inode));
	if (!ii)
		return -ENODEV;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	kref_init(&ctx->ref);

	/*
	 * TODO: Refcounting on the device to make sure it doesn't disappear out
	 * from under us.
	 */
	file->private_data = ctx;
	ctx->isbdm = ii;

/* No PASIDs in hybrid sim */
#ifndef CONFIG_RIVOS_ISBDM_HYBRID_SIM
	ctx->sva = iommu_sva_bind_device(&ii->pdev->dev, current->mm);
	if (IS_ERR(ctx->sva)) {
		rc = PTR_ERR(ctx->sva);
		dev_err(&ii->pdev->dev, "pasid allocation failed: %d\n", rc);
		kfree(ctx);
		return rc;
	}
#endif

	return 0;
}

static int isbdmex_release(struct inode *inode, struct file *file)
{
	struct isbdm_user_ctx *ctx;

	ctx = file->private_data;

	/* TODO: Refcounting on the device! See serio_raw_release() for ex. */
	isbdm_free_all_rmbs(ctx->isbdm, file);

/* No PASIDs in hybrid sim. */
#ifndef CONFIG_RIVOS_ISBDM_HYBRID_SIM
	iommu_sva_unbind_device(ctx->sva);
#endif
	kref_put(&ctx->ref, isbdmex_user_ctx_release);
	file->private_data = NULL;
	return 0;
}

static int isbdmex_get_last_error(struct isbdm *ii, struct isbdm_user_ctx *ctx,
				  void __user *argp)
{
	struct isbdm_last_error last_error;

	/* Lock the cmd ring to avoid racy updates to the last_error struct. */
	mutex_lock(&ii->cmd_ring.lock);
	memcpy(&last_error, &ctx->last_error, sizeof(last_error));
	ctx->last_error.error = ISBDM_STATUS_SUCCESS;
	mutex_unlock(&ii->cmd_ring.lock);
	if (copy_to_user(argp, &last_error, sizeof(last_error)))
		return -EFAULT;

	return 0;
}

static long isbdmex_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	u64 __user *argp64;
	struct isbdm_user_ctx *ctx = file->private_data;
	struct isbdm *ii = ctx->isbdm;
	u64 value;
	int rc;

	if (is_compat_task())
		argp64 = compat_ptr(arg);
	else
		argp64 = (void __user *)arg;
	rc = 0;

	switch (cmd) {
	case IOCTL_SET_IPMR:
		if (get_user(value, argp64) != 0)
			return -EFAULT;

		rc = put_user(isbdmex_ioctl_set_ipmr(ii, value), argp64);
		break;

	case IOCTL_CLEAR_IPMR:
		if (get_user(value, argp64) != 0)
			return -EFAULT;

		rc = put_user(isbdmex_ioctl_clear_ipmr(ii, value), argp64);
		break;

	case IOCTL_GET_IPSR:
		rc = put_user(isbdmex_ioctl_get_ipsr(ii), argp64);
		break;

	case IOCTL_RX_REFILL:
		isbdm_rx_threshold(ii);
		break;

	case IOCTL_ALLOC_RMB:
		rc = isbdmex_alloc_rmb(ii, file, argp64);
		break;

	case IOCTL_FREE_RMB:
		rc = isbdmex_free_rmb(ii, file, (unsigned long)argp64);
		break;

	case IOCTL_RDMA_CMD:
		rc = isbdmex_send_command(ii, ctx, argp64);
		break;

	case IOCTL_GET_LAST_ERROR:
		rc = isbdmex_get_last_error(ii, ctx, argp64);
		break;

	case IOCTL_GET_RX_DROP_CNT:
		rc = put_user(isbdmex_get_dropped_rx_count(ii), argp64);
		break;

	case IOCTL_LINK_STATUS_OP:
		rc = isbdmex_link_status_op(ii, argp64);
		break;

	default:
		rc = -ENOENT;
		break;
	}

	return rc;
}

static ssize_t isbdmex_read(struct file *file, char __user *va, size_t size,
			    loff_t *file_offset)
{
	struct isbdm_user_ctx *ctx = file->private_data;
	struct isbdm *ii = ctx->isbdm;
	ssize_t done;

	do {
		done = wait_event_interruptible_timeout(ii->read_wait_queue,
					!list_empty(&ii->rx_ring.wait_list) ||
					(ii->link_status == ISBDM_LINK_DOWN),
					5 * HZ);

		// if (done)
		// 	break;
		if (done <= 0) {
			printk("Read timeout. RX prod %x cons %x HEAD %llx TAIL %llx IPSR %llx IPMR %llx pending_irqs %llx\n",
				ii->rx_ring.prod_idx,
				ii->rx_ring.cons_idx,
				ISBDM_READQ(ii, ISBDM_RX_RING_HEAD),
				ISBDM_READQ(ii, ISBDM_RX_RING_TAIL),
				ISBDM_READQ(ii, ISBDM_IPSR),
				ISBDM_READQ(ii, ISBDM_IPMR),
				ii->pending_irqs.counter);

			if (done < 0)
				break;

			return -EAGAIN;
		}

		done = isbdmex_read_one(ii, va, size);
		if (!done && (file->f_flags & O_NONBLOCK)) {
			return -EAGAIN;
		}

	} while (!done);

	return done;
}

static ssize_t isbdmex_write(struct file *file, const char __user *va,
			     size_t size, loff_t *file_offset)
{
	struct isbdm_user_ctx *ctx = file->private_data;
	struct isbdm *ii = ctx->isbdm;
	ssize_t rc;

	rc = isbdmex_raw_send(ii, va, size);
	return rc;
}

static const struct file_operations isbdmex_fops = {
	.owner 		= THIS_MODULE,
	.read		= isbdmex_read,
	.write		= isbdmex_write,
	.open 		= isbdmex_open,
	.release 	= isbdmex_release,
	.unlocked_ioctl = isbdmex_ioctl,
};

/*
 * Called when the timer expires, or the first time, to send a handshake packet.
 */
void isbdm_handshake_work(struct work_struct *work)
{
	struct isbdm *ii = container_of(work, struct isbdm, handshake_work.work);
	int rc;

	rc = isbdm_send_handshake(ii);
	if (rc) {
		dev_warn(&ii->pdev->dev, "Failed to send handshake: %d\n", rc);
		return;
	}

	/* Re-arm the timer to send the handshake again. */
	if (ii->handshake_retry_count) {
		ii->handshake_retry_count -= 1;
		schedule_delayed_work(&ii->handshake_work,
				      msecs_to_jiffies(1000));

	} else {
		dev_warn(&ii->pdev->dev, "Handshake timeout\n");
	}
}

/******************************************************************************/
/* Probe, and PCI plumbing */

static int isbdmex_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int ret;
	struct device *dev = &pdev->dev;
	struct isbdm *ii;
	struct rivos_rot_device *rot;

	/*
	 * Get the RoT first, so there's no work to undo in case it hasn't
	 * probed yet.
	 */
	rot = get_rivos_rot();
	if (!rot) {
#ifdef CONFIG_RIVOS_ISBDM_HYBRID_SIM
		dev_warn(&pdev->dev, "No RoT yet, going anyway\n");
#else
		dev_warn(&pdev->dev, "No RoT yet, deferring\n");
		return -EPROBE_DEFER;
#endif
	}

	/* Allocate an instance (a struct isbdm), find resources, enable */
	ii = devm_kzalloc(dev, sizeof(struct isbdm), GFP_KERNEL);
	if (!ii) {
		dev_err_probe(dev, ret, "Can't allocate device instance\n");
		put_rivos_rot(rot);
		return -ENOMEM;
	}

	ii->pdev = pdev;
	ii->rot = rot;
	pci_set_drvdata(pdev, ii);

	ret = pcim_enable_device(pdev);
	if (ret < 0) {
		dev_err_probe(dev, ret, "Can't enable device\n");
		return ret;
	}

	/* MMIO */
	ret = pcim_iomap_regions(pdev, BIT(BAR_0), KBUILD_MODNAME);
	if (ret) {
		dev_err_probe(dev, ret, "Can't iomap regions\n");
		return ret;
	}

	ii->base = pcim_iomap_table(pdev)[BAR_0];
	ii->dvsec_cap = pci_find_dvsec_capability(pdev, PCI_VENDOR_ID_RIVOS,
						  ISBDM_DVSEC_ID);

	if (!ii->dvsec_cap) {
		ret = -ENODEV;
		dev_err_probe(dev, ret, "Failed to find ISBDM DVSEC\n");
		return ret;
	}

	isbdm_hw_reset(ii);
	ii->irq_mask = ~ISBDM_IPSR_IIP;
	init_waitqueue_head(&ii->read_wait_queue);
	ret = isbdm_init_hw(ii);
	if (ret) {
		dev_err_probe(dev, ret, "Init HW failed\n");
		return ret;
	}

	pci_set_master(pdev);
/* No PASIDs in hybrid sim. */
#ifndef CONFIG_RIVOS_ISBDM_HYBRID_SIM
	if (iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_SVA)) {
		dev_err_probe(dev, ret, "SVA enablement failed\n");
		goto deinit;
	}
#endif

	/*
	 * The device doesn't have a unique ID, so create a random one to try
	 * and avoid ID collisions with peers. Avoid 0 so it can be used as
	 * "unset".
	 */
	get_random_bytes(&ii->rand_id, sizeof(ii->rand_id));
	if (ii->rand_id == 0)
		ii->rand_id = 1;

	get_random_bytes(&ii->subnet_prefix, sizeof(ii->subnet_prefix));
	if (ii->subnet_prefix == 0)
		ii->subnet_prefix = 1;

	ii->inline_pool = dma_pool_create("isbdm-inline",
					  &ii->pdev->dev,
					  ISBDM_MAX_INLINE,
					  0,
					  0);

	if (!ii->inline_pool)  {
		ret = -ENOMEM;
		dev_err_probe(dev, ret, "Cannot create dma pool\n");
		goto deinit;
	}

	ret = isbdmex_request_irq(pdev);
	if (ret) {
		dev_err_probe(dev, ret, "IRQ setup failed\n");
		goto release_pool;
	}

	INIT_DELAYED_WORK(&ii->handshake_work, isbdm_handshake_work);
	ret = isbdmex_new_instance(ii);
	if (ret < 0) {
		dev_err_probe(dev, ret, "Too many ISBDMs!\n");
		goto release_irq;
	}

	dev_info(dev, "isbdm%d at %px, irq %d\n", ii->instance, ii->base, ii->irq);

	/* Register a misc device */
	ii->misc.minor = MISC_DYNAMIC_MINOR;
	ii->misc.fops = &isbdmex_fops;
	ii->misc.name = kasprintf(GFP_KERNEL, "isbdmex%d", ii->instance);
	if (!ii->misc.name) {
		dev_err_probe(dev, ret, "Can't alloc misc->name\n");
		goto unget_instance;
	}

	/* Get the hardware running! */
	isbdm_start(ii);
	ret = misc_register(&ii->misc);
	if (ret < 0) {
		dev_err_probe(dev, ret, "Can't register miscdev\n");
		goto free_misc_name;
	}

	isbdm_debugfs_init(ii);
	/* FIXME: sysfs: somehow expose enough info to map a /dev/isbdmexN to a PCS/hardware location */

	return 0;

free_misc_name:
	kfree(ii->misc.name);
	isbdm_disable(ii);

unget_instance:
	isbdmex_del_instance(ii);

release_irq:
	/* TODO: Undo isbdmex_request_irq(). */

release_pool:
	dma_pool_destroy(ii->inline_pool);

deinit:
	isbdm_deinit_hw(ii);
	if (ii->rot)
		put_rivos_rot(ii->rot);

	return ret;
}

static void isbdmex_remove(struct pci_dev *pdev)
{
	struct isbdm *ii = (struct isbdm *)pci_get_drvdata(pdev);

	isbdm_debugfs_cleanup(ii);

	/* TODO: Are we allowed to touch hardware in this routine? */
	isbdm_disable(ii);

	/* Some resources are freed by devres */
	misc_deregister(&ii->misc);
	isbdmex_del_instance(ii);
	dma_pool_destroy(ii->inline_pool);
	isbdm_deinit_hw(ii);
	return;
}

static const struct pci_device_id isbdmex_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_RIVOS, PCI_DEVICE_ID_RIVOS_ISBDM_PF), 0, 0, 0},
	{0,},
};

static struct pci_driver isbdmex_pci_driver = {
	.name 		= "isbdmex",
	.id_table 	= isbdmex_ids,
	.probe 		= isbdmex_probe,
	.remove		= isbdmex_remove,
};

MODULE_DEVICE_TABLE(pci, isbdmex_ids);
module_pci_driver(isbdmex_pci_driver);

static int __init isbdm_init_module(void)
{
	isbdm_init_debugfs();
	return 0;
}

static void __exit isbdm_exit_module(void)
{
	isbdm_remove_debugfs();
}

module_init(isbdm_init_module);
module_exit(isbdm_exit_module);

MODULE_AUTHOR("mev");
MODULE_LICENSE("GPL v2");

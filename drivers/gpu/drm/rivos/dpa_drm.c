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

#include <linux/kernel.h>
#include <linux/cpumask.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/device/class.h>
#include <linux/dev_printk.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/iommu.h>
#include <linux/mm.h>
#include <linux/pci.h>
#include <linux/sched/mm.h>
#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_ioctl.h>
#include <linux/pm_runtime.h>
#include <linux/of_reserved_mem.h>
#include <linux/of_address.h>
#include "dpa_drm.h"
#include "dpa_daffy.h"

#define dpa_class_name "dpa_drm"

static const struct drm_driver dpa_drm_driver;

/* device related stuff */
static struct class *dpa_class;
struct dpa_device *dpa;

struct dpa_process *dpa_get_process_by_mm(const struct mm_struct *mm)
{
	struct list_head *cur;
	struct dpa_process *dpa_app;

	mutex_lock(&dpa->dpa_processes_lock);

	list_for_each(cur, &dpa->dpa_processes) {
		struct dpa_process *cur_process =
			container_of(cur, struct dpa_process,
				     dpa_process_list);
		if (cur_process->mm == mm) {
			dpa_app = cur_process;
			kref_get(&dpa_app->ref);
			break;
		}
	}
	mutex_unlock(&dpa->dpa_processes_lock);

	return dpa_app;
}

struct dpa_process *dpa_get_process_by_pasid(u32 pasid)
{
	struct list_head *cur;
	struct dpa_process *dpa_app;

	mutex_lock(&dpa->dpa_processes_lock);

	list_for_each(cur, &dpa->dpa_processes) {
		struct dpa_process *cur_process =
			container_of(cur, struct dpa_process,
				     dpa_process_list);
		if (cur_process->pasid == pasid) {
			dpa_app = cur_process;
			kref_get(&dpa_app->ref);
			break;
		}
	}
	mutex_unlock(&dpa->dpa_processes_lock);

	return dpa_app;
}

static const struct pci_device_id dpa_pci_table[] = {
	{ PCI_VENDOR_ID_RIVOS, PCI_DEVICE_ID_RIVOS_DPA,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, dpa_pci_table);

static void dpa_setup_queue(struct dpa_device *dpa)
{
	dev_warn(dpa->dev, "DMA address of queue is: %llx\n",
		dpa->qinfo.fw_queue_dma_addr);
	dpa_fwq_write(dpa, dpa->qinfo.fw_queue_dma_addr,
		      DPA_FWQ_QUEUE_DESCRIPTOR);
}

static int dpa_drm_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct dpa_process *p;
	unsigned long mmap_offset = vma->vm_pgoff << PAGE_SHIFT;
	u64 type = mmap_offset >> DRM_MMAP_TYPE_SHIFT;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long pfn;
	int ret = -EFAULT;

	p = dpa_get_process_by_mm(current->mm);
	if (!p)
		return -EINVAL;

	dev_warn(p->dev->dev, "%s: offset 0x%lx size 0x%lx type %llu start 0x%llx\n",
			__func__, mmap_offset, size, type, (u64)vma->vm_start);
	switch (type) {

	case DRM_MMAP_TYPE_DOORBELL:
		if (size != DPA_DB_PAGE_SIZE) {
			dev_warn(p->dev->dev, "%s: invalid size for doorbell\n",
					__func__);
			kref_put(&p->ref, dpa_release_process);
			return -EINVAL;
		}

		// TODO: Right now we only support one MMIO-mapped doorbell page,
		// expand to all 16
		dev_warn(p->dev->dev, "%s: Mapping doorbell page\n", __func__);

		mutex_lock(&p->lock);
		pfn = p->doorbell_base;
		pfn >>= PAGE_SHIFT;

		ret = io_remap_pfn_range(vma, vma->vm_start, pfn, size,
			vma->vm_page_prot);
		mutex_unlock(&p->lock);

		if (ret) {
			dev_warn(p->dev->dev, "%s: failed to map doorbell page ret %d\n",
				__func__, ret);
		}
		break;
	default:
		dev_warn(p->dev->dev, "%s: doing nothing\n", __func__);
	}

	kref_put(&p->ref, dpa_release_process);
	return ret;
}

long dpa_drm_ioctl(struct file *filp,
		      unsigned int cmd, unsigned long arg)
{
	struct drm_file *file_priv = filp->private_data;
	struct drm_device *dev;
	long ret;

	dev = file_priv->minor->dev;
	ret = pm_runtime_get_sync(dev->dev);
	if (ret < 0)
		goto out;

	ret = drm_ioctl(filp, cmd, arg);

	pm_runtime_mark_last_busy(dev->dev);
out:
	pm_runtime_put_autosuspend(dev->dev);
	return ret;
}

static const struct file_operations dpa_driver_kms_fops = {
	.owner = THIS_MODULE,
	.open = drm_open,
	.release = drm_release,
	.unlocked_ioctl = dpa_drm_ioctl,
	.mmap = dpa_drm_mmap,
	.poll = drm_poll,
	.read = drm_read,
};

static void dpa_driver_release_kms(struct drm_device *dev, struct drm_file *file_priv)
{
	struct dpa_process *p = file_priv->driver_priv;

	if (p)
		kref_put(&p->ref, dpa_release_process);
	pci_set_drvdata(dpa->pdev, NULL);
}

static int dpa_driver_open_kms(struct drm_device *dev, struct drm_file *file_priv)
{
	struct dpa_process *dpa_app = NULL;
	struct device *dpa_dev;
	int ret = 0;

	/* Look for existing DPA process in a list */
	dpa_app = dpa_get_process_by_mm(current->mm);

	if (dpa_app) {
		/* Using existing dpa_process */
		dev_warn(dpa->dev, "%s: using existing dpa process\n", __func__);
		return 0;
	}

	mutex_lock(&dpa->dpa_processes_lock);

	/* Allocate a new DPA process */
	if (dpa->dpa_process_count >= DPA_PROCESS_MAX) {
		dev_warn(dpa->dev, "%s: max number of processes reached\n",
			 __func__);
		mutex_unlock(&dpa->dpa_processes_lock);
		return -EBUSY;
	}

	dpa_app = devm_kzalloc(dpa->dev, sizeof(*dpa_app), GFP_KERNEL);
	if (!dpa_app) {
		mutex_unlock(&dpa->dpa_processes_lock);
		return -ENOMEM;
	}
	file_priv->driver_priv = dpa_app;

	dev_warn(dpa->dev, "%s: associated with pid %d\n", __func__, current->tgid);
	dpa_app->mm = current->mm;
	mutex_init(&dpa_app->lock);
	INIT_LIST_HEAD(&dpa_app->queue_list);
	kref_init(&dpa_app->ref);

	// only one DPA for now
	dpa_app->dev = dpa;

	// Bind device and allocate PASID
	dpa_dev = dpa_app->dev->dev;
	dpa_app->sva = iommu_sva_bind_device(dpa_dev, dpa_app->mm);
	if (IS_ERR(dpa_app->sva)) {
		ret = PTR_ERR(dpa_app->sva);
		dev_err(dpa_dev, "SVA allocation failed: %d\n", ret);
		kfree(dpa_app);
		mutex_unlock(&dpa->dpa_processes_lock);
		return -ENODEV;
	}
	dpa_app->pasid = iommu_sva_get_pasid(dpa_app->sva);
	if (dpa_app->pasid == IOMMU_PASID_INVALID) {
		dev_err(dpa_dev, "PASID allocation failed\n");
		iommu_sva_unbind_device(dpa_app->sva);
		kfree(dpa_app);
		mutex_unlock(&dpa->dpa_processes_lock);
		return -ENODEV;
	}
	dev_warn(dpa_dev, "DPA assigned PASID value %d\n", dpa_app->pasid);

	// Setup doorbell register offsets
	dpa_app->doorbell_base = pci_resource_start(dpa_app->dev->pdev, 0) +
		DPA_DB_PAGES_BASE;

	// Init dpa_signal_waiter queue
	INIT_LIST_HEAD(&dpa_app->signal_waiters);
	spin_lock_init(&dpa_app->signal_waiters_lock);

	dpa->dpa_process_count++;
	INIT_LIST_HEAD(&dpa_app->dpa_process_list);
	list_add_tail(&dpa_app->dpa_process_list, &dpa->dpa_processes);

	dpa_app->drm_priv = file_priv;

	mutex_unlock(&dpa->dpa_processes_lock);
	return 0;
}

static int dpa_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct drm_device *ddev;
	struct device *dev = &pdev->dev;
	struct device_node *np;
	int err, vec, nid;
	u16 vendor, device;
	u32 version;

	dev_warn(dev, "%s: DPA start\n", __func__);
	dpa = devm_drm_dev_alloc(dev, &dpa_drm_driver, typeof(*dpa), ddev);
	if (IS_ERR(dpa))
		return -ENOMEM;
	dpa->dev = dev;
	dpa->pdev = pdev;
	ddev = &dpa->ddev;
	dev_set_drvdata(dev, dpa);
	pci_set_drvdata(pdev, ddev);

	pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor);
	pci_read_config_word(pdev, PCI_DEVICE_ID, &device);
	dev_info(dpa->dev, "Device vid: 0x%X pid: 0x%X\n", vendor, device);

	err = pcim_enable_device(pdev);
	if (err)
		return err;
	pci_set_master(pdev);

	err = pcim_iomap_regions(pdev, 1 << 0, dpa_class_name);
	if (err)
		return err;

	// Enable PASID support
	err = iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_SVA);
	if (err) {
		dev_warn(dev, "%s: Unable to turn on SVA feature\n", __func__);
		return err;
	}
	dev_warn(dev, "%s: SVA feature enabled successfully\n", __func__);

	dpa->regs = pcim_iomap_table(pdev)[0];

	err = daffy_alloc_fw_queue(dpa);
	if (err) {
		dev_warn(dev, "%s: unable to allocate memory\n", __func__);
		goto disable_sva;
	}
	// Write Daffy information to FW queue regs
	dpa_setup_queue(dpa);

	dpa->drm_minor = ddev->render->index;

	version = dpa_fwq_read(dpa, DPA_FWQ_VERSION_ID);
	dev_warn(dev, "%s: got version %u\n", __func__, version);

	/*
	 * HACK: Determine which NUMA node HBM is by looking for it in the DT,
	 * then set ourselves to be local to that node. Eventually this will
	 * be done via ACPI.
	 */
	np = of_find_compatible_node(NULL, NULL, "rivos,dpa-hbm");
	if (np) {
		nid = of_node_to_nid(np);
		if (nid != NUMA_NO_NODE) {
			dev_info(dev, "HBM on node %d\n", nid);
			set_dev_node(dev, nid);
		}
	} else {
		dev_info(dev, "No HBM node\n");
	}

	err = pci_alloc_irq_vectors(pdev, 1, DPA_NUM_MSIX, PCI_IRQ_MSIX);
	if (err < 0) {
		dev_err(dev, "Failed setting up IRQ\n");
		goto free_daffy;
	}

	dev_info(dev,
		"Using MSI(-X) interrupts: msi_enabled:%d, msix_enabled: %d\n",
		pdev->msi_enabled,
		pdev->msix_enabled);

	dpa->base_irq = pci_irq_vector(pdev, 0);
	for (int i = 0; i < DPA_NUM_MSIX; i++) {
		vec = pci_irq_vector(pdev, i);
		/* auto frees on device detach, nice */
		err = devm_request_threaded_irq(dev, vec, daffy_handle_irq,
			daffy_process_device_queue, IRQF_ONESHOT, "dpa-drm", dpa);
		if (err < 0) {
			dev_err(dev, "Failed setting up IRQ\n");
			goto free_irqs;
		}
	}

	init_waitqueue_head(&dpa->wq);
	mutex_init(&dpa->daffy_lock);

	INIT_LIST_HEAD(&dpa->dpa_processes);
	mutex_init(&dpa->dpa_processes_lock);

	// init drm
	err = drm_dev_register(ddev, id->driver_data);
	if (err)
		goto free_irqs;

	return 0;

free_irqs:
	pci_free_irq_vectors(pdev);
free_daffy:
	daffy_free_fw_queue(dpa);
disable_sva:
	iommu_dev_disable_feature(dev, IOMMU_DEV_FEAT_SVA);

	return err;
}

static int dpa_add_aql_queue(struct dpa_process *p, u32 queue_id,
			     u32 doorbell_offset)
{
	struct dpa_aql_queue *q = devm_kzalloc(p->dev->dev, sizeof(*q),
					       GFP_KERNEL);
	if (!q)
		return -ENOMEM;

	INIT_LIST_HEAD(&q->list);
	q->id = queue_id;
	q->mmap_offset = doorbell_offset;

	mutex_lock(&p->lock);
	list_add_tail(&q->list, &p->queue_list);
	mutex_unlock(&p->lock);

	return 0;
}

static int dpa_del_aql_queue(struct dpa_process *p, u32 queue_id)
{
	struct dpa_aql_queue *q, *tmp;
	bool found = false;

	mutex_lock(&p->lock);
	list_for_each_entry_safe(q, tmp, &p->queue_list, list) {
		if (q->id == queue_id) {
			dev_warn(p->dev->dev, "%s: deleteing aql queue %u\n",
				 __func__, queue_id);
			list_del(&q->list);
			devm_kfree(p->dev->dev, q);
			found = true;
		}
	}
	mutex_unlock(&p->lock);

	return !found;
}

static void dpa_del_all_queues(struct dpa_process *p)
{
	struct dpa_aql_queue *q;
	int ret;

	mutex_lock(&p->lock);
	while (!list_empty(&p->queue_list)) {
		q = container_of(p->queue_list.next, struct dpa_aql_queue,
				 list);
		list_del(&q->list);
		ret = daffy_destroy_queue_cmd(p->dev, p, q->id);
		if (ret)
			dev_warn(p->dev->dev, "%s: failed to destroy q %u\n",
				 __func__, q->id);
		devm_kfree(p->dev->dev, q);
	}
	mutex_unlock(&p->lock);
}

static int dpa_ioctl_create_queue(struct dpa_process *p,
	struct dpa_device *dpa, void *data)
{
	struct drm_dpa_create_queue *args = data;
	u64 doorbell_mmap_offset;
	int ret = daffy_create_queue_cmd(p->dev, p, args);

	if (ret)
		return ret;

	// we need to convert the page offset from daffy to an offset
	// mmap can recognize
	doorbell_mmap_offset = DRM_MMAP_TYPE_DOORBELL << DRM_MMAP_TYPE_SHIFT;
	ret = dpa_add_aql_queue(p, args->queue_id, args->doorbell_offset);
	if (ret) {
		dev_warn(p->dev->dev, "%s: unable to add aql queue to process, destroying id %u\n",
			__func__, args->queue_id);
		daffy_destroy_queue_cmd(p->dev, p, args->queue_id);
	}
	args->doorbell_offset = doorbell_mmap_offset;
	return ret;
}
DRM_IOCTL(create_queue)

static int dpa_ioctl_destroy_queue(struct dpa_process *p,
	struct dpa_device *dpa, void *data)
{
	struct drm_dpa_destroy_queue *args = data;
	int ret;

	ret = dpa_del_aql_queue(p, args->queue_id);

	if (ret) {
		dev_warn(p->dev->dev, "%s: queue id %u not found\n", __func__,
			 args->queue_id);
		return -EINVAL;
	}
	ret = daffy_destroy_queue_cmd(p->dev, p, args->queue_id);

	return ret;
}

DRM_IOCTL(destroy_queue)

static int dpa_ioctl_update_queue(struct dpa_process *p,
	struct dpa_device *dpa, void *data)
{
	pr_warn("%s: update_queue IOCTL not implemented\n", __func__);
	return 1;
}

DRM_IOCTL(update_queue)

static int dpa_ioctl_get_info(struct dpa_process *p,
			      struct dpa_device *dpa, void *data)
{
	struct drm_dpa_get_info *args = data;
	int ret = daffy_get_info_cmd(p->dev, p, args);

	if (ret)
		return ret;
	dev_warn(p->dev->dev, "%s: dim_x: %d dim_y: %d\n", __func__,
		args->pe_grid_dim_x, args->pe_grid_dim_y);

	return 0;
}
DRM_IOCTL(get_info);

static int dpa_drm_ioctl_create_signal_pages(struct drm_device *dev, void *data,
					     struct drm_file *file)
{
	struct dpa_process *p = file->driver_priv;
	struct drm_dpa_create_signal_pages *args = data;
	u32 num_pages = args->size / PAGE_SIZE;
	int ret = 0;
	long count;

	if (!p)
		return -EINVAL;

	if ((args->size & (PAGE_SIZE - 1)) ||
	    (num_pages > DPA_DRM_MAX_SIGNAL_PAGES) ||
	    (args->va & (PAGE_SIZE - 1)))
		return -EINVAL;

	dev_warn(dev->dev, "%s: creating %u signal pages\n", __func__,
		 num_pages);

	mutex_lock(&p->lock);

	/* XXX we don't support resize yet */
	if (p->signal_pages_count) {
		ret = -EBUSY;
		goto out_unlock;
	}

	/* assume pages are mapped writable, if not we'll get an error */
	count = pin_user_pages_fast(args->va, num_pages, FOLL_LONGTERM | FOLL_WRITE,
		p->signal_pages);
	if (count != num_pages) {
		dev_warn(dev->dev, "%s: pin_user_pages() failed %ld for 0x%llx\n",
			 __func__, count, args->va);

		/* negative count is an error code */
		if (count < 0)
			ret = count;

		/* use -EVINAL error code if only some pages were pinned */
		if (count >= 0) {
			unpin_user_pages(p->signal_pages, count);
			ret = -EINVAL;
		}

		goto out_unlock;
	}
	p->signal_pages_va = args->va;
	p->signal_pages_count = num_pages;

	// Tell the DUC we've allocated a new range of signal pages
	ret = daffy_register_signal_pages_cmd(dpa, p, args, num_pages);
	if (ret)
		unpin_user_pages(p->signal_pages, count);

out_unlock:
	mutex_unlock(&p->lock);

	return ret;
}

static void dpa_remove_signal_pages(struct dpa_process *p)
{
	struct dpa_signal_waiter *waiter;
	unsigned long flags;
	int ret = 0;

	mutex_lock(&p->lock);

	ret = daffy_unregister_signal_pages_cmd(p->dev, p);
	if (ret) {
		dev_warn(p->dev->dev, "%s: DUC failed to unmap signal page(s) for pasid %u\n",
			__func__, p->pasid);
	}

	unpin_user_pages(p->signal_pages, p->signal_pages_count);

	spin_lock_irqsave(&p->signal_waiters_lock, flags);
	list_for_each_entry(waiter, &p->signal_waiters, list) {
		waiter->error = -EINVAL;
		complete(&waiter->signal_done);
	}
	spin_unlock_irqrestore(&p->signal_waiters_lock, flags);

	mutex_unlock(&p->lock);
}

static int dpa_drm_ioctl_wait_signal(struct drm_device *drm, void *data,
				    struct drm_file *file)
{
	struct dpa_process *p = file->driver_priv;
	struct dpa_signal_waiter waiter;
	struct drm_dpa_wait_signal *args = data;
	u64 signal_idx = args->signal_idx;
	u64 timeout_ns = nsecs_to_jiffies64(args->timeout_ns);
	struct drm_dpa_signal *signal;
	u64 page_index;
	void *signal_page_buf;
	unsigned long flags;
	int ret = 0;

	if (!p)
		return -EINVAL;

	mutex_lock(&p->lock);

	/* Verify signal index is in bounds. */
	if ((signal_idx * sizeof(struct drm_dpa_signal)) >=
	    (p->signal_pages_count * PAGE_SIZE)) {
		ret = -EINVAL;
		goto out_unlock;
	}

	page_index = signal_idx * sizeof(struct drm_dpa_signal) / PAGE_SIZE;
	signal_page_buf = page_to_virt(p->signal_pages[page_index]);
	if (!signal_page_buf) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	signal = (struct drm_dpa_signal *) (signal_page_buf + ((signal_idx -
		page_index * DPA_DRM_SIGNALS_PER_PAGE) *
		sizeof(struct drm_dpa_signal)));

	/* Check if the signal has already been reset by firmware. */
	if (!READ_ONCE(signal->signal_value))
		goto out_unlock;

	INIT_LIST_HEAD(&waiter.list);
	waiter.signal_idx = signal_idx;
	init_completion(&waiter.signal_done);

	spin_lock_irqsave(&p->signal_waiters_lock, flags);
	list_add_tail(&waiter.list, &p->signal_waiters);
	spin_unlock_irqrestore(&p->signal_waiters_lock, flags);

	/*
	 * Firmware will reject a subscription if the specified signal has already
	 * been satisfied when it processes the subscription request.
	 */
	ret = daffy_subscribe_signal_cmd(p->dev, p, signal_idx);
	if (ret)
		goto out_remove_waiter;

	/* Wait for the signal, timeout value of 0 means 'no timeout' */
	mutex_unlock(&p->lock);
	if (timeout_ns == 0)
		wait_for_completion_interruptible(&waiter.signal_done);
	else
		wait_for_completion_interruptible_timeout(&waiter.signal_done, timeout_ns);
	mutex_lock(&p->lock);

	if (waiter.error == -EINVAL) {
		dev_warn(p->dev->dev, "%s: Signal page for PASID %d unregistered while waiting on signal %lld\n",
			__func__, p->pasid, signal_idx);
		ret = -EINVAL;
	} else if (signal->signal_value) {
		dev_warn(p->dev->dev, "%s: Timeout waiting for signal %lld\n", __func__, signal_idx);
		ret = -ETIMEDOUT;
	}

	dev_warn(p->dev->dev, "%s: signal idx = %llu, value = %lld\n", __func__,
		 args->signal_idx, signal->signal_value);

out_remove_waiter:
	spin_lock_irqsave(&p->signal_waiters_lock, flags);
	list_del(&waiter.list);
	spin_unlock_irqrestore(&p->signal_waiters_lock, flags);

out_unlock:
	mutex_unlock(&p->lock);

	return ret;
}

static const struct drm_ioctl_desc dpadrm_ioctls[] = {
	DRM_IOCTL_DEF_DRV(DPA_GET_INFO, dpa_drm_ioctl_get_info, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_CREATE_QUEUE, dpa_drm_ioctl_create_queue, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_DESTROY_QUEUE, dpa_drm_ioctl_destroy_queue, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_UPDATE_QUEUE, dpa_drm_ioctl_update_queue, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_CREATE_SIGNAL_PAGES, dpa_drm_ioctl_create_signal_pages, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_WAIT_SIGNAL, dpa_drm_ioctl_wait_signal, DRM_RENDER_ALLOW),
};

static const struct drm_driver dpa_drm_driver = {
	.driver_features =
	    DRIVER_ATOMIC |
	    DRIVER_GEM |
	    DRIVER_RENDER,
	.open = dpa_driver_open_kms,
	.postclose = dpa_driver_release_kms,
	.fops = &dpa_driver_kms_fops,
	.ioctls = dpadrm_ioctls,
	.num_ioctls = ARRAY_SIZE(dpadrm_ioctls),

	.name = "dpa-drm",
};

static const struct drm_driver dpa_drm_driver;

void dpa_release_process(struct kref *ref)
{
	struct dpa_process *p = container_of(ref, struct dpa_process,
						 ref);
	mutex_lock(&dpa->dpa_processes_lock);

	dev_warn(p->dev->dev, "%s: freeing process %d\n", __func__,
		 current->tgid);

	// Unpin signal pages and inform the DUC
	dpa_remove_signal_pages(p);

	if (p->drm_file)
		fput(p->drm_file);

	dpa_del_all_queues(p);
	if (p->sva)
		iommu_sva_unbind_device(p->sva);
	list_del(&p->dpa_process_list);
	dpa->dpa_process_count--;
	devm_kfree(p->dev->dev, p);
	mutex_unlock(&dpa->dpa_processes_lock);
}

static void dpa_pci_remove(struct pci_dev *pdev)
{
	if (dpa) {
		// XXX other stuff
		daffy_free_fw_queue(dpa);
		// Disable PASID support
		iommu_dev_disable_feature(dpa->dev, IOMMU_DEV_FEAT_SVA);
		// unmap regs
		iounmap(dpa->regs);
		pci_disable_device(pdev);
		// Unregister and release DRM device
		drm_dev_unplug(&dpa->ddev);
		// character device_destroy();
		devm_kfree(&pdev->dev, dpa);
	}
}

static struct pci_driver dpa_pci_driver = {
	.name = "dpa",
	.id_table = dpa_pci_table,
	.probe = dpa_pci_probe,
	.remove = dpa_pci_remove,
};

static int __init dpa_init(void)
{
	int ret;

	pr_warn("%s: DPA start\n", __func__);
	dpa_class = class_create(dpa_class_name);
	if (IS_ERR(dpa_class)) {
		ret = PTR_ERR(dpa_class);
		pr_err("Error creating DPA class: %d\n", ret);
		return ret;
	}

	return pci_register_driver(&dpa_pci_driver);
}

static void __exit dpa_exit(void)
{
	pci_unregister_driver(&dpa_pci_driver);
	class_destroy(dpa_class);
}

MODULE_LICENSE("GPL");
module_init(dpa_init);
module_exit(dpa_exit);

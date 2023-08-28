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
#include <linux/hash.h>
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

static void dpa_release_process(struct kref *ref);

static struct dpa_process *dpa_get_process_by_pasid(struct dpa_device *dpa,
						    u32 pasid)
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

static int dpa_add_aql_queue(struct dpa_process *p, u32 queue_id,
			     u32 doorbell_offset)
{
	struct dpa_aql_queue *q = kzalloc(sizeof(*q), GFP_KERNEL);

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

	mutex_lock(&p->lock);
	list_for_each_entry_safe(q, tmp, &p->queue_list, list) {
		if (q->id == queue_id) {
			dev_warn(p->dev->dev, "%s: deleteing aql queue %u\n",
				 __func__, queue_id);
			break;
		}
	}
	mutex_unlock(&p->lock);
	if (!q)
		return -ENOENT;

	list_del(&q->list);
	kfree(q);

	return 0;
}

static void dpa_del_all_queues(struct dpa_process *p)
{
	struct list_head queues;

	INIT_LIST_HEAD(&queues);
	mutex_lock(&p->lock);
	list_splice_init(&p->queue_list, &queues);
	mutex_unlock(&p->lock);

	while (!list_empty(&queues)) {
		struct dpa_aql_queue *q;
		int ret;

		q = list_first_entry(&queues, struct dpa_aql_queue, list);
		list_del(&q->list);
		ret = daffy_destroy_queue_cmd(p->dev, q->id);
		if (ret)
			dev_warn(p->dev->dev, "%s: failed to destroy q %u\n",
				 __func__, q->id);
		kfree(q);
	}
}

static int dpa_drm_ioctl_create_queue(struct drm_device *drm, void *data,
				      struct drm_file *file)
{
	struct dpa_process *p = file->driver_priv;
	struct drm_dpa_create_queue *args = data;
	u64 doorbell_mmap_offset;
	int ret = daffy_create_queue_cmd(p->dev, p, args);

	if (ret)
		return ret;

	doorbell_mmap_offset = args->doorbell_offset;
	ret = dpa_add_aql_queue(p, args->queue_id, args->doorbell_offset);
	if (ret) {
		dev_warn(p->dev->dev, "%s: unable to add aql queue to process, destroying id %u\n",
			__func__, args->queue_id);
		daffy_destroy_queue_cmd(p->dev, args->queue_id);
	}
	args->doorbell_offset = doorbell_mmap_offset;
	return ret;
}

static int dpa_drm_ioctl_destroy_queue(struct drm_device *drm, void *data,
				       struct drm_file *file)
{
	struct dpa_process *p = file->driver_priv;
	struct drm_dpa_destroy_queue *args = data;
	int ret;

	ret = dpa_del_aql_queue(p, args->queue_id);

	if (ret) {
		dev_warn(p->dev->dev, "%s: queue id %u not found\n", __func__,
			 args->queue_id);
		return -EINVAL;
	}
	ret = daffy_destroy_queue_cmd(p->dev, args->queue_id);

	return ret;
}

static int dpa_drm_ioctl_update_queue(struct drm_device *drm, void *data,
				      struct drm_file *file)
{
	pr_warn("%s: update_queue IOCTL not implemented\n", __func__);
	return -ENOSYS;
}

static int dpa_drm_ioctl_get_info(struct drm_device *drm, void *data,
				  struct drm_file *file)
{
	struct dpa_process *p = file->driver_priv;
	struct drm_dpa_get_info *args = data;
	int ret = daffy_get_info_cmd(p->dev, args);

	if (ret)
		return ret;
	args->doorbell_size = p->doorbell_size;

	return 0;
}

static int dpa_drm_ioctl_register_signal_pages(struct drm_device *dev, void *data,
					       struct drm_file *file)
{
	struct dpa_process *p = file->driver_priv;
	struct drm_dpa_register_signal_pages *args = data;
	struct page *pages[DPA_DRM_MAX_SIGNAL_PAGES];
	u32 num_pages = args->size / PAGE_SIZE;
	unsigned long flags;
	int ret = 0;
	long count;

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
	count = pin_user_pages_fast(args->va, num_pages,
				    FOLL_LONGTERM | FOLL_WRITE, pages);
	if (count != num_pages) {
		dev_warn(dev->dev, "%s: pin_user_pages() failed %ld for 0x%llx\n",
			 __func__, count, args->va);

		/* negative count is an error code */
		if (count < 0)
			ret = count;

		/* use -EVINAL error code if only some pages were pinned */
		if (count >= 0) {
			unpin_user_pages(pages, count);
			ret = -EINVAL;
		}

		goto out_unlock;
	}

	// Tell the DUC we've allocated a new range of signal pages
	ret = daffy_register_signal_pages_cmd(p->dev, p, args, num_pages);
	if (ret) {
		unpin_user_pages(pages, count);
		goto out_unlock;
	}

	spin_lock_irqsave(&p->signal_lock, flags);
	memcpy(p->signal_pages, pages, num_pages * sizeof(*p->signal_pages));
	p->signal_pages_count = num_pages;
	spin_unlock_irqrestore(&p->signal_lock, flags);

out_unlock:
	mutex_unlock(&p->lock);

	return ret;
}

static void dpa_remove_signal_pages(struct dpa_process *p)
{
	int ret = 0;

	mutex_lock(&p->lock);

	/*
	 * We only remove signal pages when the fd is closed, so there must
	 * not be any threads in wait_signal() at this piont.
	 */
	WARN_ON(p->num_signal_waiters);

	ret = daffy_unregister_signal_pages_cmd(p->dev, p);
	if (ret) {
		dev_warn(p->dev->dev, "%s: DUC failed to unmap signal page(s) for pasid %u\n",
			__func__, p->pasid);
	}

	unpin_user_pages(p->signal_pages, p->signal_pages_count);

	mutex_unlock(&p->lock);
}

int dpa_signal_wake(struct dpa_device *dpa, u32 pasid, u64 signal_idx)
{
	struct dpa_process *p;
	u32 key = hash_32(signal_idx, SIGNAL_WQ_HASH_BITS);

	p = dpa_get_process_by_pasid(dpa, pasid);
	if (!p) {
		dev_warn(dpa->dev, "%s: DPA process not found for PASID %d\n",
			 __func__, pasid);
		return -ENOENT;
	}

	wake_up_interruptible_all(&p->signal_wqs[key]);
	kref_put(&p->ref, dpa_release_process);

	return 0;
}

static int dpa_drm_ioctl_wait_signal(struct drm_device *drm, void *data,
				    struct drm_file *file)
{
	struct dpa_process *p = file->driver_priv;
	struct drm_dpa_wait_signal *args = data;
	u64 signal_idx = args->signal_idx;
	u32 key = hash_32(signal_idx, SIGNAL_WQ_HASH_BITS);
	struct timespec64 timeout = {
		.tv_sec = args->timeout.tv_sec,
		.tv_nsec = args->timeout.tv_nsec,
	};
	struct drm_dpa_signal *signals;
	unsigned int page, index;
	unsigned long flags;
	long ret = 0;

	page = signal_idx / DPA_DRM_SIGNALS_PER_PAGE;
	index = signal_idx % DPA_DRM_SIGNALS_PER_PAGE;
	spin_lock_irqsave(&p->signal_lock, flags);
	/* Verify signal index is in bounds. */
	if (page >= p->signal_pages_count) {
		spin_unlock_irqrestore(&p->signal_lock, flags);
		return -EINVAL;
	}
	p->num_signal_waiters++;
	spin_unlock_irqrestore(&p->signal_lock, flags);

	signals = page_to_virt(p->signal_pages[page]);
	ret = wait_event_interruptible_timeout(p->signal_wqs[key],
		READ_ONCE(signals[index].signal_value) == 0,
		timespec64_to_jiffies(&timeout));
	if (!ret) {
		dev_warn(p->dev->dev, "%s: Timeout waiting for signal %lld\n", __func__, signal_idx);
		ret = -ETIMEDOUT;
	} else if (ret > 0) {
		ret = 0;
	}

done:
	spin_lock_irqsave(&p->signal_lock, flags);
	p->num_signal_waiters--;
	spin_unlock_irqrestore(&p->signal_lock, flags);

	return ret;
}

static const struct drm_ioctl_desc dpadrm_ioctls[] = {
	DRM_IOCTL_DEF_DRV(DPA_GET_INFO, dpa_drm_ioctl_get_info, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_CREATE_QUEUE, dpa_drm_ioctl_create_queue, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_DESTROY_QUEUE, dpa_drm_ioctl_destroy_queue, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_UPDATE_QUEUE, dpa_drm_ioctl_update_queue, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_REGISTER_SIGNAL_PAGES, dpa_drm_ioctl_register_signal_pages, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_WAIT_SIGNAL, dpa_drm_ioctl_wait_signal, DRM_RENDER_ALLOW),
};

static int dpa_drm_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct drm_file *file_priv = filp->private_data;
	struct dpa_process *p = file_priv->driver_priv;
	unsigned long mmap_offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long pfn;

	dev_warn(p->dev->dev, "%s: Mapping doorbell pages offset 0x%lx\n",
		 __func__, mmap_offset);

	if ((size + mmap_offset) > p->doorbell_size)
		return -EINVAL;

	pfn = p->doorbell_base + mmap_offset;
	pfn >>= PAGE_SHIFT;
	return io_remap_pfn_range(vma, vma->vm_start, pfn, size,
				  vma->vm_page_prot);
}

static long dpa_drm_ioctl(struct file *filp,
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

static void dpa_release_process(struct kref *ref)
{
	struct dpa_process *p = container_of(ref, struct dpa_process,
						 ref);
	struct dpa_device *dpa = p->dev;
	int ret;

	mutex_lock(&dpa->dpa_processes_lock);

	dev_warn(dpa->dev, "%s: freeing process %d\n", __func__,
		 current->tgid);

	// Unpin signal pages and inform the DUC
	dpa_remove_signal_pages(p);

	dpa_del_all_queues(p);
	list_del(&p->dpa_process_list);
	dpa->dpa_process_count--;
	mutex_unlock(&dpa->dpa_processes_lock);

	ret = daffy_unregister_pasid_cmd(p->dev, p->pasid);
	if (ret) {
		dev_warn(dpa->dev, "%s: Failed to unregister pasid %d from DUC\n",
			__func__, p->pasid);
	}

	iommu_sva_unbind_device(p->sva);
	kfree(p);
}

static void dpa_driver_release_kms(struct drm_device *dev, struct drm_file *file_priv)
{
	struct dpa_process *p = file_priv->driver_priv;

	kref_put(&p->ref, dpa_release_process);
}

static int dpa_driver_open_kms(struct drm_device *dev, struct drm_file *file_priv)
{
	struct dpa_device *dpa = drm_to_dpa_dev(dev);
	struct dpa_process *dpa_app = NULL;
	struct device *dpa_dev;
	u32 db_offset;
	u32 db_size;
	int err, i;

	mutex_lock(&dpa->dpa_processes_lock);

	dpa_app = kzalloc(sizeof(*dpa_app), GFP_KERNEL);
	if (!dpa_app) {
		err = -ENOMEM;
		goto out_unlock;
	}
	file_priv->driver_priv = dpa_app;

	dev_warn(dpa->dev, "%s: associated with pid %d\n", __func__, current->tgid);
	mutex_init(&dpa_app->lock);
	INIT_LIST_HEAD(&dpa_app->queue_list);
	kref_init(&dpa_app->ref);

	/* Only one DPA device for now */
	dpa_app->dev = dpa;

	/* Bind device and allocate PASID */
	dpa_dev = dpa_app->dev->dev;
	dpa_app->sva = iommu_sva_bind_device(dpa_dev, current->mm);
	if (IS_ERR(dpa_app->sva)) {
		dev_err(dpa_dev, "%s: SVA bind device failed: %ld\n", __func__,
			PTR_ERR(dpa_app->sva));
		err = -ENODEV;
		goto free_proc;
	}
	dpa_app->pasid = iommu_sva_get_pasid(dpa_app->sva);
	if (dpa_app->pasid == IOMMU_PASID_INVALID) {
		dev_err(dpa_dev, "%s: PASID allocation failed\n", __func__);
		err = -ENODEV;
		goto unbind_sva;
	}
	err = daffy_register_pasid_cmd(dpa_app->dev, dpa_app->pasid,
				       &db_offset, &db_size);
	if (err) {
		dev_warn(dpa_dev, "%s: Failed to register pasid %d with DUC\n",
			__func__, dpa_app->pasid);
		goto unbind_sva;
	}
	dev_warn(dpa_dev, "%s: DPA registered PASID value %d doorbell %u\n", __func__,
		 dpa_app->pasid, db_offset);

	/* Setup doorbell register offsets */
	dpa_app->doorbell_offset = db_offset;
	dpa_app->doorbell_size = db_size;
	dpa_app->doorbell_base = pci_resource_start(dpa_app->dev->pdev, 0) +
		dpa_app->doorbell_offset;

	for (i = 0; i < ARRAY_SIZE(dpa_app->signal_wqs); i++)
		init_waitqueue_head(&dpa_app->signal_wqs[i]);
	spin_lock_init(&dpa_app->signal_lock);

	dpa->dpa_process_count++;
	INIT_LIST_HEAD(&dpa_app->dpa_process_list);
	list_add_tail(&dpa_app->dpa_process_list, &dpa->dpa_processes);

	mutex_unlock(&dpa->dpa_processes_lock);
	return 0;

unbind_sva:
	iommu_sva_unbind_device(dpa_app->sva);
free_proc:
	kfree(dpa_app);
out_unlock:
	mutex_unlock(&dpa->dpa_processes_lock);

	return err;
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

static int dpa_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct dpa_device *dpa;
	struct device_node *np;
	int err, vec, nid;
	u16 vendor, device;

	dev_warn(dev, "%s: DPA start\n", __func__);
	dpa = devm_drm_dev_alloc(dev, &dpa_drm_driver, typeof(*dpa), ddev);
	if (IS_ERR(dpa))
		return -ENOMEM;
	dpa->dev = dev;
	dpa->pdev = pdev;
	pci_set_drvdata(pdev, dpa);

	pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor);
	pci_read_config_word(pdev, PCI_DEVICE_ID, &device);
	dev_info(dpa->dev, "Device vid: 0x%X pid: 0x%X\n", vendor, device);

	err = pcim_enable_device(pdev);
	if (err)
		return err;
	pci_set_master(pdev);

	err = pcim_iomap_regions(pdev, 1 << 0, "dpa");
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

	err = daffy_init(dpa);
	if (err)
		goto disable_sva;

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

	err = pci_alloc_irq_vectors(pdev, DPA_NUM_MSI, DPA_NUM_MSI,
				    PCI_IRQ_MSIX);
	if (err < 0) {
		dev_err(dev, "Failed setting up IRQ\n");
		goto free_daffy;
	}

	dpa->base_irq = pci_irq_vector(pdev, 0);
	for (int i = 0; i < DPA_NUM_MSI; i++) {
		vec = pci_irq_vector(pdev, i);
		/* auto frees on device detach, nice */
		err = devm_request_threaded_irq(dev, vec, NULL,
			daffy_handle_irq, IRQF_ONESHOT, "dpa-drm", dpa);
		if (err < 0) {
			dev_err(dev, "Failed setting up IRQ\n");
			goto free_irqs;
		}
	}

	INIT_LIST_HEAD(&dpa->dpa_processes);
	mutex_init(&dpa->dpa_processes_lock);

	// init drm
	err = drm_dev_register(&dpa->ddev, id->driver_data);
	if (err)
		goto free_irqs;

	return 0;

free_irqs:
	pci_free_irq_vectors(pdev);
free_daffy:
	daffy_free(dpa);
disable_sva:
	iommu_dev_disable_feature(dev, IOMMU_DEV_FEAT_SVA);

	return err;
}

static void dpa_pci_remove(struct pci_dev *pdev)
{
	struct dpa_device *dpa = pci_get_drvdata(pdev);

	drm_dev_unplug(&dpa->ddev);
	pci_free_irq_vectors(pdev);
	daffy_free(dpa);
	iommu_dev_disable_feature(dpa->dev, IOMMU_DEV_FEAT_SVA);
}

static const struct pci_device_id dpa_pci_table[] = {
	{ PCI_VENDOR_ID_RIVOS, PCI_DEVICE_ID_RIVOS_DPA,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, dpa_pci_table);

static struct pci_driver dpa_pci_driver = {
	.name = "dpa",
	.id_table = dpa_pci_table,
	.probe = dpa_pci_probe,
	.remove = dpa_pci_remove,
};

module_pci_driver(dpa_pci_driver);

MODULE_LICENSE("GPL");

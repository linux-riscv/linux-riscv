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

static void dpa_release_process(struct kref *ref);
static const struct drm_driver dpa_drm_driver;

/* device related stuff */
static struct class *dpa_class;
struct dpa_device *dpa;

static struct list_head dpa_processes;
static struct mutex dpa_processes_lock;
static unsigned int dpa_process_count;

static struct dpa_process *dpa_get_current_process(void)
{
	struct list_head *cur;
	struct dpa_process *dpa_app;

	list_for_each(cur, &dpa_processes) {
		struct dpa_process *cur_process =
			container_of(cur, struct dpa_process,
				     dpa_process_list);
		if (cur_process->mm == current->mm) {
			dpa_app = cur_process;
			break;
		}
	}
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
	writeq(dpa->qinfo.fw_queue_dma_addr, dpa->regs + DUC_REGS_FW_DESC);
	writeq(0, dpa->regs + DUC_REGS_FW_PASID);
}

static int dpa_non_vram_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct dpa_process *p;
	unsigned long mmap_offset = vma->vm_pgoff << PAGE_SHIFT;
	u64 type = mmap_offset >> DRM_MMAP_TYPE_SHIFT;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long pfn;
	int ret = -EFAULT;

	mutex_lock(&dpa_processes_lock);
	p = dpa_get_current_process();
	mutex_unlock(&dpa_processes_lock);

	dev_warn(p->dev->dev, "%s: offset 0x%lx size 0x%lx type %llu start 0x%llx\n",
			__func__, mmap_offset, size, type, (u64)vma->vm_start);
	switch (type) {

	case DRM_MMAP_TYPE_DOORBELL:
		if (size != DPA_DOORBELL_PAGE_SIZE) {
			dev_warn(p->dev->dev, "%s: invalid size for doorbell\n",
					__func__);
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

	return ret;
}

static int dpa_gem_object_mmap(struct drm_gem_object *gobj, struct vm_area_struct *vma)
{
	struct dpa_drm_buffer *buf = gem_to_dpa_buf(gobj);
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long start = vma->vm_start;
	unsigned long chunk_size;
	unsigned long vma_page_count = size >> PAGE_SHIFT;
	unsigned long num_pages;
	struct drm_buddy_block *block, *on;
	u64 paddr;
	int ret = -EFAULT;

	if (buf) {
		num_pages = buf->page_count;
		if (buf->type != DPA_IOC_ALLOC_MEM_FLAGS_VRAM) {
			dev_warn(dpa->dev, "%s: unexpected type for buf %u\n",
					__func__, buf->type);
			return -EINVAL;
		}
		if (buf->page_count != vma_page_count) {
			dev_warn(dpa->dev, "%s: buf page count %u != vma %lu\n",
					__func__, buf->page_count, vma_page_count);
			return -EINVAL;
		}

		list_for_each_entry_safe(block, on, &buf->blocks, link) {
			paddr = dpa->hbm_base + drm_buddy_block_offset(block);
			chunk_size = min_t(unsigned long, size,
					   drm_buddy_block_size(&dpa->mm, block));
			ret = remap_pfn_range(vma, start, phys_to_pfn(paddr), chunk_size,
				vma->vm_page_prot);
			if (chunk_size == size)
				break;
			else {
				size -= chunk_size;
				start += chunk_size;
			}
		}

		if (ret || num_pages) {
			dev_warn(dpa->dev, "%s: vm_insert_pages ret = %d num = %lu\n",
					__func__, ret, num_pages);
			return ret;
		}
	} else {
		dev_warn(dpa->dev, "%s: buffer is not found\n",
				__func__);
		return -EINVAL;
	}
	vm_flags_set(vma, VM_DONTEXPAND);
	return 0;
}

static const struct drm_gem_object_funcs dpa_gem_object_funcs = {
	.mmap = dpa_gem_object_mmap,
};

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

static int dpa_drm_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long mmap_offset = vma->vm_pgoff << PAGE_SHIFT;
	u64 type = mmap_offset >> DRM_MMAP_TYPE_SHIFT;

	if (type == DRM_MMAP_TYPE_VRAM)
		return drm_gem_mmap(filp, vma);
	else
		return dpa_non_vram_mmap(filp, vma);
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

	// big lock for this
	mutex_lock(&dpa_processes_lock);
	// look for process in a list
	dpa_app = dpa_get_current_process();

	if (dpa_app) {
		kref_get(&dpa_app->ref);
		mutex_unlock(&dpa_processes_lock);
		// using existing dpa_process
		dev_warn(dpa->dev, "%s: using existing dpa process\n", __func__);
		return 0;
	}
	// new process
	if (dpa_process_count >= DPA_PROCESS_MAX) {
		dev_warn(dpa->dev, "%s: max number of processes reached\n",
			 __func__);
		mutex_unlock(&dpa_processes_lock);
		return -EBUSY;
		}
	dpa_app = devm_kzalloc(dpa->dev, sizeof(*dpa_app), GFP_KERNEL);
	if (!dpa_app) {
		mutex_unlock(&dpa_processes_lock);
		return -ENOMEM;
	}
	file_priv->driver_priv = dpa_app;
	dpa_process_count++;
	INIT_LIST_HEAD(&dpa_app->dpa_process_list);
	list_add_tail(&dpa_app->dpa_process_list, &dpa_processes);

	dev_warn(dpa->dev, "%s: associated with pid %d\n", __func__, current->tgid);
	dpa_app->mm = current->mm;
	mutex_init(&dpa_app->lock);
	INIT_LIST_HEAD(&dpa_app->buffers);
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
		list_del(&dpa_app->dpa_process_list);
		dpa_process_count--;
		kfree(dpa_app);
		mutex_unlock(&dpa_processes_lock);
		return -ENODEV;
	}
	dpa_app->pasid = iommu_sva_get_pasid(dpa_app->sva);
	if (dpa_app->pasid == IOMMU_PASID_INVALID) {
		dev_err(dpa_dev, "PASID allocation failed\n");
		iommu_sva_unbind_device(dpa_app->sva);
		list_del(&dpa_app->dpa_process_list);
		dpa_process_count--;
		kfree(dpa_app);
		mutex_unlock(&dpa_processes_lock);
		return -ENODEV;
	}
	dev_warn(dpa_dev, "DPA assigned PASID value %d\n", dpa_app->pasid);

	// Setup doorbell register offsets
	dpa_app->doorbell_base = pci_resource_start(dpa_app->dev->pdev, 0) + DUC_REGS_DOORBELLS;
	if (!dpa_app->doorbell_base) {
		dev_err(dpa_dev, "DPA failed to map doorbell registers\n");
		return -EIO;
	}

	dpa_app->drm_priv = file_priv;

	mutex_unlock(&dpa_processes_lock);
	return 0;
}


static int dpa_gem_object_create(unsigned long size,
			     int alignment,
			     u64 flags,
			     struct drm_gem_object **obj)
{
	struct dpa_drm_buffer *buf;
	struct device *dev = dpa->dev;
	struct drm_buddy *mm = &dpa->mm;
	struct drm_buddy_block *block, *on;
	int err;

	*obj = NULL;
	/* Memory should be aligned at least to a page size. */
	size = ALIGN(size, PAGE_SIZE);

	buf = devm_kzalloc(dev, sizeof(struct dpa_drm_buffer), GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;
	drm_gem_private_object_init(&dpa->ddev, &buf->gobj, size);

	buf->type = flags;
	buf->size = size;
	buf->page_count = buf->size >> PAGE_SHIFT;

	INIT_LIST_HEAD(&buf->blocks);
	mutex_lock(&dpa->mm_lock);
	err = drm_buddy_alloc_blocks(mm,
				     0,
				     dpa->hbm_size,
				     size,
				     mm->chunk_size,
				     &buf->blocks,
				     0);
	if (err < 0)
		goto out_unlock;

	/* Zero the blocks allocated */
	list_for_each_entry_safe(block, on, &buf->blocks, link) {
		void *va = dpa->hbm_va + drm_buddy_block_offset(block);

		memset(va, 0, drm_buddy_block_size(&dpa->mm, block));
	}

	mutex_unlock(&dpa->mm_lock);

	/* create the node in vma manager */
	err = drm_gem_create_mmap_offset(&buf->gobj);
	if (err < 0)
		goto out_free_blocks;

	*obj = &buf->gobj;
	(*obj)->funcs = &dpa_gem_object_funcs;

	return 0;

out_free_blocks:
	mutex_lock(&dpa->mm_lock);
	drm_buddy_free_list(mm, &buf->blocks);
out_unlock:
	mutex_unlock(&dpa->mm_lock);
	devm_kfree(dev, buf);
	return err;
}

static int dpa_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct drm_device *ddev;
	struct device *dev = &pdev->dev;
	struct device_node *np;
	struct resource r;
	int err, vec;
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
	pci_write_config_byte(pdev, PCI_COMMAND, PCI_COMMAND_IO |
			      PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
	dev_info(dpa->dev, "Device vid: 0x%X pid: 0x%X\n", vendor, device);

	err = pci_enable_device_mem(pdev);
	if (err)
		goto disable_device;

	err = pci_request_mem_regions(pdev, dpa_class_name);
	if (err)
		goto disable_device;

	// Enable PASID support
	if (iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_SVA)) {
		dev_warn(dev, "%s: Unable to turn on SVA feature\n", __func__);
		goto disable_device;
	} else {
		dev_warn(dev, "%s: SVA feature enabled successfully\n", __func__);
	}

	dpa->regs = ioremap(pci_resource_start(pdev, 0), DUC_MMIO_SIZE);
	if (!dpa->regs) {
		dev_warn(dev, "%s: unable to remap registers\n", __func__);
		err = -EIO;
		goto disable_device;
	}

	err = daffy_alloc_fw_queue(dpa);
	if (err) {
		dev_warn(dev, "%s: unable to allocate memory\n", __func__);
		goto unmap;
	}
	// Write Daffy information to FW queue regs
	dpa_setup_queue(dpa);

	dpa->drm_minor = ddev->render->index;
	// LIST_HEAD_INIT(&dpa->buffers);

	version = ioread64(dpa->regs + DUC_REGS_FW_VER);
	dev_warn(dev, "%s: got version %u\n", __func__, version);

	// init drm
	err = drm_dev_register(ddev, id->driver_data);
	if (err)
		goto disable_device;

	np = of_find_compatible_node(NULL, NULL, "rivos,dpa-hbm");
	dev_warn(dev, "np is %p\n", np);
	err = of_address_to_resource(np, 0, &r);
	if (err)
		dev_err(dev, "No memory address assigned to the region\n");

	dpa->hbm_base = r.start;
	dpa->hbm_size = resource_size(&r);
	dpa->hbm_va = (void *) ((u64) devm_memremap(dev, dpa->hbm_base,
		dpa->hbm_size, MEMREMAP_WB));
	if (IS_ERR(dpa->hbm_va)) {
		err = PTR_ERR(dpa->hbm_va);
		goto disable_device;
	}

	dev_info(dev, "HBM base: 0x%llx, HBM size: 0x%llx\n",
		dpa->hbm_base, dpa->hbm_size);

	err = drm_buddy_init(&dpa->mm, dpa->hbm_size, PAGE_SIZE);
	mutex_init(&dpa->mm_lock);

	err = pci_alloc_irq_vectors(pdev, 1, DUC_NUM_MSIX_INTERRUPTS, PCI_IRQ_MSIX);
	if (err < 0)
		dev_err(dev, "Failed setting up IRQ\n");

	dev_info(dev,
		"Using MSI(-X) interrupts: msi_enabled:%d, msix_enabled: %d\n",
		pdev->msi_enabled,
		pdev->msix_enabled);

	dpa->base_irq = pci_irq_vector(pdev, 0);
	for (int i = 0; i < DUC_NUM_MSIX_INTERRUPTS; i++) {
		vec = pci_irq_vector(pdev, i);
		/* auto frees on device detach, nice */
		err = devm_request_threaded_irq(dev, vec, handle_daffy, NULL,
			IRQF_ONESHOT, "dpa-drm", dpa);
		if (err < 0)
			dev_err(dev, "Failed setting up IRQ\n");
	}

	init_waitqueue_head(&dpa->wq);

	return 0;

unmap:
	iounmap(dpa->regs);

disable_device:
	dev_warn(dpa->dev, "%s: Disabling device\n", __func__);
	pci_disable_device(pdev);
	devm_kfree(dev, dpa);

	return err;
}

static int dpa_reserve_mem_limit(struct dpa_device *dpa, uint64_t size,
	u32 alloc_flag)
{
	int ret = 0;
	// XXX Actually implement this
	// if (dpa) {
	// dpa->vram_used += size;
	// dpa->vram_used_aligned += ALIGN(size, VRAM_AVAILABLITY_ALIGN);
	// }
// release:
	return ret;
}


static int dpa_alloc_vram(
		struct dpa_device *dpa,
		uint64_t size,
		void *drm_priv,
		struct dpa_drm_buffer **bo,
		uint64_t *offset, uint32_t flags) //, bool criu_resume)
{

	struct drm_gem_object *gobj = NULL;
	struct dpa_drm_buffer *buf;
	int ret;

	ret = dpa_reserve_mem_limit(dpa, size, flags);
	if (ret) {
		pr_debug("Insufficient memory\n");
		goto err;
	}

	ret = dpa_gem_object_create(size, 1, flags, &gobj);
	if (ret)
		goto err;
	ret = drm_vma_node_allow(&gobj->vma_node, drm_priv);

	*bo = gem_to_dpa_buf(gobj);
	buf = *bo;

	if (offset)
		*offset = drm_vma_node_offset_addr(&buf->gobj.vma_node);
	return 0;

err:
	return ret;
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

static struct dpa_drm_buffer *dpa_find_buffer(struct dpa_process *p, u64 id)
{
	struct dpa_drm_buffer *buf, *tmp;

	mutex_lock(&p->dev->lock);
	list_for_each_entry_safe(buf, tmp, &p->buffers, process_alloc_list) {
		if (buf->id == id) {
			mutex_unlock(&p->dev->lock);
			return buf;
		}
	}
	mutex_unlock(&p->dev->lock);

	return NULL;
}

static int dpa_ioctl_alloc_memory_of_gpu(struct dpa_process *p,
	struct dpa_device *dpa, void *data)
{
	struct drm_dpa_alloc_memory_of_gpu *args = data;
	struct device *dev = p->dev->dev;
	struct dpa_drm_buffer *buf;
	uint64_t offset = 0;
	int r = 0;

	dev_warn(dev, "%s: flags 0x%x size 0x%llx\n", __func__,
		 args->flags, args->size);

	if (args->flags & DPA_IOC_ALLOC_MEM_FLAGS_VRAM) {
		r = dpa_alloc_vram(dpa, args->size, p->drm_priv, &buf, &offset,
			DPA_IOC_ALLOC_MEM_FLAGS_VRAM);
		if (r) {
			dev_warn(dev, "%s: vram alloc failed %d\n", __func__, r);
			return -ENOMEM;
		}
	} else if (args->flags & DPA_IOC_ALLOC_MEM_FLAGS_USERPTR) {
		long page_count = 0;
		unsigned int gup_flags = FOLL_LONGTERM;
		struct vm_area_struct  *vma;

		buf = devm_kzalloc(dev, sizeof(*buf), GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		buf->type = args->flags;
		buf->size = args->size;
		buf->page_count = buf->size >> PAGE_SHIFT;
		buf->pages = devm_kzalloc(dev, sizeof(struct page *) * buf->page_count,
			GFP_KERNEL);
		if (!buf->pages) {
			devm_kfree(dev, buf);
			return -ENOMEM;
		}

		// Until we support page-faults, we should pin all user allocations
		mmap_read_lock(current->mm);
		// if VMA is not writeable we should not pass FOLL_WRITE
		// note: this doesn't correctly deal with multiple VMAs, shrug
		vma = find_vma(current->mm, args->va_addr);
		if (!vma) {
			mmap_read_unlock(current->mm);
			dev_warn(dev, "%s: find_vma() failed 0x%llx\n", __func__,
				 args->va_addr);
			devm_kfree(dev, buf->pages);
			devm_kfree(dev, buf);
			return -EFAULT;
		}
		if (vma->vm_flags & VM_WRITE)
			gup_flags |= FOLL_WRITE;

		page_count = pin_user_pages(args->va_addr, buf->page_count,
			gup_flags, buf->pages, NULL);
		if (page_count != buf->page_count) {
			mmap_read_unlock(current->mm);
			dev_warn(dev, "%s: get_user_pages() failed %ld vs %u\n", __func__,
				 page_count, buf->page_count);
			devm_kfree(dev, buf->pages);
			devm_kfree(dev, buf);

			// negative page_count is an error code
			if (page_count < 0)
				return page_count;

			return -ENOMEM;
		}
		mmap_read_unlock(current->mm);
	} else {
		dev_warn(dev, "%s: unsupported memory alloction type 0x%x\n",
			 __func__, args->flags);
		return -EINVAL;
	}

	if (!buf) {
		dev_warn(dev, "%s: buf is NULL\n", __func__);
		return -ENOMEM;
	}
	mutex_lock(&p->dev->lock);
	// XXX use an IDR/IDA for this
	buf->p = p;
	buf->id = ++p->alloc_count;
	INIT_LIST_HEAD(&buf->process_alloc_list);
	list_add_tail(&buf->process_alloc_list, &p->buffers);
	mutex_unlock(&p->dev->lock);

	// use a macro for this
	args->handle = (u64)DPA_GPU_ID << 32 | buf->id;
	if (args->flags & DPA_IOC_ALLOC_MEM_FLAGS_VRAM)
		args->mmap_offset = offset;

	dev_warn(p->dev->dev, "%s: buf id %u handle 0x%llx\n", __func__,
		 buf->id, args->handle);

	return 0;
}

DRM_IOCTL(alloc_memory_of_gpu)

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
	unsigned int num_pages = args->size / PAGE_SIZE;
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

out_unlock:
	mutex_unlock(&p->lock);

	return ret;
}

static int dpa_check_signal(struct dpa_process *p, u32 signal_index)
{
	u64 signal_va = p->signal_pages_va +
		(signal_index * sizeof(struct drm_dpa_signal));
	u64 signal_value;

	int ret = copy_from_user(&signal_value, (void __user *)signal_va,
				 sizeof(signal_value));
	if (ret < 0) {
		dev_warn(p->dev->dev, "%s: error checking signal %u at %llx\n",
			 __func__, signal_index, signal_va);
		return ret;
	}

	if (signal_value == 0)
		return 0;
	return 1;
}

static int dpa_drm_ioctl_wait_signal(struct drm_device *drm, void *data,
				     struct drm_file *file)
{
	struct dpa_process *p = file->driver_priv;
	struct drm_dpa_wait_signal *args = data;
	u64 total_usleep = 0;
	int ret = 0;

	if (!p)
		return -EINVAL;

	mutex_lock(&p->lock);

	/* verify signal index is in bounds */
	if ((args->signal_idx * sizeof(struct drm_dpa_signal)) >=
	    (p->signal_pages_count * PAGE_SIZE)) {
		ret = -EINVAL;
		goto out_unlock;
	}

	// XXX implement this using a daffy packet and event waiters
	do {
		ret = dpa_check_signal(p, args->signal_idx);
		if (ret) {
			mutex_unlock(&p->lock);
			usleep_range(10000, 10000);
			total_usleep  += 10000;
			mutex_lock(&p->lock);
		}
	} while ((ret == 1) && ((total_usleep * 1000) < args->timeout_ns));

	dev_warn(p->dev->dev, "%s: idx %llu ret = %d\n", __func__,
		 args->signal_idx, ret);

	if (ret == 1)
		ret = -EBUSY;
out_unlock:
	mutex_unlock(&p->lock);

	return ret;
}

static void dpa_drm_free_buffer(struct dpa_drm_buffer *buf)
{
	struct device *dev = buf->p->dev->dev;

	dev_warn(dev, "%s: freeing buf id %u\n",
		 __func__, buf->id);

	if (buf->type & DPA_IOC_ALLOC_MEM_FLAGS_VRAM) {
		if (buf->page_count) {
			mutex_lock(&dpa->mm_lock);
			drm_buddy_free_list(&dpa->mm, &buf->blocks);
			mutex_unlock(&dpa->mm_lock);
		}
		drm_gem_object_release(&buf->gobj);
	}

	if (buf->type & DPA_IOC_ALLOC_MEM_FLAGS_USERPTR) {
		if (buf->page_count) {
			unpin_user_pages(buf->pages, buf->page_count);
			devm_kfree(dev, buf->pages);
		}

	}
	devm_kfree(dev, buf);

}

static int dpa_ioctl_free_memory_of_gpu(struct dpa_process *p,
	struct dpa_device *dpa, void *data)
{
	struct drm_dpa_free_memory_of_gpu *args = data;
	struct dpa_drm_buffer *buf = dpa_find_buffer(p, args->handle & 0xFFFFFFFF);

	dev_warn(p->dev->dev, "%s: handle 0x%llx buf 0x%llx\n",
		 __func__, args->handle, (u64)buf);
	if (buf) {
		mutex_lock(&p->dev->lock);
		list_del(&buf->process_alloc_list);
		mutex_unlock(&p->dev->lock);
		dpa_drm_free_buffer(buf);
	}

	return 0;
}

DRM_IOCTL(free_memory_of_gpu)

static const struct drm_ioctl_desc dpadrm_ioctls[] = {
	DRM_IOCTL_DEF_DRV(DPA_GET_INFO, dpa_drm_ioctl_get_info, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_CREATE_QUEUE, dpa_drm_ioctl_create_queue, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_DESTROY_QUEUE, dpa_drm_ioctl_destroy_queue, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_UPDATE_QUEUE, dpa_drm_ioctl_update_queue, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_ALLOC_MEMORY_OF_GPU, dpa_drm_ioctl_alloc_memory_of_gpu, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_FREE_MEMORY_OF_GPU, dpa_drm_ioctl_free_memory_of_gpu, DRM_RENDER_ALLOW),
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

static void dpa_drm_release_process_buffers(struct dpa_process *p)
{
	struct dpa_drm_buffer *buf, *tmp;

	mutex_lock(&p->dev->lock);
	list_for_each_entry_safe(buf, tmp, &p->buffers, process_alloc_list) {
		if (buf->p == p) {
			list_del(&buf->process_alloc_list);
			dpa_drm_free_buffer(buf);
		} else {
			dev_warn(p->dev->dev, "%s: mismatched buffer?", __func__);
		}
	}
	mutex_unlock(&p->dev->lock);
}

static void dpa_release_process(struct kref *ref)
{
	struct dpa_process *p = container_of(ref, struct dpa_process,
						 ref);
	int i;

	mutex_lock(&dpa_processes_lock);
	dev_warn(p->dev->dev, "%s: freeing process %d\n", __func__,
		 current->tgid);
	// XXX mutex lock on process lock ?
	dpa_drm_release_process_buffers(p);

	for (i = 0; i < p->signal_pages_count; i++)
		unpin_user_page(p->signal_pages[i]);

	if (p->drm_file)
		fput(p->drm_file);

	dpa_del_all_queues(p);
	if (p->sva)
		iommu_sva_unbind_device(p->sva);
	list_del(&p->dpa_process_list);
	dpa_process_count--;
	devm_kfree(p->dev->dev, p);
	mutex_unlock(&dpa_processes_lock);
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
	dpa_class = class_create(THIS_MODULE, dpa_class_name);
	if (IS_ERR(dpa_class)) {
		ret = PTR_ERR(dpa_class);
		pr_err("Error creating DPA class: %d\n", ret);
		return ret;
	}
	INIT_LIST_HEAD(&dpa_processes);
	mutex_init(&dpa_processes_lock);

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

/*
 * Rivos DPA KFD interface
 *
 * Author: Sonny Rao <sonny@rivosinc.com>
 *
 */
#include <linux/kernel.h>
#include <linux/cpumask.h>
#include <linux/device.h>
#include <linux/device/class.h>
#include <linux/dev_printk.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/iommu.h>
#include <linux/mm.h>
#include <linux/pci.h>
#include <linux/sched/mm.h>
#include <uapi/linux/kfd_ioctl.h>
#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_ioctl.h>
#include <linux/pm_runtime.h>
#include <linux/of_reserved_mem.h>
#include <linux/of_address.h>
#include "dpa_kfd.h"
#include "dpa_daffy.h"

static long dpa_kfd_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
static int dpa_kfd_open(struct inode *inode, struct file *filep);
static int dpa_kfd_release(struct inode *inode, struct file *filep);
static int dpa_kfd_mmap(struct file *filp, struct vm_area_struct *vma);
static void dpa_kfd_release_process(struct kref *ref);
static const struct drm_driver dpa_drm_driver;

/* AMD kfd presents a character device with this name */
static const char kfd_dev_name[] = "kfd";

static const struct file_operations dpa_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = dpa_kfd_ioctl,
	.open = dpa_kfd_open,
	.release = dpa_kfd_release,
	.mmap = dpa_kfd_mmap,
};

/* device related stuff */
static int dpa_char_dev_major = -1;
static struct class *dpa_class;
struct device *dpa_device;
struct dpa_device *dpa;

static struct list_head dpa_processes;
static struct mutex dpa_processes_lock;
static unsigned int dpa_process_count;

static struct dpa_kfd_process *get_current_process(void) {
	struct list_head *cur;
	struct dpa_kfd_process *dpa_app;
	list_for_each(cur, &dpa_processes) {
		struct dpa_kfd_process *cur_process =
			container_of(cur, struct dpa_kfd_process,
				     dpa_process_list);
		if (cur_process->mm == current->mm) {
			dpa_app = cur_process;
			break;
		}
	}
	return dpa_app;
}

int dpa_kfd_chardev_init(void)
{
	int ret = 0;

	pr_warn("%s: start\n", __func__);
	if (!dpa) {
		pr_warn("%s: device not initialized\n", __func__);
		return -EINVAL;
	}

	dpa_char_dev_major = register_chrdev(0, kfd_dev_name, &dpa_fops);
	if (dpa_char_dev_major < 0) {
		return dpa_char_dev_major;
	}

	dpa_device = device_create(dpa_class, NULL, /* dpa->dev, */
				   MKDEV(dpa_char_dev_major, 0),
				   NULL, kfd_dev_name);
	if (IS_ERR(dpa_device)) {
		ret = PTR_ERR(dpa_device);
		goto out_unreg_chrdev;
	}

	return 0;

out_unreg_chrdev:
	unregister_chrdev(dpa_char_dev_major, kfd_dev_name);

	return ret;
}

/* sysfs stuff */

/* mostly hardcoded topology to give userspace what it wants to see */
/* gpu node needs to tell userspace the corresponding DRM minor number */
struct dpa_kfd_topology {
	struct dpa_device *dpa;

	struct kobject kobj_topology;
	struct attribute attr_properties;
	struct attribute attr_genid;

	struct kobject kobj_nodes;
	struct kobject kobj_cpu_node;
	struct attribute attr_cpu_node_id;
	struct attribute attr_cpu_properties;
};

static struct dpa_kfd_topology dkt;

// a grab bag of sysfs properties
static ssize_t dpa_kfd_sysfs_show(struct kobject *kobj, struct attribute *attr,
				  char *buffer)
{
	int offs = 0;

	if (attr == &dkt.attr_properties) {
		offs = snprintf(buffer, PAGE_SIZE,
				"platform_oem 0\n"
				"platform_id 0\n"
				"platform_rev 0\n");
	} else if (attr == &dkt.attr_genid) {
		offs = snprintf(buffer, PAGE_SIZE, "2\n");
	} else if (attr == &dkt.attr_cpu_properties) {
		offs += snprintf(buffer, PAGE_SIZE, "cpu_cores_count %d\n",
				 num_possible_cpus());
		/* this is used to determine if it's a gpu */
		offs += snprintf(buffer + offs, PAGE_SIZE, "simd_count 1\n");
		offs += snprintf(buffer + offs, PAGE_SIZE - offs, "mem_banks 1\n");
		offs += snprintf(buffer + offs, PAGE_SIZE - offs, "wave_front_size 32\n");
		/* this is used to open a DRM device */
		offs += snprintf(buffer + offs, PAGE_SIZE - offs, "drm_render_minor %d\n",
			dkt.dpa->drm_minor);
		/* This tells it which "ISA" to use */
		offs += snprintf(buffer + offs, PAGE_SIZE - offs, "gfx_target_version %x\n",
				 DPA_HSA_GFX_VERSION);
	} else if (attr == &dkt.attr_cpu_node_id) {
		offs = snprintf(buffer, PAGE_SIZE, "%d\n", DPA_GPU_ID);
	} else
		offs = -EINVAL;

	return offs;
}

static void dpa_kfd_sysfs_release(struct kobject *kobj)
{
	pr_warn("%s kobj %p", __func__, kobj);
	// XXX kfree(kobj);
}

static const struct sysfs_ops dpa_kfd_sysfs_ops = {
	.show = dpa_kfd_sysfs_show,
};

static struct kobj_type dkt_type = {
	.release = dpa_kfd_sysfs_release,
	.sysfs_ops = &dpa_kfd_sysfs_ops,
};

static int dpa_kfd_sysfs_init(void)
{
	int ret;

	/* class should be created */
	if (!dpa_class) {
		pr_warn("%s: no dpa class\n", __func__);
		return -EINVAL;
	}

	// XXX single device
	if (!dpa_device) {
		pr_warn("%s: no dpa_device?\n", __func__);
		return -EINVAL;
	}

	dkt.dpa = dpa;

	ret = kobject_init_and_add(&dkt.kobj_topology, &dkt_type,
				   &dpa_device->kobj, "topology");
	if (ret) {
		pr_warn("%s: unable to init topology sysfs %d\n", __func__,
			ret);
		return ret;
	}

	ret = kobject_init_and_add(&dkt.kobj_nodes, &dkt_type,
				   &dkt.kobj_topology, "nodes");
	if (ret) {
		pr_warn("%s: unable to init nodes sysfs %d\n", __func__,
			ret);
		kobject_del(&dkt.kobj_topology);
		return ret;
	}

	ret = kobject_init_and_add(&dkt.kobj_cpu_node, &dkt_type,
				   &dkt.kobj_nodes, "0");

	if (ret) {
		pr_warn("%s: unable to init cpu nodes sysfs %d\n", __func__,
			ret);
		kobject_del(&dkt.kobj_nodes);
		kobject_del(&dkt.kobj_topology);
		return ret;

	}

	dkt.attr_properties.name = "system_properties";
	dkt.attr_properties.mode = 0444;
	sysfs_attr_init(&dkt.attr_properties);
	ret = sysfs_create_file(&dkt.kobj_topology,
				&dkt.attr_properties);
	if (ret) {
		/* XXX */
	}
	dkt.attr_genid.name = "generation_id";
	dkt.attr_genid.mode = 0444;
	sysfs_attr_init(&dkt.attr_genid);
	ret = sysfs_create_file(&dkt.kobj_topology,
				&dkt.attr_genid);
	if (ret) {
		/* XXX */
	}

	dkt.attr_cpu_node_id.name = "gpu_id";
	dkt.attr_cpu_node_id.mode = 0444;
	sysfs_attr_init(&dkt.attr_cpu_node_id);
	ret = sysfs_create_file(&dkt.kobj_cpu_node,
				&dkt.attr_cpu_node_id);

	dkt.attr_cpu_properties.name = "properties";
	dkt.attr_cpu_properties.mode = 0444;
	sysfs_attr_init(&dkt.attr_cpu_properties);
	ret = sysfs_create_file(&dkt.kobj_cpu_node,
				&dkt.attr_cpu_properties);
#if 0
	dkt.attr_dpa_node_id.name = "gpu_id";
	dkt.attr_dpa_node_id.mode = 0444;
	sysfs_attr_init(&dkt.attr_dpa_node_id);
	ret = sysfs_create_file(&dkt.kobj_dpa_node,
				&dkt.attr_dpa_node_id);

	dkt.attr_dpa_properties.name = "properties";
	dkt.attr_dpa_properties.mode = 0444;
	sysfs_attr_init(&dkt.attr_dpa_properties);
	ret = sysfs_create_file(&dkt.kobj_dpa_node,
				&dkt.attr_dpa_properties);

#endif
	return ret;
}

static void dpa_kfd_sysfs_destroy(void)
{
	if (dkt.dpa) {
		/* XXX sysfs_remove_file a bunch of times */
		kobject_del(&dkt.kobj_cpu_node);
		kobject_del(&dkt.kobj_nodes);
		kobject_del(&dkt.kobj_topology);
		dkt.dpa = NULL;
	}
}

static const struct pci_device_id dpa_pci_table[] = {
	{ PCI_VENDOR_ID_RIVOS, PCI_DEVICE_ID_RIVOS_DPA,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, dpa_pci_table);

void setup_queue(struct dpa_device *dpa) {
	dev_warn(dpa->dev, "DMA address of queue is: %llx\n", dpa->qinfo.fw_queue_dma_addr);
	writeq(dpa->qinfo.fw_queue_dma_addr, dpa->regs + DUC_REGS_FW_DESC);
	writeq(0, dpa->regs + DUC_REGS_FW_PASID);
}

static int dpa_gem_object_mmap(struct drm_gem_object *gobj, struct vm_area_struct *vma) {

	struct dpa_kfd_buffer *buf = gem_to_dpa_buf(gobj);
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long start = vma->vm_start;
	unsigned long chunk_size;
	unsigned long vma_page_count = size >> PAGE_SHIFT;
	struct drm_buddy_block *block, *on;
	u64 paddr;
	int ret = -EFAULT;
	if (buf) {
		unsigned long num_pages = buf->page_count;
		if (buf->type != KFD_IOC_ALLOC_MEM_FLAGS_VRAM) {
			dev_warn(dpa_device, "%s: unexpected type for buf %u\n",
					__func__, buf->type);
			return -EINVAL;
		}
		if (buf->page_count != vma_page_count) {
			dev_warn(dpa_device, "%s: buf page count %u != vma %lu\n",
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
			dev_warn(dpa_device, "%s: vm_insert_pages ret = %d num = %lu\n",
					__func__, ret, num_pages);
			return ret;
		}
	} else {
		dev_warn(dpa_device, "%s: buffer is not found\n",
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
	u64 type = mmap_offset >> KFD_MMAP_TYPE_SHIFT;
	if (type == KFD_MMAP_TYPE_VRAM) {
		return drm_gem_mmap(filp, vma);
	} else {
		return dpa_kfd_mmap(filp, vma);
	}
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
	struct dpa_kfd_process *p = file_priv->driver_priv;
	if (p && (!p->is_kfd))
		kref_put(&p->ref, dpa_kfd_release_process);
	pci_set_drvdata(dpa->pdev, NULL);
}

static int dpa_driver_open_kms(struct drm_device *dev, struct drm_file *file_priv)
{
	struct dpa_kfd_process *dpa_app = NULL;
	struct device *dpa_dev;

	// big lock for this
	mutex_lock(&dpa_processes_lock);
	// look for process in a list
	dpa_app = get_current_process();

	if (dpa_app) {
		if (!dpa_app->is_kfd)
			kref_get(&dpa_app->ref);
		mutex_unlock(&dpa_processes_lock);
		// using existing dpa_kfd_process
		dev_warn(dpa_device, "%s: using existing kfd process\n", __func__);
		return 0;
	}
	// new process
	if (dpa_process_count >= DPA_PROCESS_MAX) {
		dev_warn(dpa_device, "%s: max number of processes reached\n",
			 __func__);
		mutex_unlock(&dpa_processes_lock);
		return -EBUSY;
		}
	dpa_app = devm_kzalloc(dpa_device, sizeof(*dpa_app), GFP_KERNEL);
	if (!dpa_app) {
		mutex_unlock(&dpa_processes_lock);
		return -ENOMEM;
	}
	file_priv->driver_priv = dpa_app;
	dpa_process_count++;
	INIT_LIST_HEAD(&dpa_app->dpa_process_list);
	list_add_tail(&dpa_app->dpa_process_list, &dpa_processes);

	dev_warn(dpa_device, "%s: associated with pid %d\n", __func__, current->tgid);
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
		int ret = PTR_ERR(dpa_app->sva);
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

	dpa_app->is_kfd = false;
	dpa_app->drm_priv = file_priv;

	mutex_unlock(&dpa_processes_lock);
	return 0;
}


int dpa_gem_object_create(unsigned long size,
			     int alignment,
			     u64 flags,
			     struct drm_gem_object **obj)
{
	struct dpa_kfd_buffer * buf;
	struct device * dev = dpa->dev;
	struct drm_buddy * mm = &dpa->mm;
	struct drm_buddy_block *block, *on;
	int err;

	*obj = NULL;
	/* Memory should be aligned at least to a page size. */
	size = ALIGN(size, PAGE_SIZE);

	buf = devm_kzalloc(dev, sizeof(struct dpa_kfd_buffer), GFP_KERNEL);
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

	dev_warn(dev, "%s: start\n", __func__);
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
	printk(KERN_INFO "Device vid: 0x%X pid: 0x%X\n", vendor, device);


	if ((err = pci_enable_device_mem(pdev)))
		goto disable_device;

	if ((err = pci_request_mem_regions(pdev, kfd_dev_name)))
		goto disable_device;

	// Enable PASID support
	if (iommu_dev_enable_feature(dpa->dev, IOMMU_DEV_FEAT_SVA)) {
		dev_warn(dpa->dev, "%s: Unable to turn on SVA feature\n", __func__);
		goto disable_device;
	} else {
		dev_warn(dpa->dev, "%s: SVA feature enabled successfully\n", __func__);
	}

	dpa->regs = ioremap(pci_resource_start(pdev, 0), DUC_MMIO_SIZE);
	if (!dpa->regs) {
		dev_warn(dpa_device, "%s: unable to remap registers\n", __func__);
		err = -EIO;
		goto disable_device;
	}

	err = daffy_alloc_fw_queue(dpa);
	if (err) {
		dev_warn(dpa_device, "%s: unable to allocate memory\n", __func__);
		goto unmap;
	}
	// Write Daffy information to FW queue regs
	setup_queue(dpa);

	dpa->drm_minor = ddev->render->index;
	// LIST_HEAD_INIT(&dpa->buffers);

	if ((err = dpa_kfd_chardev_init()))
		goto free_queue;

	if ((err = dpa_kfd_sysfs_init())) {
		dev_err(dpa_device, "%s: Error creating sysfs nodes: %d\n",
			__func__, err);
	}

	version = ioread64(dpa->regs + DUC_REGS_FW_VER);
	dev_warn(dpa_device, "%s: got version %u\n", __func__, version);

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
	dpa->hbm_va = devm_memremap(dpa_device, dpa->hbm_base, dpa->hbm_size, MEMREMAP_WB);
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

free_queue:
	daffy_free_fw_queue(dpa);

unmap:
	iounmap(dpa->regs);

disable_device:
	dev_warn(dpa->dev, "%s: Disabling device\n", __func__);
	pci_disable_device(pdev);
	devm_kfree(dev, dpa);

	return err;
}

int dpa_reserve_mem_limit(struct dpa_device *dpa, uint64_t size, u32 alloc_flag)
{
	int ret = 0;
	// XXX Actually implement this
	// if (dpa) {
	// 	dpa->vram_used += size;
	// 	dpa->vram_used_aligned += ALIGN(size, VRAM_AVAILABLITY_ALIGN);
	// }
// release:
	return ret;
}


int dpa_alloc_vram(
		struct dpa_device *dpa,
		uint64_t size,
		void *drm_priv,
		struct dpa_kfd_buffer** bo,
		uint64_t *offset, uint32_t flags) //, bool criu_resume)
{

	struct drm_gem_object *gobj = NULL;
	struct dpa_kfd_buffer* buf;
	int ret;

	ret = dpa_reserve_mem_limit(dpa, size, flags);
	if (ret) {
		pr_debug("Insufficient memory\n");
		goto err;
	}

	ret = dpa_gem_object_create(size, 1, flags, &gobj);
	if (ret) {
		goto err;
	}
	pr_info("%s: Allowing drm_priv %p\n", __func__, drm_priv);
	ret = drm_vma_node_allow(&gobj->vma_node, drm_priv);

	*bo = gem_to_dpa_buf(gobj);
	buf = *bo;

	if (offset)
		*offset = drm_vma_node_offset_addr(&buf->gobj.vma_node);
	return 0;

err:
	return ret;
}
/* Ioctl handlers */
static int dpa_ioctl_get_version(struct dpa_kfd_process *p,
	struct dpa_device *dpa, void *data)
{
	struct drm_dpa_get_version *args = data;

	args->major_version = KFD_IOCTL_MAJOR_VERSION;
	// this doesn't seem to actually effect behaviors of userspace so far
	// XXX check user code, for now just advertise minimal API support
	args->minor_version = 1;
	dev_warn(p->dev->dev, "%s: major %d minor %d\n", __func__,
		 args->major_version, args->minor_version);

	return 0;
}

DRM_KFD_IOCTL(get_version)

static int dpa_add_aql_queue(struct dpa_kfd_process *p, u32 queue_id,
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

static int dpa_del_aql_queue(struct dpa_kfd_process *p, u32 queue_id)
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

static void dpa_del_all_queues(struct dpa_kfd_process *p)
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

static int dpa_ioctl_create_queue(struct dpa_kfd_process *p,
	struct dpa_device *dpa, void *data)
{
	struct drm_dpa_create_queue *args = data;
	u64 doorbell_mmap_offset;
	int ret = daffy_create_queue_cmd(p->dev, p, args);

	if (ret)
		return ret;

	// we need to convert the page offset from daffy to an offset mmap can recognize
	doorbell_mmap_offset = KFD_MMAP_TYPE_DOORBELL << KFD_MMAP_TYPE_SHIFT;
	ret = dpa_add_aql_queue(p, args->queue_id, args->doorbell_offset);
	if (ret) {
		dev_warn(p->dev->dev, "%s: unable to add aql queue to process,"
			 " destroying id %u\n", __func__, args->queue_id);
		daffy_destroy_queue_cmd(p->dev, p, args->queue_id);
	}
	args->doorbell_offset = doorbell_mmap_offset;
	return ret;
}
DRM_KFD_IOCTL(create_queue)

static int dpa_ioctl_destroy_queue(struct dpa_kfd_process *p,
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

DRM_KFD_IOCTL(destroy_queue)

static int dpa_ioctl_set_memory_policy(struct dpa_kfd_process *p,
	struct dpa_device *dpa, void *data)
{
	/* we don't support any changes in coherency */
	dev_warn(dpa->dev, "%s: doing nothing\n", __func__);
	return 0;
}

DRM_KFD_IOCTL(set_memory_policy)

static int dpa_ioctl_get_clock_counters(struct dpa_kfd_process *p,
	struct dpa_device *dpa, void *data)
{
	struct drm_dpa_get_clock_counters *ctr_args = data;

	dev_warn(dpa->dev, "%s: gpu_id %d\n", __func__, ctr_args->gpu_id);

	/* XXX when we have a common clock with DPA use it here */
	ctr_args->gpu_clock_counter = ktime_get_raw_ns();
	ctr_args->cpu_clock_counter = ktime_get_raw_ns();

	/* using ns, so freq is 1Ghz*/
	ctr_args->system_clock_freq = 1000000;
	return 0;
}

DRM_KFD_IOCTL(get_clock_counters)


static int dpa_ioctl_get_process_apertures(struct dpa_kfd_process *p,
	struct dpa_device *dpa, void *data)
{
	struct drm_dpa_get_process_apertures *args = data;
	struct kfd_process_device_apertures *aperture = &args->process_apertures[0];

	dev_warn(dpa_device, "%s\n", __func__);

	aperture->gpu_id = DPA_GPU_ID;
	aperture->lds_base = 0;
	aperture->lds_limit = 0;
	// gpuvm is the main one
	aperture->gpuvm_base = PAGE_SIZE;  // don't allow NULL ptrs
	aperture->gpuvm_limit = DPA_GPUVM_ADDR_LIMIT; // allow everything up to 48 bits
	aperture->scratch_base = 0;
	aperture->scratch_limit = 0;
	args->num_of_nodes = 1;

	return 0;
}

DRM_KFD_IOCTL(get_process_apertures)

static int dpa_ioctl_update_queue(struct dpa_kfd_process *p,
	struct dpa_device *dpa, void *data)
{
	return -ENOSYS;
}

DRM_KFD_IOCTL(update_queue)

static int dpa_ioctl_get_process_apertures_new(struct dpa_kfd_process *p,
	struct dpa_device *dpa, void *data)
{
	struct drm_dpa_get_process_apertures_new *args = data;
	struct kfd_process_device_apertures ap; // just one for now
	int ret;

	if (args->num_of_nodes < 1) {
		/* we have to return the number of nodes so that
		 * userspace call allocate enough space
		 */
		args->num_of_nodes = 1;
		return 0;
	}

	memset(&ap, 0, sizeof(ap));
	args->num_of_nodes = 1;
	ap.gpu_id = DPA_GPU_ID;
	ap.gpuvm_base = PAGE_SIZE;
	ap.gpuvm_limit = DPA_GPUVM_ADDR_LIMIT;
	ret = copy_to_user((void __user*)args->kfd_process_device_apertures_ptr,
			   &ap, sizeof(ap));
	return ret;
}

DRM_KFD_IOCTL(get_process_apertures_new)

static int dpa_kfd_ioctl_acquire_vm(struct file *filep,
                                struct dpa_kfd_process *p, void *data)
{
	struct drm_dpa_acquire_vm *args = data;
	struct file *drm_file;
	int ret;

	drm_file = fget(args->drm_fd);
	if (!drm_file)
		return -EINVAL;

	mutex_lock(&p->lock);
	if (p->drm_file) {
		ret = p->drm_file == drm_file ? 0 : -EBUSY;
		goto err_drm_file;
	}
	p->drm_file = drm_file;
	p->drm_priv = drm_file->private_data;

	mutex_unlock(&p->lock);
	return 0;

err_drm_file:
	mutex_unlock(&p->lock);
	fput(drm_file);
	return ret;
}
static int dpa_drm_ioctl_acquire_vm(struct drm_device *dev,
						 void *data, struct drm_file *file)
{
	struct dpa_kfd_process *p = file->driver_priv;
	struct file *drm_file;
	int ret;

	if (!p)
		return -EINVAL;
	drm_file = file->filp;
	if (!drm_file)
		return -EINVAL;

	mutex_lock(&p->lock);
	if (p->drm_file) {
		ret = p->drm_file == drm_file ? 0 : -EBUSY;
		goto err_drm_file;
	}
	p->drm_file = drm_file;
	p->drm_priv = drm_file->private_data;

	mutex_unlock(&p->lock);
	return 0;

err_drm_file:
	mutex_unlock(&p->lock);
	return ret;
}
static struct dpa_kfd_buffer *find_buffer(struct dpa_kfd_process *p, u64 id)
{
	struct dpa_kfd_buffer *buf, *tmp;

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

static int dpa_ioctl_alloc_memory_of_gpu(struct dpa_kfd_process *p,
	struct dpa_device *dpa, void *data)
{
	struct drm_dpa_alloc_memory_of_gpu *args = data;
	struct device *dev = p->dev->dev;
	struct dpa_kfd_buffer *buf;
	uint64_t offset = 0;
	int r = 0;

	dev_warn(dev, "%s: flags 0x%x size 0x%llx\n", __func__,
		 args->flags, args->size);

	if (args->flags & KFD_IOC_ALLOC_MEM_FLAGS_VRAM) {
		r = dpa_alloc_vram(dpa, args->size, p->drm_priv, &buf, &offset,
			KFD_IOC_ALLOC_MEM_FLAGS_VRAM);
		if (r) {
			dev_warn(dev, "%s: vram alloc failed %d\n", __func__, r);
			return -ENOMEM;
		}
	} else if (args->flags & KFD_IOC_ALLOC_MEM_FLAGS_USERPTR) {
		long page_count = 0;
		unsigned int gup_flags = FOLL_LONGTERM;
		struct vm_area_struct  *vma;

		buf = devm_kzalloc(dev, sizeof(*buf), GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		buf->type = args->flags;
		buf->size = args->size;
		buf->page_count = buf->size >> PAGE_SHIFT;
		buf->pages = devm_kzalloc(dev, sizeof(struct page*) * buf->page_count, GFP_KERNEL);
		if (!buf->pages) {
			dev_warn(dev, "%s: cannot alloc pages\n", __func__);
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

		if ((page_count = pin_user_pages(args->va_addr, buf->page_count,
						gup_flags, buf->pages, NULL))
		    != buf->page_count) {
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
	if (args->flags & KFD_IOC_ALLOC_MEM_FLAGS_VRAM) {
		args->mmap_offset = offset;
	}
	dev_warn(p->dev->dev, "%s: buf id %u handle 0x%llx\n", __func__,
		 buf->id, args->handle);

	return 0;
}

DRM_KFD_IOCTL(alloc_memory_of_gpu)

static int dpa_ioctl_map_memory_to_gpu(struct dpa_kfd_process *p,
	struct dpa_device *dpa, void *data)
{
	struct drm_dpa_map_memory_to_gpu *args = data;

	// XXX loop over gpu id verify ID passed in matches
	// XXX check gpu id
	struct dpa_kfd_buffer *buf = find_buffer(p, args->handle & 0xFFFFFFFF);

	dev_warn(p->dev->dev, "%s: handle 0x%llx buf 0x%llx\n",
		 __func__, args->handle, (u64)buf);
	if (buf) {
		// XXX do mapping here?
		//if (buf->dma_addr)
		args->n_success = 1;
	} else {
		dev_warn(p->dev->dev, "%s: given buffer not found!\n", __func__);
		return -EINVAL;
	}

	return 0;
}

DRM_KFD_IOCTL(map_memory_to_gpu)

static int dpa_ioctl_unmap_memory_from_gpu(struct dpa_kfd_process *p,
	struct dpa_device *dpa, void *data)
{
	struct drm_dpa_unmap_memory_from_gpu *args = data;

	// XXX loop over gpu id verify ID passed in matches
	struct dpa_kfd_buffer *buf = find_buffer(p, args->handle & 0xFFFFFFFF);
	dev_warn(p->dev->dev, "%s: handle 0x%llx buf 0x%llx\n",
		 __func__, args->handle, (u64)buf);
	if (buf) {
		// XXX unmap it
		args->n_success = 1;
	}

	return 0;
}

DRM_KFD_IOCTL(unmap_memory_from_gpu)

static int dpa_ioctl_get_info(struct dpa_kfd_process *p,
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
DRM_KFD_IOCTL(get_info);

static void dpa_kfd_free_buffer(struct dpa_kfd_buffer *buf)
{
	struct device *dev = buf->p->dev->dev;
	dev_warn(dev, "%s: freeing buf id %u\n",
		 __func__, buf->id);

	if (buf->type & KFD_IOC_ALLOC_MEM_FLAGS_VRAM) {
		if (buf->page_count) {
			mutex_lock(&dpa->mm_lock);
			drm_buddy_free_list(&dpa->mm, &buf->blocks);
			mutex_unlock(&dpa->mm_lock);
		}
		drm_gem_object_release(&buf->gobj);
	}

	if (buf->type & KFD_IOC_ALLOC_MEM_FLAGS_USERPTR) {
		if (buf->page_count) {
			unpin_user_pages(buf->pages, buf->page_count);
			devm_kfree(dev, buf->pages);
		}

	}
	devm_kfree(dev, buf);

}

static int dpa_ioctl_free_memory_of_gpu(struct dpa_kfd_process *p,
	struct dpa_device *dpa, void *data)
{
	struct drm_dpa_free_memory_of_gpu *args = data;
	struct dpa_kfd_buffer *buf = find_buffer(p, args->handle & 0xFFFFFFFF);
	dev_warn(p->dev->dev, "%s: handle 0x%llx buf 0x%llx\n",
		 __func__, args->handle, (u64)buf);
	if (buf) {
		mutex_lock(&p->dev->lock);
		list_del(&buf->process_alloc_list);
		mutex_unlock(&p->dev->lock);
		dpa_kfd_free_buffer(buf);
	}

	return 0;
}

DRM_KFD_IOCTL(free_memory_of_gpu)

#define KFD_IOCTL_DEF(ioctl, _func, _flags) \
	[_IOC_NR(ioctl)] = {.cmd = ioctl, .func = _func, .flags = _flags, \
			    .cmd_drv = 0, .name = #ioctl}

/** Ioctl table */
static const struct kfd_ioctl_desc amdkfd_ioctls[] = {
	KFD_IOCTL_DEF(AMDKFD_IOC_GET_VERSION,
			dpa_kfd_ioctl_get_version, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_CREATE_QUEUE,
			dpa_kfd_ioctl_create_queue, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_DESTROY_QUEUE,
			dpa_kfd_ioctl_destroy_queue, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_SET_MEMORY_POLICY,
			dpa_kfd_ioctl_set_memory_policy, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_GET_CLOCK_COUNTERS,
			dpa_kfd_ioctl_get_clock_counters, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_GET_PROCESS_APERTURES,
			dpa_kfd_ioctl_get_process_apertures, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_UPDATE_QUEUE,
			dpa_kfd_ioctl_update_queue, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_GET_PROCESS_APERTURES_NEW,
			dpa_kfd_ioctl_get_process_apertures_new, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_ACQUIRE_VM,
			dpa_kfd_ioctl_acquire_vm, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_ALLOC_MEMORY_OF_GPU,
		      dpa_kfd_ioctl_alloc_memory_of_gpu, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_FREE_MEMORY_OF_GPU,
		      dpa_kfd_ioctl_free_memory_of_gpu, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_MAP_MEMORY_TO_GPU,
		      dpa_kfd_ioctl_map_memory_to_gpu, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_UNMAP_MEMORY_FROM_GPU,
		      dpa_kfd_ioctl_unmap_memory_from_gpu, 0),
#if 0
	AMDKFD_IOCTL_DEF(AMDKFD_IOC_SET_CU_MASK,
			kfd_ioctl_set_cu_mask, 0),

	AMDKFD_IOCTL_DEF(AMDKFD_IOC_GET_QUEUE_WAVE_STATE,
			kfd_ioctl_get_queue_wave_state, 0),

	AMDKFD_IOCTL_DEF(AMDKFD_IOC_GET_DMABUF_INFO,
				kfd_ioctl_get_dmabuf_info, 0),

	AMDKFD_IOCTL_DEF(AMDKFD_IOC_IMPORT_DMABUF,
				kfd_ioctl_import_dmabuf, 0),

	AMDKFD_IOCTL_DEF(AMDKFD_IOC_ALLOC_QUEUE_GWS,
			kfd_ioctl_alloc_queue_gws, 0),

	AMDKFD_IOCTL_DEF(AMDKFD_IOC_SMI_EVENTS,
			kfd_ioctl_smi_events, 0),

	AMDKFD_IOCTL_DEF(AMDKFD_IOC_SVM, kfd_ioctl_svm, 0),

	AMDKFD_IOCTL_DEF(AMDKFD_IOC_SET_XNACK_MODE,
			kfd_ioctl_set_xnack_mode, 0),

	AMDKFD_IOCTL_DEF(AMDKFD_IOC_CRIU_OP,
			kfd_ioctl_criu, KFD_IOC_FLAG_CHECKPOINT_RESTORE),

	KFD_IOCTL_DEF(AMDKFD_IOC_GET_TILE_CONFIG,
			kfd_ioctl_get_tile_config, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_SET_TRAP_HANDLER,
			kfd_ioctl_set_trap_handler, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_GET_PROCESS_APERTURES_NEW,
			kfd_ioctl_get_process_apertures_new, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_ACQUIRE_VM,
			kfd_ioctl_acquire_vm, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_ALLOC_MEMORY_OF_GPU,
			kfd_ioctl_alloc_memory_of_gpu, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_FREE_MEMORY_OF_GPU,
			kfd_ioctl_free_memory_of_gpu, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_MAP_MEMORY_TO_GPU,
			kfd_ioctl_map_memory_to_gpu, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_UNMAP_MEMORY_FROM_GPU,
			kfd_ioctl_unmap_memory_from_gpu, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_SET_CU_MASK,
			kfd_ioctl_set_cu_mask, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_GET_QUEUE_WAVE_STATE,
			kfd_ioctl_get_queue_wave_state, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_GET_DMABUF_INFO,
				kfd_ioctl_get_dmabuf_info, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_IMPORT_DMABUF,
				kfd_ioctl_import_dmabuf, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_ALLOC_QUEUE_GWS,
			kfd_ioctl_alloc_queue_gws, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_SMI_EVENTS,
			kfd_ioctl_smi_events, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_SVM, kfd_ioctl_svm, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_SET_XNACK_MODE,
			kfd_ioctl_set_xnack_mode, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_CRIU_OP,
			kfd_ioctl_criu, KFD_IOC_FLAG_CHECKPOINT_RESTORE),
#endif
};

static long dpa_kfd_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	kfd_ioctl_t *func;
	const struct kfd_ioctl_desc *ioctl = NULL;
	unsigned int nr = _IOC_NR(cmd);
	unsigned int usize, asize;
	int retcode = -EINVAL;
	struct dpa_kfd_process *process = filep->private_data;
	char stack_kdata[128];
	void *kdata = stack_kdata;

//	if (nr >= AMDKFD_CORE_IOCTL_COUNT)
//		return ret;

	if (nr != 0xc) // wait event is too noisy
		dev_warn(dpa_device, "ioctl cmd 0x%x (#0x%x), arg 0x%lx\n", cmd, nr, arg);

	if ((nr >= AMDKFD_COMMAND_START) && (nr < AMDKFD_COMMAND_END)) {
		u32 amdkfd_size;

		if (nr >= sizeof(amdkfd_ioctls)/sizeof(amdkfd_ioctls[0])) {
			dev_warn(dpa_device, "ioctl not yet implemented\n");
			return -EINVAL;
		}

		ioctl = &amdkfd_ioctls[nr];

		amdkfd_size = _IOC_SIZE(ioctl->cmd);
		usize = asize = _IOC_SIZE(cmd);
		if (amdkfd_size > asize)
			asize = amdkfd_size;

		cmd = ioctl->cmd;
	} else
		goto err_i1;

	/* Get the process struct from the filep. Only the process
	 * that opened /dev/kfd can use the file descriptor. Child
	 * processes need to create their own KFD device context.
	 */
	//process = filep->private_data;

	/* if (process->lead_thread != current->group_leader */
	/*     && !ptrace_attached) { */
	/*	dev_dbg(dpa_device, "Using KFD FD in wrong process\n"); */
	/*	retcode = -EBADF; */
	/*	goto err_i1; */
	/* } */

	/* Do not trust userspace, use our own definition */
	func = ioctl->func;

	if (unlikely(!func)) {
		dev_warn(dpa_device, "no function\n");
		retcode = -EINVAL;
		goto err_i1;
	}

	if (cmd & (IOC_IN | IOC_OUT)) {
		if (asize <= sizeof(stack_kdata)) {
			kdata = stack_kdata;
		} else {
			kdata = kmalloc(asize, GFP_KERNEL);
			if (!kdata) {
				retcode = -ENOMEM;
				goto err_i1;
			}
		}
		if (asize > usize)
			memset(kdata + usize, 0, asize - usize);
	}

	if (cmd & IOC_IN) {
		if (copy_from_user(kdata, (void __user *)arg, usize) != 0) {
			retcode = -EFAULT;
			goto err_i1;
		}
	} else if (cmd & IOC_OUT) {
		memset(kdata, 0, usize);
	}

	retcode = func(filep, process, kdata);

	if (cmd & IOC_OUT)
		if (copy_to_user((void __user *)arg, kdata, usize) != 0)
			retcode = -EFAULT;

err_i1:
	if (!ioctl)
		dev_warn(dpa_device, "invalid ioctl: pid=%d, cmd=0x%02x, nr=0x%02x\n",
			  task_pid_nr(current), cmd, nr);

	if (kdata != stack_kdata)
		kfree(kdata);

	if (retcode)
		dev_warn(dpa_device, "ioctl cmd (#0x%x), arg 0x%lx, ret = %d\n",
				nr, arg, retcode);
	return retcode;
}

static const struct drm_ioctl_desc dpadrm_ioctls[] = {
	DRM_IOCTL_DEF_DRV(DPA_GET_VERSION, dpa_drm_ioctl_get_version, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_CREATE_QUEUE, dpa_drm_ioctl_create_queue, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_DESTROY_QUEUE, dpa_drm_ioctl_destroy_queue, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_SET_MEMORY_POLICY, dpa_drm_ioctl_set_memory_policy, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_GET_CLOCK_COUNTERS, dpa_drm_ioctl_get_clock_counters, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_GET_PROCESS_APERTURES, dpa_drm_ioctl_get_process_apertures, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_UPDATE_QUEUE, dpa_drm_ioctl_update_queue, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_GET_PROCESS_APERTURES_NEW, dpa_drm_ioctl_get_process_apertures_new, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_ACQUIRE_VM, dpa_drm_ioctl_acquire_vm, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_ALLOC_MEMORY_OF_GPU, dpa_drm_ioctl_alloc_memory_of_gpu, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_FREE_MEMORY_OF_GPU, dpa_drm_ioctl_free_memory_of_gpu, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_MAP_MEMORY_TO_GPU, dpa_drm_ioctl_map_memory_to_gpu, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_UNMAP_MEMORY_FROM_GPU, dpa_drm_ioctl_unmap_memory_from_gpu, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(DPA_GET_INFO, dpa_drm_ioctl_get_info, DRM_RENDER_ALLOW),
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

static int dpa_kfd_open(struct inode *inode, struct file *filep)
{
	struct dpa_kfd_process *dpa_app = NULL;
	struct device *dpa_dev;

	// big lock for this
	mutex_lock(&dpa_processes_lock);
	// look for process in a list
	dpa_app = get_current_process();

	if (dpa_app) {
		kref_get(&dpa_app->ref);
		mutex_unlock(&dpa_processes_lock);
		// using existing dpa_kfd_process
		dev_warn(dpa_device, "%s: using existing kfd process\n", __func__);
		filep->private_data = dpa_app;
		return 0;
	}
	// new process
	if (dpa_process_count >= DPA_PROCESS_MAX) {
		dev_warn(dpa_device, "%s: max number of processes reached\n",
			 __func__);
		mutex_unlock(&dpa_processes_lock);
		return -EBUSY;
		}
	dpa_app = devm_kzalloc(dpa_device, sizeof(*dpa_app), GFP_KERNEL);
	if (!dpa_app) {
		mutex_unlock(&dpa_processes_lock);
		return -ENOMEM;
	}
	dpa_process_count++;
	INIT_LIST_HEAD(&dpa_app->dpa_process_list);
	list_add_tail(&dpa_app->dpa_process_list, &dpa_processes);

	dev_warn(dpa_device, "%s: associated with pid %d\n", __func__, current->tgid);
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
		int ret = PTR_ERR(dpa_app->sva);
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
	filep->private_data = dpa_app;

	dpa_app->is_kfd = true;
	mutex_unlock(&dpa_processes_lock);
	return 0;
}

static void dpa_kfd_release_process_buffers(struct dpa_kfd_process *p)
{
	struct dpa_kfd_buffer *buf, *tmp;
	mutex_lock(&p->dev->lock);
	list_for_each_entry_safe(buf, tmp, &p->buffers, process_alloc_list) {
		if (buf->p == p) {
			list_del(&buf->process_alloc_list);
			dpa_kfd_free_buffer(buf);
		} else {
			dev_warn(p->dev->dev, "%s: mismatched buffer?", __func__);
		}
	}
	mutex_unlock(&p->dev->lock);
}

static void dpa_kfd_release_process(struct kref *ref)
{
	struct dpa_kfd_process *p = container_of(ref, struct dpa_kfd_process,
						 ref);
	mutex_lock(&dpa_processes_lock);
	dev_warn(p->dev->dev, "%s: freeing process %d\n", __func__,
		 current->tgid);
	// XXX mutex lock on process lock ?
	dpa_kfd_release_process_buffers(p);

	if (p->drm_file)
		fput(p->drm_file);

	dpa_del_all_queues(p);
	if (p->sva)
		iommu_sva_unbind_device(p->sva);
	list_del(&p->dpa_process_list);
	dpa_process_count--;
	devm_kfree(dpa_device, p);
	mutex_unlock(&dpa_processes_lock);
}

static int dpa_kfd_release(struct inode *inode, struct file *filep)
{
	struct dpa_kfd_process *p = filep->private_data;
	if (p)
		kref_put(&p->ref, dpa_kfd_release_process);

	return 0;
}

static int dpa_kfd_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct dpa_kfd_process *p;
	unsigned long mmap_offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned int gpu_id = KFD_MMAP_GET_GPU_ID(mmap_offset);
	u64 type = mmap_offset >> KFD_MMAP_TYPE_SHIFT;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long pfn;
	int ret = -EFAULT;

	mutex_lock(&dpa_processes_lock);
	p = get_current_process();
	mutex_unlock(&dpa_processes_lock);

	dev_warn(p->dev->dev, "%s: offset 0x%lx size 0x%lx gpu 0x%x type %llu start 0x%llx\n",
		 __func__, mmap_offset, size, gpu_id, type, (u64)vma->vm_start);
	switch (type) {
	case KFD_MMAP_TYPE_VRAM:
	{
		u64 id = vma->vm_pgoff & 0xFFFFFFFF;
		struct dpa_kfd_buffer *buf;
		unsigned long vma_page_count = size >> PAGE_SHIFT;
		dev_warn(p->dev->dev, "%s: trying to map vram for buf id %llu vma %lu pages\n",
			 __func__, id, vma_page_count);

		buf = find_buffer(p, id);
		if (buf) {
			unsigned long num_pages = buf->page_count;
			if (buf->type != KFD_IOC_ALLOC_MEM_FLAGS_VRAM) {
				dev_warn(p->dev->dev, "%s: unexpected type for buf %u\n",
					 __func__, buf->type);
				return -EINVAL;
			}
			if (buf->page_count != vma_page_count) {
				dev_warn(p->dev->dev, "%s: buf page count %u != vma %lu\n",
					 __func__, buf->page_count, vma_page_count);
				return -EINVAL;
			}
			ret = vm_insert_pages(vma, vma->vm_start, buf->pages,
					      &num_pages);
			if (ret || num_pages) {
				dev_warn(p->dev->dev, "%s: vm_insert_pages ret = %d num = %lu\n",
					 __func__, ret, num_pages);
				return ret;
			}
		} else {
			dev_warn(p->dev->dev, "%s: buffer id %llu not found\n",
				 __func__, id);
			return -EINVAL;
		}
	}
	break;
	case KFD_MMAP_TYPE_DOORBELL:
		if (size != DPA_DOORBELL_PAGE_SIZE) {
			dev_warn(p->dev->dev, "%s: invalid size for doorbell\n",
				 __func__);
			return -EINVAL;
		}

		// TODO: Right now we only support one MMIO-mapped doorbell page, expand to all 16
		dev_warn(p->dev->dev, "%s: Mapping doorbell page\n", __func__);

		mutex_lock(&p->lock);
		pfn = p->doorbell_base;
		pfn >>= PAGE_SHIFT;

		ret = io_remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot);
		mutex_unlock(&p->lock);

		if (ret) {
			dev_warn(p->dev->dev, "%s: failed to map doorbell page"
				 "ret %d\n", __func__, ret);
		}
		break;
	default:
		dev_warn(p->dev->dev, "%s: doing nothing\n", __func__);
	}

	return ret;
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

	pr_warn("%s: start\n", __func__);
	dpa_class = class_create(THIS_MODULE, kfd_dev_name);
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
	dpa_kfd_sysfs_destroy();
	class_destroy(dpa_class);
	unregister_chrdev(dpa_char_dev_major, kfd_dev_name);
}

MODULE_LICENSE("GPL");
module_init(dpa_init);
module_exit(dpa_exit);

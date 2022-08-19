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
#include <linux/fs.h>
#include <linux/pci.h>
#include <linux/sched/mm.h>
#include <uapi/linux/kfd_ioctl.h>
#include "dpa_kfd.h"

#define VIRTIO_DEMO 1

#ifdef VIRTIO_DEMO
#include <uapi/linux/virtio_ids.h>
#include <linux/virtio_pci_modern.h>
#endif

static long dpa_kfd_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
static int dpa_kfd_open(struct inode *inode, struct file *filep);
static int dpa_kfd_release(struct inode *inode, struct file *filep);
static int dpa_kfd_mmap(struct file *filp, struct vm_area_struct *vma);

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

	struct kobject kobj_dpa_node;
	struct attribute attr_dpa_node_id;
	struct attribute attr_dpa_properties;
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
		offs += snprintf(buffer + offs , PAGE_SIZE - offs, "drm_render_minor 0\n");
	} else if (attr == &dkt.attr_dpa_properties) {
		/* this is used to determine if it's a gpu */
		offs += snprintf(buffer, PAGE_SIZE, "simd_count 1\n");
		offs += snprintf(buffer + offs , PAGE_SIZE - offs, "mem_banks 1\n");
		offs += snprintf(buffer + offs , PAGE_SIZE - offs, "wave_front_size 32\n");
		/* this is used to open a DRM device */
		offs += snprintf(buffer + offs , PAGE_SIZE - offs, "drm_render_minor %d\n",
			dkt.dpa->drm_minor);
		/* This tells it which "ISA" to use */
		offs += snprintf(buffer + offs, PAGE_SIZE - offs, "gfx_target_version %d\n",
				 DPA_HSA_GFX_VERSION);
	} else if (attr == &dkt.attr_cpu_node_id) {
		offs = snprintf(buffer, PAGE_SIZE, "0\n");
	} else if (attr == &dkt.attr_dpa_node_id) {
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

	ret = kobject_init_and_add(&dkt.kobj_dpa_node, &dkt_type,
				   &dkt.kobj_nodes, "1");

	if (ret) {
		pr_warn("%s: unable to init dpa nodes sysfs %d\n", __func__,
			ret);
		kobject_del(&dkt.kobj_cpu_node);
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


	return ret;
}

static void dpa_kfd_sysfs_destroy(void)
{
	if (dkt.dpa) {
		/* XXX sysfs_remove_file a bunch of times */
		kobject_del(&dkt.kobj_dpa_node);
		kobject_del(&dkt.kobj_cpu_node);
		kobject_del(&dkt.kobj_nodes);
		kobject_del(&dkt.kobj_topology);
		dkt.dpa = NULL;
	}
}

#ifdef VIRTIO_DEMO
static const struct pci_device_id dpa_pci_table[] = {
	{PCI_VENDOR_ID_REDHAT_QUMRANET, 0x1040 + VIRTIO_ID_TDC,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{ 0, }
};

/* Mostly a copy of vp_modern_map_capability within virtio_pci_modern_dev.c, couldn't use it directly because it expects a virtio_pci_modern_device*/
static void __iomem *
vp_modern_map_capability(struct pci_dev *dev, int modern_bars, int off,
			 size_t minlen, u32 align, u32 start, u32 size,
			 size_t *len, resource_size_t *pa)
{


	u8 bar;
	u32 offset, length;
	void __iomem *p;

	pci_read_config_byte(dev, off + offsetof(struct virtio_pci_cap,
						 bar),
			     &bar);
	pci_read_config_dword(dev, off + offsetof(struct virtio_pci_cap, offset),
			     &offset);
	pci_read_config_dword(dev, off + offsetof(struct virtio_pci_cap, length),
			      &length);

	/* Check if the BAR may have changed since we requested the region. */
	if (bar >= PCI_STD_NUM_BARS || !(modern_bars & (1 << bar))) {
		dev_err(&dev->dev,
			"virtio_pci: bar unexpectedly changed to %u\n", bar);
		return NULL;
	}

	if (length <= start) {
		dev_err(&dev->dev,
			"virtio_pci: bad capability len %u (>%u expected)\n",
			length, start);
		return NULL;
	}

	if (length - start < minlen) {
		dev_err(&dev->dev,
			"virtio_pci: bad capability len %u (>=%zu expected)\n",
			length, minlen);
		return NULL;
	}

	length -= start;

	if (start + offset < offset) {
		dev_err(&dev->dev,
			"virtio_pci: map wrap-around %u+%u\n",
			start, offset);
		return NULL;
	}

	offset += start;

	if (offset & (align - 1)) {
		dev_err(&dev->dev,
			"virtio_pci: offset %u not aligned to %u\n",
			offset, align);
		return NULL;
	}

	if (length > size)
		length = size;

	if (len)
		*len = length;

	if (minlen + offset < minlen ||
	    minlen + offset > pci_resource_len(dev, bar)) {
		dev_err(&dev->dev,
			"virtio_pci: map virtio %zu@%u "
			"out of range on bar %i length %lu\n",
			minlen, offset,
			bar, (unsigned long)pci_resource_len(dev, bar));
		return NULL;
	}

	p = pci_iomap_range(dev, bar, offset, length);
	if (!p)
		dev_err(&dev->dev,
			"virtio_pci: unable to map virtio %u@%u on bar %i\n",
			length, offset, bar);
	else if (pa)
		*pa = pci_resource_start(dev, bar) + offset;

	return p;
}

static void setup_queue(struct dpa_device *dpa_dev)
{
	vp_iowrite16(0, &dpa_dev->common->queue_select);
	vp_iowrite16(0x1000, &dpa_dev->common->queue_size);
	vp_iowrite16(0, &dpa_dev->common->queue_msix_vector);
	vp_iowrite16(0, &dpa_dev->common->queue_notify_off);

	vp_iowrite64_twopart(dpa_dev->qinfo.fw_queue_dma_addr,
			     &dpa_dev->common->queue_desc_lo,
			     &dpa_dev->common->queue_desc_hi);
	vp_iowrite64_twopart(dpa_dev->qinfo.fw_queue_dma_addr,
			     &dpa_dev->common->queue_used_lo,
			     &dpa_dev->common->queue_used_hi);
	vp_iowrite64_twopart(dpa_dev->qinfo.fw_queue_dma_addr,
			     &dpa_dev->common->queue_avail_lo,
			     &dpa_dev->common->queue_avail_hi);
	printk("%s: sending 0x%llx\n", __func__,
	       dpa_dev->qinfo.fw_queue_dma_addr);
	vp_iowrite16(1, &dpa_dev->common->queue_enable);

}

#else
/* PCI Stuff */

#ifndef PCI_VENDOR_ID_RIVOS
#define PCI_VENDOR_ID_RIVOS             0x1efd
#endif

#ifndef PCI_DEVICE_ID_TDC
#define PCI_DEVICE_ID_RIVOS_DPA       0x8002
#endif

static const struct pci_device_id dpa_pci_table[] = {
	{ PCI_VENDOR_ID_RIVOS, PCI_DEVICE_ID_RIVOS_DPA,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, dpa_pci_table);
#endif

static int dpa_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int ret = 0;
	struct device *dev = &pdev->dev;
	int modern_bars, common, err;
	u16 vendor, device;
	u32 version;

	dev_warn(dev, "%s: start\n", __func__);
	dpa = devm_kzalloc(dev, sizeof(*dpa_device), GFP_KERNEL);
	if (!dpa)
		return -ENOMEM;
	dpa->dev = dev;
	dev_set_drvdata(dev, dpa);

#ifdef VIRTIO_DEMO
	pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor);
	pci_read_config_word(pdev, PCI_DEVICE_ID, &device);
	pci_write_config_byte(pdev, PCI_COMMAND, PCI_COMMAND_IO |
			      PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
	printk(KERN_INFO "Device vid: 0x%X pid: 0x%X\n", vendor, device);

	common = virtio_pci_find_capability(pdev, VIRTIO_PCI_CAP_COMMON_CFG,
					    IORESOURCE_IO | IORESOURCE_MEM,
					    &modern_bars);
	if (!common) {
		devm_kfree(dev, dpa);
		printk("Capability common not found\n");
		return -ENODEV;
	}

	err = pci_request_selected_regions(pdev, modern_bars,
					   "virtio-pci-modern");
	if (err) {
		devm_kfree(dev, dpa);
		return err;
	}

	err = -EINVAL;
	dpa->common =
		vp_modern_map_capability(pdev, modern_bars, common,
					 sizeof(struct virtio_pci_common_cfg), 4,
					 0, sizeof(struct virtio_pci_common_cfg),
					 NULL, NULL);

	if (!dpa->common) {
		devm_kfree(dev, dpa);
		printk("Couldn't map capability\n");
		return err;
	}

	err = daffy_alloc_fw_queue(dpa);
	if (err) {
		devm_kfree(dev, dpa);
		printk("Unable to allocate shared queue memory\n");
		return err;
	}

	// write the queue parameters to the shared area
	setup_queue(dpa);

	// Sets "status" with the enable bit
	// this causes qemu vhost to send parameters across
	vp_iowrite8(0xF, &dpa->common->device_status);

	// needed? we can't request mem regions
	if ((ret = pci_enable_device_mem(pdev))) {
		daffy_free_fw_queue(dpa);
		printk("%s: pci_enable_device_mem() failed %d\n",
		       __func__, ret);
		goto disable_device;
	}

#else
	if ((ret = pci_enable_device_mem(pdev)))
		goto disable_device;

	if ((ret = pci_request_mem_regions(pdev, kfd_dev_name)))
		goto disable_device;

	pci_set_drvdata(pdev, dpa);

	dpa->regs = ioremap(pci_resource_start(pdev, 0), DPA_MMIO_SIZE);
	if (!dpa->regs) {
		dev_warn(dpa_device, "%s: unable to remap registers\n", __func__);
		ret = -EIO;
		goto disable_device;
	}

	err = daffy_alloc_fw_queue(dpa);
	if (err) {
		dev_warn(dpa_device, "%s: unable to allocate memory\n", __func__);
		goto unmap;
	}

#endif
	/* XXX need DRM init */
	dpa->drm_minor = 128;
	// LIST_HEAD_INIT(&dpa->buffers);

	if ((ret = dpa_kfd_chardev_init()))
		goto free_queue;

	if ((ret = dpa_kfd_sysfs_init())) {
		dev_err(dpa_device, "%s: Error creating sysfs nodes: %d\n",
			__func__, ret);
	}

#ifdef VIRTIO_DEMO
	if ((ret = daffy_get_version_cmd(dpa, &version))) {
		dev_err(dpa_device, "%s: get version failed %d\n",
			__func__, ret);
	} else {
		dev_warn(dpa_device, "%s: got version %u\n", __func__,
			 version);
	}

#endif

	return 0;

free_queue:
	daffy_free_fw_queue(dpa);

#ifndef VIRTIO_DEMO
unmap:
#endif
	iounmap(dpa->regs);

disable_device:
	pci_disable_device(pdev);
	devm_kfree(dev, dpa);

	return ret;
}

static void dpa_pci_remove(struct pci_dev *pdev)
{
	if (dpa) {
		// XXX other stuff
		daffy_free_fw_queue(dpa);
		// unmap regs
		iounmap(dpa->regs);
		pci_disable_device(pdev);
		// character device_destroy();
		devm_kfree(&pdev->dev, dpa);
	}
}

static struct pci_driver dpa_pci_driver = {
	.name = "dpa",
	.id_table = dpa_pci_table,
	.probe = dpa_pci_probe,
	.remove = dpa_pci_remove,
	/* .driver = { */
	/*	.pm = &dpa_dev_pm_ops, */
	/* }, */
};

/* Ioctl handlers */

static int dpa_kfd_ioctl_get_version(struct file *filep,
				     struct dpa_kfd_process *p, void *data)
{
	struct kfd_ioctl_get_version_args *args = data;

	args->major_version = KFD_IOCTL_MAJOR_VERSION;
	// this doesn't seem to actually effect behaviors of userspace so far
	// XXX check user code, for now just advertise minimal API support
	args->minor_version = 1;
	dev_warn(p->dev->dev, "%s: major %d minor %d\n", __func__,
		 args->major_version, args->minor_version);

	return 0;
}

static int dpa_kfd_ioctl_create_queue(struct file *filep, struct dpa_kfd_process *p, void *data)
{
	struct kfd_ioctl_create_queue_args *args = data;
	return daffy_create_queue_cmd(p->dev, p, args);
}

static int dpa_kfd_ioctl_destroy_queue(struct file *filep, struct dpa_kfd_process *p, void *data)
{
	return -ENOSYS;
}

static int dpa_kfd_ioctl_set_memory_policy(struct file *filep, struct dpa_kfd_process *p, void *data)
{
	/* we don't support any changes in coherency */
	dev_warn(p->dev->dev, "%s: doing nothing\n", __func__);
	return 0;
}

static int dpa_kfd_ioctl_get_clock_counters(struct file *filep, struct dpa_kfd_process *p, void *data)
{

	struct kfd_ioctl_get_clock_counters_args *ctr_args = data;

	dev_warn(p->dev->dev, "%s: gpu_id %d\n", __func__, ctr_args->gpu_id);

	/* XXX when we have a common clock with DPA use it here */
	ctr_args->gpu_clock_counter = 0;
	ctr_args->cpu_clock_counter = ktime_get_raw_ns();

	/* using ns, so freq is 1Ghz*/
	ctr_args->system_clock_freq = 1000000;
	return 0;
}

static int dpa_kfd_ioctl_get_process_apertures(struct file *filep, struct dpa_kfd_process *p,
					       void *data)
{
	struct kfd_ioctl_get_process_apertures_args *args = data;
	struct kfd_process_device_apertures *aperture = &args->process_apertures[0];

	dev_warn(dpa_device, "%s\n", __func__);

	aperture->gpu_id = DPA_GPU_ID;
	aperture->lds_base = 0;
	aperture->lds_limit = 0;
	// gpuvm is the main one
	aperture->gpuvm_base = 0;
	aperture->gpuvm_limit = DPA_GPUVM_ADDR_LIMIT; // allow everything up to 48 bits
	aperture->scratch_base = 0;
	aperture->scratch_limit = 0;
	args->num_of_nodes = 1;

	return 0;
}

static int dpa_kfd_ioctl_update_queue(struct file *filep, struct dpa_kfd_process *p,
				      void *data)
{
	return -ENOSYS;
}

static int dpa_kfd_ioctl_create_event(struct file *filep, struct dpa_kfd_process *p,
				      void *data)
{
	return -ENOSYS;
}

static int dpa_kfd_ioctl_destroy_event(struct file *filep, struct dpa_kfd_process *p,
				      void *data)
{
	return -ENOSYS;
}

static int dpa_kfd_ioctl_set_event(struct file *filep, struct dpa_kfd_process *p,
				      void *data)
{
	return -ENOSYS;
}

static int dpa_kfd_ioctl_reset_event(struct file *filep, struct dpa_kfd_process *p,
				      void *data)
{
	return -ENOSYS;
}

static int dpa_kfd_ioctl_wait_events(struct file *filep, struct dpa_kfd_process *p,
				      void *data)
{
	return -ENOSYS;
}

static int dpa_kfd_ioctl_not_implemented(struct file *filep, struct dpa_kfd_process *p,
					 void *data)
{
	return -ENOSYS;
}


static int dpa_kfd_ioctl_get_process_apertures_new(struct file *filep,
						   struct dpa_kfd_process *p,
						   void *data)
{
	struct kfd_ioctl_get_process_apertures_new_args *args = data;
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
	ap.gpuvm_limit = DPA_GPUVM_ADDR_LIMIT;
	ret = copy_to_user((void __user*)args->kfd_process_device_apertures_ptr,
			   &ap, sizeof(ap));
	return ret;
}

static int dpa_kfd_ioctl_acquire_vm(struct file *filep,
				    struct dpa_kfd_process *p, void *data)
{
	dev_warn(dpa_device, "%s: doing nothing\n", __func__);
	// we do the PASID allocation in the open call
	return 0;
}


static struct dpa_kfd_buffer *dpa_alloc_vram(struct dpa_kfd_process *p,
					     u64 size, u32 flags)
{
	struct device *dev = p->dev->dev;
	struct dpa_kfd_buffer *buf;

	buf = devm_kzalloc(dev, sizeof(*buf),  GFP_KERNEL);
	if (!buf)
		return NULL;

	buf->type = flags;
	buf->size = size;
	// XXX need to alloc from reserved HBM region not system memory
	buf->page = dma_alloc_pages(dev, size, &buf->dma_addr, DMA_BIDIRECTIONAL,
				    GFP_KERNEL);

	if (!buf->page) {
		dev_warn(dev, "%s: unable to alloc size 0x%llx\n", __func__, size);
		devm_kfree(dev, buf);
		return NULL;
	}
	buf->buf = page_to_virt(buf->page);

	return buf;
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

static int dpa_kfd_ioctl_alloc_memory_of_gpu(struct file *filep,
				    struct dpa_kfd_process *p, void *data)
{
	struct kfd_ioctl_alloc_memory_of_gpu_args *args = data;
	struct device *dev = p->dev->dev;
	struct dpa_kfd_buffer *buf;

	dev_warn(dev, "%s: flags 0x%x size 0x%llx\n", __func__,
		 args->flags, args->size);

	if (args->gpu_id != DPA_GPU_ID)
		return -ENODEV;

	if (args->flags & KFD_IOC_ALLOC_MEM_FLAGS_VRAM) {
		buf = dpa_alloc_vram(p, args->size, args->flags);
		// XXX HACK if we don't have iommu wtih svm pass the address back via
		// mmap
		args->mmap_offset = ((u64)DPA_GPU_ID << 48ULL) | buf->dma_addr;
	} else if (args->flags & KFD_IOC_ALLOC_MEM_FLAGS_USERPTR) {

		// for now just support one page
		if (args->size > PAGE_SIZE)
			return -ENOTSUPP;

		buf = devm_kzalloc(dev, sizeof(*buf), GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		buf->type = args->flags;
		buf->size = args->size;
		mmap_read_lock(current->mm);
		if (get_user_pages(args->va_addr, 1, 0, &buf->page, NULL) != 1) {
			mmap_read_unlock(current->mm);
			dev_warn(dev, "%s: get_user_pages() failed\n", __func__);
			devm_kfree(dev, buf);
			return -ENOMEM;
		}
		mmap_read_unlock(current->mm);

		buf->buf = page_to_virt(buf->page);
		buf->dma_addr = dma_map_single(dev, buf->buf, PAGE_SIZE, DMA_BIDIRECTIONAL);
		if (buf->dma_addr == DMA_MAPPING_ERROR) {
			dev_warn(dev, "%s: dma_map_single failed\n", __func__);
			devm_kfree(dev, buf);
			return -ENOMEM;
		}
	}

	mutex_lock(&p->dev->lock);
	// XXX use an IDR/IDA for this
	buf->p = p;
	buf->id = ++p->alloc_count;
	list_add_tail(&buf->process_alloc_list, &p->buffers);
	mutex_unlock(&p->dev->lock);

	// use a macro for this
	args->handle = (u64)DPA_GPU_ID << 32 | buf->id;

	return 0;
}

static int dpa_kfd_ioctl_map_memory_to_gpu(struct file *filep,
				    struct dpa_kfd_process *p, void *data)
{
	struct kfd_ioctl_map_memory_to_gpu_args *args = data;

	// XXX loop over gpu id verify ID passed in matches
	// XXX check gpu id
	struct dpa_kfd_buffer *buf = find_buffer(p, args->handle & 0xFFFFFFFF);
	dev_warn(p->dev->dev, "%s: handle 0x%llx buf 0x%llx\n",
		 __func__, args->handle, (u64)buf);
	if (buf) {
		// XXX do mapping here?
		if (buf->dma_addr)
			args->n_success = 1;
	}

	return 0;
}

static int dpa_kfd_ioctl_unmap_memory_from_gpu(struct file *filep,
					       struct dpa_kfd_process *p,
					       void *data)
{
	struct kfd_ioctl_unmap_memory_from_gpu_args *args = data;

	// XXX loop over gpu id verify ID passed in matches
	struct dpa_kfd_buffer *buf = find_buffer(p, args->handle);
	dev_warn(p->dev->dev, "%s: handle 0x%llx buf 0x%llx\n",
		 __func__, args->handle, (u64)buf);
	if (buf) {
		// XXX unmap it
		args->n_success = 1;
	}

	return 0;
}

static void dpa_kfd_free_buffer(struct dpa_kfd_buffer *buf)
{
	struct device *dev = buf->p->dev->dev;
	dev_warn(dev, "%s: freeing buf id %u\n",
		 __func__, buf->id);
	if (buf->dma_addr)
		dma_unmap_single(dev, buf->dma_addr, buf->size, DMA_BIDIRECTIONAL);
	if (buf->page)
		put_page(buf->page);
	devm_kfree(dev, buf);

}

static int dpa_kfd_ioctl_free_memory_of_gpu(struct file *filep,
					    struct dpa_kfd_process *p,
					    void *data)
{
	struct kfd_ioctl_free_memory_of_gpu_args *args = data;
	struct dpa_kfd_buffer *buf = find_buffer(p, args->handle);
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

	KFD_IOCTL_DEF(AMDKFD_IOC_CREATE_EVENT,
			dpa_kfd_ioctl_create_event, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_DESTROY_EVENT,
			dpa_kfd_ioctl_destroy_event, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_SET_EVENT,
			dpa_kfd_ioctl_set_event, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_RESET_EVENT,
			dpa_kfd_ioctl_reset_event, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_WAIT_EVENTS,
			dpa_kfd_ioctl_wait_events, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_DBG_REGISTER_DEPRECATED,
			dpa_kfd_ioctl_not_implemented, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_DBG_UNREGISTER_DEPRECATED,
			 dpa_kfd_ioctl_not_implemented, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_DBG_ADDRESS_WATCH_DEPRECATED,
			 dpa_kfd_ioctl_not_implemented, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_DBG_WAVE_CONTROL_DEPRECATED,
			 dpa_kfd_ioctl_not_implemented, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_SET_SCRATCH_BACKING_VA,
			 dpa_kfd_ioctl_not_implemented, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_GET_TILE_CONFIG,
			 dpa_kfd_ioctl_not_implemented, 0),

	KFD_IOCTL_DEF(AMDKFD_IOC_SET_TRAP_HANDLER,
			 dpa_kfd_ioctl_not_implemented, 0),

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
	void *kdata;
	struct dpa_kfd_process *process = filep->private_data;
	char stack_kdata[128];

//	if (nr >= AMDKFD_CORE_IOCTL_COUNT)
//		return ret;

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

// hack, single process for now
static struct dpa_kfd_process *dpa_app;

static int dpa_kfd_open(struct inode *inode, struct file *filep)
{
	// look for process in some structure
	// XXX for now just have a single opening process
	if (dpa_app)
		return -EBUSY;

	dpa_app = devm_kzalloc(dpa_device, sizeof(*dpa_app), GFP_KERNEL);
	if (!dpa_app)
		return -ENOMEM;

	dev_warn(dpa_device, "%s: associated with pid %d\n", __func__, current->tgid);
	dpa_app->mm = current->mm;
	mmget(dpa_app->mm);
	mutex_init(&dpa_app->lock);
	INIT_LIST_HEAD(&dpa_app->buffers);

	// only one DPA for now
	dpa_app->dev = dpa;

	// XXX alloc pasid

	filep->private_data = dpa_app;

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

static int dpa_kfd_release(struct inode *inode, struct file *filep)
{
	struct dpa_kfd_process *p = filep->private_data;
	if (p) {
		dev_warn(p->dev->dev, "%s: freeing process %d\n", __func__,
			 current->tgid);
		dpa_kfd_release_process_buffers(p);
		mmput(p->mm);
		// XXX single process hack, clear the singleton
		if (p == dpa_app)
			dpa_app = NULL;
		devm_kfree(dpa_device, p);
	}

	return 0;
}

static int dpa_kfd_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return 0;
}

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

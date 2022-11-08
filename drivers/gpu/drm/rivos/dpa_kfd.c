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
#include <linux/iommu.h>
#include <linux/pci.h>
#include <linux/sched/mm.h>
#include <uapi/linux/kfd_ioctl.h>
#include "dpa_kfd.h"

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

/* PCI Stuff */

#ifndef PCI_VENDOR_ID_RIVOS
#define PCI_VENDOR_ID_RIVOS             0x1efd
#endif

#ifndef PCI_DEVICE_ID_TDC
#define PCI_DEVICE_ID_RIVOS_DPA       0x8003
#endif

static const struct pci_device_id dpa_pci_table[] = {
	{ PCI_VENDOR_ID_RIVOS, PCI_DEVICE_ID_RIVOS_DPA,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, dpa_pci_table);

void setup_queue(struct dpa_device *dpa) {
	dev_warn(dpa->dev, "DMA address of queue is: %llx\n", dpa->qinfo.fw_queue_dma_addr);
	writeq(dpa->qinfo.fw_queue_dma_addr, dpa->regs + DUC_PCI_QUEUE_INFO_ADDRESS);
	writeq(0x1000, dpa->regs + DUC_PCI_QUEUE_INFO_SIZE);
}

static int dpa_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int ret = 0;
	struct device *dev = &pdev->dev;
	int err;
	u16 vendor, device;
	u32 version;

	dev_warn(dev, "%s: start\n", __func__);
	dpa = devm_kzalloc(dev, sizeof(*dpa_device), GFP_KERNEL);
	if (!dpa)
		return -ENOMEM;
	dpa->dev = dev;
	dev_set_drvdata(dev, dpa);


	pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor);
	pci_read_config_word(pdev, PCI_DEVICE_ID, &device);
	pci_write_config_byte(pdev, PCI_COMMAND, PCI_COMMAND_IO |
			      PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
	printk(KERN_INFO "Device vid: 0x%X pid: 0x%X\n", vendor, device);


	if ((ret = pci_enable_device_mem(pdev)))
		goto disable_device;

	if ((ret = pci_request_mem_regions(pdev, kfd_dev_name)))
		goto disable_device;

	// Enable PASID support
	if (iommu_dev_enable_feature(dpa->dev, IOMMU_DEV_FEAT_SVA)) {
		dev_warn(dpa->dev, "%s: Unable to turn on SVA feature\n", __func__);
		goto disable_device;
	} else {
		dev_warn(dpa->dev, "%s: SVA feature enabled successfully\n", __func__);
	}

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
	// write the queue parameters to the shared area
	setup_queue(dpa);

	/* XXX need DRM init */
	dpa->drm_minor = 128;
	// LIST_HEAD_INIT(&dpa->buffers);

	if ((ret = dpa_kfd_chardev_init()))
		goto free_queue;

	if ((ret = dpa_kfd_sysfs_init())) {
		dev_err(dpa_device, "%s: Error creating sysfs nodes: %d\n",
			__func__, ret);
	}

	writeb(0x4, dpa->regs);
	if ((ret = daffy_get_version_cmd(dpa, &version))) {
		dev_err(dpa_device, "%s: get version failed %d\n",
			__func__, ret);
	} else {
		dev_warn(dpa_device, "%s: got version %u\n", __func__,
			 version);
	}



	return 0;

free_queue:
	daffy_free_fw_queue(dpa);

unmap:
	iounmap(dpa->regs);

disable_device:
	dev_warn(dpa->dev, "%s: Disabling device\n", __func__);
	pci_disable_device(pdev);
	devm_kfree(dev, dpa);

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

static int dpa_kfd_ioctl_create_queue(struct file *filep, struct dpa_kfd_process *p, void *data)
{
	struct kfd_ioctl_create_queue_args *args = data;
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

static int dpa_kfd_ioctl_destroy_queue(struct file *filep, struct dpa_kfd_process *p, void *data)
{
	struct kfd_ioctl_destroy_queue_args *args = data;
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
	ctr_args->gpu_clock_counter = ktime_get_raw_ns();
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
	aperture->gpuvm_base = PAGE_SIZE;  // don't allow NULL ptrs
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

/* appropriate locks should already be taken for idr, event page */
static struct dpa_kfd_event *dpa_kfd_alloc_event(struct dpa_kfd_process *p,
						 int type,
						 uint64_t *event_page_offset,
						 uint32_t *event_slot_index)
{
	struct dpa_kfd_event *ev = devm_kzalloc(p->dev->dev,
						sizeof(struct dpa_kfd_event),
						GFP_KERNEL);
	if (ev) {
		unsigned max = INT_MAX;
		bool is_signal = (type == KFD_EVENT_TYPE_SIGNAL ||
				  type == KFD_EVENT_TYPE_DEBUG);
		if (is_signal)
			max = DPA_MAX_SIGNAL_EVENTS;

		ev->id = idr_alloc(&p->event_idr, ev, 0, max,
				   GFP_KERNEL);
		if (ev->id < 0) {
			dev_warn(p->dev->dev, "Unable to alloc event id\n");
			devm_kfree(p->dev->dev, ev);
			return NULL;
		}
		if (is_signal) {
			*event_page_offset = KFD_MMAP_TYPE_EVENTS <<
				KFD_MMAP_TYPE_SHIFT;
			*event_slot_index = ev->id;
		}
		spin_lock_init(&ev->lock);
		init_waitqueue_head(&ev->wq);
		INIT_LIST_HEAD(&ev->events);

		list_add(&ev->events, &p->event_list);
	}
	return ev;
}

static int dpa_kfd_process_alloc_event_page(struct dpa_kfd_process *p)
{
	if (!p->event_page) {
		p->event_page = devm_kzalloc(p->dev->dev, PAGE_SIZE,
					     GFP_KERNEL);
		memset(p->event_page, -1, PAGE_SIZE);
		/* XXX need to do daffy register event page or similar */

	}
	return !!p->event_page;
}

static int dpa_kfd_ioctl_create_event(struct file *filep,
				      struct dpa_kfd_process *p,
				      void *data)
{
	struct kfd_ioctl_create_event_args *args = data;
	struct dpa_kfd_event *ev;

	dev_warn(p->dev->dev, "%s: type %u event_page_offset 0x%llx\n", __func__,
		 args->event_type, args->event_page_offset);

	/* if args->event_page_offset is set, userspace is trying to supply a page */
	if (args->event_page_offset) {
		dev_warn(p->dev->dev, "%s: unexpected event_page_offset\n", __func__);
		return -EINVAL;
	}

	mutex_lock(&p->lock);
	if (!p->event_page) {
		if (!dpa_kfd_process_alloc_event_page(p)) {
			mutex_unlock(&p->lock);
			return -ENOMEM;
		}
	}
	ev = dpa_kfd_alloc_event(p, args->event_type, &args->event_page_offset,
		&args->event_slot_index);
	if (!ev) {
		mutex_unlock(&p->lock);
		return -ENOMEM;
	}
	args->event_id = ev->id;
	/* XXX trigger data needs to be set? */
	mutex_unlock(&p->lock);

	dev_warn(p->dev->dev, "%s: created event id %u\n", __func__, args->event_id);

	return 0;
}

static void dpa_kfd_destroy_event(struct dpa_kfd_process *p, struct dpa_kfd_event *ev)
{
	spin_lock(&ev->lock);
	// XXX,  list_for_each_entry() null out waiter event?
	wake_up_all(&ev->wq);
	spin_unlock(&ev->lock);

	list_del(&ev->events);
	idr_remove(&p->event_idr, ev->id);
	devm_kfree(p->dev->dev, ev);
}

static int dpa_kfd_ioctl_destroy_event(struct file *filep, struct dpa_kfd_process *p,
				      void *data)
{
	struct kfd_ioctl_destroy_event_args *args = data;
	struct dpa_kfd_event *ev;
	int ret = -EINVAL;

	dev_warn(p->dev->dev, "%s: destroy id %u\n", __func__, args->event_id);

	mutex_lock(&p->lock);
	ev = idr_find(&p->event_idr, args->event_id);
	if (ev) {
		dpa_kfd_destroy_event(p, ev);
		ret = 0;
	}
	mutex_unlock(&p->lock);
	return ret;
}

static void dpa_kfd_release_process_events(struct dpa_kfd_process *p)
{
	struct list_head *cur, *tmp;
	list_for_each_safe(cur, tmp, &p->event_list) {
		dpa_kfd_destroy_event(p, container_of(cur, struct dpa_kfd_event, events));
	}
}

static void dpa_set_event(struct dpa_kfd_event *ev)
{
	struct dpa_kfd_event_waiter *waiter;

	/* Auto reset if the list is non-empty and we're waking
	 * someone. waitqueue_active is safe here because we're
	 * protected by the p->event_mutex, which is also held when
	 * updating the wait queues in kfd_wait_on_events.
	 */
	ev->signaled = !ev->auto_reset || !waitqueue_active(&ev->wq);

	list_for_each_entry(waiter, &ev->wq.head, wait.entry)
		waiter->activated = true;

	wake_up_all(&ev->wq);
}

static int dpa_kfd_ioctl_set_event(struct file *filep, struct dpa_kfd_process *p,
				      void *data)
{
	struct kfd_ioctl_set_event_args *args = data;
	struct dpa_kfd_event *ev;
	int ret = 0;

	mutex_lock(&p->lock);

	ev = idr_find(&p->event_idr, args->event_id);

	if (ev && (ev->type == KFD_EVENT_TYPE_SIGNAL))
		dpa_set_event(ev);
	else
		ret = -EINVAL;

	mutex_unlock(&p->lock);
	dev_warn(p->dev->dev, "%s: id %u ret %d\n", __func__, args->event_id,
		ret);

	return ret;
}

static int dpa_kfd_ioctl_reset_event(struct file *filep, struct dpa_kfd_process *p,
				      void *data)
{
	struct kfd_ioctl_reset_event_args *args = data;
	struct dpa_kfd_event *ev;
	int ret = 0;


	mutex_lock(&p->lock);

	ev = idr_find(&p->event_idr, args->event_id);

	if (ev && (ev->type == KFD_EVENT_TYPE_SIGNAL))
		ev->signaled = false;
	else
		ret = -EINVAL;

	mutex_unlock(&p->lock);
	dev_warn(p->dev->dev, "%s: id %u ret %d\n", __func__, args->event_id,
		 ret);

	return ret;
}

static struct dpa_kfd_event_waiter *alloc_event_waiters(uint32_t num_events)
{
	struct dpa_kfd_event_waiter *event_waiters;
	uint32_t i;

	event_waiters = kmalloc_array(num_events,
					sizeof(struct dpa_kfd_event_waiter),
					GFP_KERNEL);
	if (!event_waiters)
		return NULL;

	for (i = 0; (event_waiters) && (i < num_events) ; i++) {
		init_wait(&event_waiters[i].wait);
		event_waiters[i].activated = false;
	}

	return event_waiters;
}

static void free_waiters(uint32_t num_events,
			 struct dpa_kfd_event_waiter *waiters)
{
	uint32_t i;

	for (i = 0; i < num_events; i++)
		if (waiters[i].event)
			remove_wait_queue(&waiters[i].event->wq,
					  &waiters[i].wait);

	kfree(waiters);
}

/* event lock held */
static int init_event_waiter_get_status(struct dpa_kfd_process *p,
		struct dpa_kfd_event_waiter *waiter,
		uint32_t event_id)
{
	struct dpa_kfd_event *ev;

	ev = idr_find(&p->event_idr, event_id);

	if (!ev)
		return -EINVAL;

	waiter->event = ev;
	waiter->activated = ev->signaled;
	ev->signaled = ev->signaled && !ev->auto_reset;

	return 0;
}

static void init_event_waiter_add_to_waitlist(struct dpa_kfd_event_waiter *waiter)
{
	struct dpa_kfd_event *ev = waiter->event;

	/* Only add to the wait list if we actually need to
	 * wait on this event.
	 */
	if (!waiter->activated)
		add_wait_queue(&ev->wq, &waiter->wait);
}

/* test_event_condition - Test condition of events being waited for
 * @all:           Return completion only if all events have signaled
 * @num_events:    Number of events to wait for
 * @event_waiters: Array of event waiters, one per event
 *
 * Returns KFD_IOC_WAIT_RESULT_COMPLETE if all (or one) event(s) have
 * signaled. Returns KFD_IOC_WAIT_RESULT_TIMEOUT if no (or not all)
 * events have signaled. Returns KFD_IOC_WAIT_RESULT_FAIL if any of
 * the events have been destroyed.
 */
static uint32_t test_event_condition(bool all, uint32_t num_events,
				struct dpa_kfd_event_waiter *event_waiters)
{
	uint32_t i;
	uint32_t activated_count = 0;

	for (i = 0; i < num_events; i++) {
		if (!event_waiters[i].event)
			return KFD_IOC_WAIT_RESULT_FAIL;

		if (event_waiters[i].activated) {
			if (!all)
				return KFD_IOC_WAIT_RESULT_COMPLETE;

			activated_count++;
		}
	}

	return activated_count == num_events ?
		KFD_IOC_WAIT_RESULT_COMPLETE : KFD_IOC_WAIT_RESULT_TIMEOUT;
}

static long user_timeout_to_jiffies(uint32_t user_timeout_ms)
{
	if (user_timeout_ms == KFD_EVENT_TIMEOUT_IMMEDIATE)
		return 0;

	if (user_timeout_ms == KFD_EVENT_TIMEOUT_INFINITE)
		return MAX_SCHEDULE_TIMEOUT;

	/*
	 * msecs_to_jiffies interprets all values above 2^31-1 as infinite,
	 * but we consider them finite.
	 * This hack is wrong, but nobody is likely to notice.
	 */
	user_timeout_ms = min_t(uint32_t, user_timeout_ms, 0x7FFFFFFF);

	return msecs_to_jiffies(user_timeout_ms) + 1;
}

static int dpa_kfd_ioctl_wait_events(struct file *filep,
				     struct dpa_kfd_process *p, void *data)
{
	struct kfd_ioctl_wait_events_args *args = data;
	struct dpa_kfd_event_waiter *waiters;
	struct kfd_event_data __user *events =
			(struct kfd_event_data __user *) args->events_ptr;
	u32 num_events = args->num_events;
	uint32_t *wait_result = &args->wait_result;
	bool wait_all = (args->wait_for_all != 0);
	long timeout = user_timeout_to_jiffies(args->timeout);
	int ret = 0;
	int i;


	/* dev_warn(p->dev->dev, "%s: %u events wait_all %d timeout %lu\n", __func__, */
	/* 	 num_events, wait_all, timeout); */

	waiters = alloc_event_waiters(num_events);
	if (!waiters)
		return -ENOMEM;

	mutex_lock(&p->lock);
	for (i = 0; i < num_events; i++) {
		struct kfd_event_data event_data;

		if (copy_from_user(&event_data, &events[i],
				sizeof(struct kfd_event_data))) {
			ret = -EFAULT;
			goto out_unlock;
		}

		ret = init_event_waiter_get_status(p, &waiters[i],
				event_data.event_id);
		if (ret)
			goto out_unlock;
	}
	*wait_result = test_event_condition(wait_all, num_events, waiters);
	if (*wait_result == KFD_IOC_WAIT_RESULT_COMPLETE) {
		// no event data yet
		//ret = copy_signaled_event_data(num_events, waiters,
		//events);
		goto out_unlock;
	} else if (*wait_result == KFD_IOC_WAIT_RESULT_FAIL) {
		dev_err(p->dev->dev, "%s: failure during test_event\n",
			__func__);
		ret = -EIO; /* ??? */
		goto out_unlock;
	}

	/* Add to wait lists if we need to wait. */
	for (i = 0; i < num_events; i++)
		init_event_waiter_add_to_waitlist(&waiters[i]);

	mutex_unlock(&p->lock);
	while (true) {
		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		if (signal_pending(current)) {
			/*
			 * This is wrong when a nonzero, non-infinite timeout
			 * is specified. We need to use
			 * ERESTARTSYS_RESTARTBLOCK, but struct restart_block
			 * contains a union with data for each user and it's
			 * in generic kernel code that I don't want to
			 * touch yet.
			 */
			ret = -ERESTARTSYS;
			break;
		}

		/* Set task state to interruptible sleep before
		 * checking wake-up conditions. A concurrent wake-up
		 * will put the task back into runnable state. In that
		 * case schedule_timeout will not put the task to
		 * sleep and we'll get a chance to re-check the
		 * updated conditions almost immediately. Otherwise,
		 * this race condition would lead to a soft hang or a
		 * very long sleep.
		 */
		set_current_state(TASK_INTERRUPTIBLE);

		*wait_result = test_event_condition(wait_all, num_events,
						    waiters);
		if (*wait_result != KFD_IOC_WAIT_RESULT_TIMEOUT)
			break;

		if (timeout <= 0)
			break;

		timeout = schedule_timeout(timeout);
	}
	__set_current_state(TASK_RUNNING);

	/* copy_signaled_event_data may sleep. So this has to happen
	 * after the task state is set back to RUNNING.
	 */
	//if (!ret && *wait_result == KFD_IOC_WAIT_RESULT_COMPLETE)
	// no event data yet
	//ret = copy_signaled_event_data(num_events,
	//			       waiters, events);
	goto out;

out_unlock:
	mutex_unlock(&p->lock);

out:
	free_waiters(num_events, waiters);

	/* dev_warn(p->dev->dev, "%s: ret = %d result = %d\n", __func__, ret, */
	/* 	*wait_result); */

	return ret;
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
	ap.gpuvm_base = PAGE_SIZE;
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
	unsigned i;

	buf = devm_kzalloc(dev, sizeof(*buf),  GFP_KERNEL);
	if (!buf)
		return NULL;

	buf->type = flags;
	buf->size = size;
	buf->page_count = buf->size >> PAGE_SHIFT;
	buf->pages = devm_kzalloc(dev, sizeof(struct page*) * buf->page_count, GFP_KERNEL);
	if (!buf->pages) {
		dev_warn(dev, "%s: cannot alloc pages\n", __func__);
		devm_kfree(dev, buf);
		return NULL;
	}
	if (alloc_pages_bulk_array(GFP_KERNEL, buf->page_count, buf->pages) <
	    buf->page_count)
		goto out_free;
	return buf;

out_free:
	for (i = 0; i < buf->page_count; i++) {
		if (buf->pages[i]) {
			__free_pages(buf->pages[i], 0);
		}
	}
	devm_kfree(dev, buf);
	return NULL;
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
		if (!buf)
			return -ENOMEM;
	} else if (args->flags & KFD_IOC_ALLOC_MEM_FLAGS_USERPTR) {
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

		mmap_read_lock(current->mm);
		if (get_user_pages(args->va_addr, buf->page_count, 0, buf->pages, NULL) != buf->page_count) {
			mmap_read_unlock(current->mm);
			dev_warn(dev, "%s: get_user_pages() failed\n", __func__);
			devm_kfree(dev, buf->pages);
			devm_kfree(dev, buf);
			return -ENOMEM;
		}
		mmap_read_unlock(current->mm);
	} else {
		dev_warn(dev, "%s: unsupported memory alloction type 0x%x\n",
			 __func__, args->flags);
		return -EINVAL;
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
	dev_warn(p->dev->dev, "%s: buf id %u handle 0x%llx\n", __func__,
		 buf->id, args->handle);

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
		//if (buf->dma_addr)
		args->n_success = 1;
	} else {
		dev_warn(p->dev->dev, "%s: given buffer not found!\n", __func__);
		return -EINVAL;
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

	if (buf->type & KFD_IOC_ALLOC_MEM_FLAGS_VRAM)  {
		if (buf->page_count) {
			int i;
			for (i = 0; i < buf->page_count; i++) {
				__free_pages(buf->pages[i], 0);
			}
		}
	}

	if (buf->type & KFD_IOC_ALLOC_MEM_FLAGS_USERPTR) {
		if (buf->page_count) {
			int i;
			for (i = 0; i < buf->page_count; i++) {
				put_page(buf->pages[i]);
			}
			devm_kfree(dev, buf->pages);
		}

	}
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

static struct list_head dpa_processes;
static struct mutex dpa_processes_lock;
static unsigned int dpa_process_count;

static int dpa_kfd_open(struct inode *inode, struct file *filep)
{
	struct dpa_kfd_process *dpa_app = NULL;
	struct list_head *cur;


	// big lock for this
	mutex_lock(&dpa_processes_lock);
	// look for process in a list
	list_for_each(cur, &dpa_processes) {
		struct dpa_kfd_process *cur_process =
			container_of(cur, struct dpa_kfd_process,
				     dpa_process_list);
		if (cur_process->mm == current->mm) {
			dpa_app = cur_process;
			break;
		}
	}

	if (dpa_app) {
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
	mmget(dpa_app->mm);
	mutex_init(&dpa_app->lock);
	INIT_LIST_HEAD(&dpa_app->buffers);
	idr_init(&dpa_app->event_idr);
	INIT_LIST_HEAD(&dpa_app->event_list);
	INIT_LIST_HEAD(&dpa_app->queue_list);

	// only one DPA for now
	dpa_app->dev = dpa;

	// Bind device and allocate PASID
	struct device *dpa_dev = dpa_app->dev->dev;
	dpa_app->sva = iommu_sva_bind_device(dpa_dev, dpa_app->mm, NULL);
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

	filep->private_data = dpa_app;
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

static int dpa_kfd_release(struct inode *inode, struct file *filep)
{
	struct dpa_kfd_process *p = filep->private_data;
	if (p) {
		mutex_lock(&dpa_processes_lock);
		dev_warn(p->dev->dev, "%s: freeing process %d\n", __func__,
			 current->tgid);
		// XXX mutex lock on process lock ?
		dpa_kfd_release_process_buffers(p);
		mmput(p->mm);
		dpa_kfd_release_process_events(p);
		idr_destroy(&p->event_idr);
		if (p->event_page)
			devm_kfree(p->dev->dev, p->event_page);
		if (p->fake_doorbell_page)
			devm_kfree(p->dev->dev, p->fake_doorbell_page);
		dpa_del_all_queues(p);
		list_del(&p->dpa_process_list);
		dpa_process_count--;
		devm_kfree(dpa_device, p);
		mutex_unlock(&dpa_processes_lock);
	}

	return 0;
}

static int dpa_kfd_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct dpa_kfd_process *p = filep->private_data;
	unsigned long mmap_offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned int gpu_id = KFD_MMAP_GET_GPU_ID(mmap_offset);
	u64 type = mmap_offset >> KFD_MMAP_TYPE_SHIFT;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long pfn;
	int ret = -EFAULT;

	dev_warn(p->dev->dev, "%s: offset 0x%lx size 0x%lx gpu 0x%x type %llu start 0x%llx\n",
		 __func__, mmap_offset, size, gpu_id, type, (u64)vma->vm_start);
	switch (type) {
	case KFD_MMAP_TYPE_EVENTS:
		if (size != DPA_MAX_EVENT_PAGE_SIZE) {
			dev_warn(p->dev->dev, "%s: invalid size for event \n",
				 __func__);
			return -EINVAL;
		}

		mutex_lock(&p->lock);
		if (!p->event_page) {
			if (!dpa_kfd_process_alloc_event_page(p)) {
				mutex_unlock(&p->lock);
				return -ENOMEM;
			}
		}
		mutex_unlock(&p->lock);

		pfn = __pa(p->event_page);
		pfn >>= PAGE_SHIFT;

		pr_debug("Mapping signal page\n");
		pr_debug("     start user address  == 0x%08lx\n", vma->vm_start);
		pr_debug("     end user address    == 0x%08lx\n", vma->vm_end);
		pr_debug("     pfn                 == 0x%016lX\n", pfn);
		pr_debug("     vm_flags            == 0x%08lX\n", vma->vm_flags);
		pr_debug("     size                == 0x%08lX\n",
			vma->vm_end - vma->vm_start);

		/* XXX why does amd keep the user address? */
//		page->user_address = (uint64_t __user *)vma->vm_start;

		/* mapping the page to user process */
		ret = remap_pfn_range(vma, vma->vm_start, pfn,
				      vma->vm_end - vma->vm_start, vma->vm_page_prot);
		if (ret) {
			dev_warn(p->dev->dev, "%s: failed to map event page 0x%llx"
				 " ret %d\n",
				 __func__, (u64)p->event_page, ret);
		}
		break;
	case KFD_MMAP_TYPE_DOORBELL:
		// XXX hack for now until real doorbell mmio is implemented
		// allocate a regular page and put it there, device will be
		// polling on the queues until real doorbells are implemented
		mutex_lock(&p->lock);
		if (!p->fake_doorbell_page) {
			p->fake_doorbell_page = devm_kzalloc(p->dev->dev, size,
							     GFP_KERNEL);
			if (!p->fake_doorbell_page) {
				dev_warn(p->dev->dev, "%s: failed to alloc fake"
					 " db page\n", __func__);
				ret = -ENOMEM;
				mutex_unlock(&p->lock);
				goto out;
			}
		}
		mutex_unlock(&p->lock);

		pfn = __pa(p->fake_doorbell_page);
		pfn >>= PAGE_SHIFT;

		ret = remap_pfn_range(vma, vma->vm_start, pfn,
				      vma->vm_end - vma->vm_start, vma->vm_page_prot);
		if (ret) {
			dev_warn(p->dev->dev, "%s: failed to map doorbell page"
				 "ret %d\n",
				 __func__, ret);
		}
		break;
	default:
		dev_warn(p->dev->dev, "%s: doing nothing\n", __func__);
	}
out:
	return ret;
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

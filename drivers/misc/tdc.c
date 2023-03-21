#include <linux/io.h>
#include <linux/cdev.h>
#include <linux/dma-mapping.h>
#include <linux/hashtable.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <uapi/linux/virtio_ids.h>
#include <linux/virtio_pci_modern.h>


#ifndef PCI_VENDOR_ID_RIVOS
#define PCI_VENDOR_ID_RIVOS             0x1efd
#endif

#ifndef PCI_DEVICE_ID_TDC
#define PCI_DEVICE_ID_RIVOS_TDC       0x8002
#endif

#define TDC_DEVICE_NAME "tdc"
#define TDC_REGS_MIN_SIZE 0x0300 //TODO: need to change
#define DRV_NAME "tdc"

//TODO: register formatting
#define TDC_REG_SRC 0x0000
#define TDC_REG_DST 0x0008
#define TDC_REG_SZ  0x000F
#define TDC_REG_CTRL  0x0018
#define TDC_REG_STATUS 0x0100

#define TDC_CTRL_DMA (1 << 0)



#define TDC_STATUS_DMAD (1 << 0)


#define TDC_DMA_F 0x1


#define TDC_DMA 0x1
#define TDC_CHECK_CACHE 0x2
#define TDC_FLUSH_CACHE 0x3
#define TDC_UNMAP_ENTRY 0X4 //TODO: refactor into enum

static const struct pci_device_id tdc_pci_tbl[] = {
	{PCI_VENDOR_ID_REDHAT_QUMRANET, 0x1040 + VIRTIO_ID_TDC,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{ 0, }
};

struct tdc_dev {
    struct device *dev;
    struct pci_dev *pdev;
    struct cdev cdev;
    struct virtio_pci_common_cfg __iomem *common;
    void __iomem *device;
	/* Base of vq notifications (non-legacy mode). */
	void __iomem *notify_base;
    unsigned char __iomem *regs;
    int modern_bars;
};

static struct tdc_dev* tdev;
//TODO

struct ioctl_dma_command {
	void* src;
	void* dst;
	uint64_t size;
};

struct ioctl_check_cache_command {
	void* addr;
	int* res;
};

struct ioctl_unmap_command {
	void* addr;
	void* size;
};

struct tdc_hashtable_entry {
	uint64_t va;
	uint64_t iova;
	struct hlist_node ht_link;
};
static struct class *tdc_class;

static struct kmem_cache *tdc_hashtable_entry_cache;

#define TDC_HASHTABLE_BITS 4
static DEFINE_HASHTABLE(va_map, TDC_HASHTABLE_BITS); //TODO: this should be per process

static int tdc_file_open(struct inode *inode, struct file *file) {
	return 0;
}

static struct tdc_hashtable_entry* get_cached_entry(uint64_t va) {
	struct tdc_hashtable_entry* entry;
	hash_for_each_possible(va_map, entry, ht_link, va) {
		if(entry->va==va){
			printk(KERN_INFO "Hash entry found for va %llx -> %llx\n", va, entry->iova);
			return entry;
		}
	}
	return NULL;
}

static uint64_t get_iova_cached_or_create(struct device* dev, uint64_t va, struct page* page,
					  enum dma_data_direction dir, int create)
{
	struct tdc_hashtable_entry* entry = get_cached_entry(va);
	if(entry != NULL) {
		return entry->iova;
	}

	printk("Could not find entry for va %llx\n", va);
	if(create) {
		entry = kmem_cache_alloc(tdc_hashtable_entry_cache, GFP_KERNEL);
		if(!entry){
			printk(KERN_INFO "Error: could not allocate hash table entry\n");
			return -1;
		}
		entry->va = va;
		entry->iova = dma_map_page(dev, page, 0, PAGE_SIZE, dir);
		printk(KERN_INFO "Creaed new hash entry: va %llx -> iova %llx\n", entry->va, entry->iova);
		hash_add(va_map, &entry->ht_link, va);
		return entry->iova;
	}
	else {
		return -1; //TODO: handle this better
	}


}

static long tdc_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
	struct ioctl_dma_command ioctl_dma_cmd;
	uint32_t status;
	uint64_t npages;
	struct page *src_pages, *dst_pages;
	int src_res, dst_res;
	uint64_t n, src_va, dst_va, va;

	switch(cmd) {
	case TDC_DMA_F: {
		printk(KERN_INFO "IOCTL TDC_DMA_F\n");
		if (copy_from_user(&ioctl_dma_cmd ,(struct ioctl_dma_cmd*) arg, sizeof(ioctl_dma_cmd))) {
			pr_err("Error in copying structure\n")       ;
		}
		printk(KERN_INFO "ioctl_dma_cmd, src: %p, dst: %p, size: %lld\n", ioctl_dma_cmd.src, ioctl_dma_cmd.dst, ioctl_dma_cmd.size);
		status = readl(tdev->regs + TDC_REG_STATUS);
		npages = 1; //TODO: change to actual sioze
		down_read(&current->mm->mmap_lock);
		src_res = get_user_pages((uint64_t) ioctl_dma_cmd.src, npages, 0, &src_pages, NULL);
		dst_res = get_user_pages((uint64_t) ioctl_dma_cmd.dst, npages, FOLL_WRITE, &dst_pages, NULL);
		up_read(&current->mm->mmap_lock);
		if (src_res < 0) {
			pr_err("Error in getting src user pages\n");
		}
		if (dst_res < 0) {
			pr_err("Error in getting dst user pages\n");
			//TODO: cleanup pages
		}

		//TODO: use scatter gather list
		for (n = 0; n < npages; n++) {
			src_va = get_iova_cached_or_create(tdev->dev, (uint64_t)ioctl_dma_cmd.src + n * PAGE_SIZE, src_pages+n, DMA_TO_DEVICE, 1);
			dst_va = get_iova_cached_or_create(tdev->dev, (uint64_t)ioctl_dma_cmd.dst + n * PAGE_SIZE, dst_pages+n, DMA_FROM_DEVICE, 1);

			printk(KERN_INFO "src_va is: %llx, dst_va is: %llx\n", src_va, dst_va);
			writeq(src_va, tdev->regs + TDC_REG_SRC);
			writeq(dst_va, tdev->regs + TDC_REG_DST);
			writeq(PAGE_SIZE, tdev->regs + TDC_REG_SZ);
			writel(status & ~TDC_STATUS_DMAD, tdev->regs + TDC_REG_STATUS);
			writel(TDC_CTRL_DMA, tdev->regs + TDC_REG_CTRL);
			while(!(readl(tdev->regs + TDC_REG_STATUS) & TDC_STATUS_DMAD)); //TODO: busy looping, use waitqueue
		}

		break;
	}

	case TDC_CHECK_CACHE: {
		//To check whether present in the cache
	}

	case TDC_UNMAP_ENTRY: {
		//Remove from hashmap
		struct ioctl_unmap_command ioctl_unmap_cmd;
		uint64_t npages = 1; //TODO: actually handle npages
		if(copy_from_user(&ioctl_unmap_cmd ,(struct ioctl_dma_cmd*) arg, sizeof(ioctl_unmap_cmd))) {
			pr_err("Error in copying structure\n")       ;
		}


		for(n = 0; n < npages; n++) {
			struct tdc_hashtable_entry* entry;
			va = (uint64_t) ioctl_unmap_cmd.addr + n * PAGE_SIZE;
			entry = get_cached_entry(va);
			if (entry==NULL){
				pr_err("No va->iova mapping in request to unmap\n");
			} else {
				dma_unmap_page(tdev->dev, entry->iova, PAGE_SIZE, DMA_BIDIRECTIONAL); //TODO: better thing than bidirectoinal?
				hash_del(&entry->ht_link);
			}

			//TODO: need to unpin pages
		}

	}

	case TDC_FLUSH_CACHE: {
		//flush the cache
	}
	}
	return 0;
}

static struct file_operations tdc_file_ops =
{
	.open = tdc_file_open,
	.unlocked_ioctl = tdc_ioctl

};


MODULE_DEVICE_TABLE(pci, tdc_pci_table);


static void tdc_setup_virtqueue(struct tdc_dev *tdev, dma_addr_t desc, dma_addr_t used, dma_addr_t avail)
{

    vp_iowrite16(0, &tdev->common->queue_select);
    vp_iowrite16(0x1000, &tdev->common->queue_size);
    vp_iowrite16(0xabcd, &tdev->common->queue_msix_vector);
    vp_iowrite16(0xbcde, &tdev->common->queue_notify_off);
    
    vp_iowrite64_twopart(desc, &tdev->common->queue_desc_lo, &tdev->common->queue_desc_hi);
    vp_iowrite64_twopart(used, &tdev->common->queue_used_lo, &tdev->common->queue_used_hi);
    vp_iowrite64_twopart(avail, &tdev->common->queue_avail_lo, &tdev->common->queue_avail_hi);
    printk("%s: desc 0x%llx used 0x%llx avail 0x%llx\n", __func__,
	   desc, used, avail);
    vp_iowrite16(1, &tdev->common->queue_enable);
}

/* Mostly a copy of vp_modern_map_capability within virtio_pci_modern_dev.c, couldn't use it directly because it expects a virtio_pci_modern_device*/
static void __iomem *
vp_modern_map_capability(struct tdc_dev *tdev, int off,
			 size_t minlen, u32 align, u32 start, u32 size,
			 size_t *len, resource_size_t *pa)
{
	
	struct pci_dev* dev  = tdev->pdev;
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
	if (bar >= PCI_STD_NUM_BARS || !(tdev->modern_bars & (1 << bar))) {
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

static int tdc_probe(struct pci_dev *pdev, const struct pci_device_id *id) {
	int err, common;
	u16 vendor, device;
	dev_t dev_num;
	struct device* dev = &pdev->dev;
	void *qaddr;
	dma_addr_t qdma_addr;

	pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor);
	pci_read_config_word(pdev, PCI_DEVICE_ID, &device);
	pci_write_config_byte(pdev, PCI_COMMAND, PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
	printk(KERN_INFO "Device vid: 0x%X pid: 0x%X\n", vendor, device);

	tdev = devm_kzalloc(dev, sizeof(*tdev), GFP_KERNEL);
	if(!tdev)
		return -ENOMEM;
	tdev->dev = dev;
	dev_set_drvdata(dev, tdev);
	common = virtio_pci_find_capability(pdev, VIRTIO_PCI_CAP_COMMON_CFG,
					    IORESOURCE_IO | IORESOURCE_MEM,
					    &tdev->modern_bars);
	if (!common) {
		devm_kfree(dev, tdev);
		printk("Capability common not found\n");
		return -ENODEV;
	}

	err = pci_request_selected_regions(pdev, tdev->modern_bars,
					   "virtio-pci-modern");
	if (err)
		return err;
	
	err = -EINVAL;
	tdev->pdev = pdev;
	tdev->common = vp_modern_map_capability(tdev, common,
						sizeof(struct virtio_pci_common_cfg), 4,
						0, sizeof(struct virtio_pci_common_cfg),
						NULL, NULL);
	
	if (!tdev->common)
		printk("Couldn't map capability\n");

	qaddr = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!qaddr) {
		dev_warn(dev, "cannot alloc qaddr\n");
		devm_kfree(dev, tdev);
		return -ENOMEM;
					      
	}
	snprintf(qaddr, PAGE_SIZE, "Hello from Sentinel!\n");
	qdma_addr = dma_map_single(dev, qaddr, PAGE_SIZE, DMA_BIDIRECTIONAL);
	if (qdma_addr == DMA_MAPPING_ERROR) {
		dev_warn(dev, "cannot map qaddr\n");
		kfree(qaddr);
		devm_kfree(dev, tdev);
		return -ENOMEM;
	}
	
	tdc_setup_virtqueue(tdev, qdma_addr, qdma_addr, qdma_addr);
	vp_iowrite8(0xF, &tdev->common->device_status); //Setting status


	err = pci_enable_device_mem(pdev);
	if (err) goto disable_device_and_fail;

	/* if (pci_request_mem_regions(pdev, DRV_NAME)) */
	/* 	goto disable_device_and_fail; */
	/* tdev->regs = pci_iomap(pdev, 0, TDC_REGS_MIN_SIZE); */

	/* if (err) goto free_resources_and_fail; */

	pci_set_drvdata(pdev, tdev);
	err = alloc_chrdev_region(&dev_num, 0, 1, TDC_DEVICE_NAME);
	if(err) goto disable_device_and_fail;
	dev = device_create(tdc_class, &pdev->dev, MKDEV(MAJOR(dev_num), 0), NULL, TDC_DEVICE_NAME);
	if(IS_ERR(dev)) goto disable_device_and_fail;
	cdev_init(&tdev->cdev, &tdc_file_ops);
	tdev->cdev.owner = THIS_MODULE;
	err = cdev_add(&tdev->cdev, MKDEV(MAJOR(dev_num), 0), 1);
	if(err) goto free_resources_and_fail; //TODO: free all resources correctly on error



	return 0;

disable_device_and_fail:
	pci_disable_device(pdev);
	return err;

free_resources_and_fail:
	pci_disable_device(pdev);
	devm_kfree(dev, tdev);
	return err;
}

static void tdc_pci_remove(struct pci_dev *pdev) {

}


static int __maybe_unused tdc_suspend(struct device *device)
{
	/* TODO: impl */
	return 0;
}

static int __maybe_unused tdc_resume(struct device *device)
{
	/* TODO: impl */
	return 0;
}



static SIMPLE_DEV_PM_OPS(tdc_dev_pm_ops, tdc_suspend, tdc_resume);
static struct pci_driver tdc_pci_driver = {
	.name     = TDC_DEVICE_NAME,
	.id_table = tdc_pci_tbl,
	.probe    = tdc_probe,
	.remove   = tdc_pci_remove,

	.driver	= {
		.pm = &tdc_dev_pm_ops,
	},
};


static int __init tdc_init(void) {
	tdc_class = class_create(THIS_MODULE, TDC_DEVICE_NAME);
	if(IS_ERR(tdc_class)){
		int err = PTR_ERR(tdc_class);
		pr_err("Error in creating class: %d\n", err);
		return err;
	}
	tdc_hashtable_entry_cache = kmem_cache_create("tdc_hashtable_entry_cache", sizeof(struct tdc_hashtable_entry), 0, SLAB_PANIC, NULL);
	return pci_register_driver(&tdc_pci_driver);
}
static void __exit tdc_exit(void) {
	pci_unregister_driver(&tdc_pci_driver);
}
MODULE_LICENSE("GPL");
module_init(tdc_init);
module_exit(tdc_exit);

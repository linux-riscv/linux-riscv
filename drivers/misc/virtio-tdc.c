#include <linux/cdev.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/hashtable.h>
#include <linux/mm.h>
#include <linux/pci.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>

#define VIRTIO_TDC_DEVICE_NAME "virtio-tdc"

#define TDC_DMA_F 0x1
#define TDC_UNMAP_ENTRY 0X4 //TODO: refactor into enum

struct virttdc_info {
	struct cdev cdev;
	struct device* dev;
	struct completion dma_completion; //TODO: better option than this
	struct virtqueue *vq;
	int index;
	int data_avail;
};
struct virttdc_info *vi = NULL; //Figure out a way to not have this global variable

static struct kmem_cache *tdc_hashtable_entry_cache;
static struct class *tdc_class;

#define TDC_HASHTABLE_BITS 4
static DEFINE_HASHTABLE(va_map, TDC_HASHTABLE_BITS); //TODO: this should be per process
static DEFINE_IDA(tdc_index_ida);

static const struct virtio_device_id id_table[] = {
	// { VIRTIO_ID_TDC, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

struct tdc_hashtable_entry {
	uint64_t va;
	uint64_t iova;
	struct hlist_node ht_link;
};

struct ioctl_dma_command {
	uint64_t src;
	uint64_t dst;
	uint64_t size;
} __attribute__((packed));

struct ioctl_unmap_command {
    void* addr;
    void* size;
}__attribute__((packed));



static void dma_done(struct virtqueue *vq){
	printk("DMA Done\n");

	/* We can get spurious callbacks, e.g. shared IRQs + virtio_pci. */
	if (!virtqueue_get_buf(vi->vq, &vi->data_avail)){
		printk("spurious kick\n");
		return;
	}

	complete(&vi->dma_completion);
}

static void send_dma_request(struct virttdc_info* vi, struct ioctl_dma_command* cmd)
{
	struct scatterlist sg;
	int err, res;

	//Addr should be IOVA
	reinit_completion(&vi->dma_completion);
	printk("cmd is: %p\n", cmd);
	printk("size of *cmd is: %ld\n", sizeof(*cmd));
	sg_init_one(&sg, cmd, sizeof(*cmd));
	err = virtqueue_add_outbuf(vi->vq, &sg, 1, cmd, GFP_KERNEL); //TODO: wha'ts the use of data  here
	if(err < 0){
		printk("virtqueue_add_outbuf failed: %d\n", err);
	}
	res = virtqueue_kick(vi->vq);
	printk("res of kick is: %d\n", res);
	wait_for_completion_killable(&vi->dma_completion);
}

static int tdc_file_open(struct inode *inode, struct file *file)
{
	return 0;
}


static struct tdc_hashtable_entry* get_cached_entry(uint64_t va)
{
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
    printk("get_iova_cached_or_create called with device: %lx, va: %lx, page: %lx\n", dev, va, page);
    struct tdc_hashtable_entry* entry = get_cached_entry(va);
    // return page_to_phys(page); //TEMPORARY
    if(entry != NULL) {
        return entry->iova;
    }

    printk("Could not find entry for va %lx\n", va);
    if(create) {
        entry = kmem_cache_alloc(tdc_hashtable_entry_cache, GFP_KERNEL);
        if(!entry){
            printk(KERN_INFO "Error: could not allocate hash table entry\n");
            return -1;
        }
        entry->va = va;
        printk("Page physical address is: %lx\n", page_to_phys(page));
        entry->iova = dma_map_page(dev, page, 0, PAGE_SIZE, dir);
        printk(KERN_INFO "Creaed new hash entry: va %lx -> iova %lx\n", entry->va, entry->iova);
        hash_add(va_map, &entry->ht_link, va);
        return entry->iova;
    }
    else {
        return -1; //TODO: handle this better
    }
}

static long tdc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case TDC_DMA_F: {
		struct ioctl_dma_command ioctl_dma_cmd;
		uint64_t n, npages = 1; //TODO: change to actual sioze
		struct page **src_pages, **dst_pages;
		int src_res, dst_res;

		printk(KERN_INFO "IOCTL TDC_DMA_F\n");

		if (copy_from_user(&ioctl_dma_cmd ,(struct ioctl_dma_cmd*) arg, sizeof(ioctl_dma_cmd))) {
			pr_err("Error in copying structure\n")       ;
		}
		printk(KERN_INFO "ioctl_dma_cmd, src: %llx, dst: %llx, size: %lld\n", ioctl_dma_cmd.src, ioctl_dma_cmd.dst, ioctl_dma_cmd.size);

		src_pages = kmalloc_array(npages, sizeof(struct page*), GFP_KERNEL);
		if (!src_pages) {
			return -ENOMEM;
		}
		dst_pages = kmalloc_array(npages, sizeof(struct page*), GFP_KERNEL);
		if (!dst_pages) {
			kfree(src_pages);
			return -ENOMEM;
		}
		down_read(&current->mm->mmap_lock);
		src_res = get_user_pages((uint64_t) ioctl_dma_cmd.src, npages, 0, src_pages, NULL);
		dst_res = get_user_pages((uint64_t) ioctl_dma_cmd.dst, npages, FOLL_WRITE, dst_pages, NULL);
		up_read(&current->mm->mmap_lock);
		if(src_res < 0){
			pr_err("Error in getting src user pages\n");
		}
		if(dst_res < 0){
			pr_err("Error in getting dst user pages\n");
			//TODO: cleanup pages
		}

		//TODO: use scatter gather list
		for (n = 0; n < npages; n++) {
			struct ioctl_dma_command* d_cmd = kmalloc(sizeof(*d_cmd), GFP_KERNEL);
			uint64_t src_va = get_iova_cached_or_create(vi->dev, ioctl_dma_cmd.src + n * PAGE_SIZE,
								    src_pages[n], DMA_BIDIRECTIONAL, 1);
			uint64_t dst_va = get_iova_cached_or_create(vi->dev, ioctl_dma_cmd.dst + n * PAGE_SIZE,
								    dst_pages[n], DMA_BIDIRECTIONAL, 1);

			printk(KERN_INFO "src_va is: %llx, dst_va is: %llx\n", src_va, dst_va);

			d_cmd->src = src_va;
			d_cmd->dst = dst_va;
			d_cmd->size = PAGE_SIZE; //TODO: fix
			send_dma_request(vi, d_cmd);
			kfree(d_cmd);
			//Make DMA request
			//Wait for result somehow
		}
		break;
	}
	case TDC_UNMAP_ENTRY: {
		//Remove from hashmap 
		struct ioctl_unmap_command ioctl_unmap_cmd;
		if(copy_from_user(&ioctl_unmap_cmd ,(struct ioctl_dma_cmd*) arg, sizeof(ioctl_unmap_cmd))) {
			pr_err("Error in copying structure\n")       ;
		}
		uint64_t npages = 1; //TODO: actually handle npages 
		
		
		for(uint64_t n = 0; n < npages; n++){
			uint64_t va = (uint64_t) ioctl_unmap_cmd.addr + n * PAGE_SIZE;
			struct tdc_hashtable_entry* entry = get_cached_entry(va);
			if(entry==NULL){
				pr_err("No va->iova mapping in request to unmap\n");
			}
			else{
				uint64_t iova = entry->iova;
				dma_unmap_page(vi->dev, iova, PAGE_SIZE, DMA_BIDIRECTIONAL); //TODO: better thing than bidirectoinal?
				hash_del(&entry->ht_link);
			}
			
			//TODO: need to unpin pages
		}
        }
		break;
		
	}

	return 0;
}

static struct file_operations tdc_file_ops =
{
	.open = tdc_file_open,
	.unlocked_ioctl = tdc_ioctl

};

static int virttdc_probe(struct virtio_device *vdev)
{
	// printk("virttdc probe: vdev dev is_pci result: %d\n", dev_is_pci(vdev->dev.parent));
	int err, index;
	dev_t dev_num;
	struct device *chr_dev;

	tdc_class = class_create(THIS_MODULE, VIRTIO_TDC_DEVICE_NAME);
	if(IS_ERR(tdc_class)) {
		int err = PTR_ERR(tdc_class);
		pr_err("Error in creating class: %d\n", err);
		return err;
	}
	tdc_hashtable_entry_cache = kmem_cache_create("tdc_hashtable_entry_cache", sizeof(struct tdc_hashtable_entry), 0, SLAB_PANIC, NULL);

	vi = kzalloc(sizeof(struct virttdc_info), GFP_KERNEL);
	if(!vi){
		return -ENOMEM;
	}
	vi->index = ida_simple_get(&tdc_index_ida, 0, 0, GFP_KERNEL);
	vi->vq = virtio_find_single_vq(vdev, dma_done, "output");
	vi->dev = vdev->dev.parent;
	vdev->priv = vi;
	if (IS_ERR(vi->vq)) {
		printk("Error in finding vq\n");
		err = PTR_ERR(vi->vq);
		printk("Error is: %d\n", err);
		goto err_find;
	}
	err = alloc_chrdev_region(&dev_num, 0, 1, VIRTIO_TDC_DEVICE_NAME);
	if(err) goto err_find;
	chr_dev = device_create(tdc_class, &vdev->dev, MKDEV(MAJOR(dev_num), 0), NULL, VIRTIO_TDC_DEVICE_NAME);
	if(IS_ERR(chr_dev)) goto err_chrdev;
	cdev_init(&vi->cdev, &tdc_file_ops);
	vi->cdev.owner = THIS_MODULE;
	err = cdev_add(&vi->cdev, MKDEV(MAJOR(dev_num), 0), 1);
	if(err) goto err_chrdev;
	init_completion(&vi->dma_completion);
	virtio_device_ready(vdev);
	// send_dma_request(vi, PAGE_ALIGN((uint64_t)vi), 4096);
	return 0;

 err_chrdev:
	//deallocate region

 err_find:
	ida_simple_remove(&tdc_index_ida, index);
//err_ida:
	kfree(vi);
	return err;
}

static void virttdc_remove(struct virtio_device *vdev) {
	struct virttdc_info *vi = vdev->priv;
	virtio_reset_device(vdev);
	vdev->config->del_vqs(vdev);
	ida_simple_remove(&tdc_index_ida, vi->index);
	kfree(vi);
}

static void virttdc_scan(struct virtio_device *vdev)
{

}

static struct virtio_driver virtio_tdc_driver = {
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.probe = virttdc_probe,
	.remove = virttdc_remove,
	.scan = virttdc_scan
};
module_virtio_driver(virtio_tdc_driver);
MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio test device cache driver");
MODULE_LICENSE("GPL");

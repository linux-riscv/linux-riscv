
#include <asm-generic/int-ll64.h>
#include <linux/cdev.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/pci_regs.h>
#include <linux/of_device.h>

#include "dce.h"

static dev_t dev_num;

uint64_t dce_reg_read(struct dce_driver_priv *priv, int reg) {
	uint64_t result = ioread64((void __iomem *)(priv->mmio_start + reg));
	printk(KERN_INFO "Read 0x%llx from address 0x%llx\n", result, priv->mmio_start + reg);
	return result;
}

void dce_reg_write(struct dce_driver_priv *priv, int reg, uint64_t value) {
	printk(KERN_INFO "Writing 0x%llx to address 0x%llx\n", value, priv->mmio_start + reg);
	iowrite64(value, (void __iomem *)(priv->mmio_start + reg));
}

int dce_ops_open(struct inode *inode, struct file *file)
{
	file->private_data = container_of(inode->i_cdev, struct dce_driver_priv, cdev);
	struct dce_driver_priv *priv = file->private_data;
	/* Assign a WQ to the file descriptor */
	/* FIXME: lock , better assignemnt algo, error if full */
	mutex_lock(&priv->lock);
	for(int slot = 0; slot < NUM_WQ; slot++) {
		if (priv->wq_assignment[slot] == 0) {
			priv->wq_assignment[slot] = file;
			printk(KERN_INFO "Assigning file handle 0x%lx to slot %u\n", file, slot);
			break;
		}
	}
	mutex_unlock(&priv->lock);
	return 0;
}

int dce_ops_release(struct inode *inode, struct file *file)
{
	struct dce_driver_priv *priv = file->private_data;
	/* FIXME: do we need lock here? */
	mutex_lock(&priv->lock);
	for(int slot = 0; slot < NUM_WQ; slot++) {
		if (priv->wq_assignment[slot] == file) {
			priv->wq_assignment[slot] = 0;
			printk(KERN_INFO "Unassigning file handle 0x%lx from slot %u\n", file, slot);
			break;
		}
	}
	mutex_unlock(&priv->lock);
	printk(KERN_INFO "Closing file 0x%lx\n", file);
	return 0;
}

ssize_t dce_ops_write(struct file *fp, const char __user *buf, size_t count, loff_t *ppos)
{
	return 0;
}

ssize_t dce_ops_read(struct file *fp, char __user *buf, size_t count, loff_t *ppos)
{
	return 0;
}

static void dce_push_descriptor(struct dce_driver_priv *priv, DCEDescriptor* descriptor, int wq_num)
{
	uint64_t tail_idx = priv->hti[wq_num]->tail;
	uint64_t base = priv->descriptor_ring[wq_num].descriptors;
	uint64_t tail_ptr = base + ((tail_idx % NUM_DSC_PER_WQ) * sizeof(DCEDescriptor));

	// TODO: handle the case where ring will be full
	// TODO: something here with error handling
	memcpy(tail_ptr, descriptor, sizeof(DCEDescriptor));
	/* increment tail index */
	priv->hti[wq_num]->tail++;
	/* notify DCE */
	uint64_t WQCR_REG = ((wq_num + 1) * PAGE_SIZE) + DCE_REG_WQCR;
	dce_reg_write(priv, WQCR_REG, 1);
	// TODO: release semantics here
}

static dma_addr_t copy_to_kernel_and_setup_dma(struct dce_driver_priv *drv_priv, void ** kern_ptr,
						uint8_t __user * user_ptr, size_t size, uint8_t dma_direction)
{
	*kern_ptr = kzalloc(size, GFP_KERNEL);
	if (copy_from_user(*kern_ptr, user_ptr, size))
		return -EFAULT;
	return dma_map_single(&drv_priv->dev, *kern_ptr, size, dma_direction);
}

static uint64_t setup_dma_for_user_buffer(struct dce_driver_priv *drv_priv, int index, bool * result_is_list,
                                          uint8_t __user * user_ptr, size_t size, uint8_t dma_direction, int wq_num) {
	int i, count;
	int first, last, nr_pages;
	struct scatterlist * sg;
	struct scatterlist * sglist;

	first = ((uint64_t)user_ptr & PAGE_MASK) >> PAGE_SHIFT;
	last  = (((uint64_t)user_ptr + size - 1) & PAGE_MASK) >> PAGE_SHIFT;
	nr_pages = last - first + 1;
	struct page * pages[nr_pages];

	int flag = (dma_direction == DMA_FROM_DEVICE) ? FOLL_WRITE : 0;

	printk(KERN_INFO"User address is 0x%lx\n", user_ptr);
	int ret = get_user_pages_fast(user_ptr, nr_pages, flag, pages);
	printk(KERN_INFO"get_user_pages_fast return value is %d, nrpages is %d\n", ret, nr_pages);

	drv_priv->sg_tables[wq_num][index].sgl = kzalloc(nr_pages * sizeof(struct scatterlist), GFP_KERNEL);
	drv_priv->sg_tables[wq_num][index].orig_nents = nr_pages;

	sglist = drv_priv->sg_tables[wq_num][index].sgl;
	for (int i = 0; i < nr_pages; i++) {
		uint64_t _size, _offset = 0;
		if (i == 0) {
			/* first page */
			_size = offset_in_page(user_ptr) + size > PAGE_SIZE ?
								 (PAGE_SIZE - offset_in_page(user_ptr)) :
								 size;
			_offset = offset_in_page(user_ptr);
		} else if (i == nr_pages - 1) {
			/* last page */
			_size = offset_in_page(user_ptr + size);
		} else {
			/* middle pages */
			_size = PAGE_SIZE;
		}
		printk(KERN_INFO"parameters passed to sg_set_page: 0x%lx, 0x%lx, 0x%lx", pages[i], _size, _offset);
		sg_set_page(&sglist[i], pages[i], _size, _offset);
	}
	count = dma_map_sg(&drv_priv->dev, sglist, nr_pages, dma_direction);
	printk(KERN_INFO "Count is %d\n", count);
	if (count > 1)
		*result_is_list = true;

	drv_priv->sg_tables[wq_num][index].nents = count;
	drv_priv->hw_addr[wq_num][index] = kzalloc(count * sizeof(DataAddrNode), GFP_KERNEL);

	for_each_sg(sglist, sg, count, i) {
		drv_priv->hw_addr[wq_num][index][i].ptr = sg_dma_address(sg);
		drv_priv->hw_addr[wq_num][index][i].size = sg_dma_len(sg);
		printk(KERN_INFO "Address 0x%lx, Size 0x%lx\n", sg_dma_address(sg), sg_dma_len(sg));
	}

	// printk(KERN_INFO "num_dma_entries: %d, Address is 0x%lx\n", num_dma_entries, sg_dma_address(&sg[0]));
	if (count > 1) {
		return dma_map_single(&drv_priv->dev,
					drv_priv->hw_addr[wq_num][index],
					count, dma_direction);
	}
	else return (uint64_t)(drv_priv->hw_addr[wq_num][index][0].ptr);
}

void parse_descriptor_based_on_opcode(struct dce_driver_priv *drv_priv,
	struct DCEDescriptor * desc, struct DCEDescriptor * input, int wq_num)
{
	size_t size, dest_size;
	bool src_is_list = false;
	bool src2_is_list = false;
	bool dest_is_list = false;

	desc->opcode = input->opcode;
	desc->ctrl = input->ctrl;
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


	size = desc->operand1;
	dest_size = (desc->opcode == DCE_OPCODE_MEMCMP && !(desc->operand0 & 1)) ?
				8 : size;
	/* Override based on opcode */
	switch (desc->opcode)
	{
		case DCE_OPCODE_MEMCMP:
			/* src2 */
			desc->source = setup_dma_for_user_buffer(drv_priv, SRC,
				&src_is_list, (uint8_t __user *)input->source,
				size, DMA_TO_DEVICE, wq_num);
			desc->operand2 = setup_dma_for_user_buffer(drv_priv, SRC2,
				&src2_is_list, (uint8_t __user *)input->operand2,
				size, DMA_TO_DEVICE, wq_num);
			desc->destination = setup_dma_for_user_buffer(drv_priv, DEST,
				&dest_is_list, (uint8_t __user *)input->destination,
				dest_size, DMA_FROM_DEVICE, wq_num);
			break;
		case DCE_OPCODE_ENCRYPT:
		case DCE_OPCODE_DECRYPT:
		case DCE_OPCODE_MEMCPY:
			desc->source = setup_dma_for_user_buffer(drv_priv, SRC,
				&src_is_list, (uint8_t __user *)input->source,
				size, DMA_TO_DEVICE, wq_num);
			desc->destination = setup_dma_for_user_buffer(drv_priv, DEST,
				&dest_is_list, (uint8_t __user *)input->destination,
				size, DMA_FROM_DEVICE, wq_num);
			break;
		case DCE_OPCODE_MEMSET:
			desc->destination = setup_dma_for_user_buffer(drv_priv, DEST,
				&dest_is_list, (uint8_t __user *)input->destination,
				size, DMA_FROM_DEVICE, wq_num);
			break;
		case DCE_OPCODE_COMPRESS:
		case DCE_OPCODE_DECOMPRESS:
		case DCE_OPCODE_COMPRESS_ENCRYPT:
		case DCE_OPCODE_DECRYPT_DECOMPRESS:
			desc->source = setup_dma_for_user_buffer(drv_priv, SRC,
				&src_is_list, (uint8_t __user *)input->source,
				size, DMA_TO_DEVICE, wq_num);
			desc->destination = setup_dma_for_user_buffer(drv_priv, DEST,
				&dest_is_list, (uint8_t __user *)input->destination,
				desc->operand2, DMA_FROM_DEVICE, wq_num);
			break;
		case DCE_OPCODE_LOAD_KEY:
			/* Keys are 32B */
			desc->source = setup_dma_for_user_buffer(drv_priv, SRC,
				&src_is_list, (uint8_t __user *)input->source,
				32, DMA_TO_DEVICE, wq_num);
			break;
		default:
			break;
	}

	if (src_is_list)
		desc->ctrl |= SRC_IS_LIST;
	if (src2_is_list)
		desc->ctrl |= SRC2_IS_LIST;
	if (dest_is_list)
		desc->ctrl |= DEST_IS_LIST;

	desc->completion = setup_dma_for_user_buffer(drv_priv, COMP,
		&src_is_list, (uint8_t __user *)input->completion,
		8, DMA_FROM_DEVICE, wq_num);
}

void dce_reset_descriptor_ring(struct dce_driver_priv *drv_priv, int wq_num) {
	memset(&drv_priv->descriptor_ring[wq_num], 0, sizeof(DescriptorRing));
}

static void setup_memory_for_wq(struct dce_driver_priv * drv_priv, int wq_num)
{
	int DSCSZ = 0;
	/* Supervisor memory setup */
	/* per DCE spec: Actual ring size is computed by: 2^(DSCSZ + 12) */
	size_t length = 0x1000 * (1 << DSCSZ);
	dce_reset_descriptor_ring(drv_priv, wq_num);

	// Allcate the descriptors as coherent DMA memory
	drv_priv->descriptor_ring[wq_num].descriptors =
		dma_alloc_coherent(&drv_priv->dev, length * sizeof(DCEDescriptor),
			&drv_priv->descriptor_ring[wq_num].dma, GFP_KERNEL);

	drv_priv->descriptor_ring[wq_num].length = length;
	printk(KERN_INFO "Allocated wq %u descriptors at 0x%llx\n", wq_num,
		(uint64_t)drv_priv->descriptor_ring[wq_num].descriptors);


	drv_priv->hti[wq_num] = dma_alloc_coherent(&drv_priv->dev,
		sizeof(HeadTailIndex), &drv_priv->hti_dma[wq_num], GFP_KERNEL);
	drv_priv->hti[wq_num]->head = 0;
	drv_priv->hti[wq_num]->tail = 0;

	/* populate WQITE TODO: only first one for now*/
	drv_priv->WQIT[wq_num].DSCBA = drv_priv->descriptor_ring[wq_num].dma;
	drv_priv->WQIT[wq_num].DSCSZ = DSCSZ;
	drv_priv->WQIT[wq_num].DSCPTA = drv_priv->hti_dma[wq_num];

	/* set the enable bit in dce*/
	uint64_t wq_enable = dce_reg_read(drv_priv, DCE_REG_WQENABLE);
	wq_enable |= BIT(wq_num);
	dce_reg_write(drv_priv, DCE_REG_WQENABLE, wq_enable);

	/* mark the WQ as enabled in driver */
	drv_priv->wq_enabled[wq_num] = true;
}

static void free_resources(struct dce_driver_priv *priv, DCEDescriptor * input)
{
	return;
}

long dce_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	uint64_t val;
	struct DCEDescriptor descriptor;
	struct dce_driver_priv *priv = file->private_data;

	switch (cmd) {
		case RAW_READ: {
			struct AccessInfoRead __user *__access_info;
			struct AccessInfoRead access_info;

			__access_info = (struct AccessInfoRead __user*) arg;
			if (copy_from_user(&access_info, __access_info, sizeof(access_info)))
				return -EFAULT;

			val = ioread64((void __iomem *)(priv->mmio_start + access_info.offset));
			if (copy_to_user(access_info.value, &val, 8)) {
				printk(KERN_INFO "error during ioctl!\n");
			}

			break;
		}

		case RAW_WRITE: {
			struct AccessInfoWrite __user *__access_info;
			struct AccessInfoWrite access_info;

			__access_info = (struct AccessInfoWrite __user*) arg;
			if (copy_from_user(&access_info, __access_info, sizeof(access_info)))
				return -EFAULT;

			iowrite64(access_info.value, (void __iomem *)(priv->mmio_start + access_info.offset));

			break;
		}

		case SUBMIT_DESCRIPTOR: {
			struct DCEDescriptor __user *__descriptor_input;
			struct DCEDescriptor descriptor_input;

			__descriptor_input = (struct DCEDescriptor __user*) arg;
			if (copy_from_user(&descriptor_input, __descriptor_input, sizeof(descriptor_input)))
				return -EFAULT;

			/* figure out WQ number, should have been assigned in open() */
			bool wq_found = false;
			int wq_num = 0;
			for(wq_num = 0; wq_num < NUM_WQ; wq_num++) {
				if (priv->wq_assignment[wq_num] == file) {
					wq_found = true;
					break;
				}
			}
			/* error out if no WQ found */
			if (!wq_found) return -1;
			/* setup the memory for the WQ and enable it if not already */
			if (priv->wq_enabled[wq_num] == false) {
				setup_memory_for_wq(priv, wq_num);
			}

			parse_descriptor_based_on_opcode(priv, &descriptor, &descriptor_input, wq_num);
			printk(KERN_INFO "pushing descriptor thru ioctl with opcode %d!\n", descriptor.opcode);
			printk(KERN_INFO "submitting source 0x%lx\n", descriptor.source);
			dce_push_descriptor(priv, &descriptor, wq_num);

			// Free up resources when its done
			free_resources(priv, &descriptor_input);
		}
	}

	return 0;
}

static const struct file_operations dce_ops = {
	.owner		= THIS_MODULE,
	.open		= dce_ops_open,
	.release	= dce_ops_release,
	.read		= dce_ops_read,
	.write		= dce_ops_write,
	.unlocked_ioctl	= dce_ioctl
};

static struct class *dce_char_class;


static irqreturn_t handle_dce(int irq, void *dev_id) {
	printk(KERN_INFO "Got interrupt %d!\n", irq);
	return IRQ_HANDLED;
}


void setup_memory_regions(struct dce_driver_priv * drv_priv)
{
	struct device * dev = &drv_priv->dev;
	if (!dev->coherent_dma_mask)
		dev->coherent_dma_mask = 0xffffffff;
	of_dma_configure(dev, dev->of_node, true);

	int err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (err) printk(KERN_INFO "DMA set mask failed: %d\n", err);

	// printk(KERN_INFO"dma_mask: 0x%lx\n",dev->dma_mask);
	/* WQIT is 4KiB */
	drv_priv->WQIT = dma_alloc_coherent(dev, 0x1000,
								  &drv_priv->WQIT_dma, GFP_KERNEL);

	printk(KERN_INFO "Writing to DCE_REG_WQITBA!\n");
	dce_reg_write(drv_priv, DCE_REG_WQITBA,
				 (uint64_t) drv_priv->WQIT_dma);
}

static int dce_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int bar, err;

	printk(KERN_INFO " in %s\n", __func__);
	err = pci_enable_sriov(pdev, DCE_NR_VIRTFN);
	printk(KERN_INFO "return code %d\n", err);

	u16 vendor, device;
	// unsigned long mmio_start,mmio_len;
	struct dce_driver_priv *drv_priv;
	struct device* dev;
	struct cdev *cdev;

	pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor);
	pci_read_config_word(pdev, PCI_DEVICE_ID, &device);
	pci_write_config_byte(pdev, PCI_COMMAND, PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
	printk(KERN_INFO "Device vaid: 0x%X pid: 0x%X\n", vendor, device);

	err = pci_enable_device(pdev);
	if (err) goto disable_device_and_fail;

	bar = pci_select_bars(pdev, IORESOURCE_MEM);
	printk(KERN_INFO "io bar: 0x%X", bar);

	err = pci_request_selected_regions(pdev, bar, DEVICE_NAME);
	if (err) goto disable_device_and_fail;

	// mmio_start = pci_resource_start(pdev, 0);
	// mmio_len   = pci_resource_len  (pdev, 0);

	drv_priv = kzalloc_node(sizeof(struct dce_driver_priv), GFP_KERNEL,
			     dev_to_node(&pdev->dev));
	if (!drv_priv) goto disable_device_and_fail;

	drv_priv->pdev = pdev;
	dev = &drv_priv->dev;

	device_initialize(dev);
	dev->class = dce_char_class;
	dev->parent = &pdev->dev;

	dev->devt = MKDEV(MAJOR(dev_num), 0);
	dev_set_name(dev, "dce");
	cdev = &drv_priv->cdev;
	cdev_init(cdev, &dce_ops);
	cdev->owner = THIS_MODULE;

	drv_priv->mmio_start = (uint64_t)pci_iomap(pdev, 0, 0);

	pci_set_drvdata(pdev, drv_priv);

	/* priv mem regions setup */
	setup_memory_regions(drv_priv);

	err = cdev_device_add(&drv_priv->cdev, &drv_priv->dev);
	if (err) {
		printk(KERN_INFO "cdev add failed\n");
	}

	/* MSI setup */
	if (pci_match_id(pci_use_msi, pdev)) {
		pci_dbg(pdev, "Using MSI(-X) interrupts\n");
		pci_set_master(pdev);
		err = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_ALL_TYPES);

		int vec = pci_irq_vector(pdev, 0);
		devm_request_threaded_irq(dev, vec, handle_dce, NULL, IRQF_ONESHOT, DEVICE_NAME, pdev);
	} else {
		printk(KERN_INFO "DCE: MSI enable failed\n");
	}
	return 0;

	disable_device_and_fail:
		pci_disable_device(pdev);
		return err;

	free_resources_and_fail:
		pci_disable_device(pdev);
		// free_resources(dev, drv_priv);
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
	// free_resources(&pdev->dev, pci_get_drvdata(pdev));
}

static SIMPLE_DEV_PM_OPS(vmd_dev_pm_ops, vmd_suspend, vmd_resume);

static const struct pci_device_id dce_id_table[] = {
	{ PCI_DEVICE(VENDOR_ID, DEVICE_ID) } ,
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

static char *pci_char_devnode(struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, DEVICE_NAME);
}

static int __init dce_driver_init(void)
{
	int err;
	err = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
	if (err) return -err;

	dce_char_class = class_create(THIS_MODULE, DEVICE_NAME);
	if (IS_ERR(dce_char_class)) {
		err = PTR_ERR(dce_char_class);
		return err;
	}

	dce_char_class->devnode = pci_char_devnode;

	err = pci_register_driver(&dce_driver);
	return err;
}

static void __exit dce_driver_exit(void)
{
	pci_unregister_driver(&dce_driver);
}

MODULE_LICENSE("GPL");

module_init(dce_driver_init);
module_exit(dce_driver_exit);

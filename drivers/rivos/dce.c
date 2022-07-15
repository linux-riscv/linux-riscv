
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

#define DEVICE_NAME "dce"
#define VENDOR_ID 0x1FED
#define DEVICE_ID 0x0001

#define DCE_CTRL 0

#define DCE_STATUS 8

#define DCE_DESCRIPTOR_RING_CTRL_BASE  16
#define DCE_DESCRIPTOR_RING_CTRL_LIMIT 24
#define DCE_DESCRIPTOR_RING_CTRL_HEAD  32
#define DCE_DESCRIPTOR_RING_CTRL_TAIL  40

#define DCE_INTERRUPT_CONFIG_DESCRIPTOR_COMPLETION 48
#define DCE_INTERRUPT_CONFIG_TIMEOUT               56
#define DCE_INTERRUPT_CONFIG_ERROR_CONDITION       64
#define DCE_INTERRUPT_STATUS                       72
#define DCE_INTERRUPT_MASK                         80

#define DCE_OPCODE_CLFLUSH            0
#define DCE_OPCODE_MEMCPY             1
#define DCE_OPCODE_MEMSET             2
#define DCE_OPCODE_MEMCMP             3
#define DCE_OPCODE_COMPRESS           4
#define DCE_OPCODE_DECOMPRESS         5
#define DCE_OPCODE_LOAD_KEY           6
#define DCE_OPCODE_CLEAR_KEY          7
#define DCE_OPCODE_ENCRYPT            8
#define DCE_OPCODE_DECRYPT            9
#define DCE_OPCODE_DECRYPT_DECOMPRESS 10
#define DCE_OPCODE_COMPRESS_ENCRYPT   11

#define SRC_IS_LIST                 (1 << 1)
#define SRC2_IS_LIST                (1 << 2)
#define DEST_IS_LIST                (1 << 3)

typedef struct AccessInfoRead {
	uint64_t* value;
	uint64_t  offset;
} AccessInfoRead;

typedef struct AccessInfoWrite {
	uint64_t value;
	uint64_t offset;
} AccessInfoWrite;

typedef struct DataAddrNode {
       uint64_t ptr;
       uint64_t size;
} DataAddrNode;

typedef struct __attribute__((packed)) DCEDescriptor {
	uint8_t  opcode;
	uint8_t  ctrl;
	uint16_t operand0;
	uint32_t pasid;
	uint64_t source;
	uint64_t destination;
	uint64_t completion;
	uint64_t operand1;
	uint64_t operand2;
	uint64_t operand3;
	uint64_t operand4;
} __attribute__((packed)) DCEDescriptor;

typedef struct __attribute__((packed)) KernDCEDescriptor {
	uint8_t  opcode;
	uint8_t  ctrl;
	uint16_t operand0;
	uint32_t pasid;
	uint64_t source;
	uint64_t destination;
	uint64_t completion;
	uint64_t operand1;
	uint64_t operand2;
	uint64_t operand3;
	uint64_t operand4;
} __attribute__((packed)) KernDCEDescriptor;

typedef struct DescriptorRing {
	DCEDescriptor* descriptors;
	dma_addr_t dma;
	size_t length;
	int enabled;
} DescriptorRing;

#define RAW_READ          _IOR(0xAA, 0, struct AccessInfo*)
#define RAW_WRITE         _IOW(0xAA, 1, struct AccessInfo*)
#define SUBMIT_DESCRIPTOR _IOW(0xAA, 2, struct DescriptorInput*)

#define MIN(a, b) \
	({ __typeof__ (a) _a = (a); \
	   __typeof__ (b) _b = (b); \
	   _a < _b ? _a : _b; })

enum {
	DEST,
	SRC,
	SRC2,
	COMP,
	NUM_SG_TBLS
};

static const struct pci_device_id pci_use_msi[] = {

	{ PCI_DEVICE_SUB(VENDOR_ID, DEVICE_ID,
			 PCI_ANY_ID, PCI_ANY_ID) },
	{ }
};

struct dce_driver_priv
{
	struct device* dev;
	dev_t dev_num;
	struct cdev cdev;

	KernDCEDescriptor k_descriptor;

	u32* in;
	u32* out;
	u32* temp;

	uint64_t mmio_start;

	DescriptorRing descriptor_ring;
	struct sg_table sg_tables[NUM_SG_TBLS];
	DataAddrNode * hw_addr[NUM_SG_TBLS];
};

static uint64_t dce_reg_read(struct dce_driver_priv *priv, int reg) {
	uint64_t result = ioread64((void __iomem *)(priv->mmio_start + reg));
	printk(KERN_INFO "Read 0x%llx from address 0x%llx\n", result, priv->mmio_start + reg);
	return result;
}

static void dce_reg_write(struct dce_driver_priv *priv, int reg, uint64_t value) {
	printk(KERN_INFO "Writing 0x%llx to address 0x%llx\n", value, priv->mmio_start + reg);
	iowrite64(value, (void __iomem *)(priv->mmio_start + reg));
}

static int dce_ops_open(struct inode *inode, struct file *file)
{
	file->private_data = container_of(inode->i_cdev, struct dce_driver_priv, cdev);
	return 0;
}

static ssize_t dce_ops_write(struct file *fp, const char __user *buf, size_t count, loff_t *ppos)
{
	return 0;
}

static ssize_t dce_ops_read(struct file *fp, char __user *buf, size_t count, loff_t *ppos)
{
	return 0;
}

static void dce_push_descriptor(struct dce_driver_priv *priv, DCEDescriptor* descriptor)
{
	uint64_t tail = dce_reg_read(priv, DCE_DESCRIPTOR_RING_CTRL_TAIL);
	uint64_t base = dce_reg_read(priv, DCE_DESCRIPTOR_RING_CTRL_BASE);
	int tail_offset = (tail - base) / sizeof(DCEDescriptor);
	uint64_t next_offset = (tail_offset + 1) % priv->descriptor_ring.length;

	// TODO: handle the case where ring will be full
	// TODO: something here with error handling
	memcpy(priv->descriptor_ring.descriptors + tail_offset, descriptor, sizeof(DCEDescriptor));
	dce_reg_write(priv, DCE_DESCRIPTOR_RING_CTRL_TAIL, base + (next_offset * sizeof(DCEDescriptor)));
	// TODO: release semantics here
}

static dma_addr_t copy_to_kernel_and_setup_dma(struct dce_driver_priv *drv_priv, void ** kern_ptr,
						uint8_t __user * user_ptr, size_t size, uint8_t dma_direction)
{
	*kern_ptr = kzalloc(size, GFP_KERNEL);
	if (copy_from_user(*kern_ptr, user_ptr, size))
		return -EFAULT;
	return dma_map_single(drv_priv->dev, *kern_ptr, size, dma_direction);
}

static uint64_t setup_dma_for_user_buffer(struct dce_driver_priv *drv_priv, int index, bool * result_is_list,
                                          uint8_t __user * user_ptr, size_t size, uint8_t dma_direction) {
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

	drv_priv->sg_tables[index].sgl = kzalloc(nr_pages * sizeof(struct scatterlist), GFP_KERNEL);
	drv_priv->sg_tables[index].orig_nents = nr_pages;

	sglist = drv_priv->sg_tables[index].sgl;
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
	count = dma_map_sg(drv_priv->dev, sglist, nr_pages, dma_direction);
	printk(KERN_INFO "Count is %d\n", count);
	if (count > 1)
		*result_is_list = true;

	drv_priv->sg_tables[index].nents = count;
    drv_priv->hw_addr[index] = kzalloc(count * sizeof(DataAddrNode), GFP_KERNEL);

	for_each_sg(sglist, sg, count, i) {
		drv_priv->hw_addr[index][i].ptr = sg_dma_address(sg);
		drv_priv->hw_addr[index][i].size = sg_dma_len(sg);
		printk(KERN_INFO "Address 0x%lx, Size 0x%lx\n", sg_dma_address(sg), sg_dma_len(sg));
	}

	// printk(KERN_INFO "num_dma_entries: %d, Address is 0x%lx\n", num_dma_entries, sg_dma_address(&sg[0]));
	if (count > 1) {
		return dma_map_single(drv_priv->dev,
					drv_priv->hw_addr[index],
					count, dma_direction);
	}
	else return (uint64_t)(drv_priv->hw_addr[index][0].ptr);
}

void parse_descriptor_based_on_opcode(struct dce_driver_priv *drv_priv, struct DCEDescriptor * desc, struct DCEDescriptor * input)
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
			desc->source = setup_dma_for_user_buffer(drv_priv, SRC, &src_is_list, (uint8_t __user *)input->source,
														  size, DMA_TO_DEVICE);
			desc->operand2 = setup_dma_for_user_buffer(drv_priv, SRC2, &src2_is_list, (uint8_t __user *)input->operand2,
														  size, DMA_TO_DEVICE);
			desc->destination = setup_dma_for_user_buffer(drv_priv, DEST, &dest_is_list, (uint8_t __user *)input->destination,
														  dest_size, DMA_FROM_DEVICE);
			break;
		case DCE_OPCODE_ENCRYPT:
		case DCE_OPCODE_DECRYPT:
		case DCE_OPCODE_MEMCPY:
			desc->source = setup_dma_for_user_buffer(drv_priv, SRC, &src_is_list, (uint8_t __user *)input->source,
														size, DMA_TO_DEVICE);
			desc->destination = setup_dma_for_user_buffer(drv_priv, DEST, &dest_is_list, (uint8_t __user *)input->destination,
														size, DMA_FROM_DEVICE);
			break;
		case DCE_OPCODE_MEMSET:
			desc->destination = setup_dma_for_user_buffer(drv_priv, DEST, &dest_is_list, (uint8_t __user *)input->destination,
														  size, DMA_FROM_DEVICE);
			break;
		case DCE_OPCODE_COMPRESS:
		case DCE_OPCODE_DECOMPRESS:
		case DCE_OPCODE_COMPRESS_ENCRYPT:
		case DCE_OPCODE_DECRYPT_DECOMPRESS:
			desc->source = setup_dma_for_user_buffer(drv_priv, SRC, &src_is_list, (uint8_t __user *)input->source,
														size, DMA_TO_DEVICE);
			desc->destination = setup_dma_for_user_buffer(drv_priv, DEST, &dest_is_list, (uint8_t __user *)input->destination,
														desc->operand2, DMA_FROM_DEVICE);
			break;
		case DCE_OPCODE_LOAD_KEY:
			/* Keys are 32B */
			desc->source = setup_dma_for_user_buffer(drv_priv, SRC, &src_is_list, (uint8_t __user *)input->source,
														32, DMA_TO_DEVICE);
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

	desc->completion = setup_dma_for_user_buffer(drv_priv, COMP, &src_is_list, (uint8_t __user *)input->completion,
														8, DMA_FROM_DEVICE);
	// desc->completion = copy_to_kernel_and_setup_dma(drv_priv, (void **)&drv_priv->k_descriptor.completion,
	// 						(uint8_t __user *)input->completion, 8, DMA_FROM_DEVICE);
}

static void free_resources(struct dce_driver_priv *priv, DCEDescriptor * input)
{
	return;
	for(int i = 0; i < NUM_SG_TBLS; i++) {
		if (priv->sg_tables[i].sgl) {
			/* free up the memory in DMA space and kernel space */
			dma_unmap_sg(priv->dev, priv->sg_tables[i].sgl,
						 priv->sg_tables[i].orig_nents, DMA_FROM_DEVICE);
			kfree((void *)priv->sg_tables[i].sgl);
			/* zero out the entries */
			priv->sg_tables[i].sgl = 0;
			priv->sg_tables[i].orig_nents = 0;
			priv->sg_tables[i].nents = 0;
		}
	}
	copy_to_user((void __user *) input->completion,
	             (void *)priv->k_descriptor.completion, input->operand1);
	kfree((void *)priv->k_descriptor.completion);
}

static long dce_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	uint64_t val;
	struct DCEDescriptor descriptor;
	struct dce_driver_priv *priv = file->private_data;
		printk(KERN_INFO "Got to ioctl with cmd %u!\n", cmd);


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

			parse_descriptor_based_on_opcode(priv, &descriptor, &descriptor_input);
			printk(KERN_INFO "pushing descriptor thru ioctl with opcode %d!\n", descriptor.opcode);
			printk(KERN_INFO "submitting source 0x%lx\n", descriptor.source);
			dce_push_descriptor(priv, &descriptor);

			// Free up resources when its done
			// while(!(priv->k_descriptor.completion & (1ULL << 63))) {}
			free_resources(priv, &descriptor_input);
		}
	}

	return 0;
}

static const struct file_operations dce_ops = {
	.owner          = THIS_MODULE,
	.open           = dce_ops_open,
	.read		= dce_ops_read,
	.write          = dce_ops_write,
	.unlocked_ioctl = dce_ioctl
};

static struct class *dce_char_class;

void dce_reset_descriptor_ring(struct dce_driver_priv *drv_priv) {
	memset(&drv_priv->descriptor_ring, 0, sizeof(DescriptorRing));

	dce_reg_write(drv_priv, DCE_CTRL, dce_reg_read(drv_priv, DCE_CTRL) | (1 << 1));
	while (dce_reg_read(drv_priv, DCE_STATUS) & (1 << 1));
}

void dce_init_descriptor_ring(struct dce_driver_priv *drv_priv, size_t length)
{
	size_t adjusted_length = length + 1;

	dce_reset_descriptor_ring(drv_priv);

	// added 1 because there can only ever be n - 1 valid entries in a descriptor ring.
	// the +1 adjusts for that.
	of_dma_configure(drv_priv->dev, drv_priv->dev->of_node, true);
	if (!drv_priv->dev->dma_mask)
		drv_priv->dev->dma_mask = &drv_priv->dev->coherent_dma_mask;
	if (!drv_priv->dev->coherent_dma_mask)
		drv_priv->dev->coherent_dma_mask = 0xffffffff;
	// Allcate the descriptors as coherent DMA memory
	drv_priv->descriptor_ring.descriptors = dma_alloc_coherent(drv_priv->dev, adjusted_length * sizeof(DCEDescriptor),
								  &drv_priv->descriptor_ring.dma, GFP_KERNEL);
	drv_priv->descriptor_ring.length      = adjusted_length;
	printk(KERN_INFO "Allocated descriptors at 0x%llx\n", (uint64_t)drv_priv->descriptor_ring.descriptors);
	dce_reg_write(drv_priv, DCE_DESCRIPTOR_RING_CTRL_BASE,  (uint64_t) drv_priv->descriptor_ring.dma);
	dce_reg_write(drv_priv, DCE_DESCRIPTOR_RING_CTRL_LIMIT, (uint64_t) drv_priv->descriptor_ring.dma + adjusted_length * sizeof(DCEDescriptor));
	dce_reg_write(drv_priv, DCE_CTRL, dce_reg_read(drv_priv, DCE_CTRL) | 1);
	while (!(dce_reg_read(drv_priv, DCE_STATUS) & 1));
}

static irqreturn_t handle_dce(int irq, void *dev_id) {
	printk(KERN_INFO "Got interrupt!\n");
	return IRQ_HANDLED;
}

static int dce_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int bar, err;
	u16 vendor, device;
	// unsigned long mmio_start,mmio_len;
	struct dce_driver_priv *drv_priv;
	struct device* dev;
	dev_t dev_num;

	pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor);
	pci_read_config_word(pdev, PCI_DEVICE_ID, &device);
	pci_write_config_byte(pdev, PCI_COMMAND, PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
	printk(KERN_INFO "Device vaid: 0x%X pid: 0x%X\n", vendor, device);

	err = pci_enable_device_mem(pdev);
	if (err) goto disable_device_and_fail;

	bar = pci_select_bars(pdev, IORESOURCE_MEM);
	printk(KERN_INFO "io bar: 0x%X", bar);

	err = pci_request_selected_regions(pdev, bar, DEVICE_NAME);
	if (err) goto disable_device_and_fail;

	// mmio_start = pci_resource_start(pdev, 0);
	// mmio_len   = pci_resource_len  (pdev, 0);

	err = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
	if (err) goto disable_device_and_fail;

	dev = device_create(dce_char_class, &pdev->dev, MKDEV(MAJOR(dev_num), 0), NULL, DEVICE_NAME);
	if (IS_ERR(dev)) goto disable_device_and_fail;

	drv_priv = devm_kzalloc(dev, sizeof(struct dce_driver_priv), GFP_KERNEL);
	if (!drv_priv) goto free_resources_and_fail;

	drv_priv->dev = dev;
	cdev_init(&drv_priv->cdev, &dce_ops);
	drv_priv->cdev.owner = THIS_MODULE;
	drv_priv->mmio_start = (uint64_t)pci_iomap(pdev, 0, 0);

	err = cdev_add(&drv_priv->cdev, MKDEV(MAJOR(dev_num), 0), 1);
	if (err) goto free_resources_and_fail;

	pci_set_drvdata(pdev, drv_priv);

	dce_init_descriptor_ring(drv_priv, 0x100);

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

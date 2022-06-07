
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

typedef struct AccessInfoRead {
	uint64_t* value;
	uint64_t  offset;
} AccessInfoRead;

typedef struct AccessInfoWrite {
	uint64_t value;
	uint64_t offset;
} AccessInfoWrite;

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


typedef struct DescriptorRing {
	DCEDescriptor* descriptors;
	size_t length;
	size_t tail;
	int enabled;
} DescriptorRing;

#define RAW_READ          _IOR(0xAA, 0, struct AccessInfo*)
#define RAW_WRITE         _IOW(0xAA, 1, struct AccessInfo*)
#define SUBMIT_DESCRIPTOR _IOW(0xAA, 2, struct DescriptorInput*)
// im surprised that this isn't already defined somewhere
#define MIN(a, b) \
	({ __typeof__ (a) _a = (a); \
	   __typeof__ (b) _b = (b); \
	   _a < _b ? _a : _b; })

struct dce_driver_priv
{
	struct device* dev;
	dev_t dev_num;
	struct cdev cdev;

	u32* in;
	u32* out;
	u32* temp;

	uint64_t mmio_start;

	DescriptorRing descriptor_ring;
};

static uint64_t dce_reg_read(struct dce_driver_priv *priv, int reg) {
	uint64_t result = ioread64(priv->mmio_start + reg);
	printk(KERN_INFO "Read 0x%lx from address 0x%llx\n", result, priv->mmio_start + reg);
	return result;
}

static void dce_reg_write(struct dce_driver_priv *priv, int reg, uint64_t value) {
	printk(KERN_INFO "Writing 0x%llx to address 0x%llx\n", value, priv->mmio_start + reg);
	iowrite64(value, priv->mmio_start + reg);
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
	size_t tail_offset_bytes = tail - base;
	size_t descriptor_size_bytes = priv->descriptor_ring.length * sizeof(DCEDescriptor);

	uint64_t next_offset = tail_offset_bytes + sizeof(DCEDescriptor);
	next_offset %= descriptor_size_bytes;

	// TODO: something here with error handling

	memcpy((DCEDescriptor*)phys_to_virt(tail), descriptor, sizeof(DCEDescriptor));

	dce_reg_write(priv, DCE_DESCRIPTOR_RING_CTRL_TAIL, base + next_offset);
}

static uint64_t get_pa_for_user_va(uint64_t va, uint64_t num_bytes, bool write)
{
	int flag = write ? FOLL_WRITE : 0;
	int num_pages = (num_bytes / PAGE_SIZE) + 1;
	uint64_t offset = va % PAGE_SIZE;
	uint64_t offset_length = num_bytes % PAGE_SIZE;
	if (offset + offset_length >= PAGE_SIZE) num_pages += 1;
	struct page* page_ptr_array[num_pages];
	uint64_t pa;

	get_user_pages_fast(va, num_pages, flag, page_ptr_array);
	pa = (uint64_t)page_to_phys(page_ptr_array[0]);
	pa += offset;
	return pa;
}

void parse_descriptor_based_on_opcode(struct DCEDescriptor * desc, struct DCEDescriptor * input) {
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

	/* Override based on opcode */
	switch (desc->opcode)
	{
		case DCE_OPCODE_MEMCPY:
			desc->source = get_pa_for_user_va(input->source, input->operand1, 0);
			desc->destination = get_pa_for_user_va(input->destination, input->operand1, FOLL_WRITE);
			desc->completion = get_pa_for_user_va(input->completion, 8, FOLL_WRITE);
			break;
		case DCE_OPCODE_MEMCMP:
			desc->source = get_pa_for_user_va(input->source, input->operand1, 0);
			desc->destination = get_pa_for_user_va(input->destination, input->operand1, FOLL_WRITE);
			desc->completion = get_pa_for_user_va(input->completion, 8, FOLL_WRITE);
			/* src2 */
			desc->operand2 = get_pa_for_user_va(input->operand2, input->operand1, 0);
			break;
		default:
			break;
	}
}

static long dce_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct dce_driver_priv *priv = file->private_data;
		printk(KERN_INFO "Got to ioctl with cmd %u!\n", cmd);

	switch (cmd) {
		case RAW_READ: {
			struct AccessInfoRead __user *__access_info;
			struct AccessInfoRead access_info;

			__access_info = (struct AccessInfoRead __user*) arg;
			if (copy_from_user(&access_info, __access_info, sizeof(access_info)))
				return -EFAULT;

			uint64_t val = ioread64(priv->mmio_start + access_info.offset);
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

			iowrite64(access_info.value, priv->mmio_start + access_info.offset);

			break;
		}

		case SUBMIT_DESCRIPTOR: {
			struct DCEDescriptor __user *__descriptor_input;
			struct DCEDescriptor descriptor_input;

			__descriptor_input = (struct DCEDescriptor __user*) arg;
			if (copy_from_user(&descriptor_input, __descriptor_input, sizeof(descriptor_input)))
				return -EFAULT;

			struct DCEDescriptor descriptor;
			parse_descriptor_based_on_opcode(&descriptor, &descriptor_input);
			printk(KERN_INFO "pushing descriptor thru ioctl with opcode %d!\n", descriptor.opcode);
			dce_push_descriptor(priv, &descriptor);
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

static void free_resources(struct device *dev, struct dce_driver_priv *drv_priv)
{

}

void dce_reset_descriptor_ring(struct dce_driver_priv *drv_priv) {
	memset(&drv_priv->descriptor_ring, 0, sizeof(DescriptorRing));

	dce_reg_write(drv_priv, DCE_CTRL, dce_reg_read(drv_priv, DCE_CTRL) | (1 << 1));
	while (dce_reg_read(drv_priv, DCE_STATUS) & (1 << 1));
}

void dce_init_descriptor_ring(struct dce_driver_priv *drv_priv, size_t length)
{
	dce_reset_descriptor_ring(drv_priv);

	// added 1 because there can only ever be n - 1 valid entries in a descriptor ring.
	// the +1 adjusts for that.
	size_t adjusted_length = length + 1;

	drv_priv->descriptor_ring.descriptors = devm_kzalloc(drv_priv->dev, adjusted_length * sizeof(DCEDescriptor), GFP_KERNEL);
	drv_priv->descriptor_ring.length      = adjusted_length;
	printk(KERN_INFO "Allocated descriptors at 0x%lx\n", drv_priv->descriptor_ring.descriptors);
	dce_reg_write(drv_priv, DCE_DESCRIPTOR_RING_CTRL_BASE,  (uint64_t) virt_to_phys(drv_priv->descriptor_ring.descriptors));
	dce_reg_write(drv_priv, DCE_DESCRIPTOR_RING_CTRL_LIMIT, (uint64_t) virt_to_phys(drv_priv->descriptor_ring.descriptors) + adjusted_length * sizeof(DCEDescriptor));
	dce_reg_write(drv_priv, DCE_CTRL, dce_reg_read(drv_priv, DCE_CTRL) | 1);
	while (!(dce_reg_read(drv_priv, DCE_STATUS) & 1));
}

static int dce_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int bar, err;
	u16 vendor, device;
	unsigned long mmio_start,mmio_len;
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

	dev_num;
	err = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
	if (err) goto disable_device_and_fail;

	dev = device_create(dce_char_class, &pdev->dev, MKDEV(MAJOR(dev_num), 0), NULL, DEVICE_NAME);
	if (IS_ERR(dev)) goto disable_device_and_fail;

	drv_priv = devm_kzalloc(dev, sizeof(struct dce_driver_priv), GFP_KERNEL);
	if (!drv_priv) goto free_resources_and_fail;

	drv_priv->dev = dev;
	cdev_init(&drv_priv->cdev, &dce_ops);
	drv_priv->cdev.owner = THIS_MODULE;
	drv_priv->mmio_start = pci_iomap(pdev, 0, 0);

	err = cdev_add(&drv_priv->cdev, MKDEV(MAJOR(dev_num), 0), 1);
	if (err) goto free_resources_and_fail;

	pci_set_drvdata(pdev, drv_priv);

	dce_init_descriptor_ring(drv_priv, 0x100);

	return 0;

	disable_device_and_fail:
		pci_disable_device(pdev);
		return err;

	free_resources_and_fail:
		pci_disable_device(pdev);
		free_resources(dev, drv_priv);
		return err;
}

static void dce_remove(struct pci_dev *pdev)
{
	free_resources(&pdev->dev, pci_get_drvdata(pdev));
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

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

static struct class *dcevf_char_class;
static dev_t dev_num;

static const struct file_operations dcevf_ops = {
	.owner		= THIS_MODULE,
	.open		= dce_ops_open,
	.release	= dce_ops_release,
	.read		= dce_ops_read,
	.write		= dce_ops_write,
	.unlocked_ioctl = dce_ioctl,
};
// FIXME: clean up ida
static DEFINE_IDA(dce_minor_ida);

static int dcevf_probe(struct pci_dev *pdev, const struct pci_device_id *id) {
	printk(KERN_INFO "in %s\n", __func__);

	int bar, err;
	u16 vendor, device;
	struct cdev *cdev;
	// unsigned long mmio_start,mmio_len;
	struct dce_driver_priv *drv_priv;
	struct device* dev = &pdev->dev;

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

	drv_priv = kzalloc_node(sizeof(struct dce_driver_priv), GFP_KERNEL,
			     dev_to_node(&pdev->dev));
	if (!drv_priv) goto disable_device_and_fail;

	drv_priv->pdev = pdev;
	drv_priv->pci_dev = &pdev->dev;
	dev = &drv_priv->dev;

	device_initialize(dev);
	dev->class = dcevf_char_class;
	dev->parent = &pdev->dev;

	int minor = ida_simple_get(&dce_minor_ida, 0, 0, GFP_KERNEL);

	dev->devt = MKDEV(MAJOR(dev_num), minor);
	dev_set_name(dev, "dcevf%d", minor);
	printk(KERN_INFO "Got minor number %d, name: %s\n", minor, dev_name(dev));
	cdev = &drv_priv->cdev;
	cdev_init(cdev, &dcevf_ops);
	cdev->owner = THIS_MODULE;

	drv_priv->mmio_start = (uint64_t)pci_iomap(pdev, 0, 0);
	drv_priv->vf_number = minor;

	pci_set_drvdata(pdev, drv_priv);

	/* priv mem regions setup */
	setup_memory_regions(drv_priv);

	err = cdev_device_add(&drv_priv->cdev, &drv_priv->dev);
	if (err) {
		printk(KERN_INFO "cdev add failed\n");
	}

	printk(KERN_INFO "VF MMIO: 0x%x\n", drv_priv->mmio_start);

	return 0;
disable_device_and_fail:
	printk(KERN_INFO "VF probe failed!\n");
	return -1;
}

static SIMPLE_DEV_PM_OPS(vmd_dev_pm_ops, vmd_suspend, vmd_resume);

static void dcevf_remove(struct pci_dev *pdev) {}

static const struct pci_device_id dcevf_id_table[] = {
	{ PCI_DEVICE(VENDOR_ID, DEVICE_VF_ID) } ,
	{0, },
};

static struct pci_driver dcevf_driver = {
	.name     = DEVICE_VF_NAME,
	.id_table = dcevf_id_table,
	.probe    = dcevf_probe,
	.remove   = dcevf_remove,
	.driver	= {
		.pm = &vmd_dev_pm_ops,
	},
};

static char *pci_char_devnode(struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, DEVICE_VF_NAME);
}

static int __init dcevf_driver_init(void)
{
	int err;
	err = alloc_chrdev_region(&dev_num, 0, DCE_NR_VIRTFN, DEVICE_VF_NAME);
	if (err) return -err;

	printk(KERN_INFO "DCEVF: in module init\n");
	dcevf_char_class = class_create(THIS_MODULE, DEVICE_VF_NAME);
	if (IS_ERR(dcevf_char_class)) {
		err = PTR_ERR(dcevf_char_class);
		return err;
	}

	//dcevf_char_class->devnode = pci_char_devnode;

	err = pci_register_driver(&dcevf_driver);
	return err;
}

static void __exit dcevf_driver_exit(void)
{
	pci_unregister_driver(&dcevf_driver);
}

MODULE_LICENSE("GPL");

module_init(dcevf_driver_init);
module_exit(dcevf_driver_exit);

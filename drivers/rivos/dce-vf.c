
#include <asm-generic/int-ll64.h>
#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/iommu.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/pci_regs.h>
#include <linux/of_device.h>
#include <linux/mm.h>
#include <linux/workqueue.h>

#include "dce.h"

static struct class *dcevf_char_class;
static dev_t dev_num;

static const struct file_operations dcevf_ops = {
	.owner		= THIS_MODULE,
	.open		= dce_ops_open,
	.release	= dce_ops_release,
#if 0
	.read		= dce_ops_read,
	.write		= dce_ops_write,
#endif
	.mmap 		= dce_mmap,
	.unlocked_ioctl = dce_ioctl,
};
// FIXME: clean up ida
static DEFINE_IDA(dce_minor_ida);

static int dcevf_probe(struct pci_dev *pdev, const struct pci_device_id *id) {
	int bar, err;
	u16 vendor, device;
	struct cdev *cdev;
	// unsigned long mmio_start,mmio_len;
	struct dce_driver_priv *drv_priv;
	struct device* dev = &pdev->dev;
	int minor;

	printk(KERN_INFO "in %s\n", __func__);

	pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor);
	pci_read_config_word(pdev, PCI_DEVICE_ID, &device);
	pci_write_config_byte(pdev, PCI_COMMAND, PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);

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
	drv_priv->pci_dev = dev;

	drv_priv->mmio_start_phys = pci_resource_start(pdev, 0);
	// mmio_len   = pci_resource_len  (pdev, 0);

	if (iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_SVA)) {
	// FIXME: Enable for testing non-SVA
	// if (1) {
		dev_warn(dev, "DCE:Unable to turn on user SVA feature.\n");
		drv_priv->sva_enabled = false;
	} else {
		dev_info(dev, "DCE:SVA feature enabled.\n");
		drv_priv->sva_enabled = true;
	}

	// initialize the child device
	dev = &drv_priv->dev;

	device_initialize(dev);
	dev->class = dcevf_char_class;
	dev->parent = &pdev->dev;

	minor = ida_simple_get(&dce_minor_ida, 0, 0, GFP_KERNEL);
	if(minor <0){
		dev_err(dev, "Failure to get minor\n");
		goto free_resources_and_fail;
	}

	dev->devt = MKDEV(MAJOR(dev_num), minor);
	err= dev_set_name(dev, "dcevf%d", minor);
	if(err<0){
		dev_err(dev, "Failure naming device\n");
	}
	dev_info(dev,"Got minor number %d, name: %s\n", minor, dev_name(dev));
	cdev = &drv_priv->cdev;
	cdev_init(cdev, &dcevf_ops);
	cdev->owner = THIS_MODULE;

	drv_priv->mmio_start = (uint64_t)pci_iomap(pdev, 0, 0);
	drv_priv->vf_number = minor;

	pci_set_drvdata(pdev, drv_priv);

	/* priv mem regions setup */
	err = setup_memory_regions(drv_priv);
	if (err)
		goto disable_device_and_fail;

	err = cdev_device_add(&drv_priv->cdev, &drv_priv->dev);
	if (err) {
		printk(KERN_ERR "DCE: cdev add failed\n");
		goto free_resources_and_fail;
	}

	/* MSI setup */
	if (pci_match_id(pci_use_msi, pdev)) {
		int vec;
		dev_info(dev, "Using MSI(-X) interrupts\n");
		pci_set_master(pdev);
		dev_info(dev, "dev->msi_enabled: %d\n", pdev->msix_enabled);
		err = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_ALL_TYPES);
		if(err<0){
			dev_err(dev, "Failled to allocate interrupt vectors\n");
			goto free_resources_and_fail;
		}
		vec = pci_irq_vector(pdev, 0);
		if(vec<0){
			dev_err(dev, "DCE-VF: Failure getting IRQ nr");
			goto free_resources_and_fail;
		}
		dev_info(dev, "IRQ vector is %d\n", vec);
		/* auto frees on device detach, nice */
		err = devm_request_threaded_irq(dev, vec, handle_dce, NULL, IRQF_ONESHOT, DEVICE_NAME, drv_priv);
		if(err<0){
			dev_err(dev, "DCE-VF: Failure registering irq handler\n");
			goto free_resources_and_fail;
		}
	} else {
		dev_warn(dev, "DCE-VF: MSI enable failed\n");
	}

	/* work queue setup */
	INIT_WORK(&drv_priv->clean_up_worker, clean_up_work);

	/* init mutex */
	mutex_init(&drv_priv->lock);

	/* setup WQ 0 for SHARED_KERNEL usage */
	setup_default_kernel_queue(drv_priv);

	return 0;

free_resources_and_fail:
		dev_err(dev, "Failure in probe, device unavailable\n");
		free_resources(dev, drv_priv);
disable_device_and_fail:
		pci_disable_device(pdev);
		return err;
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

/* TODO: remove if not useful, currently unused, keeping here just incase

static char *pci_char_devnode(struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, DEVICE_VF_NAME);
}
*/

static int __init dcevf_driver_init(void)
{
	int err;
	err = alloc_chrdev_region(&dev_num, 0, DCE_NR_VIRTFN, DEVICE_VF_NAME);
	if (err) return err;

	printk(KERN_INFO "DCEVF: in module init\n");
	dcevf_char_class = class_create(THIS_MODULE, DEVICE_VF_NAME);
	if (IS_ERR(dcevf_char_class)) {
		err = PTR_ERR(dcevf_char_class);
		return err;
	}

	/* TODO: Check whqtthis is for, seems to generate device name
	 * from device struct device and umode_t
	 * The current impl makes all VF named dcevf, unsurpisingly from impl
	dcevf_char_class->devnode = pci_char_devnode;
	*/

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

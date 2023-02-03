/* isbdmex
 *
 * ISBDM exerciser driver
 *
 * SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * 3 Feb 2023 mev
 */


#include <linux/bitmap.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pci-epf.h>
#include <linux/pci_ids.h>

#include "isbdmex.h"


/******************************************************************************/
/* Multiple device/instance management */

/* Driver'll be instantiated several times, probed in order of discovery in PCI.
 * This bitmap holds which indices have been probed/are live:
 */
#define ISBDM_MAX_INSTANCES	64			/* In reality, 32! */

static DEFINE_MUTEX(isbdm_instance_bmap_mutex);
static unsigned long		isbdm_instance_bmap = 0;

/* Finds an available instance index, or returns -1 if full: */
static int isbdmex_get_instance(void)
{
	int r;

	mutex_lock(&isbdm_instance_bmap_mutex);
	r = bitmap_find_free_region(&isbdm_instance_bmap, ISBDM_MAX_INSTANCES, 0);
	mutex_unlock(&isbdm_instance_bmap_mutex);

	return r;
}

static void isbdmex_put_instance(int i)
{
	mutex_lock(&isbdm_instance_bmap_mutex);
	bitmap_release_region(&isbdm_instance_bmap, i, 0);
	mutex_unlock(&isbdm_instance_bmap_mutex);
}


/******************************************************************************/
/* IRQ handling */

static irqreturn_t isbdmex_irq_handler(int irq, void *data)
{
	int r = IRQ_NONE;
	/* If status blah, r = IRQ_WAKE_THREAD */
	/* Ack IRQ (no internal ISBDM state change :P ) */
	return r;
}

static irqreturn_t isbdmex_irq_thread(int irq, void *data)
{
	/* */
	return IRQ_HANDLED;
}

static int isbdmex_request_irq(struct pci_dev *pdev)
{
	int ret, irq;
	struct device *dev = &pdev->dev;
	struct isbdm *ii = (struct isbdm *)pci_get_drvdata(pdev);

	/* FIXME: Can this leak/does devm sweep this? */
	ret = pci_alloc_irq_vectors(pdev,
				    /* Just the one? */ 1, 1,
				    PCI_IRQ_MSI | PCI_IRQ_MSIX);
	if (ret < 0) {
		dev_err(dev, "Failed to allocate MSI (%d)\n", ret);
		return ret;
	}

	/* Get Linux IRQ number from the MSI vector #0: */
	irq = pci_irq_vector(pdev, 0);
	if (irq < 0) {
		dev_err(dev, "IRQ vector invalid (%d)\n", irq);
		return irq;
	}
	ii->irq = irq;

	ret = devm_request_threaded_irq(dev, irq,
					isbdmex_irq_handler, isbdmex_irq_thread,
					IRQF_ONESHOT, dev_name(dev), ii);
	if (ret < 0) {
		dev_err(dev, "Request for IRQ%d failed (%d)\n", irq, ret);
		return ret;
	}

	return ret;
}


/******************************************************************************/
/* fops/user handling */

static int isbdmex_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int isbdmex_release(struct inode *inode, struct file *file)
{
	/* Which node? */
	return 0;
}

static long isbdmex_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return 0;
}

static const struct file_operations isbdmex_fops = {
	.owner 		= THIS_MODULE,
	.open 		= isbdmex_open,
	.release 	= isbdmex_release,
	/* .mmap ? */
	.unlocked_ioctl = isbdmex_ioctl,
};


/******************************************************************************/
/* Probe, and PCI plumbing */

static int isbdmex_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int ret;
	struct device *dev = &pdev->dev;
	struct isbdm *ii;

	/* Allocate an instance (a struct isbdm), find resources, enable */
	ii = devm_kzalloc(dev, sizeof(struct isbdm), GFP_KERNEL);
	if (!ii) {
		dev_err_probe(dev, ret, "Can't allocate device instance\n");
		return -ENOMEM;
	}

	ii->pdev = pdev;
	pci_set_drvdata(pdev, ii);

	ret = pcim_enable_device(pdev);
	if (ret < 0) {
		dev_err_probe(dev, ret, "Can't enable device\n");
		return ret;
	}

	/* MMIO */
	ret = pcim_iomap_regions(pdev, BIT(BAR_0), KBUILD_MODNAME);
	if (ret) {
		dev_err_probe(dev, ret, "Can't iomap regions\n");
		return ret;
	}

	ii->base = pcim_iomap_table(pdev)[BAR_0];

	isbdmex_hw_reset(ii);

	/* FIXME: Ensure quiescent before setting BME! */
	pci_set_master(pdev);

	/* IRQs */
	ret = isbdmex_request_irq(pdev);
	if (ret) {
		dev_err_probe(dev, ret, "IRQ setup failed\n");
		return ret;
	}

	ii->instance = isbdmex_get_instance();
	if (ii->instance < 0) {
		dev_err_probe(dev, ret, "Too many ISBDMs!\n");
		return ret;
	}

	dev_info(dev, "isbdm%d at %px, irq %d\n", ii->instance, ii->base, ii->irq);

	/* Register a misc device */
	ii->misc.minor = MISC_DYNAMIC_MINOR;
	ii->misc.fops = &isbdmex_fops;
	ii->misc.name = kasprintf(GFP_KERNEL, "isbdmex%d", ii->instance);
	if (!ii->misc.name) {
		dev_err_probe(dev, ret, "Can't alloc misc->name\n");
		return ret;
	}

	ret = misc_register(&ii->misc);
	if (ret < 0) {
		dev_err_probe(dev, ret, "Can't register miscdev\n");
		return ret;
	}

	/* FIXME: sysfs: somehow expose enough info to map a /dev/isbdmexN to a PCS/hardware location */

	return 0;
}

static void isbdmex_remove(struct pci_dev *pdev)
{
	struct isbdm *ii = (struct isbdm *)pci_get_drvdata(pdev);

	/* Some resources are freed by devres */
	misc_deregister(&ii->misc);
	isbdmex_put_instance(ii->instance);
}

static const struct pci_device_id isbdmex_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_RIVOS, PCI_DEVICE_ID_RIVOS_ISBDM_PF), 0, 0, 0},
	{0,},
};

static struct pci_driver isbdmex_pci_driver = {
	.name 		= "isbdmex",
	.id_table 	= isbdmex_ids,
	.probe 		= isbdmex_probe,
	.remove		= isbdmex_remove,
};

MODULE_DEVICE_TABLE(pci, isbdmex_ids);
module_pci_driver(isbdmex_pci_driver);

MODULE_AUTHOR("mev");
MODULE_LICENSE("GPL v2");

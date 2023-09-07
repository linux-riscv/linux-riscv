/* rasd
 *
 * Rivos Accelerator Super-Duper!
 *
 * SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * 2023-07-27 Evan Green <evan@rivosinc.com>
 */

#include <linux/bitmap.h>
#include <linux/device.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pci-epf.h>
#include <linux/pci_ids.h>

#include "rasd.h"

/******************************************************************************/
/* Multiple device/instance management */

#define RASD_MAX_INSTANCES	32

static DEFINE_MUTEX(rasd_mutex);
static unsigned long rasd_instance_bmap = 0;

/*
 * Keep a global list of devices so at open time they can be looked up by minor
 * number, also protected by the mutex.
 */
static LIST_HEAD(rasd_list);

/* Finds an available instance index, or returns -1 if full: */
static int rasd_new_instance(struct rasd *ra)
{
	mutex_lock(&rasd_mutex);
	ra->instance = bitmap_find_free_region(&rasd_instance_bmap,
					       RASD_MAX_INSTANCES, 0);

	if (ra->instance >= 0)
		list_add_tail(&ra->node, &rasd_list);

	mutex_unlock(&rasd_mutex);
	return ra->instance;
}

static void rasd_del_instance(struct rasd *ra)
{
	mutex_lock(&rasd_mutex);
	if (ra->instance >= 0)
		bitmap_release_region(&rasd_instance_bmap, ra->instance, 0);

	list_del(&ra->node);
	mutex_unlock(&rasd_mutex);
}

static struct rasd *rasd_locate(int minor)
{
	struct rasd *found = NULL;
	struct rasd *ra;

	mutex_lock(&rasd_mutex);
	list_for_each_entry(ra, &rasd_list, node) {
		if (ra->misc.minor == minor) {
			found = ra;
			break;
		}
	}

	mutex_unlock(&rasd_mutex);
	return found;
}

/******************************************************************************/
/* IRQ handling */

static irqreturn_t rasd_irq_handler(int irq, void *data)
{
	if (1) {
		return IRQ_WAKE_THREAD;
	}

	return IRQ_NONE;
}

static irqreturn_t rasd_irq_thread(int irq, void *data)
{
	struct rasd *ra = data;

	dev_info(&ra->pdev->dev, "Interrupt %d!", irq);
	return IRQ_HANDLED;
}

static int rasd_request_irqs(struct pci_dev *pdev)
{
	int ret, irq, i;
	struct device *dev = &pdev->dev;
	struct rasd *ra = (struct rasd *)pci_get_drvdata(pdev);

	/* FIXME: Can this leak/does devm sweep this? */
	ret = pci_alloc_irq_vectors(pdev,
				    1, 2,
				    PCI_IRQ_MSI | PCI_IRQ_MSIX);
	if (ret < 0) {
		dev_err(dev, "Failed to allocate MSI (%d)\n", ret);
		return ret;
	}

	for (i = 0; i < RASD_IRQ_COUNT; i++) {
		irq = pci_irq_vector(pdev, i);
		if (irq < 0) {
			dev_err(dev, "IRQ vector invalid (%d)\n", irq);
			return irq;
		}

		ra->irqs[i] = irq;
		ret = devm_request_threaded_irq(dev, irq,
						rasd_irq_handler, rasd_irq_thread,
						IRQF_ONESHOT, dev_name(dev), ra);
		if (ret < 0) {
			dev_err(dev, "Request for IRQ%d failed (%d)\n", irq, ret);
			return ret;
		}
	}

	return ret;
}

/******************************************************************************/
/* fops/user handling */

static int rasd_open(struct inode *inode, struct file *file)
{

	struct rasd *ra;

	ra = rasd_locate(iminor(inode));
	if (!ra)
		return -ENODEV;

	file->private_data = ra;
	return 0;
}

static int rasd_release(struct inode *inode, struct file *file)
{
	file->private_data = NULL;
	return 0;
}

static long rasd_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	u64 __user *argp64;
	int rc;

	if (is_compat_task())
		argp64 = compat_ptr(arg);
	else
		argp64 = (void __user *)arg;

	rc = 0;
	switch (cmd) {
	default:
		rc = -ENOENT;
		break;
	}

	return rc;
}

static ssize_t rasd_read(struct file *file, char __user *va, size_t size,
			 loff_t *file_offset)
{
	return -EINVAL;
}

static ssize_t rasd_write(struct file *file, const char __user *va,
			  size_t size, loff_t *file_offset)
{
	return -EINVAL;
}

static const struct file_operations rasd_fops = {
	.owner 		= THIS_MODULE,
	.read		= rasd_read,
	.write		= rasd_write,
	.open 		= rasd_open,
	.release 	= rasd_release,
	.unlocked_ioctl = rasd_ioctl,
};

/******************************************************************************/
/* Probe, and PCI plumbing */

/* Map a region fixed in IOVA space that Sentinel can DMA to and from. */
int alloc_test_region(struct rasd *ra)
{
	struct iommu_domain *domain = iommu_get_domain_for_dev(&ra->pdev->dev);
	int ret;

	ra->test_region = dma_alloc_coherent(&ra->pdev->dev,
					     RASD_TEST_REGION_SIZE,
					     &ra->test_region_physical,
					     GFP_KERNEL);

	if (!ra->test_region) {
		dev_warn(&ra->pdev->dev, "Failed to allocate test region\n");
		return -ENOMEM;
	}

	ret = iommu_map(domain, RASD_TEST_REGION_IOVA, ra->test_region_physical,
			RASD_TEST_REGION_SIZE,
			IOMMU_READ | IOMMU_WRITE | IOMMU_MMIO,
			GFP_KERNEL);

	if (ret) {
		dev_warn(&ra->pdev->dev, "Failed to map test region: %d", ret);
		dma_free_coherent(&ra->pdev->dev, RASD_TEST_REGION_SIZE,
				  ra->test_region, ra->test_region_physical);

		ra->test_region = NULL;
		return ret;
	}

	return 0;
}

void free_test_region(struct rasd *ra)
{
	struct iommu_domain *domain = iommu_get_domain_for_dev(&ra->pdev->dev);

	iommu_unmap(domain,
		    RASD_TEST_REGION_IOVA,
		    RASD_TEST_REGION_SIZE);

	dma_free_coherent(&ra->pdev->dev, RASD_TEST_REGION_SIZE,
			  ra->test_region, ra->test_region_physical);

	ra->test_region = NULL;
}

static int rasd_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int ret;
	struct device *dev = &pdev->dev;
	struct rasd *ra;

	/* Allocate an instance (a struct rasd), find resources, enable */
	ra = devm_kzalloc(dev, sizeof(struct rasd), GFP_KERNEL);
	if (!ra) {
		dev_err_probe(dev, ret, "Can't allocate device instance\n");
		return -ENOMEM;
	}

	ra->pdev = pdev;
	pci_set_drvdata(pdev, ra);
	ret = pcim_enable_device(pdev);
	if (ret < 0) {
		dev_err_probe(dev, ret, "Can't enable device\n");
		return ret;
	}

	/* MMIO */
	ret = pcim_iomap_regions(pdev, BIT(0) | BIT(2) | BIT(4),
				 KBUILD_MODNAME);

	if (ret) {
		dev_err_probe(dev, ret, "Can't iomap regions\n");
		return ret;
	}

	ra->regs = pcim_iomap_table(pdev)[BAR_0];
	ra->ddr = pcim_iomap_table(pdev)[BAR_2];
	ra->hbm = pcim_iomap_table(pdev)[BAR_4];
	pci_set_master(pdev);
	ret = rasd_request_irqs(pdev);
	if (ret) {
		dev_err_probe(dev, ret, "IRQ setup failed\n");
		goto deinit;
	}

	ret = rasd_new_instance(ra);
	if (ret < 0) {
		dev_err_probe(dev, ret, "Too many RASDs!\n");
		goto release_irq;
	}

	dev_info(dev, "rasd%d at %px, ddr at %px, hbm at %px, irq %d,%d\n",
		 ra->instance, ra->regs, ra->ddr, ra->hbm, ra->irqs[0],
		 ra->irqs[1]);

	alloc_test_region(ra);
	/* Register a misc device */
	ra->misc.minor = MISC_DYNAMIC_MINOR;
	ra->misc.fops = &rasd_fops;
	ra->misc.name = kasprintf(GFP_KERNEL, "rasd%d", ra->instance);
	if (!ra->misc.name) {
		dev_err_probe(dev, ret, "Can't alloc misc->name\n");
		goto unget_instance;
	}

	/* Get the hardware running! */
	// rasd_start(ra);
	ret = misc_register(&ra->misc);
	if (ret < 0) {
		dev_err_probe(dev, ret, "Can't register miscdev\n");
		goto free_misc_name;
	}

	return 0;

free_misc_name:
	kfree(ra->misc.name);

unget_instance:
	rasd_del_instance(ra);

release_irq:
	/* TODO: Undo rasd_request_irq(). */

deinit:
	return ret;
}

static void rasd_remove(struct pci_dev *pdev)
{
	struct rasd *ra = (struct rasd *)pci_get_drvdata(pdev);

	/* Some resources are freed by devres */
	free_test_region(ra);
	misc_deregister(&ra->misc);
	rasd_del_instance(ra);
	return;
}

static const struct pci_device_id rasd_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_RIVOS, PCI_DEVICE_ID_RIVOS_RASD), 0, 0, 0},
	{0,},
};

static struct pci_driver rasd_pci_driver = {
	.name 		= "rasd",
	.id_table 	= rasd_ids,
	.probe 		= rasd_probe,
	.remove		= rasd_remove,
};

MODULE_DEVICE_TABLE(pci, rasd_ids);
module_pci_driver(rasd_pci_driver);

MODULE_AUTHOR("Evan Green <evan@rivosinc.com>");
MODULE_LICENSE("GPL v2");

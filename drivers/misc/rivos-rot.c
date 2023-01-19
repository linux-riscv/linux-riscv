// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2023 Rivos Inc.

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define DRV_NAME       "rivos-rot"
#define DRV_VERSION    "0.0.1"

#include <linux/device.h>
#include <linux/io.h>
#include <linux/cdev.h>
#include <linux/dma-mapping.h>
#include <linux/hashtable.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/pci-doe.h>

/* Rivos Inc. assigned PCI Vendor and Device IDs */
#ifndef PCI_VENDOR_ID_RIVOS
#define PCI_VENDOR_ID_RIVOS             0x1efd
#endif

#ifndef PCI_DEVICE_ID_RIVOS_ROT
#define PCI_DEVICE_ID_RIVOS_ROT         0x0009
#endif

struct rivos_rot_state {
	struct device *dev;
	struct mutex mbox_mutex; /* Protects device mailbox and firmware */
	struct xarray doe_mbs;
};

static void rivos_rot_destroy_doe(void *mbs)
{
	xa_destroy(mbs);
}

struct rivos_rot_state *rivos_rot_state_create(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	struct rivos_rot_state *rrs;
	u16 off = 0;

	rrs = devm_kzalloc(dev, sizeof(*rrs), GFP_KERNEL);
	if (!rrs)
		return ERR_PTR(-ENOMEM);

	mutex_init(&rrs->mbox_mutex);
	rrs->dev = dev;

	xa_init(&rrs->doe_mbs);
	if (devm_add_action(dev, rivos_rot_destroy_doe, &rrs->doe_mbs)) {
		dev_err(dev, "Failed to create XArray for DOE's\n");
		return ERR_PTR(-ENOMEM);
	}

	dev_err(dev, "Adding mailboxes");
	pci_doe_for_each_off(pdev, off) {
		struct pci_doe_mb *doe_mb;

		doe_mb = pcim_doe_create_mb(pdev, off);
		if (IS_ERR(doe_mb)) {
			dev_err(dev, "Failed to create MB object for MB @ %x\n",
				off);
			continue;
		}

		if (xa_insert(&rrs->doe_mbs, off, doe_mb, GFP_KERNEL)) {
			dev_err(dev, "xa_insert failed to insert MB @ %x\n",
				off);
			continue;
		}

		dev_err(dev, "Created DOE mailbox @%x\n", off);
	}

	return rrs;
}

static int rivos_rot_pci_probe(struct pci_dev *pdev,
			const struct pci_device_id *ent)
{
	int ret;
	struct rivos_rot_state *rrs;

	pr_err("Probing");

	ret = pci_enable_device_io(pdev);
	if (ret < 0)
		return ret;

	rrs = rivos_rot_state_create(pdev);
	if (IS_ERR(rrs))
		return PTR_ERR(rrs);

	dev_set_drvdata(&pdev->dev, rrs);

	return 0;
}

static void rivos_rot_pci_remove(struct pci_dev *pdev)
{
	pci_disable_device(pdev);
}

static const struct pci_device_id rivos_rot_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_RIVOS, PCI_DEVICE_ID_RIVOS_ROT) },
	{0, },
};
MODULE_DEVICE_TABLE(pci, rivos_rot_id_table);

static struct pci_driver rivos_rot_pci_driver = {
	.name     = DRV_NAME,
	.id_table = rivos_rot_id_table,
	.probe    = rivos_rot_pci_probe,
	.remove   = rivos_rot_pci_remove,
};

static int __init rivos_rot_init_module(void)
{
	return pci_register_driver(&rivos_rot_pci_driver);
}

static void __exit rivos_rot_cleanup_module(void)
{
	pci_unregister_driver(&rivos_rot_pci_driver);
}

module_init(rivos_rot_init_module);
module_exit(rivos_rot_cleanup_module);

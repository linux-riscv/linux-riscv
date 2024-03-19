// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2023 Rivos Inc.

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define DRV_NAME       "rivos-rot"
#define DRV_VERSION    "0.0.3"

#include <linux/device.h>
#include <linux/io.h>
#include <linux/cdev.h>
#include <linux/dma-mapping.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/rivos-rot.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/pci-doe.h>

struct rivos_rot_device {
	struct device *dev;
	struct mutex mbox_mutex; /* Protects device mailbox and firmware */
	struct pci_doe_mb *ridl_mb;
};

/* Store the singleton device. */
static struct rivos_rot_device *rivos_rot_device;
static spinlock_t rivos_rot_lock;

static struct rivos_rot_device *rivos_rot_device_create(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	struct rivos_rot_device *rot;

	rot = devm_kzalloc(dev, sizeof(*rot), GFP_KERNEL);
	if (!rot)
		return ERR_PTR(-ENOMEM);

	mutex_init(&rot->mbox_mutex);
	rot->dev = dev;
	rot->ridl_mb = pci_find_doe_mailbox(pdev,
					    PCI_VENDOR_ID_RIVOS,
					    RIVOS_DOE_ROT_SERVICE_ID);

	if (!rot->ridl_mb) {
		dev_warn(&pdev->dev, "Failed to find RIDL mailbox\n");
	}

	return rot;
}

/**
 * get_rivos_rot() - Return a pointer to the Rivos Root of Trust device
 *
 * Returns a pointer to the device on success, with its reference count
 * incremented. Returns NULL if there is no device or the device failed to
 * probe.
 */
struct rivos_rot_device *get_rivos_rot(void)
{
	struct rivos_rot_device *rot;
	unsigned long flags;

	/* Avoid touching a potentially uninited spinlock. */
	rot = rivos_rot_device;
	if (!rot)
		return NULL;

	spin_lock_irqsave(&rivos_rot_lock, flags);
	rot = rivos_rot_device;
	if (rot)
		get_device(rot->dev);

	spin_unlock_irqrestore(&rivos_rot_lock, flags);
	return rot;
}

EXPORT_SYMBOL(get_rivos_rot);

void put_rivos_rot(struct rivos_rot_device *rot)
{
	put_device(rot->dev);
}

EXPORT_SYMBOL(put_rivos_rot);

static int rivos_ridl_doe(struct rivos_rot_device *rot, const void *request,
			  size_t request_sz, void *response, size_t response_sz)
{
	int rc;

	if (!response || !request ||
	    (request_sz < sizeof(struct ridl_request_header)) ||
	    (response_sz < sizeof(struct ridl_response_header)))
		return -EINVAL;

	mutex_lock(&rot->mbox_mutex);
	if (!rot->ridl_mb) {
		rc = -ENODEV;
		goto out;
	}

	rc = pci_doe(rot->ridl_mb, PCI_VENDOR_ID_RIVOS,
		     RIVOS_DOE_ROT_SERVICE_ID, request, request_sz,
		     response, response_sz);

	if (rc < 0) {
		dev_warn(rot->dev, "DOE error: %d\n", rc);

	} else if (rc >= 0 && rc < sizeof(struct ridl_response_header)) {
		dev_warn(rot->dev,
			 "Discarding undersized ridl DOE response, size %d\n",
			 rc);

		rc = -EINVAL;

	} else {
		struct ridl_response_header *rsp_hdr = response;

		if ((rsp_hdr->status != RESPONSE_RESULT_SUCCESS) &&
		    (rsp_hdr->status != RESPONSE_RESULT_UNIMPLEMENTED_METHOD))
			dev_warn(rot->dev, "DOE method %x:%x returned: %u\n",
				 rsp_hdr->category,
				 rsp_hdr->method,
				 rsp_hdr->status);
	}

out:
	mutex_unlock(&rot->mbox_mutex);
	return rc;
}

int rivos_rot_isbdm_update_status(struct rivos_rot_device *rot,
				  uint32_t rid,
				  enum isbdm_connection_state state)
{

	struct isbdm_status_request_wrapper request;
	struct isbdm_status_response_wrapper response;
	int rc;

	memset(&request, 0, sizeof(request));
	request.hdr.category = CATEGORY_REPORTING;
	request.hdr.method = ISBDM_STATUS;
	request.data.rid = rid;
	request.data.state = state;
	rc = rivos_ridl_doe(rot, &request, sizeof(request), &response,
			    sizeof(response));

	if (rc < 0)
		return rc;

	if (rc < sizeof(response.hdr))
		return -EINVAL;

	if ((response.hdr.status != RESPONSE_RESULT_SUCCESS) &&
	    (response.hdr.status != RESPONSE_RESULT_UNIMPLEMENTED_METHOD))
		return -ERANGE;

	return 0;
}

EXPORT_SYMBOL(rivos_rot_isbdm_update_status);

static int rivos_rot_pci_probe(struct pci_dev *pdev,
			       const struct pci_device_id *ent)
{
	unsigned long flags;
	struct rivos_rot_device *rot;

	pr_err("Probing");
	rot = rivos_rot_device_create(pdev);
	if (IS_ERR(rot))
		return PTR_ERR(rot);

	dev_set_drvdata(&pdev->dev, rot);
	spin_lock_irqsave(&rivos_rot_lock, flags);
	if (rivos_rot_device) {
		dev_warn(&pdev->dev, "Expected only one RoT\n");

	} else {
		rivos_rot_device = rot;
	}

	spin_unlock_irqrestore(&rivos_rot_lock, flags);
	return 0;
}

static void rivos_rot_pci_remove(struct pci_dev *pdev)
{
	unsigned long flags;
	struct rivos_rot_device *rot = dev_get_drvdata(&pdev->dev);

	spin_lock_irqsave(&rivos_rot_lock, flags);
	if (rivos_rot_device == rot)
		rivos_rot_device = NULL;

	spin_unlock_irqrestore(&rivos_rot_lock, flags);
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
	spin_lock_init(&rivos_rot_lock);
	return pci_register_driver(&rivos_rot_pci_driver);
}

static void __exit rivos_rot_cleanup_module(void)
{
	pci_unregister_driver(&rivos_rot_pci_driver);
}

module_init(rivos_rot_init_module);
module_exit(rivos_rot_cleanup_module);

MODULE_LICENSE("GPL");

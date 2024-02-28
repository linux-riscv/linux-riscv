// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Rivos Inc.
 * Author: Clément Léger <cleger@rivosinc.com>
 */

#include <linux/bitfield.h>
#include <linux/module.h>
#include <linux/pci.h>
#include "rivos-pwc.h"

#define PCI_DEVICE_ID_RIVOS_PWC		0x000a

#define RIVOS_PWC_DVSEC_REV		1

#define RIVOS_PWC_DVSEC_HEADER		0xc
#define  RIVOS_PWC_DVSEC_HEADER_BAR(x)	(x & 0xff)
#define  RIVOS_PWC_DVSEC_HEADER_MMIO(x)	(x >> 8)

#define MISC_PM_OFFSET			0x29E8

#define MISC_DEVICE_ID_MAPPING_OFFSET	(MISC_PM_OFFSET + 0x18)
#define MISC_DEVICE_ID_CHIPLET_ID	GENMASK(1, 0)
#define MISC_DEVICE_ID_SOC_ID		GENMASK(5, 4)
#define MISC_DEVICE_ID_CHIPLET_TYPE	GENMASK(10, 8)
#define MISC_DEVICE_ID_SOC_CONFIG	GENMASK(21, 16)

#define MISC_INTR_PENDING_OFFSET	(MISC_PM_OFFSET + 0x58)
#define MISC_INTR_PENDING_MASK		GENMASK(4, 0)

#define MISC_INTR_ROUTING_OFFSET	(MISC_PM_OFFSET + 0x60)
#define MISC_INTR_ROUTING_INDEX		GENMASK(2, 0)
#define MISC_INTR_ROUTING_STRIDE	4

#define MISC_INTR_COUNT			5

static const struct rivos_pwc_dvsec_desc rivos_pwc_dvsec_descs[] = {
	{ DVSEC_ID_CHIPLET_THERMAL, 0x170, 1, "chiplet_thermal" },
	{ DVSEC_ID_CHIPLET_POWER, 0x168, -1, "chiplet_power" },
	{ DVSEC_ID_DIMM_THERMAL, 0x40, 3, "dimm_thermal" },
	{ DVSEC_ID_DIMM_POWER, 0x48, -1, "dimm_power" },
	{ DVSEC_ID_DPA_THERMAL, 0x24, 2, "dpa_thermal" },
	{ DVSEC_ID_DPA_POWER, 0x28, -1, "dpa_power" },
	{ DVSEC_ID_DPA_PERF, 0x48, -1, "dpa_perf" },
	{ DVSEC_ID_HBM_THERMAL, 0x38, 4, "hbm_thermal" },
	{ DVSEC_ID_HBM_POWER, 0x38, -1, "hbm_power" },
	{ DVSEC_ID_SOC_THERMAL, 0x20, 0, "soc_thermal" },
	{ DVSEC_ID_SOC_POWER, 0x40, -1, "soc_power" },
};

struct rivos_pwc_dvsec_header {
	u8 rev;
	u16 dev_id;
	u8 bar;
	u32 mmio_offset;
};

#define PWC_SHOW(_name) \
static ssize_t _name ## _show(struct device *dev, struct device_attribute *attr, char *buf) \
{ \
	struct rivos_pwc *pwc = dev_get_drvdata(dev); \
	return sysfs_emit(buf, "%d\n", pwc->_name); \
} \
static DEVICE_ATTR_RO(_name);


PWC_SHOW(chiplet_id);
PWC_SHOW(soc_id);
PWC_SHOW(chiplet_type);
PWC_SHOW(soc_config);

static struct attribute *pwc_attrs[] = {
	&dev_attr_chiplet_id.attr,
	&dev_attr_soc_id.attr,
	&dev_attr_chiplet_type.attr,
	&dev_attr_soc_config.attr,
	NULL
};

static const struct attribute_group pwc_group = {
	.attrs = pwc_attrs,
};
__ATTRIBUTE_GROUPS(pwc);

void rivos_pwc_irq_ack(struct rivos_pwc_dvsec_dev *rpd_dev)
{
	struct rivos_pwc *pwc = rpd_dev->pwc;
	u32 reg;

	spin_lock(&pwc->lock);

	reg = ioread32(pwc->base + MISC_INTR_PENDING_OFFSET);
	reg &= ~BIT(rpd_dev->rpd_dev->it_index);
	iowrite32(reg, pwc->base + MISC_INTR_PENDING_OFFSET);

	spin_unlock(&pwc->lock);
}

static const
struct rivos_pwc_dvsec_desc *rivos_dvsec_get_desc(enum rivos_pwc_dvsec_id id)
{
	int i = 0;

	for (i = 0; i < ARRAY_SIZE(rivos_pwc_dvsec_descs); i++) {
		if (rivos_pwc_dvsec_descs[i].id == id)
			return &rivos_pwc_dvsec_descs[i];
	}

	return NULL;
}

static void rivos_pwc_dvsec_remove_aux(void *data)
{
	auxiliary_device_delete(data);
	auxiliary_device_uninit(data);
}

static void rivos_pwc_dvsec_dev_free(struct rivos_pwc_dvsec_dev *rpd_dev)
{
	struct rivos_pwc *pwc = rpd_dev->pwc;

	ida_free(&pwc->auxdev_ida, rpd_dev->auxdev.id);

	kfree(rpd_dev);
}

static void rivos_pwc_dev_release(struct device *dev)
{
	struct rivos_pwc_dvsec_dev *rpd_dev = dev_to_rpd_dev(dev);

	rivos_pwc_dvsec_dev_free(rpd_dev);
}

static int rivos_pwc_dvsec_add_aux(struct pci_dev *pdev,
				   struct rivos_pwc *pwc,
				   struct rivos_pwc_dvsec_dev *rpd_dev,
				   const char *name)
{
	struct auxiliary_device *auxdev = &rpd_dev->auxdev;
	int ret;

	ret = ida_alloc(&pwc->auxdev_ida, GFP_KERNEL);
	if (ret < 0) {
		kfree(rpd_dev);
		return ret;
	}

	auxdev->id = ret;
	auxdev->name = name;
	auxdev->dev.parent = &pdev->dev;
	auxdev->dev.release = rivos_pwc_dev_release;

	ret = auxiliary_device_init(auxdev);
	if (ret < 0) {
		rivos_pwc_dvsec_dev_free(rpd_dev);
		return ret;
	}

	ret = auxiliary_device_add(auxdev);
	if (ret < 0) {
		auxiliary_device_uninit(auxdev);
		return ret;
	}

	ret = devm_add_action_or_reset(&pdev->dev, rivos_pwc_dvsec_remove_aux,
				       auxdev);
	if (ret < 0)
		return ret;

	return 0;
}

static int rivos_pwc_dvsec_add_dev(struct pci_dev *pdev,
				   struct rivos_pwc_dvsec_header *header,
				   struct rivos_pwc *pwc)
{
	struct rivos_pwc_dvsec_dev *rpd_dev = NULL;
	const struct rivos_pwc_dvsec_desc *desc;

	desc = rivos_dvsec_get_desc(header->dev_id);
	if (!desc)
		return -EINVAL;

	dev_dbg(&pdev->dev, "Got drv name %s for dvsec %x, bar %d, offset 0x%x\n",
		desc->name, header->dev_id, header->bar, header->mmio_offset);

	rpd_dev = kzalloc(sizeof(*rpd_dev), GFP_KERNEL);
	if (!rpd_dev)
		return -ENOMEM;

	rpd_dev->resource.start = pdev->resource[header->bar].start +
				  header->mmio_offset;
	rpd_dev->resource.end = rpd_dev->resource.start + desc->reg_size - 1;
	rpd_dev->resource.flags = IORESOURCE_MEM;
	rpd_dev->pwc = pwc;
	rpd_dev->rpd_dev = desc;

	if (desc->it_index >= 0)
		rpd_dev->irq = pci_irq_vector(pdev, desc->it_index);

	return rivos_pwc_dvsec_add_aux(pdev, pwc, rpd_dev, desc->name);
}

static int rivos_pwc_probe_dvsec(struct pci_dev *pdev,
				 struct rivos_pwc *pwc)
{
	int pos = 0;

	do {
		struct rivos_pwc_dvsec_header header;
		u16 vid;
		u8 rev;
		u32 hdr;
		int ret;

		pos = pci_find_next_ext_capability(pdev, pos,
						   PCI_EXT_CAP_ID_DVSEC);
		if (!pos)
			break;

		pci_read_config_dword(pdev, pos + PCI_DVSEC_HEADER1, &hdr);
		vid = PCI_DVSEC_HEADER1_VID(hdr);
		if (vid != PCI_VENDOR_ID_RIVOS)
			continue;

		rev = PCI_DVSEC_HEADER1_REV(hdr);
		if (rev != RIVOS_PWC_DVSEC_REV) {
			dev_dbg(&pdev->dev,
				"Unsupported revision of DVSEC resource\n");
			continue;
		}

		pci_read_config_dword(pdev, pos + RIVOS_PWC_DVSEC_HEADER, &hdr);
		header.bar = RIVOS_PWC_DVSEC_HEADER_BAR(hdr);
		header.mmio_offset = RIVOS_PWC_DVSEC_HEADER_MMIO(hdr);

		pci_read_config_dword(pdev, pos + PCI_DVSEC_HEADER2, &hdr);
		header.dev_id = PCI_DVSEC_HEADER2_ID(hdr);

		ret = rivos_pwc_dvsec_add_dev(pdev, &header, pwc);
		if (ret)
			continue;

	} while (true);

	return 0;
}

static void rivos_pwc_hw_init(struct rivos_pwc *pwc)
{
	u32 reg = 0;
	int i;

	/* Clear pending interrupts */
	iowrite32(MISC_INTR_PENDING_MASK,
		  pwc->base + MISC_INTR_PENDING_OFFSET);

	/* Set a different MSIx interrupt for each DVSEC component */
	for (i = 0; i < MISC_INTR_COUNT; i++)
		reg |= (i << i * MISC_INTR_ROUTING_STRIDE);

	iowrite32(reg, pwc->base + MISC_INTR_ROUTING_OFFSET);

	reg = ioread32(pwc->base + MISC_DEVICE_ID_MAPPING_OFFSET);
	pwc->chiplet_id = FIELD_GET(MISC_DEVICE_ID_CHIPLET_ID, reg);
	pwc->soc_id = FIELD_GET(MISC_DEVICE_ID_SOC_ID, reg);
	pwc->chiplet_type = FIELD_GET(MISC_DEVICE_ID_CHIPLET_TYPE, reg);
	pwc->soc_config = FIELD_GET(MISC_DEVICE_ID_SOC_CONFIG, reg);
}

static int rivos_pwc_pci_probe(struct pci_dev *pdev,
			       const struct pci_device_id *id)
{
	struct rivos_pwc *pwc;
	struct device *dev = &pdev->dev;
	int ret;

	ret = pcim_enable_device(pdev);
	if (ret)
		return ret;

	pwc = devm_kzalloc(dev, sizeof(*pwc), GFP_KERNEL);
	if (!pwc)
		return -ENOMEM;

	pwc->base = pcim_iomap(pdev, 0, pci_resource_len(pdev, 0));
	if (!pwc->base)
		return dev_err_probe(dev, -ENOMEM, "pcim_iomap failed\n");

	ret = pci_alloc_irq_vectors(pdev, 8, 8, PCI_IRQ_MSIX);
	if (ret != 8)
		return dev_err_probe(dev, ret, "pci_alloc_irq_vectors failed\n");

	ida_init(&pwc->auxdev_ida);
	spin_lock_init(&pwc->lock);
 	pci_set_drvdata(pdev, pwc);

	rivos_pwc_hw_init(pwc);

	return rivos_pwc_probe_dvsec(pdev, pwc);
}

static const struct pci_device_id rivos_pwc_pci_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_RIVOS, PCI_DEVICE_ID_RIVOS_PWC) },
	{ }
};
MODULE_DEVICE_TABLE(pci, rivos_pwc_pci_ids);

static struct pci_driver rivos_pwc_pci_driver = {
	.dev_groups = pwc_groups,
	.name = "rivos_pwc",
	.id_table = rivos_pwc_pci_ids,
	.probe = rivos_pwc_pci_probe,
};
module_pci_driver(rivos_pwc_pci_driver);

MODULE_AUTHOR("Clément Léger <cleger@rivosinc.com>");
MODULE_DESCRIPTION("Rivos PWC PCIe auxiliary bus driver");
MODULE_LICENSE("GPL");

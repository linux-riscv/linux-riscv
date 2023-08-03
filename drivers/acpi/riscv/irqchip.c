// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023, Ventana Micro Systems Inc
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 *
 */

#include <linux/acpi.h>
#include <linux/fwnode.h>
#include <linux/irqdomain.h>
#include <linux/list.h>
#include <linux/msi.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include "../../../drivers/pci/pci.h"

struct riscv_irqchip_list {
	struct fwnode_handle *fwnode;
	struct list_head list;
};

LIST_HEAD(rintc_list);

static struct fwnode_handle *imsic_acpi_fwnode;

LIST_HEAD(aplic_list);

LIST_HEAD(plic_list);

static int acpi_rintc_create_irqchip_fwnode(struct acpi_madt_rintc *rintc)
{
	struct property_entry props[7] = {};
	struct fwnode_handle *fwnode;
	struct riscv_irqchip_list *rintc_element;

	props[0] = PROPERTY_ENTRY_U32("version", rintc->version);
	props[1] = PROPERTY_ENTRY_U64("hartid", rintc->hart_id);
	props[2] = PROPERTY_ENTRY_U32("acpi_uid", rintc->uid);
	props[3] = PROPERTY_ENTRY_U32("ext_intc_id", rintc->ext_intc_id);
	props[4] = PROPERTY_ENTRY_U64("imsic_addr", rintc->imsic_addr);
	props[5] = PROPERTY_ENTRY_U32("imsic_size", rintc->imsic_size);
	props[6] = PROPERTY_ENTRY_U32("#interrupt-cells", 1);

	fwnode = fwnode_create_software_node_early(props, NULL);
	if (fwnode) {
		rintc_element = kzalloc(sizeof(*rintc_element), GFP_KERNEL);
		if (!rintc_element) {
			return -ENOMEM;
		}

		rintc_element->fwnode = fwnode;
		list_add_tail(&rintc_element->list, &rintc_list);
	}

	return fwnode ? 0 : -ENODEV;
}

struct fwnode_handle *acpi_rintc_get_fwnode(u32 uid)
{
	struct riscv_irqchip_list *rintc_element;
	struct list_head *i, *tmp;
	struct fwnode_handle *fwnode;
	u32 acpi_id;
	int rc;

	list_for_each_safe(i, tmp, &rintc_list) {
		rintc_element = list_entry(i, struct riscv_irqchip_list, list);
		fwnode = rintc_element->fwnode;
		rc = fwnode_property_read_u32_array(fwnode, "acpi_uid", &acpi_id, 1);
		if (!rc && acpi_id == uid)
			return fwnode;
	}

	return NULL;
}

static struct fwnode_handle *acpi_imsic_get_rintc_fwnode(u32 idx)
{
	struct riscv_irqchip_list *rintc_element;
	struct fwnode_handle *fwnode;
	struct list_head *i, *tmp;
	unsigned int j = 0;

	list_for_each_safe(i, tmp, &rintc_list) {
		rintc_element = list_entry(i, struct riscv_irqchip_list, list);
		fwnode = rintc_element->fwnode;

		if (j == idx)
			return fwnode;

		j++;
	}

	return NULL;
}

static int acpi_imsic_create_fwnode(struct acpi_madt_imsic *imsic)
{
	struct property_entry props[7] = {};
	struct software_node_ref_args *refs;
	struct fwnode_handle *parent_fwnode;
	unsigned int nr_rintc, i;

	props[0] = PROPERTY_ENTRY_U32("riscv,guest-index-bits", imsic->guest_index_bits);
	props[1] = PROPERTY_ENTRY_U32("riscv,hart-index-bits", imsic->hart_index_bits);
	props[2] = PROPERTY_ENTRY_U32("riscv,group-index-bits", imsic->group_index_bits);
	props[3] = PROPERTY_ENTRY_U32("riscv,group-index-shift", imsic->group_index_shift);
	props[4] = PROPERTY_ENTRY_U32("riscv,num-ids", imsic->num_ids);
	props[5] = PROPERTY_ENTRY_U32("riscv,num-guest-ids", imsic->num_guest_ids);

	nr_rintc = list_count_nodes(&rintc_list);
	refs = kzalloc(sizeof(*refs) * nr_rintc, GFP_KERNEL);
	for (i = 0; i < nr_rintc; i++) {
		parent_fwnode = acpi_imsic_get_rintc_fwnode(i);
		refs[i] = SOFTWARE_NODE_REFERENCE(to_software_node(parent_fwnode), RV_IRQ_EXT);
	}
	props[6] = PROPERTY_ENTRY_REF_ARRAY_LEN("interrupts-extended", refs, nr_rintc);

	imsic_acpi_fwnode = fwnode_create_software_node_early(props, NULL);

	return imsic_acpi_fwnode ? 0 : -1;
}

struct fwnode_handle *acpi_riscv_get_msi_fwnode(struct device *dev)
{
	return imsic_acpi_fwnode;
}

/*
 * the ext_intc_id format is as follows:
 * Bits [31:24] APLIC/PLIC ID
 * Bits [15:0] APLIC IDC ID / PLIC S-Mode Context ID for this hart
 */
#define APLIC_PLIC_ID(x) (x >> 24)
#define IDC_CONTEXT_ID(x) (x & 0x0000ffff)

static struct fwnode_handle *acpi_ext_intc_get_rintc_fwnode(u8 aplic_plic_id, u16 index)
{
	struct riscv_irqchip_list *rintc_element;
	struct fwnode_handle *fwnode;
	struct list_head *i, *tmp;
	u32 id;
	int rc;

	list_for_each_safe(i, tmp, &rintc_list) {
		rintc_element = list_entry(i, struct riscv_irqchip_list, list);
		fwnode = rintc_element->fwnode;
		rc = fwnode_property_read_u32_array(fwnode, "ext_intc_id", &id, 1);
		if (rc)
			continue;

		if ((APLIC_PLIC_ID(id) == aplic_plic_id) && (IDC_CONTEXT_ID(id) == index))
			return fwnode;
	}

	return NULL;
}

static int acpi_aplic_create_fwnode(struct acpi_madt_aplic *aplic)
{
	struct property_entry props[7];
	struct fwnode_handle *fwnode, *parent_fwnode;
	struct riscv_irqchip_list *aplic_element;
	struct software_node_ref_args *refs;
	unsigned int i;

	props[0] = PROPERTY_ENTRY_U32("riscv,gsi-base", aplic->gsi_base);
	props[1] = PROPERTY_ENTRY_U32("riscv,num-sources", aplic->num_sources);
	props[2] = PROPERTY_ENTRY_U32("riscv,num-idcs", aplic->num_idcs);
	props[3] = PROPERTY_ENTRY_U32("riscv,aplic-id", aplic->id);
	props[4] = PROPERTY_ENTRY_U64("riscv,aplic-base", aplic->base_addr);
	props[5] = PROPERTY_ENTRY_U32("riscv,aplic-size", aplic->size);
	if (aplic->num_idcs) {
		refs = kzalloc(sizeof(*refs) * aplic->num_idcs, GFP_KERNEL);
		for (i = 0; i < aplic->num_idcs; i++) {
			parent_fwnode = acpi_ext_intc_get_rintc_fwnode(aplic->id, i);
			refs[i] = SOFTWARE_NODE_REFERENCE(to_software_node(parent_fwnode), RV_IRQ_EXT);
		}
		props[6] = PROPERTY_ENTRY_REF_ARRAY_LEN("interrupts-extended", refs, aplic->num_idcs);
	} else {
		props[6] = PROPERTY_ENTRY_BOOL("msi-parent");

	}

	fwnode = fwnode_create_software_node_early(props, NULL);

	if (fwnode) {
		aplic_element = kzalloc(sizeof(*aplic_element), GFP_KERNEL);
		if (!aplic_element) {
			return -1;
		}

		aplic_element->fwnode = fwnode;
		list_add_tail(&aplic_element->list, &aplic_list);
	}

	return (fwnode) ? 0 : -1;
}

static int __init rintc_parse_madt_swnode(union acpi_subtable_headers *header,
					  const unsigned long end)
{
	struct acpi_madt_rintc *rintc = (struct acpi_madt_rintc *)header;

	return acpi_rintc_create_irqchip_fwnode(rintc);
}

static int __init imsic_parse_madt_fwnode(union acpi_subtable_headers *header,
					  const unsigned long end)
{
	struct acpi_madt_imsic *imsic = (struct acpi_madt_imsic *)header;

	return acpi_imsic_create_fwnode(imsic);
}

static int __init aplic_parse_madt_fwnode(union acpi_subtable_headers *header,
					  const unsigned long end)
{
	struct acpi_madt_aplic *aplic = (struct acpi_madt_aplic *)header;

	return acpi_aplic_create_fwnode(aplic);
}

void __init acpi_init_irqchip_fwnodes(void)
{
	acpi_table_parse_madt(ACPI_MADT_TYPE_RINTC, rintc_parse_madt_swnode, 0);
	acpi_table_parse_madt(ACPI_MADT_TYPE_IMSIC, imsic_parse_madt_fwnode, 1);
	acpi_table_parse_madt(ACPI_MADT_TYPE_APLIC, aplic_parse_madt_fwnode, 0);
}

static struct fwnode_handle *aplic_get_gsi_domain_id(u32 gsi)
{
	struct riscv_irqchip_list *aplic_element;
	struct list_head *i, *tmp;
	struct fwnode_handle *fwnode;
	int rc;
	u32 gsi_base;
	u32 nr_irqs;

	list_for_each_safe(i, tmp, &aplic_list) {
		aplic_element = list_entry(i, struct riscv_irqchip_list, list);
		fwnode = aplic_element->fwnode;
		rc = fwnode_property_read_u32_array(fwnode, "riscv,gsi-base", &gsi_base, 1);
		rc = fwnode_property_read_u32_array(fwnode, "riscv,num-sources", &nr_irqs, 1);
		if ((!rc) && (gsi >= gsi_base && gsi < gsi_base + nr_irqs))
			return fwnode;
	}

	return NULL;
}

static u32 aplic_gsi_to_irq(u32 gsi)
{
	return acpi_register_gsi(NULL, gsi, ACPI_LEVEL_SENSITIVE, ACPI_ACTIVE_HIGH);
}

static int __init aplic_create_platform_device(struct fwnode_handle *fwnode)
{
	struct platform_device *pdev;
	struct irq_domain *msi_domain = NULL;
	struct fwnode_handle *msi_fwnode;
	struct resource *res;
	u64 aplic_base;
	u32 aplic_size, aplic_id;
	int ret;

	if (!fwnode)
		return -ENODEV;

	ret = fwnode_property_read_u64_array(fwnode, "riscv,aplic-base", &aplic_base, 1);
	if (ret)
		return -ENODEV;

	ret = fwnode_property_read_u32_array(fwnode, "riscv,aplic-size", &aplic_size, 1);
	if (ret)
		return -ENODEV;

	ret = fwnode_property_read_u32_array(fwnode, "riscv,aplic-id", &aplic_id, 1);
	if (ret)
		return -ENODEV;

	pdev = platform_device_alloc("riscv-aplic", aplic_id);
	if (!pdev)
		return -ENOMEM;

	res = kcalloc(1, sizeof(*res), GFP_KERNEL);
	if (!res) {
		ret = -ENOMEM;
		goto dev_put;
	}

	res->start = aplic_base;
	res->end = res->start + aplic_size - 1;
	res->flags = IORESOURCE_MEM;
	ret = platform_device_add_resources(pdev, res, 1);
	/*
	 * Resources are duplicated in platform_device_add_resources,
	 * free their allocated memory
	 */
	kfree(res);

	pdev->dev.fwnode = fwnode;
	msi_fwnode = acpi_riscv_get_msi_fwnode(&pdev->dev);
	if (msi_fwnode)
		msi_domain = irq_find_matching_fwnode(msi_fwnode, DOMAIN_BUS_PLATFORM_MSI);

	if (msi_domain)
		dev_set_msi_domain(&pdev->dev, msi_domain);
	else
		pci_no_msi();

	ret = platform_device_add(pdev);
	if (ret)
		goto dev_put;

	return 0;

dev_put:
	if (res)
		kfree(res);

	platform_device_put(pdev);

	return ret;
}

void __init riscv_acpi_aplic_platform_init(void)
{
	struct riscv_irqchip_list *aplic_element;
	struct list_head *i, *tmp;
	struct fwnode_handle *fwnode;

	list_for_each_safe(i, tmp, &aplic_list) {
		aplic_element = list_entry(i, struct riscv_irqchip_list, list);
		fwnode = aplic_element->fwnode;
		aplic_create_platform_device(fwnode);
	}
	acpi_set_irq_model(ACPI_IRQ_MODEL_APLIC, aplic_get_gsi_domain_id);
	acpi_set_gsi_to_irq_fallback(aplic_gsi_to_irq);
}

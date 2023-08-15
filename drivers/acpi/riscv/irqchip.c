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

struct fwnode_handle *acpi_rintc_create_irqchip_fwnode(struct acpi_madt_rintc *rintc)
{
	struct property_entry props[6] = {};
	struct fwnode_handle *fwnode;
	struct riscv_irqchip_list *rintc_element;

	props[0] = PROPERTY_ENTRY_U64("hartid", rintc->hart_id);
	props[1] = PROPERTY_ENTRY_U32("riscv,ext-intc-id", rintc->ext_intc_id);
	props[2] = PROPERTY_ENTRY_U64("riscv,imsic-addr", rintc->imsic_addr);
	props[3] = PROPERTY_ENTRY_U32("riscv,imsic-size", rintc->imsic_size);
	props[4] = PROPERTY_ENTRY_U32("#interrupt-cells", 1);

	fwnode = fwnode_create_software_node_early(props, NULL);
	if (fwnode) {
		rintc_element = kzalloc(sizeof(*rintc_element), GFP_KERNEL);
		if (!rintc_element) {
			fwnode_remove_software_node(fwnode);
			return NULL;
		}

		rintc_element->fwnode = fwnode;
		list_add_tail(&rintc_element->list, &rintc_list);
	}

	return fwnode;
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

struct fwnode_handle *acpi_imsic_create_fwnode(struct acpi_madt_imsic *imsic)
{
	struct property_entry props[8] = {};
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
	refs = kcalloc(nr_rintc, sizeof(*refs), GFP_KERNEL);
	if (!refs)
		return NULL;

	for (i = 0; i < nr_rintc; i++) {
		parent_fwnode = acpi_imsic_get_rintc_fwnode(i);
		refs[i] = SOFTWARE_NODE_REFERENCE(to_software_node(parent_fwnode), RV_IRQ_EXT);
	}
	props[6] = PROPERTY_ENTRY_REF_ARRAY_LEN("interrupts-extended", refs, nr_rintc);

	imsic_acpi_fwnode = fwnode_create_software_node_early(props, NULL);

	return imsic_acpi_fwnode;
}

struct fwnode_handle *acpi_riscv_get_msi_fwnode(struct device *dev)
{
	return imsic_acpi_fwnode;
}

void __init riscv_acpi_imsic_platform_init(void)
{
	struct platform_device *pdev;
	int ret;

	if (!acpi_riscv_get_msi_fwnode(NULL)) {
		pci_no_msi();
		return;
	}

	pdev = platform_device_alloc("riscv-imsic", 0);
	if (!pdev)
		return;

	pdev->dev.fwnode = acpi_riscv_get_msi_fwnode(NULL);
	ret = platform_device_add(pdev);
	if (ret)
		platform_device_put(pdev);
}

/*
 * The ext_intc_id format is as follows:
 * Bits [31:24] APLIC/PLIC ID
 * Bits [15:0] APLIC IDC ID / PLIC S-Mode Context ID for this hart
 */
#define APLIC_PLIC_ID(x) ((x) >> 24)
#define IDC_CONTEXT_ID(x) ((x) & 0x0000ffff)

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
		rc = fwnode_property_read_u32_array(fwnode, "riscv,ext-intc-id", &id, 1);
		if (rc)
			continue;

		if ((APLIC_PLIC_ID(id) == aplic_plic_id) && (IDC_CONTEXT_ID(id) == index))
			return fwnode;
	}

	return NULL;
}

static struct fwnode_handle *acpi_aplic_create_fwnode(struct acpi_madt_aplic *aplic)
{
	struct fwnode_handle *fwnode, *parent_fwnode;
	struct riscv_irqchip_list *aplic_element;
	struct software_node_ref_args *refs;
	struct property_entry props[8] = {};
	unsigned int i;

	props[0] = PROPERTY_ENTRY_U32("riscv,gsi-base", aplic->gsi_base);
	props[1] = PROPERTY_ENTRY_U32("riscv,num-sources", aplic->num_sources);
	props[2] = PROPERTY_ENTRY_U32("riscv,num-idcs", aplic->num_idcs);
	props[3] = PROPERTY_ENTRY_U32("riscv,aplic-id", aplic->id);
	props[4] = PROPERTY_ENTRY_U64("riscv,aplic-base", aplic->base_addr);
	props[5] = PROPERTY_ENTRY_U32("riscv,aplic-size", aplic->size);
	if (aplic->num_idcs) {
		refs = kcalloc(aplic->num_idcs, sizeof(*refs), GFP_KERNEL);
		if (!refs)
			return NULL;

		for (i = 0; i < aplic->num_idcs; i++) {
			parent_fwnode = acpi_ext_intc_get_rintc_fwnode(aplic->id, i);
			refs[i] = SOFTWARE_NODE_REFERENCE(to_software_node(parent_fwnode),
							  RV_IRQ_EXT);
		}
		props[6] = PROPERTY_ENTRY_REF_ARRAY_LEN("interrupts-extended",
							refs, aplic->num_idcs);
	} else {
		props[6] = PROPERTY_ENTRY_BOOL("msi-parent");
	}

	fwnode = fwnode_create_software_node_early(props, NULL);

	if (fwnode) {
		aplic_element = kzalloc(sizeof(*aplic_element), GFP_KERNEL);
		if (!aplic_element) {
			fwnode_remove_software_node(fwnode);
			return NULL;
		}

		aplic_element->fwnode = fwnode;
		list_add_tail(&aplic_element->list, &aplic_list);
	}

	return fwnode;
}

static struct fwnode_handle *aplic_get_gsi_domain_id(u32 gsi)
{
	struct riscv_irqchip_list *aplic_element;
	struct fwnode_handle *fwnode;
	struct list_head *i, *tmp;
	u32 gsi_base;
	u32 nr_irqs;
	int rc;

	list_for_each_safe(i, tmp, &aplic_list) {
		aplic_element = list_entry(i, struct riscv_irqchip_list, list);
		fwnode = aplic_element->fwnode;
		rc = fwnode_property_read_u32_array(fwnode, "riscv,gsi-base", &gsi_base, 1);
		if (!rc) {
			rc = fwnode_property_read_u32_array(fwnode, "riscv,num-sources",
							    &nr_irqs, 1);
			if (!rc && (gsi >= gsi_base && gsi < gsi_base + nr_irqs))
				return fwnode;
		}
	}

	return NULL;
}

static u32 __init aplic_gsi_to_irq(u32 gsi)
{
	return acpi_register_gsi(NULL, gsi, ACPI_LEVEL_SENSITIVE, ACPI_ACTIVE_HIGH);
}

static int __init aplic_create_platform_device(struct fwnode_handle *fwnode)
{
	struct platform_device *pdev;
	u32 aplic_size, aplic_id;
	struct resource *res;
	u64 aplic_base;
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
	ret = platform_device_add(pdev);
	if (ret)
		goto dev_put;

	return 0;

dev_put:
	platform_device_put(pdev);
	return ret;
}

static int __init aplic_parse_madt(union acpi_subtable_headers *header,
				   const unsigned long end)
{
	struct acpi_madt_aplic *aplic = (struct acpi_madt_aplic *)header;
	struct fwnode_handle *fwnode;

	fwnode = acpi_aplic_create_fwnode(aplic);
	if (fwnode)
		aplic_create_platform_device(fwnode);

	return 0;
}

void __init riscv_acpi_aplic_platform_init(void)
{
	if (acpi_table_parse_madt(ACPI_MADT_TYPE_APLIC, aplic_parse_madt, 0) > 0) {
		acpi_set_irq_model(ACPI_IRQ_MODEL_APLIC, aplic_get_gsi_domain_id);
		acpi_set_gsi_to_irq_fallback(aplic_gsi_to_irq);
	}
}

static int acpi_plic_get_nr_contexts(u8 plic_id)
{
	struct riscv_irqchip_list *rintc_element;
	struct fwnode_handle *fwnode;
	struct list_head *i, *tmp;
	u32 id;
	int rc, nr_contexts = 0;

	list_for_each_safe(i, tmp, &rintc_list) {
		rintc_element = list_entry(i, struct riscv_irqchip_list, list);
		fwnode = rintc_element->fwnode;
		rc = fwnode_property_read_u32_array(fwnode, "riscv,ext-intc-id", &id, 1);
		if (rc)
			continue;

		if (APLIC_PLIC_ID(id) == plic_id)
			nr_contexts++;
	}

	return nr_contexts * 2;
}

int acpi_plic_get_context_id(u8 plic_id, u16 idx)
{
	struct riscv_irqchip_list *rintc_element;
	struct fwnode_handle *fwnode;
	struct list_head *i, *tmp;
	u32 id;
	int rc, nr_contexts = -1;

	list_for_each_safe(i, tmp, &rintc_list) {
		rintc_element = list_entry(i, struct riscv_irqchip_list, list);
		fwnode = rintc_element->fwnode;
		rc = fwnode_property_read_u32_array(fwnode, "riscv,ext-intc-id", &id, 1);
		if (rc)
			continue;

		if (APLIC_PLIC_ID(id) == plic_id)
			nr_contexts++;
		if (nr_contexts == idx)
			return IDC_CONTEXT_ID(id);
	}

	return -1;
}

static struct fwnode_handle *acpi_plic_create_fwnode(struct acpi_madt_plic *plic)
{
	struct fwnode_handle *fwnode, *parent_fwnode;
	struct riscv_irqchip_list *plic_element;
	struct software_node_ref_args *refs;
	struct property_entry props[8] = {};
	int nr_contexts;

	props[0] = PROPERTY_ENTRY_U32("riscv,gsi-base", plic->gsi_base);
	props[1] = PROPERTY_ENTRY_U32("riscv,ndev", plic->num_irqs);
	props[2] = PROPERTY_ENTRY_U32("riscv,max_prio", plic->max_prio);
	props[3] = PROPERTY_ENTRY_U8("riscv,plic-id", plic->id);
	props[4] = PROPERTY_ENTRY_U64("riscv,plic-base", plic->base_addr);
	props[5] = PROPERTY_ENTRY_U32("riscv,plic-size", plic->size);

	nr_contexts = acpi_plic_get_nr_contexts(plic->id);
	if (nr_contexts) {
		refs = kcalloc(nr_contexts, sizeof(*refs), GFP_KERNEL);
		for (int i = 0; i < nr_contexts / 2; i++) {
			int context_id = acpi_plic_get_context_id(plic->id, i);

			parent_fwnode = acpi_ext_intc_get_rintc_fwnode(plic->id, context_id);
			refs[2 * i] = SOFTWARE_NODE_REFERENCE(to_software_node(parent_fwnode), 0);
			refs[2 * i + 1] = SOFTWARE_NODE_REFERENCE(to_software_node(parent_fwnode),
								  RV_IRQ_EXT);
		}
		props[6] = PROPERTY_ENTRY_REF_ARRAY_LEN("interrupts-extended", refs, nr_contexts);
	}

	fwnode = fwnode_create_software_node_early(props, NULL);

	if (fwnode) {
		plic_element = kzalloc(sizeof(*plic_element), GFP_KERNEL);
		if (!plic_element) {
			fwnode_remove_software_node(fwnode);
			return NULL;
		}

		plic_element->fwnode = fwnode;
		list_add_tail(&plic_element->list, &plic_list);
	}

	return fwnode;
}

static struct fwnode_handle *plic_get_gsi_domain_id(u32 gsi)
{
	struct riscv_irqchip_list *plic_element;
	struct fwnode_handle *fwnode;
	struct list_head *i, *tmp;
	u32 gsi_base;
	u32 nr_irqs;
	int rc;

	list_for_each_safe(i, tmp, &plic_list) {
		plic_element = list_entry(i, struct riscv_irqchip_list, list);
		fwnode = plic_element->fwnode;
		rc = fwnode_property_read_u32_array(fwnode, "riscv,gsi-base", &gsi_base, 1);
		if (!rc) {
			rc = fwnode_property_read_u32_array(fwnode, "riscv,ndev", &nr_irqs, 1);
			if (!rc && (gsi >= gsi_base && gsi < gsi_base + nr_irqs))
				return fwnode;
		}
	}

	return NULL;
}

static u32 plic_gsi_to_irq(u32 gsi)
{
	return acpi_register_gsi(NULL, gsi, ACPI_LEVEL_SENSITIVE, ACPI_ACTIVE_HIGH);
}

static int __init plic_create_platform_device(struct fwnode_handle *fwnode)
{
	struct platform_device *pdev;
	u32 plic_size;
	u8  plic_id;
	struct resource *res;
	u64 plic_base;
	int ret;

	if (!fwnode)
		return -ENODEV;

	ret = fwnode_property_read_u64_array(fwnode, "riscv,plic-base", &plic_base, 1);
	if (ret)
		return -ENODEV;

	ret = fwnode_property_read_u32_array(fwnode, "riscv,plic-size", &plic_size, 1);
	if (ret)
		return -ENODEV;

	ret = fwnode_property_read_u8_array(fwnode, "riscv,plic-id", &plic_id, 1);
	if (ret)
		return -ENODEV;

	pdev = platform_device_alloc("riscv-plic", plic_id);
	if (!pdev)
		return -ENOMEM;

	res = kcalloc(1, sizeof(*res), GFP_KERNEL);
	if (!res) {
		ret = -ENOMEM;
		goto dev_put;
	}

	res->start = plic_base;
	res->end = res->start + plic_size - 1;
	res->flags = IORESOURCE_MEM;
	ret = platform_device_add_resources(pdev, res, 1);
	/*
	 * Resources are duplicated in platform_device_add_resources,
	 * free their allocated memory
	 */
	kfree(res);

	pdev->dev.fwnode = fwnode;
	ret = platform_device_add(pdev);
	if (ret)
		goto dev_put;

	return 0;

dev_put:
	platform_device_put(pdev);
	return ret;
}

static int __init plic_parse_madt(union acpi_subtable_headers *header,
				  const unsigned long end)
{
	struct acpi_madt_plic *plic = (struct acpi_madt_plic *)header;
	struct fwnode_handle *fwnode;

	fwnode = acpi_plic_create_fwnode(plic);
	if (fwnode)
		plic_create_platform_device(fwnode);

	return 0;
}

void __init riscv_acpi_plic_platform_init(void)
{
	if (acpi_table_parse_madt(ACPI_MADT_TYPE_PLIC, plic_parse_madt, 0) > 0) {
		acpi_set_irq_model(ACPI_IRQ_MODEL_PLIC, plic_get_gsi_domain_id);
		acpi_set_gsi_to_irq_fallback(plic_gsi_to_irq);
	}
}

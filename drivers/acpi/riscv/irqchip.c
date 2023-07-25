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
#include <linux/property.h>

struct riscv_irqchip_list {
	struct fwnode_handle *fwnode;
	struct list_head list;
};

LIST_HEAD(rintc_list);

static struct fwnode_handle *imsic_acpi_fwnode;

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

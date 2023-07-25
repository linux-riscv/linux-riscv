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

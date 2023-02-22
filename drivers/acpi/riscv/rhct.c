// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022-2023, Ventana Micro Systems Inc
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 *
 */

#define pr_fmt(fmt)	"ACPI: RHCT: " fmt

#include <linux/acpi.h>

static void acpi_rhct_warn_missing(void)
{
	pr_warn_once("No RHCT table found\n");
}

static struct acpi_table_header *acpi_get_rhct(void)
{
	static struct acpi_table_header *rhct;
	acpi_status status;

	/*
	 * RHCT will be used at runtime on every CPU, so we
	 * don't need to call acpi_put_table() to release the table mapping.
	 */
	if (!rhct) {
		status = acpi_get_table(ACPI_SIG_RHCT, 0, &rhct);
		if (ACPI_FAILURE(status))
			acpi_rhct_warn_missing();
	}

	return rhct;
}

/*
 * During early boot, the caller should call acpi_get_table() and pass its pointer to
 * these functions(and free up later). At run time, since this table can be used
 * multiple times, pass NULL so that the table remains in memory
 */
int acpi_get_riscv_isa(struct acpi_table_header *table, unsigned int acpi_cpu_id, const char **isa)
{
	struct acpi_rhct_node_header *node, *ref_node, *end;
	struct acpi_table_rhct *rhct;
	struct acpi_rhct_hart_info *hart_info;
	struct acpi_rhct_isa_string *isa_node;
	u32 *hart_info_node_offset;
	int i, j;

	if (acpi_disabled) {
		pr_debug("%s: acpi is disabled\n", __func__);
		return -1;
	}

	if (!table) {
		rhct = (struct acpi_table_rhct *)acpi_get_rhct();
		if (!rhct)
			return -ENOENT;
	} else {
		rhct = (struct acpi_table_rhct *)table;
	}

	node = ACPI_ADD_PTR(struct acpi_rhct_node_header, rhct, rhct->node_offset);
	end = ACPI_ADD_PTR(struct acpi_rhct_node_header, rhct, rhct->header.length);

	for (i = 0; i < rhct->node_count; i++) {
		if (node >= end)
			break;
		switch (node->type) {
		case ACPI_RHCT_NODE_TYPE_HART_INFO:
			hart_info = ACPI_ADD_PTR(struct acpi_rhct_hart_info, node,
					sizeof(struct acpi_rhct_node_header));
			hart_info_node_offset = ACPI_ADD_PTR(u32, hart_info,
					sizeof(struct acpi_rhct_hart_info));
			if (acpi_cpu_id != hart_info->uid)
				break;
			for (j = 0; j < hart_info->num_offsets; j++) {
				ref_node = ACPI_ADD_PTR(struct acpi_rhct_node_header,
						rhct, hart_info_node_offset[j]);
				if (ref_node->type == ACPI_RHCT_NODE_TYPE_ISA_STRING) {
					isa_node = ACPI_ADD_PTR(struct acpi_rhct_isa_string,
							ref_node,
							sizeof(struct acpi_rhct_node_header));
					*isa = isa_node->isa;
					return 0;
				}
			}
			break;
		}
		node = ACPI_ADD_PTR(struct acpi_rhct_node_header, node, node->length);
	}

	return -1;
}

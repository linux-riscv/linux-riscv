// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023, Ventana Micro Systems Inc
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 *
 */

#include <linux/acpi.h>
#include <linux/irqdomain.h>
#include <linux/platform_device.h>
#include <linux/sort.h>

static int irqchip_cmp_func(const void *in0, const void *in1)
{
	struct acpi_probe_entry *elem0 = (struct acpi_probe_entry *)in0;
	struct acpi_probe_entry *elem1 = (struct acpi_probe_entry *)in1;

	return (elem0->type > elem1->type) - (elem0->type < elem1->type);
}

/*
 * RISC-V irqchips in MADT of ACPI spec are defined in the same order how
 * they should be probed. Since IRQCHIP_ACPI_DECLARE doesn't define any
 * order, this arch function will reorder the probe functions as per the
 * required order for the architecture.
 */
void arch_sort_irqchip_probe(struct acpi_probe_entry *ap_head, int nr)
{
	struct acpi_probe_entry *ape = ap_head;

	if (nr == 1 || !ACPI_COMPARE_NAMESEG(ACPI_SIG_MADT, ape->id))
		return;
	sort(ape, nr, sizeof(*ape), irqchip_cmp_func, NULL);
}

static int __init irqchip_add_platform_device(char *irqchip_name, u32 irqchip_id,
					      resource_size_t iomem_res_start,
					      resource_size_t iomem_res_size,
					      union acpi_subtable_headers *header)
{
	struct platform_device *pdev;
	struct fwnode_handle *fn;
	struct resource *res;
	int ret;

	fn = irq_domain_alloc_named_id_fwnode(irqchip_name, irqchip_id);
	if (!fn)
		return -ENOMEM;

	pdev = platform_device_alloc(irqchip_name, irqchip_id);
	if (!pdev) {
		irq_domain_free_fwnode(fn);
		return -ENOMEM;
	}

	res = kcalloc(1, sizeof(*res), GFP_KERNEL);
	if (!res) {
		irq_domain_free_fwnode(fn);
		platform_device_put(pdev);
		return -ENOMEM;
	}

	res->start = iomem_res_start;
	res->end = res->start + iomem_res_size - 1;
	res->flags = IORESOURCE_MEM;
	ret = platform_device_add_resources(pdev, res, 1);
	/*
	 * Resources are duplicated in platform_device_add_resources,
	 * free their allocated memory
	 */
	kfree(res);

	/*
	 * Add copy of aplic pointer so that platform driver get aplic details.
	 */
	ret = platform_device_add_data(pdev, &header, sizeof(header));
	if (ret) {
		irq_domain_free_fwnode(fn);
		platform_device_put(pdev);
		return ret;
	}

	pdev->dev.fwnode = fn;
	ret = platform_device_add(pdev);
	if (ret) {
		irq_domain_free_fwnode(fn);
		platform_device_put(pdev);
		return ret;
	}

	return 0;
}

static int __init aplic_parse_madt(union acpi_subtable_headers *header,
				   const unsigned long end)
{
	struct acpi_madt_aplic *aplic = (struct acpi_madt_aplic *)header;

	return irqchip_add_platform_device("riscv-aplic", aplic->id, aplic->base_addr,
					   aplic->size, header);
}

void __init riscv_acpi_aplic_platform_init(void)
{
	acpi_table_parse_madt(ACPI_MADT_TYPE_APLIC, aplic_parse_madt, 0);
}

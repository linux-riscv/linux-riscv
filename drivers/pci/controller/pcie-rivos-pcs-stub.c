// SPDX-License-Identifier: GPL-2.0
/*
 * Rivos PCS driver stub.
 *
 * WARNING: THIS IS FOR TESTING ONLY AND SHOULDN'T EVER RUN IN PRODUCTION.
 *  ___   ___    _  _  ___ _____   _   _ ___  ___ _____ ___ ___   _   __  __
 * |   \ / _ \  | \| |/ _ \_   _| | | | | _ \/ __|_   _| _ \ __| /_\ |  \/  |
 * | |) | (_) | | .` | (_) || |   | |_| |  _/\__ \ | | |   / _| / _ \| |\/| |
 * |___/ \___/  |_|\_|\___/ |_|    \___/|_|  |___/ |_| |_|_\___/_/ \_\_|  |_|
 *
 * Creates a PCI root bridge with memory regions etc. specified in command line
 * parameters. Intended for use with PCS hybrid simulation to help Linux find
 * PCS without having to adjust device tree / ACPI / firmware etc.
 */

#include <linux/irqdomain.h>
#include <linux/moduleparam.h>
#include <linux/of.h>
#include <linux/pci.h>
#include <linux/pci-ecam.h>
#include <linux/platform_device.h>

static struct resource rivos_pcs_stub_bus_range = {
	.start = 0,
	.end = 1,
	.flags = IORESOURCE_BUS,
	.name = "rivos-pcs-stub-bus-range",
};
static struct resource rivos_pcs_stub_ecam = {
	.flags = IORESOURCE_MEM,
	.name = "rivos-pcs-stub-ecam",
};
static struct resource rivos_pcs_stub_lmmio = {
	.flags = IORESOURCE_MEM,
	.name = "rivos-pcs-stub-lmmio",
};
static struct resource rivos_pcs_stub_hmmio = {
	.flags = IORESOURCE_MEM,
	.name = "rivos-pcs-stub-hmmio",
};
static u16 rivos_pcs_stub_pci_domain;

static struct platform_device *rivos_pcs_stub_pdev;

static int rivos_pcs_stub_resource_param_set(const char *val,
					     const struct kernel_param *kp)
{
	struct resource *res = kp->arg;
	int n;

	n = sscanf(val, "%llx-%llx", &res->start, &res->end);
	return (n == 2 && res->end > res->start) ? 0 : -EINVAL;
}

static int rivos_pcs_stub_resource_param_get(char *buffer,
					     const struct kernel_param *kp)
{
	struct resource *res = kp->arg;

	return snprintf(buffer, 4096, "%#llx-%#llx\n", res->start, res->end);
}

static const struct kernel_param_ops rivos_pcs_stub_resource_param_ops = {
	.set = rivos_pcs_stub_resource_param_set,
	.get = rivos_pcs_stub_resource_param_get,
};

module_param_cb(bus_range, &rivos_pcs_stub_resource_param_ops,
		&rivos_pcs_stub_bus_range, 0400);
module_param_cb(ecam, &rivos_pcs_stub_resource_param_ops, &rivos_pcs_stub_ecam,
		0400);
module_param_cb(lmmio, &rivos_pcs_stub_resource_param_ops,
		&rivos_pcs_stub_lmmio, 0400);
module_param_cb(hmmio, &rivos_pcs_stub_resource_param_ops,
		&rivos_pcs_stub_hmmio, 0400);
module_param_named(pci_domain, rivos_pcs_stub_pci_domain, ushort, 0400);

static int __init rivos_pcs_stub_init(void)
{
	struct device_node *imsic_node = NULL;
	struct pci_host_bridge *bridge = NULL;
	struct pci_config_window *cfg = NULL;
	struct irq_domain *irq_domain = NULL;
	struct device *dev = NULL;

	if (rivos_pcs_stub_ecam.end == 0)
		return 0;

	rivos_pcs_stub_pdev =
		platform_device_register_simple("rivos-pcs-stub", 0, NULL, 0);
	if (IS_ERR(rivos_pcs_stub_pdev))
		return PTR_ERR(rivos_pcs_stub_pdev);

	dev = &rivos_pcs_stub_pdev->dev;

	bridge = devm_pci_alloc_host_bridge(dev, 0);
	if (!bridge) {
		dev_warn(dev, "Failed to alloc host bridge!");
		return -ENOMEM;
	}

	pci_add_resource(&bridge->windows, &rivos_pcs_stub_bus_range);
	if (rivos_pcs_stub_lmmio.end > 0)
		pci_add_resource(&bridge->windows, &rivos_pcs_stub_lmmio);
	if (rivos_pcs_stub_hmmio.end > 0)
		pci_add_resource(&bridge->windows, &rivos_pcs_stub_hmmio);

	cfg = pci_ecam_create(dev, &rivos_pcs_stub_ecam,
			      &rivos_pcs_stub_bus_range, &pci_generic_ecam_ops);
	if (IS_ERR(cfg)) {
		dev_warn(dev, "Failed to create ECAM config window!");
		return PTR_ERR(cfg);
	}

	bridge->sysdata = cfg;
	bridge->ops = (struct pci_ops *)&pci_generic_ecam_ops.pci_ops;
	bridge->domain_nr = rivos_pcs_stub_pci_domain;

	/*
	 * This locates the first IMSIC MSI PCI IRQ domain we can find. This is
	 * good enough for now, but if anything more sophisticated is ever
	 * needed, we could alternatively configure via another parameter that
	 * identifies the IRQ domain in OF or ACPI.
	 */
	for_each_compatible_node(imsic_node, NULL, "riscv,imsics") {
		irq_domain =
			irq_find_matching_host(imsic_node, DOMAIN_BUS_PCI_MSI);
		if (irq_domain)
			break;
	}

	if (!irq_domain) {
		dev_warn(dev, "Failed to find IRQ domain!");
		return -ENODEV;
	}
	dev_set_msi_domain(&bridge->dev, irq_domain);

	return pci_host_probe(bridge);
}

device_initcall(rivos_pcs_stub_init);

MODULE_DESCRIPTION("Rivos PCS stub");
MODULE_LICENSE("GPL");

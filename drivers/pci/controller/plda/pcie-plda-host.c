// SPDX-License-Identifier: GPL-2.0
/*
 * PLDA PCIe XpressRich host controller driver
 *
 * Copyright (C) 2023 Microchip Co. Ltd
 *		      StarFive Co. Ltd.
 *
 * Author: Daire McNamara <daire.mcnamara@microchip.com>
 * Author: Minda Chen <minda.chen@starfivetech.com>
 */

#include <linux/irqchip/chained_irq.h>
#include <linux/irqdomain.h>
#include <linux/msi.h>
#include <linux/of_address.h>
#include <linux/of_pci.h>
#include <linux/pci_regs.h>
#include <linux/pci-ecam.h>
#include <linux/platform_device.h>

#include "pcie-plda.h"

irqreturn_t plda_event_handler(int irq, void *dev_id)
{
	return IRQ_HANDLED;
}

static u32 plda_get_events(struct plda_pcie_rp *port)
{
	u32 events, val, origin;

	origin = readl_relaxed(port->bridge_addr + ISTATUS_LOCAL);

	/* Error events and doorbell events */
	events = (origin >> A_ATR_EVT_POST_ERR_SHIFT) & 0xff;

	/* INTx events */
	if (origin & PM_MSI_INT_INTX_MASK)
		events |= BIT(EVENT_PM_MSI_INT_INTX);

	/* MSI event and sys events */
	val = (origin >> PM_MSI_INT_MSI_SHIFT) & 0xf;
	events |= val << EVENT_PM_MSI_INT_MSI;

	return events;
}

static u32 plda_hwirq_to_mask(int hwirq)
{
	u32 mask;

	if (hwirq < EVENT_PM_MSI_INT_INTX)
		mask = BIT(hwirq + A_ATR_EVT_POST_ERR_SHIFT);
	else if (hwirq == EVENT_PM_MSI_INT_INTX)
		mask = PM_MSI_INT_INTX_MASK;
	else
		mask = BIT(hwirq + PM_MSI_TO_MASK_OFFSET);

	return mask;
}

static void plda_ack_event_irq(struct irq_data *data)
{
	struct plda_pcie_rp *port = irq_data_get_irq_chip_data(data);

	writel_relaxed(plda_hwirq_to_mask(data->hwirq),
		       port->bridge_addr + ISTATUS_LOCAL);
}

static void plda_mask_event_irq(struct irq_data *data)
{
	struct plda_pcie_rp *port = irq_data_get_irq_chip_data(data);
	u32 mask, val;

	mask = plda_hwirq_to_mask(data->hwirq);

	raw_spin_lock(&port->lock);
	val = readl_relaxed(port->bridge_addr + IMASK_LOCAL);
	val &= ~mask;
	writel_relaxed(val, port->bridge_addr + IMASK_LOCAL);
	raw_spin_unlock(&port->lock);
}

static void plda_unmask_event_irq(struct irq_data *data)
{
	struct plda_pcie_rp *port = irq_data_get_irq_chip_data(data);
	u32 mask, val;

	mask = plda_hwirq_to_mask(data->hwirq);

	raw_spin_lock(&port->lock);
	val = readl_relaxed(port->bridge_addr + IMASK_LOCAL);
	val |= mask;
	writel_relaxed(val, port->bridge_addr + IMASK_LOCAL);
	raw_spin_unlock(&port->lock);
}

static struct irq_chip plda_event_irq_chip = {
	.name = "PLDA PCIe EVENT",
	.irq_ack = plda_ack_event_irq,
	.irq_mask = plda_mask_event_irq,
	.irq_unmask = plda_unmask_event_irq,
};

static int plda_pcie_event_map(struct irq_domain *domain, unsigned int irq,
			       irq_hw_number_t hwirq)
{
	irq_set_chip_and_handler(irq, &plda_event_irq_chip, handle_level_irq);
	irq_set_chip_data(irq, domain->host_data);

	return 0;
}

struct irq_domain_ops plda_evt_dom_ops = {
	.map = plda_pcie_event_map,
};

struct plda_event_ops plda_event_ops = {
	.get_events = plda_get_events,
};

void plda_pcie_setup_window(void __iomem *bridge_base_addr, u32 index,
			    phys_addr_t axi_addr, phys_addr_t pci_addr,
			    size_t size)
{
	u32 atr_sz = ilog2(size) - 1;
	u32 val;

	if (index == 0)
		val = PCIE_CONFIG_INTERFACE;
	else
		val = PCIE_TX_RX_INTERFACE;

	writel(val, bridge_base_addr + (index * ATR_ENTRY_SIZE) +
	       ATR0_AXI4_SLV0_TRSL_PARAM);

	val = lower_32_bits(axi_addr) | (atr_sz << ATR_SIZE_SHIFT) |
			    ATR_IMPL_ENABLE;
	writel(val, bridge_base_addr + (index * ATR_ENTRY_SIZE) +
	       ATR0_AXI4_SLV0_SRCADDR_PARAM);

	val = upper_32_bits(axi_addr);
	writel(val, bridge_base_addr + (index * ATR_ENTRY_SIZE) +
	       ATR0_AXI4_SLV0_SRC_ADDR);

	val = lower_32_bits(pci_addr);
	writel(val, bridge_base_addr + (index * ATR_ENTRY_SIZE) +
	       ATR0_AXI4_SLV0_TRSL_ADDR_LSB);

	val = upper_32_bits(pci_addr);
	writel(val, bridge_base_addr + (index * ATR_ENTRY_SIZE) +
	       ATR0_AXI4_SLV0_TRSL_ADDR_UDW);

	val = readl(bridge_base_addr + ATR0_PCIE_WIN0_SRCADDR_PARAM);
	val |= (ATR0_PCIE_ATR_SIZE << ATR0_PCIE_ATR_SIZE_SHIFT);
	writel(val, bridge_base_addr + ATR0_PCIE_WIN0_SRCADDR_PARAM);
	writel(0, bridge_base_addr + ATR0_PCIE_WIN0_SRC_ADDR);
}
EXPORT_SYMBOL_GPL(plda_pcie_setup_window);

int plda_pcie_setup_iomems(struct pci_host_bridge *bridge,
			   struct plda_pcie_rp *port)
{
	void __iomem *bridge_base_addr = port->bridge_addr;
	struct resource_entry *entry;
	u64 pci_addr;
	u32 index = 1;

	resource_list_for_each_entry(entry, &bridge->windows) {
		if (resource_type(entry->res) == IORESOURCE_MEM) {
			pci_addr = entry->res->start - entry->offset;
			plda_pcie_setup_window(bridge_base_addr, index,
					       entry->res->start, pci_addr,
					       resource_size(entry->res));
			index++;
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(plda_pcie_setup_iomems);

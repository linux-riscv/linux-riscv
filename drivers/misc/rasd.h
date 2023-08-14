/*
 * SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __RASD_H
#define __RASD_H

#include <linux/miscdevice.h>
#include <linux/types.h>

#define RASD_IRQ_COUNT 2

/* Per-instance hardware info */
struct rasd {
	struct pci_dev 		*pdev;
	void __iomem		*regs;
	void __iomem		*ddr;
	void __iomem		*hbm;

	int			irqs[RASD_IRQ_COUNT];
	int			instance;
	struct miscdevice	misc;
	/* Node on the isbdmex_list. */
	struct list_head	node;
};

#endif

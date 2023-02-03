/*
 * SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 * SPDX-License-Identifier: GPL-2.0-only
 */


#ifndef __ISBDMEX_H
#define __ISBDMEX_H


/* Per-instance hardware info */
struct isbdm {
	struct pci_dev 		*pdev;
	void __iomem		*base;
	int			irq;
	int			instance;
	struct miscdevice	misc;
};

/* Hardware-poking routines */

void	isbdmex_hw_reset(struct isbdm *ii);


#endif

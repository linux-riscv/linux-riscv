/*
 * SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __ISBDM_RASD_HORRORS_H
#define __ISBDM_RASD_HORRORS_H

/* RASD BAR offsets and sizes. */
#define RASD_CONTROL_BAR_IOVA 0x12000000000ull
#define RASD_CONTROL_BAR_SIZE 0x40000000
#define RASD_DDR_BAR_IOVA 0x200000000000ull
#define RASD_DDR_BAR_SIZE 0x10000000000ull
#define RASD_HBM_BAR_IOVA 0x10000000000ull
#define RASD_HBM_BAR_SIZE 0x2000000000ull

/* Define the number of non-admin doorbell pages. */
#define RASD_APP_DOORBELL_PAGES 16

#define IMSIC_DISABLE_EIDELIVERY		0
#define IMSIC_ENABLE_EIDELIVERY			1
#define IMSIC_DISABLE_EITHRESHOLD		1
#define IMSIC_ENABLE_EITHRESHOLD		0

#define vimsic_csr_write(__c, __v)		\
do {						\
	csr_write(CSR_VSISELECT, __c);		\
	csr_write(CSR_VSIREG, __v);		\
} while (0)

#define vimsic_csr_read(__c)			\
({						\
	unsigned long __v;			\
	csr_write(CSR_VSISELECT, __c);		\
	__v = csr_read(CSR_VSIREG);		\
	__v;					\
})

int isbdm_map_rasd_regions(struct isbdm *ii);
void isbdm_free_rasd_control(struct isbdm *ii);

#endif /* __ISBDM_RASD_HORRORS_H */

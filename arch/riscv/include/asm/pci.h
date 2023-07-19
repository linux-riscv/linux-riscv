/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2016 SiFive
 */

#ifndef _ASM_RISCV_PCI_H
#define _ASM_RISCV_PCI_H

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>

#include <asm/io.h>

#define PCIBIOS_MIN_IO		4
#define PCIBIOS_MIN_MEM		16

/* Generic PCI */
#include <asm-generic/pci.h>

#endif  /* _ASM_RISCV_PCI_H */

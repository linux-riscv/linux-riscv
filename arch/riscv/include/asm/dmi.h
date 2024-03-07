/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024 Intel Corporation
 *
 * based on arch/arm64/include/asm/dmi.h
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */

#ifndef __ASM_DMI_H
#define __ASM_DMI_H

#include <linux/io.h>
#include <linux/slab.h>

/*
 * According to section 2.3.6 of the UEFI spec, the firmware should not
 * request a virtual mapping for configuration tables such as SMBIOS.
 * This means we have to map them before use.
 */
#define dmi_early_remap(x, l)		ioremap_prot(x, l, _PAGE_KERNEL)
#define dmi_early_unmap(x, l)		iounmap(x)
#define dmi_remap(x, l)			ioremap_prot(x, l, _PAGE_KERNEL)
#define dmi_unmap(x)			iounmap(x)
#define dmi_alloc(l)			kzalloc(l, GFP_KERNEL)

#endif

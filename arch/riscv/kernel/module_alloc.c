// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Copyright (c) 2017 Zihao Yu
 *  Copyright (c) 2024 Jarkko Sakkinen
 */

#include <linux/mm.h>
#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
#include <asm/sections.h>

#if defined(CONFIG_MMU) && defined(CONFIG_64BIT)
void *module_alloc(unsigned long size)
{
	return __vmalloc_node_range(size, 1, MODULES_VADDR,
				    MODULES_END, GFP_KERNEL,
				    PAGE_KERNEL, 0, NUMA_NO_NODE,
				    __builtin_return_address(0));
}

void module_memfree(void *module_region)
{
	if (in_interrupt())
		pr_warn("In interrupt context: vmalloc may not work.\n");

	vfree(module_region);
}
#endif

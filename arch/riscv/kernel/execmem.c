// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/mm.h>
#include <linux/execmem.h>
#include <linux/vmalloc.h>
#include <asm/sections.h>

void *alloc_execmem(unsigned long size, gfp_t /* gfp */)
{
	return __vmalloc_node_range(size, 1, MODULES_VADDR,
				    MODULES_END, GFP_KERNEL,
				    PAGE_KERNEL, 0, NUMA_NO_NODE,
				    __builtin_return_address(0));
}

void free_execmem(void *region)
{
	if (in_interrupt())
		pr_warn("In interrupt context: vmalloc may not work.\n");

	vfree(region);
}

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_EXECMEM_H
#define _LINUX_EXECMEM_H

#ifdef CONFIG_HAVE_ALLOC_EXECMEM
void *alloc_execmem(unsigned long size, gfp_t gfp);
void free_execmem(void *region);
#else
#define alloc_execmem(size, gfp)	module_alloc(size)
#define free_execmem(region)		module_memfree(region)
#endif

#endif /* _LINUX_EXECMEM_H */

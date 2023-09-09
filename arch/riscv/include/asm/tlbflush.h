/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2009 Chen Liqin <liqin.chen@sunplusct.com>
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_TLBFLUSH_H
#define _ASM_RISCV_TLBFLUSH_H

#include <linux/mm_types.h>
#include <asm/smp.h>
#include <asm/errata_list.h>

#ifdef CONFIG_MMU
static inline void local_flush_tlb_all(void)
{
	__asm__ __volatile__ ("sfence.vma" : : : "memory");
}

static inline void local_flush_tlb_all_asid(unsigned long asid)
{
	ALT_SFENCE_VMA_ASID(asid);
}

/* Flush one page from local TLB */
static inline void local_flush_tlb_page(unsigned long addr)
{
	ALT_SFENCE_VMA_ADDR(addr);
}

static inline void local_flush_tlb_page_asid(unsigned long addr,
					     unsigned long asid)
{
	ALT_SFENCE_VMA_ADDR_ASID(addr, asid);
}

#ifdef CONFIG_SMP
void flush_tlb_all(void);
#else
#define flush_tlb_all() local_flush_tlb_all()
#endif
void flush_tlb_mm(struct mm_struct *mm);
void flush_tlb_page(struct vm_area_struct *vma, unsigned long addr);
void flush_tlb_range(struct vm_area_struct *vma, unsigned long start,
		     unsigned long end);
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
#define __HAVE_ARCH_FLUSH_PMD_TLB_RANGE
void flush_pmd_tlb_range(struct vm_area_struct *vma, unsigned long start,
			unsigned long end);
#endif
#else /* CONFIG_MMU */
#define local_flush_tlb_all()			do { } while (0)
#define local_flush_tlb_page(addr)		do { } while (0)
#endif /* CONFIG_MMU */

/* Flush a range of kernel pages */
static inline void flush_tlb_kernel_range(unsigned long start,
	unsigned long end)
{
	flush_tlb_all();
}

#endif /* _ASM_RISCV_TLBFLUSH_H */

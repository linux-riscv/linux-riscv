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
#include <asm/tlbbatch.h>

#define FLUSH_TLB_MAX_SIZE      ((unsigned long)-1)
#define FLUSH_TLB_NO_ASID       ((unsigned long)-1)

#ifdef CONFIG_MMU
extern unsigned long asid_mask;
DECLARE_STATIC_KEY_FALSE(use_asid_allocator);

struct flush_tlb_range_data {
	unsigned long asid;
	unsigned long start;
	unsigned long size;
	unsigned long stride;
};

static inline void local_flush_tlb_all(void)
{
	__asm__ __volatile__ ("sfence.vma" : : : "memory");
}

/* Flush one page from local TLB */
static inline void local_flush_tlb_page(unsigned long addr)
{
	ALT_FLUSH_TLB_PAGE(__asm__ __volatile__ ("sfence.vma %0" : : "r" (addr) : "memory"));
}

static inline void local_flush_tlb_all_asid(unsigned long asid)
{
	if (asid != FLUSH_TLB_NO_ASID)
		__asm__ __volatile__ ("sfence.vma x0, %0"
				:
				: "r" (asid)
				: "memory");
	else
		local_flush_tlb_all();
}

static inline void local_flush_tlb_page_asid(unsigned long addr,
		unsigned long asid)
{
	if (asid != FLUSH_TLB_NO_ASID)
		__asm__ __volatile__ ("sfence.vma %0, %1"
				:
				: "r" (addr), "r" (asid)
				: "memory");
	else
		local_flush_tlb_page(addr);
}

static inline unsigned long get_mm_asid(struct mm_struct *mm)
{
	return static_branch_unlikely(&use_asid_allocator) ?
			atomic_long_read(&mm->context.id) & asid_mask : FLUSH_TLB_NO_ASID;
}
#else /* CONFIG_MMU */
#define local_flush_tlb_all()			do { } while (0)
#define local_flush_tlb_page(addr)		do { } while (0)
#endif /* CONFIG_MMU */

void flush_tlb_all(void);
void flush_tlb_mm(struct mm_struct *mm);
void flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
			unsigned long end, unsigned int page_size);
void flush_tlb_page(struct vm_area_struct *vma, unsigned long addr);
void flush_tlb_range(struct vm_area_struct *vma, unsigned long start,
		     unsigned long end);
void flush_tlb_kernel_range(unsigned long start, unsigned long end);
void local_flush_tlb_kernel_range(unsigned long start, unsigned long end);
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
#define __HAVE_ARCH_FLUSH_PMD_TLB_RANGE
void flush_pmd_tlb_range(struct vm_area_struct *vma, unsigned long start,
			unsigned long end);
#endif

bool arch_tlbbatch_should_defer(struct mm_struct *mm);
void arch_tlbbatch_add_pending(struct arch_tlbflush_unmap_batch *batch,
			       struct mm_struct *mm,
			       unsigned long uaddr);
void arch_flush_tlb_batched_pending(struct mm_struct *mm);
void arch_tlbbatch_flush(struct arch_tlbflush_unmap_batch *batch);

#endif /* _ASM_RISCV_TLBFLUSH_H */

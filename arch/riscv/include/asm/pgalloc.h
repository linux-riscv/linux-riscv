/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2009 Chen Liqin <liqin.chen@sunplusct.com>
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_PGALLOC_H
#define _ASM_RISCV_PGALLOC_H

#include <linux/mm.h>
#include <asm/tlb.h>

#ifdef CONFIG_MMU
#define __HAVE_ARCH_PUD_ALLOC_ONE
#define __HAVE_ARCH_PUD_FREE
#include <asm-generic/pgalloc.h>

static inline void pmd_populate_kernel(struct mm_struct *mm,
	pmd_t *pmdp, pte_t *ptep)
{
	unsigned long pfn = virt_to_pfn(ptep);

	set_pmd(pmdp, __pmd((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
}

static inline void pmd_populate(struct mm_struct *mm,
	pmd_t *pmdp, pgtable_t pte)
{
	unsigned long pfn = virt_to_pfn(page_address(pte));

	set_pmd(pmdp, __pmd((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
}

#ifndef __PAGETABLE_PMD_FOLDED
static inline void pud_populate(struct mm_struct *mm, pud_t *pudp, pmd_t *pmdp)
{
	unsigned long pfn = virt_to_pfn(pmdp);

	set_pud(pudp, __pud((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
}

static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4dp, pud_t *pudp)
{
	if (pgtable_l4_enabled) {
		unsigned long pfn = virt_to_pfn(pudp);

		set_p4d(p4dp, __p4d((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
	}
}

static inline void p4d_populate_safe(struct mm_struct *mm, p4d_t *p4dp,
				     pud_t *pudp)
{
	if (pgtable_l4_enabled) {
		unsigned long pfn = virt_to_pfn(pudp);

		set_p4d_safe(p4dp,
			     __p4d((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
	}
}

static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgdp, p4d_t *p4dp)
{
	if (pgtable_l5_enabled) {
		unsigned long pfn = virt_to_pfn(p4dp);

		set_pgd(pgdp, __pgd((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
	}
}

static inline void pgd_populate_safe(struct mm_struct *mm, pgd_t *pgdp,
				     p4d_t *p4dp)
{
	if (pgtable_l5_enabled) {
		unsigned long pfn = virt_to_pfn(p4dp);

		set_pgd_safe(pgdp,
			     __pgd((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
	}
}

#define pud_alloc_one pud_alloc_one
static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	if (pgtable_l4_enabled)
		return __pud_alloc_one(mm, addr);

	return NULL;
}

#define pud_free pud_free
static inline void pud_free(struct mm_struct *mm, pud_t *pudp)
{
	if (pgtable_l4_enabled)
		__pud_free(mm, pudp);
}

#define __pud_free_tlb(tlb, pudp, addr)  pud_free((tlb)->mm, pudp)

#define p4d_alloc_one p4d_alloc_one
static inline p4d_t *p4d_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	if (pgtable_l5_enabled) {
		gfp_t gfp = GFP_PGTABLE_USER;

		if (mm == &init_mm)
			gfp = GFP_PGTABLE_KERNEL;
		return (p4d_t *)get_zeroed_page(gfp);
	}

	return NULL;
}

static inline void __p4d_free(struct mm_struct *mm, p4d_t *p4dp)
{
	BUG_ON((unsigned long)p4dp & (PAGE_SIZE-1));
	free_page((unsigned long)p4dp);
}

#define p4d_free p4d_free
static inline void p4d_free(struct mm_struct *mm, p4d_t *p4dp)
{
	if (pgtable_l5_enabled)
		__p4d_free(mm, p4dp);
}

#define __p4d_free_tlb(tlb, p4d, addr)  p4d_free((tlb)->mm, p4d)
#endif /* __PAGETABLE_PMD_FOLDED */

static inline void sync_kernel_mappings(pgd_t *pgdp)
{
	memcpy(pgdp + USER_PTRS_PER_PGD,
	       init_mm.pgd + USER_PTRS_PER_PGD,
	       (PTRS_PER_PGD - USER_PTRS_PER_PGD) * sizeof(pgd_t));
}

static inline pgd_t *pgd_alloc(struct mm_struct *mm)
{
	pgd_t *pgdp;

	pgdp = (pgd_t *)__get_free_page(GFP_KERNEL);
	if (likely(pgdp != NULL)) {
		memset(pgdp, 0, USER_PTRS_PER_PGD * sizeof(pgd_t));
		/* Copy kernel mappings */
		sync_kernel_mappings(pgdp);
	}
	return pgdp;
}

#ifndef __PAGETABLE_PMD_FOLDED

#define __pmd_free_tlb(tlb, pmdp, addr)  pmd_free((tlb)->mm, pmdp)

#endif /* __PAGETABLE_PMD_FOLDED */

#define __pte_free_tlb(tlb, ptep, buf)				\
do {								\
	pagetable_pte_dtor(page_ptdesc(ptep));			\
	tlb_remove_page_ptdesc((tlb), page_ptdesc(ptep));	\
} while (0)
#endif /* CONFIG_MMU */

#endif /* _ASM_RISCV_PGALLOC_H */

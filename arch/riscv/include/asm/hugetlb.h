/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_RISCV_HUGETLB_H
#define _ASM_RISCV_HUGETLB_H

#include <asm/cacheflush.h>
#include <asm/page.h>
#include <asm/pgtable.h>

static inline void arch_clear_hugepage_flags(struct page *page)
{
	clear_bit(PG_dcache_clean, &page->flags);
}
#define arch_clear_hugepage_flags arch_clear_hugepage_flags

#ifdef CONFIG_RISCV_ISA_SVNAPOT

#define __HAVE_ARCH_HUGE_PTE_CLEAR
void huge_pte_clear(struct mm_struct *mm, unsigned long addr,
		    pte_t *ptep, unsigned long sz);

#define __HAVE_ARCH_HUGE_SET_HUGE_PTE_AT
void set_huge_pte_at(struct mm_struct *mm,
		     unsigned long addr, pte_t *ptep, pte_t pte,
		     unsigned long sz);

#define __HAVE_ARCH_HUGE_PTEP_GET_AND_CLEAR
pte_t huge_ptep_get_and_clear(struct mm_struct *mm,
			      unsigned long addr, pte_t *ptep);

#define __HAVE_ARCH_HUGE_PTEP_CLEAR_FLUSH
pte_t huge_ptep_clear_flush(struct vm_area_struct *vma,
			    unsigned long addr, pte_t *ptep);

#define __HAVE_ARCH_HUGE_PTEP_SET_WRPROTECT
void huge_ptep_set_wrprotect(struct mm_struct *mm,
			     unsigned long addr, pte_t *ptep);

#define __HAVE_ARCH_HUGE_PTEP_SET_ACCESS_FLAGS
int huge_ptep_set_access_flags(struct vm_area_struct *vma,
			       unsigned long addr, pte_t *ptep,
			       pte_t pte, int dirty);

#define __HAVE_ARCH_HUGE_PTEP_GET
pte_t huge_ptep_get(pte_t *ptep);

#define __HAVE_ARCH_HUGE_PTEP_GET_LOCKLESS
static inline pte_t huge_ptep_get_lockless(pte_t *ptep)
{
	unsigned long pteval = READ_ONCE(ptep->ptes[0]);

	return __pte(pteval);
}

pte_t arch_make_huge_pte(pte_t entry, unsigned int shift, vm_flags_t flags);
#define arch_make_huge_pte arch_make_huge_pte

#else /* CONFIG_RISCV_ISA_SVNAPOT */

#define __HAVE_ARCH_HUGE_PTEP_GET
static inline pte_t huge_ptep_get(pte_t *ptep)
{
	pmd_t *pmdp = (pmd_t *)ptep;

	return pmd_pte(pmdp_get(pdmp));
}

#define __HAVE_ARCH_HUGE_PTEP_GET_LOCKLESS
static inline pte_t huge_ptep_get_lockless(pte_t *ptep)
{
	return huge_ptep_get(ptep);
}

#define __HAVE_ARCH_HUGE_SET_HUGE_PTE_AT
static inline void set_huge_pte_at(struct mm_struct *mm, unsigned long addr,
		pte_t *ptep, pte_t pte)
{
	set_pmd_at(mm, addr, (pmd_t *)ptep, pte_pmd(pte));
}

#define __HAVE_ARCH_HUGE_PTEP_SET_ACCESS_FLAGS
static inline int huge_ptep_set_access_flags(struct vm_area_struct *vma,
		unsigned long addr, pte_t *ptep,
		pte_t pte, int dirty)
{
	return pmdp_set_access_flags(vma, addr, (pmd_t *)ptep, pte_pmd(pte), dirty);
}

#define __HAVE_ARCH_HUGE_PTEP_GET_AND_CLEAR
static inline pte_t huge_ptep_get_and_clear(struct mm_struct *mm,
		unsigned long addr, pte_t *ptep)
{
	return pmd_pte(pmdp_get_and_clear(mm, addr, (pmd_t *)ptep));
}

#define __HAVE_ARCH_HUGE_PTEP_SET_WRPROTECT
static inline void huge_ptep_set_wrprotect(struct mm_struct *mm,
		unsigned long addr, pte_t *ptep)
{
	pmdp_set_wrprotect(mm, addr, (pmd_t *)ptep);
}

#define __HAVE_ARCH_HUGE_PTEP_CLEAR_FLUSH
static inline pte_t huge_ptep_clear_flush(struct vm_area_struct *vma,
		unsigned long addr, pte_t *ptep)
{
	return pmd_pte(pmdp_clear_flush(vma, addr, (pmd_t *)ptep));
}

#define __HAVE_ARCH_HUGE_PTE_CLEAR
static inline void huge_pte_clear(struct mm_struct *mm, unsigned long addr,
		    pte_t *ptep, unsigned long sz)
{
	pmd_clear((pmd_t *)ptep);
}

#endif /* CONFIG_RISCV_ISA_SVNAPOT */

#include <asm-generic/hugetlb.h>

#endif /* _ASM_RISCV_HUGETLB_H */

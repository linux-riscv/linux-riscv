/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_RISCV_HUGETLB_H
#define _ASM_RISCV_HUGETLB_H

#include <asm/cacheflush.h>
#include <asm/page.h>
#ifdef CONFIG_ARCH_WANT_GENERAL_HUGETLB_CONTPTE
#include <linux/hugetlb_contpte.h>
#endif

static inline void arch_clear_hugetlb_flags(struct folio *folio)
{
	clear_bit(PG_dcache_clean, &folio->flags);
}
#define arch_clear_hugetlb_flags arch_clear_hugetlb_flags

#ifdef CONFIG_ARCH_ENABLE_HUGEPAGE_MIGRATION
bool arch_hugetlb_migration_supported(struct hstate *h);
#define arch_hugetlb_migration_supported arch_hugetlb_migration_supported
#endif

#ifdef CONFIG_RISCV_ISA_SVNAPOT
#define __HAVE_ARCH_HUGE_PTEP_CLEAR_FLUSH
pte_t huge_ptep_clear_flush(struct vm_area_struct *vma,
			    unsigned long addr, pte_t *ptep);

#define __HAVE_ARCH_HUGE_PTEP_SET_WRPROTECT
void huge_ptep_set_wrprotect(struct mm_struct *mm,
			     unsigned long addr, pte_t *ptep);

pte_t arch_make_huge_pte(pte_t entry, unsigned int shift, vm_flags_t flags);
#define arch_make_huge_pte arch_make_huge_pte

#endif /*CONFIG_RISCV_ISA_SVNAPOT*/

#include <asm-generic/hugetlb.h>

#endif /* _ASM_RISCV_HUGETLB_H */

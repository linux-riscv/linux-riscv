// SPDX-License-Identifier: GPL-2.0-only
/*
 * arch/arm64/mm/hugetlbpage.c
 *
 * Copyright (C) 2013 Linaro Ltd.
 *
 * Based on arch/x86/mm/hugetlbpage.c.
 */

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/pagemap.h>
#include <linux/err.h>
#include <linux/sysctl.h>
#include <asm/mman.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>

/*
 * HugeTLB Support Matrix
 *
 * ---------------------------------------------------
 * | Page Size | CONT PTE |  PMD  | CONT PMD |  PUD  |
 * ---------------------------------------------------
 * |     4K    |   64K    |   2M  |    32M   |   1G  |
 * |    16K    |    2M    |  32M  |     1G   |       |
 * |    64K    |    2M    | 512M  |    16G   |       |
 * ---------------------------------------------------
 */

/*
 * Reserve CMA areas for the largest supported gigantic
 * huge page when requested. Any other smaller gigantic
 * huge pages could still be served from those areas.
 */
#ifdef CONFIG_CMA
void __init arm64_hugetlb_cma_reserve(void)
{
	int order;

	if (pud_sect_supported())
		order = PUD_SHIFT - PAGE_SHIFT;
	else
		order = CONT_PMD_SHIFT - PAGE_SHIFT;

	hugetlb_cma_reserve(order);
}
#endif /* CONFIG_CMA */

static bool __hugetlb_valid_size(unsigned long size)
{
	switch (size) {
#ifndef __PAGETABLE_PMD_FOLDED
	case PUD_SIZE:
		return pud_sect_supported();
#endif
	case CONT_PMD_SIZE:
	case PMD_SIZE:
	case CONT_PTE_SIZE:
		return true;
	}

	return false;
}

#ifdef CONFIG_ARCH_ENABLE_HUGEPAGE_MIGRATION
bool arch_hugetlb_migration_supported(struct hstate *h)
{
	size_t pagesize = huge_page_size(h);

	if (!__hugetlb_valid_size(pagesize)) {
		pr_warn("%s: unrecognized huge page size 0x%lx\n",
			__func__, pagesize);
		return false;
	}
	return true;
}
#endif

int pmd_huge(pmd_t pmd)
{
	return pmd_val(pmd) && !(pmd_val(pmd) & PMD_TABLE_BIT);
}

int pud_huge(pud_t pud)
{
#ifndef __PAGETABLE_PMD_FOLDED
	return pud_val(pud) && !(pud_val(pud) & PUD_TABLE_BIT);
#else
	return 0;
#endif
}

int find_num_contig(struct mm_struct *mm, unsigned long addr,
		    pte_t *ptep, size_t *pgsize)
{
	pgd_t *pgdp = pgd_offset(mm, addr);
	p4d_t *p4dp;
	pud_t *pudp;
	pmd_t *pmdp;

	*pgsize = PAGE_SIZE;
	p4dp = p4d_offset(pgdp, addr);
	pudp = pud_offset(p4dp, addr);
	pmdp = pmd_offset(pudp, addr);
	if ((pte_t *)pmdp == ptep) {
		*pgsize = PMD_SIZE;
		return CONT_PMDS;
	}
	return CONT_PTES;
}

pte_t *huge_pte_alloc(struct mm_struct *mm, struct vm_area_struct *vma,
		      unsigned long addr, unsigned long sz)
{
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep = NULL;

	pgdp = pgd_offset(mm, addr);
	p4dp = p4d_offset(pgdp, addr);
	pudp = pud_alloc(mm, p4dp, addr);
	if (!pudp)
		return NULL;

	if (sz == PUD_SIZE) {
		ptep = (pte_t *)pudp;
	} else if (sz == (CONT_PTE_SIZE)) {
		pmdp = pmd_alloc(mm, pudp, addr);
		if (!pmdp)
			return NULL;

		WARN_ON(addr & (sz - 1));
		ptep = pte_alloc_huge(mm, pmdp, addr);
	} else if (sz == PMD_SIZE) {
		if (want_pmd_share(vma, addr) && pud_none(READ_ONCE(*pudp)))
			ptep = huge_pmd_share(mm, vma, addr, pudp);
		else
			ptep = (pte_t *)pmd_alloc(mm, pudp, addr);
	} else if (sz == (CONT_PMD_SIZE)) {
		pmdp = pmd_alloc(mm, pudp, addr);
		WARN_ON(addr & (sz - 1));
		return (pte_t *)pmdp;
	}

	return ptep;
}

pte_t *huge_pte_offset(struct mm_struct *mm,
		       unsigned long addr, unsigned long sz)
{
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;

	pgdp = pgd_offset(mm, addr);
	if (!pgd_present(READ_ONCE(*pgdp)))
		return NULL;

	p4dp = p4d_offset(pgdp, addr);
	if (!p4d_present(READ_ONCE(*p4dp)))
		return NULL;

	pudp = pud_offset(p4dp, addr);
	pud = READ_ONCE(*pudp);
	if (sz != PUD_SIZE && pud_none(pud))
		return NULL;
	/* hugepage or swap? */
	if (pud_huge(pud) || !pud_present(pud))
		return (pte_t *)pudp;
	/* table; check the next level */

	if (sz == CONT_PMD_SIZE)
		addr &= CONT_PMD_MASK;

	pmdp = pmd_offset(pudp, addr);
	pmd = READ_ONCE(*pmdp);
	if (!(sz == PMD_SIZE || sz == CONT_PMD_SIZE) &&
	    pmd_none(pmd))
		return NULL;
	if (pmd_huge(pmd) || !pmd_present(pmd))
		return (pte_t *)pmdp;

	if (sz == CONT_PTE_SIZE)
		return pte_offset_huge(pmdp, (addr & CONT_PTE_MASK));

	return NULL;
}

unsigned long hugetlb_mask_last_page(struct hstate *h)
{
	unsigned long hp_size = huge_page_size(h);

	switch (hp_size) {
#ifndef __PAGETABLE_PMD_FOLDED
	case PUD_SIZE:
		return PGDIR_SIZE - PUD_SIZE;
#endif
	case CONT_PMD_SIZE:
		return PUD_SIZE - CONT_PMD_SIZE;
	case PMD_SIZE:
		return PUD_SIZE - PMD_SIZE;
	case CONT_PTE_SIZE:
		return PMD_SIZE - CONT_PTE_SIZE;
	default:
		break;
	}

	return 0UL;
}

pte_t arch_make_huge_pte(pte_t entry, unsigned int shift, vm_flags_t flags)
{
	size_t pagesize = 1UL << shift;

	entry = pte_mkhuge(entry);
	if (pagesize == CONT_PTE_SIZE) {
		entry = pte_mkcont(entry);
	} else if (pagesize == CONT_PMD_SIZE) {
		entry = pmd_pte(pmd_mkcont(pte_pmd(entry)));
	} else if (pagesize != PUD_SIZE && pagesize != PMD_SIZE) {
		pr_warn("%s: unrecognized huge page size 0x%lx\n",
			__func__, pagesize);
	}
	return entry;
}

static int __init hugetlbpage_init(void)
{
	if (pud_sect_supported())
		hugetlb_add_hstate(PUD_SHIFT - PAGE_SHIFT);

	hugetlb_add_hstate(CONT_PMD_SHIFT - PAGE_SHIFT);
	hugetlb_add_hstate(PMD_SHIFT - PAGE_SHIFT);
	hugetlb_add_hstate(CONT_PTE_SHIFT - PAGE_SHIFT);

	return 0;
}
arch_initcall(hugetlbpage_init);

bool __init arch_hugetlb_valid_size(unsigned long size)
{
	return __hugetlb_valid_size(size);
}

pte_t huge_ptep_modify_prot_start(struct vm_area_struct *vma, unsigned long addr, pte_t *ptep)
{
	if (alternative_has_cap_unlikely(ARM64_WORKAROUND_2645198)) {
		/*
		 * Break-before-make (BBM) is required for all user space mappings
		 * when the permission changes from executable to non-executable
		 * in cases where cpu is affected with errata #2645198.
		 */
		if (pte_user_exec(__ptep_get(ptep)))
			return huge_ptep_clear_flush(vma, addr, ptep);
	}
	return huge_ptep_get_and_clear(vma->vm_mm, addr, ptep);
}

void huge_ptep_modify_prot_commit(struct vm_area_struct *vma, unsigned long addr, pte_t *ptep,
				  pte_t old_pte, pte_t pte)
{
	unsigned long psize = huge_page_size(hstate_vma(vma));

	set_huge_pte_at(vma->vm_mm, addr, ptep, pte, psize);
}

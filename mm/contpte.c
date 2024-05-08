// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Rivos Inc.
 */

#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/hugetlb.h>

/*
 * Any arch that wants to use that needs to define:
 *   - __ptep_get()
 *   - __set_ptes()
 *   - __ptep_get_and_clear()
 *   - __pte_clear()
 *   - pte_cont()
 *   - arch_contpte_get_num_contig()
 */

/*
 * This file implements the following contpte aware API:
 *   - huge_ptep_get()
 *   - set_huge_pte_at()
 *   - huge_pte_clear()
 *   - huge_ptep_get_and_clear()
 */

pte_t huge_ptep_get(pte_t *ptep)
{
	int ncontig, i;
	size_t pgsize;
	pte_t orig_pte = __ptep_get(ptep);

	if (!pte_present(orig_pte) || !pte_cont(orig_pte))
		return orig_pte;

	ncontig = arch_contpte_get_num_contig(NULL, 0, ptep,
					      page_size(pte_page(orig_pte)),
					      &pgsize);

	for (i = 0; i < ncontig; i++, ptep++) {
		pte_t pte = __ptep_get(ptep);

		if (pte_dirty(pte))
			orig_pte = pte_mkdirty(orig_pte);

		if (pte_young(pte))
			orig_pte = pte_mkyoung(orig_pte);
	}
	return orig_pte;
}

/*
 * ARM64: Changing some bits of contiguous entries requires us to follow a
 * Break-Before-Make approach, breaking the whole contiguous set
 * before we can change any entries. See ARM DDI 0487A.k_iss10775,
 * "Misprogramming of the Contiguous bit", page D4-1762.
 *
 * RISCV: When dealing with NAPOT mappings, the privileged specification
 * indicates that "if an update needs to be made, the OS generally should first
 * mark all of the PTEs invalid, then issue SFENCE.VMA instruction(s) covering
 * all 4 KiB regions within the range, [...] then update the PTE(s), as
 * described in Section 4.2.1.". That's the equivalent of the Break-Before-Make
 * approach used by arm64.
 *
 * This helper performs the break step for use cases where the
 * original pte is not needed.
 */
static void clear_flush(struct mm_struct *mm,
			unsigned long addr,
			pte_t *ptep,
			unsigned long pgsize,
			unsigned long ncontig)
{
	struct vm_area_struct vma = TLB_FLUSH_VMA(mm, 0);
	unsigned long i, saddr = addr;

	for (i = 0; i < ncontig; i++, addr += pgsize, ptep++)
		__ptep_get_and_clear(mm, addr, ptep);

	flush_tlb_range(&vma, saddr, addr);
}

void set_huge_pte_at(struct mm_struct *mm, unsigned long addr,
		     pte_t *ptep, pte_t pte, unsigned long sz)
{
	size_t pgsize;
	int i;
	int ncontig;

	ncontig = arch_contpte_get_num_contig(mm, addr, ptep, sz, &pgsize);

	if (!pte_present(pte)) {
		for (i = 0; i < ncontig; i++, ptep++, addr += pgsize)
			__set_ptes(mm, addr, ptep, pte, 1);
		return;
	}

	if (!pte_cont(pte)) {
		__set_ptes(mm, addr, ptep, pte, 1);
		return;
	}

	clear_flush(mm, addr, ptep, pgsize, ncontig);

	set_contptes(mm, addr, ptep, pte, ncontig, pgsize);
}

void huge_pte_clear(struct mm_struct *mm, unsigned long addr,
		    pte_t *ptep, unsigned long sz)
{
	int i, ncontig;
	size_t pgsize;

	ncontig = arch_contpte_get_num_contig(mm, addr, ptep, sz, &pgsize);

	for (i = 0; i < ncontig; i++, addr += pgsize, ptep++)
		__pte_clear(mm, addr, ptep);
}

static pte_t get_clear_contig(struct mm_struct *mm,
			      unsigned long addr,
			      pte_t *ptep,
			      unsigned long pgsize,
			      unsigned long ncontig)
{
	pte_t orig_pte = __ptep_get(ptep);
	unsigned long i;

	for (i = 0; i < ncontig; i++, addr += pgsize, ptep++) {
		pte_t pte = __ptep_get_and_clear(mm, addr, ptep);

		/*
		 * If HW_AFDBM (arm64) or svadu (riscv) is enabled, then the HW
		 * could turn on the dirty or accessed bit for any page in the
		 * set, so check them all.
		 */
		if (pte_dirty(pte))
			orig_pte = pte_mkdirty(orig_pte);

		if (pte_young(pte))
			orig_pte = pte_mkyoung(orig_pte);
	}
	return orig_pte;
}

pte_t huge_ptep_get_and_clear(struct mm_struct *mm,
			      unsigned long addr, pte_t *ptep)
{
	int ncontig;
	size_t pgsize;
	pte_t orig_pte = __ptep_get(ptep);

	if (!pte_cont(orig_pte))
		return __ptep_get_and_clear(mm, addr, ptep);

	ncontig = arch_contpte_get_num_contig(mm, addr, ptep, 0, &pgsize);

	return get_clear_contig(mm, addr, ptep, pgsize, ncontig);
}

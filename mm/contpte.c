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
 *   - __ptep_set_access_flags()
 *   - __ptep_set_wrprotect()
 *   - pte_cont()
 *   - arch_contpte_get_num_contig()
 */

/*
 * This file implements the following contpte aware API:
 *   - huge_ptep_get()
 *   - set_huge_pte_at()
 *   - huge_pte_clear()
 *   - huge_ptep_get_and_clear()
 *   - huge_ptep_set_access_flags()
 *   - huge_ptep_set_wrprotect()
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

/*
 * huge_ptep_set_access_flags will update access flags (dirty, accesssed)
 * and write permission.
 *
 * For a contiguous huge pte range we need to check whether or not write
 * permission has to change only on the first pte in the set. Then for
 * all the contiguous ptes we need to check whether or not there is a
 * discrepancy between dirty or young.
 */
static int __cont_access_flags_changed(pte_t *ptep, pte_t pte, int ncontig)
{
	int i;

	if (pte_write(pte) != pte_write(__ptep_get(ptep)))
		return 1;

	for (i = 0; i < ncontig; i++) {
		pte_t orig_pte = __ptep_get(ptep + i);

		if (pte_dirty(pte) != pte_dirty(orig_pte))
			return 1;

		if (pte_young(pte) != pte_young(orig_pte))
			return 1;
	}

	return 0;
}

static pte_t get_clear_contig_flush(struct mm_struct *mm,
				    unsigned long addr,
				    pte_t *ptep,
				    unsigned long pgsize,
				    unsigned long ncontig)
{
	pte_t orig_pte = get_clear_contig(mm, addr, ptep, pgsize, ncontig);
	struct vm_area_struct vma = TLB_FLUSH_VMA(mm, 0);

	flush_tlb_range(&vma, addr, addr + (pgsize * ncontig));
	return orig_pte;
}

int huge_ptep_set_access_flags(struct vm_area_struct *vma,
			       unsigned long addr, pte_t *ptep,
			       pte_t pte, int dirty)
{
	int ncontig;
	size_t pgsize = 0;
	struct mm_struct *mm = vma->vm_mm;
	pte_t orig_pte;

	if (!pte_cont(pte))
		return __ptep_set_access_flags(vma, addr, ptep, pte, dirty);

	ncontig = arch_contpte_get_num_contig(vma->vm_mm, addr, ptep, 0, &pgsize);

	if (!__cont_access_flags_changed(ptep, pte, ncontig))
		return 0;

	orig_pte = get_clear_contig_flush(mm, addr, ptep, pgsize, ncontig);

	/* Make sure we don't lose the dirty or young state */
	if (pte_dirty(orig_pte))
		pte = pte_mkdirty(pte);

	if (pte_young(orig_pte))
		pte = pte_mkyoung(pte);

	set_contptes(mm, addr, ptep, pte, ncontig, pgsize);

	return 1;
}

void huge_ptep_set_wrprotect(struct mm_struct *mm,
			     unsigned long addr, pte_t *ptep)
{
	int ncontig;
	size_t pgsize;
	pte_t pte;

	if (!pte_cont(__ptep_get(ptep))) {
		__ptep_set_wrprotect(mm, addr, ptep);
		return;
	}

	ncontig = arch_contpte_get_num_contig(mm, addr, ptep, 0, &pgsize);

	pte = get_clear_contig_flush(mm, addr, ptep, pgsize, ncontig);
	pte = pte_wrprotect(pte);

	set_contptes(mm, addr, ptep, pte, ncontig, pgsize);
}

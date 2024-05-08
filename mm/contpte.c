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
 *   - pte_cont()
 *   - arch_contpte_get_num_contig()
 */

/*
 * This file implements the following contpte aware API:
 *   - huge_ptep_get()
 */

pte_t huge_ptep_get(pte_t *ptep)
{
	int ncontig, i;
	size_t pgsize;
	pte_t orig_pte = __ptep_get(ptep);

	if (!pte_present(orig_pte) || !pte_cont(orig_pte))
		return orig_pte;

	ncontig = arch_contpte_get_num_contig(ptep,
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

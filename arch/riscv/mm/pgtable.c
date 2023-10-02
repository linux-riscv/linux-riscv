// SPDX-License-Identifier: GPL-2.0

#include <asm/pgalloc.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/pgtable.h>

#ifdef CONFIG_HAVE_ARCH_HUGE_VMAP
int p4d_set_huge(p4d_t *p4dp, phys_addr_t addr, pgprot_t prot)
{
	return 0;
}

void p4d_clear_huge(p4d_t *p4dp)
{
}

int pud_set_huge(pud_t *pudp, phys_addr_t phys, pgprot_t prot)
{
	pud_t new_pud = pfn_pud(__phys_to_pfn(phys), prot);

	set_pud(pudp, new_pud);
	return 1;
}

int pud_clear_huge(pud_t *pudp)
{
	if (!pud_leaf(READ_ONCE(*pudp)))
		return 0;
	pud_clear(pudp);
	return 1;
}

int pud_free_pmd_page(pud_t *pudp, unsigned long addr)
{
	pmd_t *pmdp = pud_pgtable(*pudp);
	int i;

	pud_clear(pudp);

	flush_tlb_kernel_range(addr, addr + PUD_SIZE);

	for (i = 0; i < PTRS_PER_PMD; i++) {
		if (!pmd_none(pmdp[i])) {
			pte_t *ptep = (pte_t *)pmd_page_vaddr(pmdp[i]);

			pte_free_kernel(NULL, ptep);
		}
	}

	pmd_free(NULL, pmdp);

	return 1;
}

int pmd_set_huge(pmd_t *pmdp, phys_addr_t phys, pgprot_t prot)
{
	pmd_t new_pmd = pfn_pmd(__phys_to_pfn(phys), prot);

	set_pmd(pmdp, new_pmd);
	return 1;
}

int pmd_clear_huge(pmd_t *pmdp)
{
	if (!pmd_leaf(READ_ONCE(*pmdp)))
		return 0;
	pmd_clear(pmdp);
	return 1;
}

int pmd_free_pte_page(pmd_t *pmdp, unsigned long addr)
{
	pte_t *ptep = (pte_t *)pmd_page_vaddr(*pmdp);

	pmd_clear(pmdp);

	flush_tlb_kernel_range(addr, addr + PMD_SIZE);
	pte_free_kernel(NULL, ptep);
	return 1;
}

#endif /* CONFIG_HAVE_ARCH_HUGE_VMAP */
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
pmd_t pmdp_collapse_flush(struct vm_area_struct *vma,
					unsigned long address, pmd_t *pmdp)
{
	pmd_t pmd = pmdp_huge_get_and_clear(vma->vm_mm, address, pmdp);

	VM_BUG_ON(address & ~HPAGE_PMD_MASK);
	VM_BUG_ON(pmd_trans_huge(*pmdp));
	/*
	 * When leaf PTE entries (regular pages) are collapsed into a leaf
	 * PMD entry (huge page), a valid non-leaf PTE is converted into a
	 * valid leaf PTE at the level 1 page table.  Since the sfence.vma
	 * forms that specify an address only apply to leaf PTEs, we need a
	 * global flush here.  collapse_huge_page() assumes these flushes are
	 * eager, so just do the fence here.
	 */
	flush_tlb_mm(vma->vm_mm);
	return pmd;
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

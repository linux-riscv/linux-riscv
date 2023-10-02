// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2019 SiFive
 */

#include <linux/pagewalk.h>
#include <linux/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/bitops.h>
#include <asm/set_memory.h>

struct pageattr_masks {
	pgprot_t set_mask;
	pgprot_t clear_mask;
};

static unsigned long set_pageattr_masks(unsigned long val, struct mm_walk *walk)
{
	struct pageattr_masks *masks = walk->private;
	unsigned long new_val = val;

	new_val &= ~(pgprot_val(masks->clear_mask));
	new_val |= (pgprot_val(masks->set_mask));

	return new_val;
}

static int pageattr_pgd_entry(pgd_t *pgdp, unsigned long addr,
			      unsigned long next, struct mm_walk *walk)
{
	pgd_t val = pgdp_get(pgdp);

	if (pgd_leaf(val)) {
		val = __pgd(set_pageattr_masks(pgd_val(val), walk));
		set_pgd(pgdp, val);
	}

	return 0;
}

static int pageattr_p4d_entry(p4d_t *p4dp, unsigned long addr,
			      unsigned long next, struct mm_walk *walk)
{
	p4d_t val = p4dp_get(p4dp);

	if (p4d_leaf(val)) {
		val = __p4d(set_pageattr_masks(p4d_val(val), walk));
		set_p4d(p4dp, val);
	}

	return 0;
}

static int pageattr_pud_entry(pud_t *pudp, unsigned long addr,
			      unsigned long next, struct mm_walk *walk)
{
	pud_t val = pudp_get(pudp);

	if (pud_leaf(val)) {
		val = __pud(set_pageattr_masks(pud_val(val), walk));
		set_pud(pudp, val);
	}

	return 0;
}

static int pageattr_pmd_entry(pmd_t *pmdp, unsigned long addr,
			      unsigned long next, struct mm_walk *walk)
{
	pmd_t val = pmdp_get(pmdp);

	if (pmd_leaf(val)) {
		val = __pmd(set_pageattr_masks(pmd_val(val), walk));
		set_pmd(pmdp, val);
	}

	return 0;
}

static int pageattr_pte_entry(pte_t *ptep, unsigned long addr,
			      unsigned long next, struct mm_walk *walk)
{
	pte_t val = ptep_get(ptep);

	val = __pte(set_pageattr_masks(pte_val(val), walk));
	set_pte(ptep, val);

	return 0;
}

static int pageattr_pte_hole(unsigned long addr, unsigned long next,
			     int depth, struct mm_walk *walk)
{
	/* Nothing to do here */
	return 0;
}

static const struct mm_walk_ops pageattr_ops = {
	.pgd_entry = pageattr_pgd_entry,
	.p4d_entry = pageattr_p4d_entry,
	.pud_entry = pageattr_pud_entry,
	.pmd_entry = pageattr_pmd_entry,
	.pte_entry = pageattr_pte_entry,
	.pte_hole = pageattr_pte_hole,
	.walk_lock = PGWALK_RDLOCK,
};

static int __set_memory(unsigned long addr, int numpages, pgprot_t set_mask,
			pgprot_t clear_mask)
{
	int ret;
	unsigned long start = addr;
	unsigned long end = start + PAGE_SIZE * numpages;
	struct pageattr_masks masks = {
		.set_mask = set_mask,
		.clear_mask = clear_mask
	};

	if (!numpages)
		return 0;

	mmap_write_lock(&init_mm);
	ret =  walk_page_range_novma(&init_mm, start, end, &pageattr_ops, NULL,
				     &masks);
	mmap_write_unlock(&init_mm);

	flush_tlb_kernel_range(start, end);

	return ret;
}

int set_memory_rw_nx(unsigned long addr, int numpages)
{
	return __set_memory(addr, numpages, __pgprot(_PAGE_READ | _PAGE_WRITE),
			    __pgprot(_PAGE_EXEC));
}

int set_memory_ro(unsigned long addr, int numpages)
{
	return __set_memory(addr, numpages, __pgprot(_PAGE_READ),
			    __pgprot(_PAGE_WRITE));
}

int set_memory_rw(unsigned long addr, int numpages)
{
	return __set_memory(addr, numpages, __pgprot(_PAGE_READ | _PAGE_WRITE),
			    __pgprot(0));
}

int set_memory_x(unsigned long addr, int numpages)
{
	return __set_memory(addr, numpages, __pgprot(_PAGE_EXEC), __pgprot(0));
}

int set_memory_nx(unsigned long addr, int numpages)
{
	return __set_memory(addr, numpages, __pgprot(0), __pgprot(_PAGE_EXEC));
}

int set_direct_map_invalid_noflush(struct page *page)
{
	int ret;
	unsigned long start = (unsigned long)page_address(page);
	unsigned long end = start + PAGE_SIZE;
	struct pageattr_masks masks = {
		.set_mask = __pgprot(0),
		.clear_mask = __pgprot(_PAGE_PRESENT)
	};

	mmap_read_lock(&init_mm);
	ret = walk_page_range(&init_mm, start, end, &pageattr_ops, &masks);
	mmap_read_unlock(&init_mm);

	return ret;
}

int set_direct_map_default_noflush(struct page *page)
{
	int ret;
	unsigned long start = (unsigned long)page_address(page);
	unsigned long end = start + PAGE_SIZE;
	struct pageattr_masks masks = {
		.set_mask = PAGE_KERNEL,
		.clear_mask = __pgprot(0)
	};

	mmap_read_lock(&init_mm);
	ret = walk_page_range(&init_mm, start, end, &pageattr_ops, &masks);
	mmap_read_unlock(&init_mm);

	return ret;
}

#ifdef CONFIG_DEBUG_PAGEALLOC
void __kernel_map_pages(struct page *page, int numpages, int enable)
{
	if (!debug_pagealloc_enabled())
		return;

	if (enable)
		__set_memory((unsigned long)page_address(page), numpages,
			     __pgprot(_PAGE_PRESENT), __pgprot(0));
	else
		__set_memory((unsigned long)page_address(page), numpages,
			     __pgprot(0), __pgprot(_PAGE_PRESENT));
}
#endif

bool kernel_page_present(struct page *page)
{
	unsigned long addr = (unsigned long)page_address(page);
	pgd_t *pgdp, pgd;
	pud_t *pudp, pud;
	p4d_t *p4dp, p4d;
	pmd_t *pmdp, pmd;
	pte_t *ptep;

	pgdp = pgd_offset_k(addr);
	pgd = pgdp_get(pgdp);
	if (!pgd_present(pgd))
		return false;
	if (pgd_leaf(pgd))
		return true;

	p4dp = p4d_offset(pgdp, addr);
	p4d = p4dp_get(p4dp);
	if (!p4d_present(p4d))
		return false;
	if (p4d_leaf(p4d))
		return true;

	pudp = pud_offset(p4dp, addr);
	pud = pudp_get(pudp);
	if (!pud_present(pud))
		return false;
	if (pud_leaf(pud))
		return true;

	pmdp = pmd_offset(pudp, addr);
	pmd = pmdp_get(pmdp);
	if (!pmd_present(pmd))
		return false;
	if (pmd_leaf(pmd))
		return true;

	ptep = pte_offset_kernel(pmdp, addr);
	return pte_present(ptep_get(ptep));
}

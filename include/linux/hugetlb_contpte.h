/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024 Rivos Inc.
 */

#ifndef _LINUX_HUGETLB_CONTPTE_H
#define _LINUX_HUGETLB_CONTPTE_H

#define __HAVE_ARCH_HUGE_PTEP_GET
extern pte_t huge_ptep_get(struct mm_struct *mm, unsigned long addr, pte_t *ptep);

#define __HAVE_ARCH_HUGE_SET_HUGE_PTE_AT
extern void set_huge_pte_at(struct mm_struct *mm,
			    unsigned long addr, pte_t *ptep, pte_t pte,
			    unsigned long sz);

#define __HAVE_ARCH_HUGE_PTE_CLEAR
extern void huge_pte_clear(struct mm_struct *mm, unsigned long addr,
			   pte_t *ptep, unsigned long sz);

#define __HAVE_ARCH_HUGE_PTEP_GET_AND_CLEAR
extern pte_t huge_ptep_get_and_clear(struct mm_struct *mm,
				     unsigned long addr, pte_t *ptep);

#endif /* _LINUX_HUGETLB_CONTPTE_H */

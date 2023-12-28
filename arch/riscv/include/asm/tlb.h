/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_TLB_H
#define _ASM_RISCV_TLB_H

struct mmu_gather;

static void tlb_flush(struct mmu_gather *tlb);

#define tlb_flush tlb_flush
#include <asm-generic/tlb.h>
#include <asm/mmu_context.h>

static inline void tlb_flush(struct mmu_gather *tlb)
{
#ifdef CONFIG_MMU
	/*
	 * If ASID is supported, the ASID allocator will either invalidate the
	 * ASID or mark it as used. So we can avoid TLB invalidation when
	 * pulling down a full mm.
	 */
	if (static_branch_likely(&use_asid_allocator) && tlb->fullmm)
		return;

	if (tlb->fullmm || tlb->need_flush_all)
		flush_tlb_mm(tlb->mm);
	else
		flush_tlb_mm_range(tlb->mm, tlb->start, tlb->end,
				   tlb_get_unmap_size(tlb));
#endif
}

#endif /* _ASM_RISCV_TLB_H */

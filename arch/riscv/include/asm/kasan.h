/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2019 Andes Technology Corporation */

#ifndef __ASM_KASAN_H
#define __ASM_KASAN_H

#ifndef __ASSEMBLY__

#ifdef CONFIG_KASAN

/*
 * The following comment was copied from arm64:
 * KASAN_SHADOW_START: beginning of the kernel virtual addresses.
 * KASAN_SHADOW_END: KASAN_SHADOW_START + 1/N of kernel virtual addresses,
 * where N = (1 << KASAN_SHADOW_SCALE_SHIFT).
 *
 * KASAN_SHADOW_OFFSET:
 * This value is used to map an address to the corresponding shadow
 * address by the following formula:
 *     shadow_addr = (address >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET
 *
 * (1 << (64 - KASAN_SHADOW_SCALE_SHIFT)) shadow addresses that lie in range
 * [KASAN_SHADOW_OFFSET, KASAN_SHADOW_END) cover all 64-bits of virtual
 * addresses. So KASAN_SHADOW_OFFSET should satisfy the following equation:
 *      KASAN_SHADOW_OFFSET = KASAN_SHADOW_END -
 *                              (1ULL << (64 - KASAN_SHADOW_SCALE_SHIFT))
 */
#if defined(CONFIG_KASAN_GENERIC)
#define KASAN_SHADOW_SCALE_SHIFT	3
#elif defined(CONFIG_KASAN_SW_TAGS)
#define KASAN_SHADOW_SCALE_SHIFT	4
#endif

#define KASAN_SHADOW_SIZE	(UL(1) << ((VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
/*
 * Depending on the size of the virtual address space, the region may not be
 * aligned on PGDIR_SIZE, so force its alignment to ease its population.
 */
#define KASAN_SHADOW_START	((KASAN_SHADOW_END - KASAN_SHADOW_SIZE) & PGDIR_MASK)
#define KASAN_SHADOW_END	MODULES_LOWEST_VADDR

#define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)

#ifdef CONFIG_KASAN_SW_TAGS
#define KASAN_TAG_KERNEL	0x7f /* native kernel pointers tag */
#endif

#define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
#define arch_kasan_reset_tag(addr)	__tag_reset(addr)
#define arch_kasan_get_tag(addr)	__tag_get(addr)

void kasan_init(void);
asmlinkage void kasan_early_init(void);
void kasan_swapper_init(void);

#else /* CONFIG_KASAN */

#define KASAN_SHADOW_START	MODULES_LOWEST_VADDR
#define KASAN_SHADOW_END	MODULES_LOWEST_VADDR

#endif /* CONFIG_KASAN */

#ifdef CONFIG_KASAN_SW_TAGS
bool kasan_boot_cpu_enabled(void);
int kasan_cpu_enable(void);
#else
static inline bool kasan_boot_cpu_enabled(void) { return false; }
static inline int kasan_cpu_enable(void) { return 0; }
#endif

#endif
#endif /* __ASM_KASAN_H */

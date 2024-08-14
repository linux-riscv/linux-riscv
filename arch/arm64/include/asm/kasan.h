/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_KASAN_H
#define __ASM_KASAN_H

#ifndef __ASSEMBLY__

#include <linux/linkage.h>
#include <asm/memory.h>

#ifdef CONFIG_KASAN_HW_TAGS
#define KASAN_TAG_MIN			0xF0 /* minimum value for random tags */
#endif

#define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
#define arch_kasan_reset_tag(addr)	__tag_reset(addr)
#define arch_kasan_get_tag(addr)	__tag_get(addr)

#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)

asmlinkage void kasan_early_init(void);
void kasan_init(void);

#else
static inline void kasan_init(void) { }
#endif

#endif
#endif

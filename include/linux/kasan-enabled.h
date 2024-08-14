/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KASAN_ENABLED_H
#define _LINUX_KASAN_ENABLED_H

#include <linux/static_key.h>

#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)

DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);

static __always_inline bool kasan_enabled(void)
{
	return static_branch_likely(&kasan_flag_enabled);
}

#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */

static inline bool kasan_enabled(void)
{
	return IS_ENABLED(CONFIG_KASAN);
}

#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */

static inline bool kasan_hw_tags_enabled(void)
{
	return IS_ENABLED(CONFIG_KASAN_HW_TAGS) && kasan_enabled();
}

#endif /* LINUX_KASAN_ENABLED_H */

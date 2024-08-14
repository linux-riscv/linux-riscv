/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KASAN_TAGS_H
#define _LINUX_KASAN_TAGS_H

#include <asm/kasan.h>

#ifndef KASAN_TAG_KERNEL
#define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
#endif

#define KASAN_TAG_INVALID	(KASAN_TAG_KERNEL - 1) /* inaccessible memory tag */
#define KASAN_TAG_MAX		(KASAN_TAG_KERNEL - 2) /* maximum value for random tags */

#ifndef KASAN_TAG_MIN
#define KASAN_TAG_MIN		0x00 /* minimum value for random tags */
#endif

#endif /* LINUX_KASAN_TAGS_H */

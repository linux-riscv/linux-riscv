/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2014 Regents of the University of California
 */

#ifndef _ASM_RISCV_CMPXCHG_H
#define _ASM_RISCV_CMPXCHG_H

#include <linux/bug.h>

#include <asm/fence.h>
#include <asm/alternative.h>

#define __arch_xchg_masked(prepend, append, r, p, n)			\
({									\
	u32 *__ptr32b = (u32 *)((ulong)(p) & ~0x3);			\
	ulong __s = ((ulong)(p) & (0x4 - sizeof(*p))) * BITS_PER_BYTE;	\
	ulong __mask = GENMASK(((sizeof(*p)) * BITS_PER_BYTE) - 1, 0)	\
			<< __s;						\
	ulong __newx = (ulong)(n) << __s;				\
	ulong __retx;							\
	ulong __rc;							\
									\
	__asm__ __volatile__ (						\
	       prepend							\
	       "0:	lr.w %0, %2\n"					\
	       "	and  %1, %0, %z4\n"				\
	       "	or   %1, %1, %z3\n"				\
	       "	sc.w %1, %1, %2\n"				\
	       "	bnez %1, 0b\n"					\
	       append							\
	       : "=&r" (__retx), "=&r" (__rc), "+A" (*(__ptr32b))	\
	       : "rJ" (__newx), "rJ" (~__mask)				\
	       : "memory");						\
									\
	r = (__typeof__(*(p)))((__retx & __mask) >> __s);		\
})

#define __arch_xchg(sfx, prepend, append, r, p, n)			\
({									\
	__asm__ __volatile__ (						\
		prepend							\
		"	amoswap" sfx " %0, %2, %1\n"			\
		append							\
		: "=r" (r), "+A" (*(p))					\
		: "r" (n)						\
		: "memory");						\
})

#define _arch_xchg(ptr, new, sfx, prepend, append)			\
({									\
	__typeof__(ptr) __ptr = (ptr);					\
	__typeof__(*(__ptr)) __new = (new);				\
	__typeof__(*(__ptr)) __ret;					\
									\
	switch (sizeof(*__ptr)) {					\
	case 1:								\
	case 2:								\
		__arch_xchg_masked(prepend, append,			\
				   __ret, __ptr, __new);		\
		break;							\
	case 4:								\
		__arch_xchg(".w" sfx, prepend, append,			\
			      __ret, __ptr, __new);			\
		break;							\
	case 8:								\
		__arch_xchg(".d" sfx, prepend, append,			\
			      __ret, __ptr, __new);			\
		break;							\
	default:							\
		BUILD_BUG();						\
	}								\
	(__typeof__(*(__ptr)))__ret;					\
})

#define arch_xchg_relaxed(ptr, x)					\
	_arch_xchg(ptr, x, "", "", "")

#define arch_xchg_acquire(ptr, x)					\
	_arch_xchg(ptr, x, "", "", RISCV_ACQUIRE_BARRIER)

#define arch_xchg_release(ptr, x)					\
	_arch_xchg(ptr, x, "", RISCV_RELEASE_BARRIER, "")

#define arch_xchg(ptr, x)						\
	_arch_xchg(ptr, x, ".aqrl", "", "")

#define xchg32(ptr, x)							\
({									\
	BUILD_BUG_ON(sizeof(*(ptr)) != 4);				\
	arch_xchg((ptr), (x));						\
})

#define xchg64(ptr, x)							\
({									\
	BUILD_BUG_ON(sizeof(*(ptr)) != 8);				\
	arch_xchg((ptr), (x));						\
})

/*
 * Atomic compare and exchange.  Compare OLD with MEM, if identical,
 * store NEW in MEM.  Return the initial value in MEM.  Success is
 * indicated by comparing RETURN with OLD.
 */

#define __arch_cmpxchg_masked(sc_sfx, cas_sfx, prepend, append, r, p, o, n)	\
({									\
	__label__ zabha, end;						\
									\
	asm goto(ALTERNATIVE("nop", "j %[zabha]", 0,			\
			     RISCV_ISA_EXT_ZABHA, 1)			\
			: : : : zabha);					\
									\
	u32 *__ptr32b = (u32 *)((ulong)(p) & ~0x3);			\
	ulong __s = ((ulong)(p) & (0x4 - sizeof(*p))) * BITS_PER_BYTE;	\
	ulong __mask = GENMASK(((sizeof(*p)) * BITS_PER_BYTE) - 1, 0)	\
			<< __s;						\
	ulong __newx = (ulong)(n) << __s;				\
	ulong __oldx = (ulong)(o) << __s;				\
	ulong __retx;							\
	ulong __rc;							\
									\
	__asm__ __volatile__ (						\
		prepend							\
		"0:	lr.w %0, %2\n"					\
		"	and  %1, %0, %z5\n"				\
		"	bne  %1, %z3, 1f\n"				\
		"	and  %1, %0, %z6\n"				\
		"	or   %1, %1, %z4\n"				\
		"	sc.w" sc_sfx " %1, %1, %2\n"			\
		"	bnez %1, 0b\n"					\
		append							\
		"1:\n"							\
		: "=&r" (__retx), "=&r" (__rc), "+A" (*(__ptr32b))	\
		: "rJ" ((long)__oldx), "rJ" (__newx),			\
		  "rJ" (__mask), "rJ" (~__mask)				\
		: "memory");						\
									\
	r = (__typeof__(*(p)))((__retx & __mask) >> __s);		\
	goto end;							\
									\
zabha:									\
	__asm__ __volatile__ (						\
		prepend							\
		"	amocas" cas_sfx " %0, %z2, %1\n"		\
		append							\
		: "+&r" (r), "+A" (*(p))				\
		: "rJ" (n)						\
		: "memory");						\
end:									\
})

#define __arch_cmpxchg(lr_sfx, sc_cas_sfx, prepend, append, r, p, co, o, n)	\
({									\
	__label__ zacas, end;						\
	register unsigned int __rc;					\
									\
	asm goto(ALTERNATIVE("nop", "j %[zacas]", 0,			\
			     RISCV_ISA_EXT_ZACAS, 1)			\
			: : : : zacas);					\
									\
	__asm__ __volatile__ (						\
		prepend							\
		"0:	lr" lr_sfx " %0, %2\n"				\
		"	bne  %0, %z3, 1f\n"				\
		"	sc" sc_cas_sfx " %1, %z4, %2\n"			\
		"	bnez %1, 0b\n"					\
		append							\
		"1:\n"							\
		: "=&r" (r), "=&r" (__rc), "+A" (*(p))			\
		: "rJ" (co o), "rJ" (n)					\
		: "memory");						\
	goto end;							\
									\
zacas:									\
	__asm__ __volatile__ (						\
		prepend							\
		"	amocas" sc_cas_sfx " %0, %z2, %1\n"		\
		append							\
		: "+&r" (r), "+A" (*(p))				\
		: "rJ" (n)						\
		: "memory");						\
end:									\
})

#define _arch_cmpxchg(ptr, old, new, sc_sfx, prepend, append)		\
({									\
	__typeof__(ptr) __ptr = (ptr);					\
	__typeof__(*(__ptr)) __old = (old);				\
	__typeof__(*(__ptr)) __new = (new);				\
	__typeof__(*(__ptr)) __ret = (old);				\
									\
	switch (sizeof(*__ptr)) {					\
	case 1:								\
		__arch_cmpxchg_masked(sc_sfx, ".b" sc_sfx,		\
					prepend, append,		\
					__ret, __ptr, __old, __new);    \
		break;							\
	case 2:								\
		__arch_cmpxchg_masked(sc_sfx, ".h" sc_sfx,		\
					prepend, append,		\
					__ret, __ptr, __old, __new);	\
		break;							\
	case 4:								\
		__arch_cmpxchg(".w", ".w" sc_sfx, prepend, append,	\
				__ret, __ptr, (long), __old, __new);	\
		break;							\
	case 8:								\
		__arch_cmpxchg(".d", ".d" sc_sfx, prepend, append,	\
				__ret, __ptr, /**/, __old, __new);	\
		break;							\
	default:							\
		BUILD_BUG();						\
	}								\
	(__typeof__(*(__ptr)))__ret;					\
})

#define arch_cmpxchg_relaxed(ptr, o, n)					\
	_arch_cmpxchg((ptr), (o), (n), "", "", "")

#define arch_cmpxchg_acquire(ptr, o, n)					\
	_arch_cmpxchg((ptr), (o), (n), "", "", RISCV_ACQUIRE_BARRIER)

#define arch_cmpxchg_release(ptr, o, n)					\
	_arch_cmpxchg((ptr), (o), (n), "", RISCV_RELEASE_BARRIER, "")

#define arch_cmpxchg(ptr, o, n)						\
	_arch_cmpxchg((ptr), (o), (n), ".rl", "", "	fence rw, rw\n")

#define arch_cmpxchg_local(ptr, o, n)					\
	arch_cmpxchg_relaxed((ptr), (o), (n))

#define arch_cmpxchg64(ptr, o, n)					\
({									\
	BUILD_BUG_ON(sizeof(*(ptr)) != 8);				\
	arch_cmpxchg((ptr), (o), (n));					\
})

#define arch_cmpxchg64_local(ptr, o, n)					\
({									\
	BUILD_BUG_ON(sizeof(*(ptr)) != 8);				\
	arch_cmpxchg_relaxed((ptr), (o), (n));				\
})

#define arch_cmpxchg64_relaxed(ptr, o, n)				\
({									\
	BUILD_BUG_ON(sizeof(*(ptr)) != 8);				\
	arch_cmpxchg_relaxed((ptr), (o), (n));				\
})

#define arch_cmpxchg64_acquire(ptr, o, n)				\
({									\
	BUILD_BUG_ON(sizeof(*(ptr)) != 8);				\
	arch_cmpxchg_acquire((ptr), (o), (n));				\
})

#define arch_cmpxchg64_release(ptr, o, n)				\
({									\
	BUILD_BUG_ON(sizeof(*(ptr)) != 8);				\
	arch_cmpxchg_release((ptr), (o), (n));				\
})

#ifdef CONFIG_RISCV_ISA_ZACAS

#define system_has_cmpxchg128()						\
			riscv_has_extension_unlikely(RISCV_ISA_EXT_ZACAS)

union __u128_halves {
	u128 full;
	struct {
		u64 low, high;
	};
};

#define __arch_cmpxchg128(p, o, n, prepend, append)			\
({									\
	__typeof__(*(p)) __o = (o);					\
	union __u128_halves new = { .full = (n) };			\
	union __u128_halves old = { .full = (__o) };			\
	register unsigned long x6 asm ("x6") = new.low;			\
	register unsigned long x7 asm ("x7") = new.high;		\
	register unsigned long x28 asm ("x28") = old.low;		\
	register unsigned long x29 asm ("x29") = old.high;		\
									\
	__asm__ __volatile__ (						\
		prepend							\
		"	amocas.q %0, %z2, %1\n"				\
		append							\
		: "+&r" (x28), "+A" (*(p))				\
		: "rJ" (x6)						\
		: "memory");						\
									\
	__o;								\
})

#define arch_cmpxchg128(ptr, o, n)					\
	__arch_cmpxchg128((ptr), (o), (n), "", "     fence rw, rw\n")

#define arch_cmpxchg128_local(ptr, o, n)				\
	__arch_cmpxchg128((ptr), (o), (n), "", "")

#endif /* CONFIG_RISCV_ISA_ZACAS */

#endif /* _ASM_RISCV_CMPXCHG_H */

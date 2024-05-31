// SPDX-License-Identifier: GPL-2.0-only

/*
 * To avoid rewriteing code include asm/archrandom.h and create macros
 * for the functions that won't be included.
 */

#define riscv_has_extension_likely(...) false
#define pr_err_once(...)

#include <linux/types.h>
#include <asm/hwcap.h>
#include <asm/archrandom.h>

/*
 * Asm goto is needed so that the compiler does not remove the label.
 */

#define csr_goto_swap(csr, val)						\
({									\
	unsigned long __v;						\
	__asm__ __volatile__ goto("csrrw %0, " __ASM_STR(csr) ", %1"	\
				  : "=r" (__v) : "rK" (&&val)		\
				  : "memory" : val);			\
	__v;								\
})

/*
 * Declare the functions that are exported (but prefixed) here so that LLVM
 * does not complain it lacks the 'static' keyword (which, if added, makes
 * LLVM complain because the function is actually unused in this file).
 */

u64 get_kaslr_seed_zkr(void);

/*
 * This function is called by setup_vm to check if the kernel has the ZKR.
 * Traps haven't been set up yet, but save and restore the TVEC to avoid
 * any side effects.
 */

static inline bool __must_check riscv_has_zkr(void)
{
	unsigned long tvec;

	tvec = csr_goto_swap(CSR_TVEC, not_zkr);
	csr_swap(CSR_SEED, 0);
	csr_write(CSR_TVEC, tvec);
	return true;
not_zkr:
	csr_write(CSR_TVEC, tvec);
	return false;
}

u64 get_kaslr_seed_zkr(void)
{
	const int needed_seeds = sizeof(u64) / sizeof(long);
	int i = 0;
	u64 seed = 0;
	long *entropy = (long *)(&seed);

	if (!riscv_has_zkr())
		return 0;

	for (i = 0; i < needed_seeds; i++) {
		if (!csr_seed_long(&entropy[i]))
			return 0;
	}

	return seed;
}

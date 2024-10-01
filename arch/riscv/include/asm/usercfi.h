/* SPDX-License-Identifier: GPL-2.0
 * Copyright (C) 2024 Rivos, Inc.
 * Deepak Gupta <debug@rivosinc.com>
 */
#ifndef _ASM_RISCV_USERCFI_H
#define _ASM_RISCV_USERCFI_H

#ifndef __ASSEMBLY__
#include <linux/types.h>

#ifdef CONFIG_RISCV_USER_CFI
struct cfi_status {
	unsigned long ubcfi_en : 1; /* Enable for backward cfi. */
	unsigned long rsvd : ((sizeof(unsigned long)*8) - 1);
	unsigned long user_shdw_stk; /* Current user shadow stack pointer */
	unsigned long shdw_stk_base; /* Base address of shadow stack */
	unsigned long shdw_stk_size; /* size of shadow stack */
};

#endif /* CONFIG_RISCV_USER_CFI */

#endif /* __ASSEMBLY__ */

#endif /* _ASM_RISCV_USERCFI_H */

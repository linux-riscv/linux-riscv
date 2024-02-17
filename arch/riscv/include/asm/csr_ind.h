/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024 Rivos Inc.
 */

#ifndef _ASM_RISCV_CSR_IND_H
#define _ASM_RISCV_CSR_IND_H

#include <asm/csr.h>

#define csr_ind_read(iregcsr, iselbase, iseloff) ({	\
	unsigned long value = 0;			\
	unsigned long flags;				\
	local_irq_save(flags);				\
	csr_write(CSR_ISELECT, iselbase + iseloff);	\
	value = csr_read(iregcsr);			\
	local_irq_restore(flags);			\
	value;						\
})

#define csr_ind_write(iregcsr, iselbase, iseloff, value) ({	\
	unsigned long flags;					\
	local_irq_save(flags);					\
	csr_write(CSR_ISELECT, iselbase + iseloff);		\
	csr_write(iregcsr, value);				\
	local_irq_restore(flags);				\
})

#define csr_ind_warl(iregcsr, iselbase, iseloff, warl_val) ({	\
	unsigned long old_val = 0, value = 0;			\
	unsigned long flags;					\
	local_irq_save(flags);					\
	csr_write(CSR_ISELECT, iselbase + iseloff);		\
	old_val = csr_read(iregcsr);				\
	csr_write(iregcsr, value);				\
	value = csr_read(iregcsr);				\
	csr_write(iregcsr, old_val);				\
	local_irq_restore(flags);				\
	value;							\
})

#endif

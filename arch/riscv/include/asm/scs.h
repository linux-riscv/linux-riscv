/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SCS_H
#define _ASM_SCS_H

#ifdef __ASSEMBLY__
#include <asm/asm-offsets.h>

#ifdef CONFIG_SHADOW_CALL_STACK

/* Load init_shadow_call_stack to gp. */
.macro scs_load_init_stack
#ifndef CONFIG_DYNAMIC_SCS
	la	gp, init_shadow_call_stack
	XIP_FIXUP_OFFSET gp
#endif
.endm

/* Load the per-CPU IRQ shadow call stack to gp. */
.macro scs_load_irq_stack tmp tmp1
#ifdef CONFIG_DYNAMIC_SCS
	load_per_cpu \tmp1, irq_shadow_call_stack_ptr, \tmp
	li \tmp, 4096
	add \tmp, \tmp, \tmp1
	csrw CSR_SSP, \tmp
#else
	load_per_cpu gp, irq_shadow_call_stack_ptr, \tmp
#endif
.endm

/* Load task_scs_sp(current) to gp. */
.macro scs_load_current tmp
#ifdef CONFIG_DYNAMIC_SCS
	REG_L	\tmp, TASK_TI_SCS_SP(tp)
	csrw CSR_SSP, \tmp
#else
	REG_L	gp, TASK_TI_SCS_SP(tp)
#endif
.endm

/* Load task_scs_sp(current) to gp, but only if tp has changed. */
.macro scs_load_current_if_task_changed prev tmp
	beq	\prev, tp, _skip_scs
	scs_load_current \tmp
_skip_scs:
.endm

/* Save gp to task_scs_sp(current). */
.macro scs_save_current tmp
#ifdef CONFIG_DYNAMIC_SCS
	csrr \tmp, CSR_SSP
	REG_S	\tmp, TASK_TI_SCS_SP(tp)
#else
	REG_S	gp, TASK_TI_SCS_SP(tp)
#endif
.endm

#else /* CONFIG_SHADOW_CALL_STACK */

.macro scs_load_init_stack
.endm
.macro scs_load_irq_stack tmp tmp1
.endm
.macro scs_load_current tmp
.endm
.macro scs_load_current_if_task_changed prev tmp
.endm
.macro scs_save_current tmp
.endm

#endif /* CONFIG_SHADOW_CALL_STACK */
#endif /* __ASSEMBLY__ */

#ifdef CONFIG_DYNAMIC_SCS
#define arch_scs_store(ss_addr, magic_val)	\
	asm volatile ("ssamoswap.d %0, %2, %1"	\
					: "=r" (magic_val), "+A" (*ss_addr)	\
					: "r" (magic_val)	\
					: "memory")
#else
#define arch_scs_store(ss_addr, magic_val)
#endif

#endif /* _ASM_SCS_H */

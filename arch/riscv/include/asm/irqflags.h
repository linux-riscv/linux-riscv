/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 */


#ifndef _ASM_RISCV_IRQFLAGS_H
#define _ASM_RISCV_IRQFLAGS_H

#include <asm/processor.h>
#include <asm/csr.h>

#ifdef CONFIG_RISCV_PSEUDO_NMI

#define __ALLOWED_NMI_MASK			BIT(IRQ_PMU_OVF)
#define ALLOWED_NMI_MASK			(__ALLOWED_NMI_MASK & irqs_enabled_ie)

static inline bool nmi_allowed(int irq)
{
	return (BIT(irq) & ALLOWED_NMI_MASK);
}

static inline bool is_nmi(int irq)
{
	return (BIT(irq) & ALLOWED_NMI_MASK);
}

static inline void set_nmi(int irq) {}

static inline void unset_nmi(int irq) {}

static inline void enable_nmis(void)
{
	csr_set(CSR_IE, ALLOWED_NMI_MASK);
}

static inline void disable_nmis(void)
{
	csr_clear(CSR_IE, ALLOWED_NMI_MASK);
}

static inline void local_irq_switch_on(void)
{
	csr_set(CSR_STATUS, SR_IE);
}

static inline void local_irq_switch_off(void)
{
	csr_clear(CSR_STATUS, SR_IE);
}

/* read interrupt enabled status */
static inline unsigned long arch_local_save_flags(void)
{
	return csr_read(CSR_IE);
}

/* unconditionally enable interrupts */
static inline void arch_local_irq_enable(void)
{
	csr_set(CSR_IE, irqs_enabled_ie);
}

/* unconditionally disable interrupts */
static inline void arch_local_irq_disable(void)
{
	csr_clear(CSR_IE, ~ALLOWED_NMI_MASK);
}

/* get status and disable interrupts */
static inline unsigned long arch_local_irq_save(void)
{
	return csr_read_clear(CSR_IE, ~ALLOWED_NMI_MASK);
}

/* test flags */
static inline int arch_irqs_disabled_flags(unsigned long flags)
{
	return (flags != irqs_enabled_ie);
}

/* test hardware interrupt enable bit */
static inline int arch_irqs_disabled(void)
{
	return arch_irqs_disabled_flags(arch_local_save_flags());
}

/* set interrupt enabled status */
static inline void arch_local_irq_restore(unsigned long flags)
{
	csr_write(CSR_IE, flags);
}

#define local_irq_enable_vcpu_run		local_irq_switch_on
#define local_irq_disable_vcpu_run		local_irq_switch_off

#else /* CONFIG_RISCV_PSEUDO_NMI */

/* read interrupt enabled status */
static inline unsigned long arch_local_save_flags(void)
{
	return csr_read(CSR_STATUS);
}

/* unconditionally enable interrupts */
static inline void arch_local_irq_enable(void)
{
	csr_set(CSR_STATUS, SR_IE);
}

/* unconditionally disable interrupts */
static inline void arch_local_irq_disable(void)
{
	csr_clear(CSR_STATUS, SR_IE);
}

/* get status and disable interrupts */
static inline unsigned long arch_local_irq_save(void)
{
	return csr_read_clear(CSR_STATUS, SR_IE);
}

/* test flags */
static inline int arch_irqs_disabled_flags(unsigned long flags)
{
	return !(flags & SR_IE);
}

/* test hardware interrupt enable bit */
static inline int arch_irqs_disabled(void)
{
	return arch_irqs_disabled_flags(arch_local_save_flags());
}

/* set interrupt enabled status */
static inline void arch_local_irq_restore(unsigned long flags)
{
	csr_set(CSR_STATUS, flags & SR_IE);
}

static inline void enable_nmis(void) {}
static inline void disable_nmis(void) {}

#endif /* !CONFIG_RISCV_PSEUDO_NMI */

#endif /* _ASM_RISCV_IRQFLAGS_H */

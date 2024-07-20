/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_RISCV_PROTOTYPES_H
#define _ASM_RISCV_PROTOTYPES_H

#include <linux/ftrace.h>
#include <asm-generic/asm-prototypes.h>

long long __lshrti3(long long a, int b);
long long __ashrti3(long long a, int b);
long long __ashlti3(long long a, int b);

#ifdef CONFIG_RISCV_ISA_V

#ifdef CONFIG_MMU
asmlinkage int enter_vector_usercopy(void *dst, void *src, size_t n);
#endif /* CONFIG_MMU  */

void xor_regs_2_(unsigned long bytes, unsigned long *__restrict p1,
		 const unsigned long *__restrict p2);
void xor_regs_3_(unsigned long bytes, unsigned long *__restrict p1,
		 const unsigned long *__restrict p2,
		 const unsigned long *__restrict p3);
void xor_regs_4_(unsigned long bytes, unsigned long *__restrict p1,
		 const unsigned long *__restrict p2,
		 const unsigned long *__restrict p3,
		 const unsigned long *__restrict p4);
void xor_regs_5_(unsigned long bytes, unsigned long *__restrict p1,
		 const unsigned long *__restrict p2,
		 const unsigned long *__restrict p3,
		 const unsigned long *__restrict p4,
		 const unsigned long *__restrict p5);

#ifdef CONFIG_RISCV_ISA_V_PREEMPTIVE
void riscv_v_context_nesting_start(struct pt_regs *regs);
asmlinkage void riscv_v_context_nesting_end(struct pt_regs *regs);
#endif /* CONFIG_RISCV_ISA_V_PREEMPTIVE */

#endif /* CONFIG_RISCV_ISA_V */

asmlinkage void handle_bad_stack(struct pt_regs *regs);
asmlinkage void do_traps(struct pt_regs *regs, unsigned long cause);

#endif /* _ASM_RISCV_PROTOTYPES_H */

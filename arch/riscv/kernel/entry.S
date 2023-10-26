/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 */

#include <linux/init.h>
#include <linux/linkage.h>

#include <asm/asm.h>
#include <asm/csr.h>
#include <asm/unistd.h>
#include <asm/thread_info.h>
#include <asm/asm-offsets.h>
#include <asm/errata_list.h>

#ifdef CONFIG_RISCV_SSE
#define IN_TP			0
#define IN_SSCRATCH		1
#define PRV_U_TASK_LOC(loc)	(loc << 0)
#define PRV_S_TASK_LOC(loc)	(loc << 1)
#define TASK_LOC(s_loc, u_loc)	(PRV_U_TASK_LOC(u_loc) | PRV_S_TASK_LOC(s_loc))
#define TASK_LOC_ENTRY_SIZE	(RISCV_SZPTR + 1)

/* __SSE_TASK_LOC - Annotate e'xception code with the location of current task
 *		    struct when coming from S/U mode
 *
 * When entering handle_exception(), the current task struct is located either
 * in tp or sscratch depending on interrupted mode. Since SSE handlers can be
 * triggered at any time during the execution of the kernel, we need to be able
 * to retrieve the current task struct even if in handle_exception. This macro
 * create an entry into the __task_loc section that holds the location of
 * the current task struct for the subsequent assembly located after that up to
 * _ret_from_exception_end or the next __TASK_LOC.
 */
#define __SSE_TASK_LOC(s_loc, u_loc)			\
	.pushsection __task_loc,"a";	\
	RISCV_PTR 99f;				\
	.byte TASK_LOC(s_loc, u_loc);		\
	.popsection;				\
	99:
#else
#define __SSE_TASK_LOC(s_loc, u_loc)
#endif

SYM_CODE_START(handle_exception)
	/*
	 * If coming from userspace, preserve the user thread pointer and load
	 * the kernel thread pointer.  If we came from the kernel, the scratch
	 * register will contain 0, and we should continue on the current TP.
	 */
__SSE_TASK_LOC(IN_TP, IN_SSCRATCH)
	csrrw tp, CSR_SCRATCH, tp
__SSE_TASK_LOC(IN_SSCRATCH, IN_TP)
	bnez tp, _save_context

_restore_kernel_tpsp:
	csrr tp, CSR_SCRATCH
__SSE_TASK_LOC(IN_TP, IN_TP)
	REG_S sp, TASK_TI_KERNEL_SP(tp)

#ifdef CONFIG_VMAP_STACK
	addi sp, sp, -(PT_SIZE_ON_STACK)
	srli sp, sp, THREAD_SHIFT
	andi sp, sp, 0x1
	bnez sp, handle_kernel_stack_overflow
	REG_L sp, TASK_TI_KERNEL_SP(tp)
#endif

_save_context:
	REG_S sp, TASK_TI_USER_SP(tp)
	REG_L sp, TASK_TI_KERNEL_SP(tp)
	addi sp, sp, -(PT_SIZE_ON_STACK)
	REG_S x1,  PT_RA(sp)
	REG_S x3,  PT_GP(sp)
	REG_S x5,  PT_T0(sp)
	save_from_x6_to_x31

	/*
	 * Disable user-mode memory access as it should only be set in the
	 * actual user copy routines.
	 *
	 * Disable the FPU/Vector to detect illegal usage of floating point
	 * or vector in kernel space.
	 */
	li t0, SR_SUM | SR_FS_VS

	REG_L s0, TASK_TI_USER_SP(tp)
	csrrc s1, CSR_STATUS, t0
	csrr s2, CSR_EPC
	csrr s3, CSR_TVAL
	csrr s4, CSR_CAUSE
	csrr s5, CSR_SCRATCH
	REG_S s0, PT_SP(sp)
	REG_S s1, PT_STATUS(sp)
	REG_S s2, PT_EPC(sp)
	REG_S s3, PT_BADADDR(sp)
	REG_S s4, PT_CAUSE(sp)
	REG_S s5, PT_TP(sp)

	/*
	 * Set the scratch register to 0, so that if a recursive exception
	 * occurs, the exception vector knows it came from the kernel
	 */
	csrw CSR_SCRATCH, x0

	/* Load the global pointer */
.option push
.option norelax
	la gp, __global_pointer$
.option pop
	move a0, sp /* pt_regs */
	la ra, ret_from_exception

	/*
	 * MSB of cause differentiates between
	 * interrupts and exceptions
	 */
	bge s4, zero, 1f

	/* Handle interrupts */
	tail do_irq
1:
	/* Handle other exceptions */
	slli t0, s4, RISCV_LGPTR
	la t1, excp_vect_table
	la t2, excp_vect_table_end
	add t0, t1, t0
	/* Check if exception code lies within bounds */
	bgeu t0, t2, 1f
	REG_L t0, 0(t0)
	jr t0
1:
	tail do_trap_unknown
SYM_CODE_END(handle_exception)

/*
 * The ret_from_exception must be called with interrupt disabled. Here is the
 * caller list:
 *  - handle_exception
 *  - ret_from_fork
 */
SYM_CODE_START_NOALIGN(ret_from_exception)
	REG_L s0, PT_STATUS(sp)
#ifdef CONFIG_RISCV_M_MODE
	/* the MPP value is too large to be used as an immediate arg for addi */
	li t0, SR_MPP
	and s0, s0, t0
#else
	andi s0, s0, SR_SPP
#endif
	bnez s0, 1f

	/* Save unwound kernel stack pointer in thread_info */
	addi s0, sp, PT_SIZE_ON_STACK
	REG_S s0, TASK_TI_KERNEL_SP(tp)

	/*
	 * Save TP into the scratch register , so we can find the kernel data
	 * structures again.
	 */
	csrw CSR_SCRATCH, tp
1:
	REG_L a0, PT_STATUS(sp)
	/*
	 * The current load reservation is effectively part of the processor's
	 * state, in the sense that load reservations cannot be shared between
	 * different hart contexts.  We can't actually save and restore a load
	 * reservation, so instead here we clear any existing reservation --
	 * it's always legal for implementations to clear load reservations at
	 * any point (as long as the forward progress guarantee is kept, but
	 * we'll ignore that here).
	 *
	 * Dangling load reservations can be the result of taking a trap in the
	 * middle of an LR/SC sequence, but can also be the result of a taken
	 * forward branch around an SC -- which is how we implement CAS.  As a
	 * result we need to clear reservations between the last CAS and the
	 * jump back to the new context.  While it is unlikely the store
	 * completes, implementations are allowed to expand reservations to be
	 * arbitrarily large.
	 */
	REG_L  a2, PT_EPC(sp)
	REG_SC x0, a2, PT_EPC(sp)

	csrw CSR_STATUS, a0
__SSE_TASK_LOC(IN_TP, IN_SSCRATCH)
	csrw CSR_EPC, a2

	REG_L x1,  PT_RA(sp)
	REG_L x3,  PT_GP(sp)
	REG_L x4,  PT_TP(sp)
	REG_L x5,  PT_T0(sp)
	restore_from_x6_to_x31

	REG_L x2,  PT_SP(sp)

#ifdef CONFIG_RISCV_M_MODE
	mret
#else
	sret
#endif
_ret_from_exception_end:
SYM_CODE_END(ret_from_exception)

#ifdef CONFIG_VMAP_STACK
SYM_CODE_START_LOCAL(handle_kernel_stack_overflow)
	/*
	 * Takes the psuedo-spinlock for the shadow stack, in case multiple
	 * harts are concurrently overflowing their kernel stacks.  We could
	 * store any value here, but since we're overflowing the kernel stack
	 * already we only have SP to use as a scratch register.  So we just
	 * swap in the address of the spinlock, as that's definately non-zero.
	 *
	 * Pairs with a store_release in handle_bad_stack().
	 */
1:	la sp, spin_shadow_stack
	REG_AMOSWAP_AQ sp, sp, (sp)
	bnez sp, 1b

	la sp, shadow_stack
	addi sp, sp, SHADOW_OVERFLOW_STACK_SIZE

	//save caller register to shadow stack
	addi sp, sp, -(PT_SIZE_ON_STACK)
	REG_S x1,  PT_RA(sp)
	REG_S x5,  PT_T0(sp)
	REG_S x6,  PT_T1(sp)
	REG_S x7,  PT_T2(sp)
	REG_S x10, PT_A0(sp)
	REG_S x11, PT_A1(sp)
	REG_S x12, PT_A2(sp)
	REG_S x13, PT_A3(sp)
	REG_S x14, PT_A4(sp)
	REG_S x15, PT_A5(sp)
	REG_S x16, PT_A6(sp)
	REG_S x17, PT_A7(sp)
	REG_S x28, PT_T3(sp)
	REG_S x29, PT_T4(sp)
	REG_S x30, PT_T5(sp)
	REG_S x31, PT_T6(sp)

	la ra, restore_caller_reg
	tail get_overflow_stack

restore_caller_reg:
	//save per-cpu overflow stack
	REG_S a0, -8(sp)
	//restore caller register from shadow_stack
	REG_L x1,  PT_RA(sp)
	REG_L x5,  PT_T0(sp)
	REG_L x6,  PT_T1(sp)
	REG_L x7,  PT_T2(sp)
	REG_L x10, PT_A0(sp)
	REG_L x11, PT_A1(sp)
	REG_L x12, PT_A2(sp)
	REG_L x13, PT_A3(sp)
	REG_L x14, PT_A4(sp)
	REG_L x15, PT_A5(sp)
	REG_L x16, PT_A6(sp)
	REG_L x17, PT_A7(sp)
	REG_L x28, PT_T3(sp)
	REG_L x29, PT_T4(sp)
	REG_L x30, PT_T5(sp)
	REG_L x31, PT_T6(sp)

	//load per-cpu overflow stack
	REG_L sp, -8(sp)
	addi sp, sp, -(PT_SIZE_ON_STACK)

	//save context to overflow stack
	REG_S x1,  PT_RA(sp)
	REG_S x3,  PT_GP(sp)
	REG_S x5,  PT_T0(sp)
	save_from_x6_to_x31

	REG_L s0, TASK_TI_KERNEL_SP(tp)
	csrr s1, CSR_STATUS
	csrr s2, CSR_EPC
	csrr s3, CSR_TVAL
	csrr s4, CSR_CAUSE
	csrr s5, CSR_SCRATCH
	REG_S s0, PT_SP(sp)
	REG_S s1, PT_STATUS(sp)
	REG_S s2, PT_EPC(sp)
	REG_S s3, PT_BADADDR(sp)
	REG_S s4, PT_CAUSE(sp)
	REG_S s5, PT_TP(sp)
	move a0, sp
	tail handle_bad_stack
SYM_CODE_END(handle_kernel_stack_overflow)
#endif

SYM_CODE_START(ret_from_fork)
	call schedule_tail
	beqz s0, 1f	/* not from kernel thread */
	/* Call fn(arg) */
	move a0, s1
	jalr s0
1:
	move a0, sp /* pt_regs */
	la ra, ret_from_exception
	tail syscall_exit_to_user_mode
SYM_CODE_END(ret_from_fork)

#ifdef CONFIG_RISCV_SSE
SYM_CODE_START(handle_sse)
	move s3, a0
	/*
	 * Depending on where the sse event interrupted the kernel execution,
	 * sscratch content might be 0 or not even if kernel was interrupted.
	 * This might happen if the sse event was triggered while in
	 * handle_exception() right after entry. In that case, sscratch might
	 * contain 0 if coming from kernel. In order to handle that easily,
	 * simply save sscratch content and restore it when returning from sse
	 * event.
	 */
	csrr s4, CSR_SSCRATCH
	/*
	 * Save CAUSE and TVAL in case of nested exceptions, EPC/STATUS are
	 * already saved/restored by handle_exception() for nested exceptions.
	 */
	csrr s5, CSR_SCAUSE
	csrr s6, CSR_STVAL
	REG_L t0, SSE_INTERRUPTED_EXEC_MODE(a1)
	andi t1, t0, 0x1

	/* Userspace was interrupted, simply restore TP from scratch */
	bnez t1, _sse_from_kernel
	move tp, s4
	j _call_do_sse

_sse_from_kernel:
	REG_L t0, SSE_INTERRUPTED_PC(a1)
#ifdef CONFIG_FRAME_POINTER
	/*
	 * Else, kernel was interrupted and we will create a correct stack frame
	 * from interrupted context.
	 */
	addi sp, sp, -(STACKFRAME_SIZE_ON_STACK)
	REG_L t2, SSE_INTERRUPTED_S0(a1)
	REG_S t2, STACKFRAME_FP(sp)
	REG_S t0, STACKFRAME_RA(sp)
	addi s0, sp, STACKFRAME_SIZE_ON_STACK
#endif
	REG_L tp, SSE_INTERRUPTED_TP(a1)

	/*
	 * If interrupting the kernel during exception handling
	 * (see handle_exception), then, we might have tp either in SSCRATCH or
	 * in tp, this part is non regular and requires some more work to
	 * determine were is located the current task.
	 */
	la t1, handle_exception
	la t2, _ret_from_exception_end
	bltu t0, t1, _call_do_sse
	bltu t0, t2, _sse_exception_slow_path

_call_do_sse:

	/* TODO: remove this sanity check once sure everything works ! */
	li t1, ASM_PAGE_OFFSET
	bgeu tp, t1, _tp_ok
	la tp, init_task
	la a0, sse_panic_string
	la t0, panic
	jalr t0
_tp_ok:

	csrw CSR_SCRATCH, x0
	la ra, ret_from_sse
	tail do_sse

.global ret_from_sse
ret_from_sse:
	/* Restore saved CSRs */
	csrw CSR_SSCRATCH, s4
	csrw CSR_SCAUSE, s5
	csrw CSR_STVAL, s6
	li a2, 0
	move a1, a0
	move a0, s3
	li a7, SBI_EXT_SSE
	li a6, SBI_SSE_EVENT_COMPLETE
	ecall

/*
 * t0 contains interrupted pc
 * t1 contains handle_exception address
 * When called, t0 must be in [handle_exception, _ret_from_exception_end[
 */
_sse_exception_slow_path:
	la t3, __stop___task_loc
	add t3, t3, -TASK_LOC_ENTRY_SIZE
	la t4, __start___task_loc
	/*
	 * Reverse iterate the task location section to find where is located
	 * the task struct
	 */
1:
	REG_L	t2, 0(t3)
	bgeu t0, t2, 2f
	add t3, t3, -TASK_LOC_ENTRY_SIZE
	bgeu t3, t4, 1b

2:
	lbu t2, RISCV_SZPTR(t3)

	/* Get the value of SR_SPP */
	csrr t1, CSR_SSTATUS
	andi t1, t1, SR_SPP
	snez t1, t1

	srl t2, t2, t1
	andi t2, t2, 1
	beqz t2, _call_do_sse

_restore_tp_from_sscratch:
	csrr tp, CSR_SCRATCH
	j _call_do_sse

SYM_CODE_END(handle_sse)
#endif

/*
 * Integer register context switch
 * The callee-saved registers must be saved and restored.
 *
 *   a0: previous task_struct (must be preserved across the switch)
 *   a1: next task_struct
 *
 * The value of a0 and a1 must be preserved by this function, as that's how
 * arguments are passed to schedule_tail.
 */
SYM_FUNC_START(__switch_to)
	/* Save context into prev->thread */
	li    a4,  TASK_THREAD_RA
	add   a3, a0, a4
	add   a4, a1, a4
	REG_S ra,  TASK_THREAD_RA_RA(a3)
	REG_S sp,  TASK_THREAD_SP_RA(a3)
	REG_S s0,  TASK_THREAD_S0_RA(a3)
	REG_S s1,  TASK_THREAD_S1_RA(a3)
	REG_S s2,  TASK_THREAD_S2_RA(a3)
	REG_S s3,  TASK_THREAD_S3_RA(a3)
	REG_S s4,  TASK_THREAD_S4_RA(a3)
	REG_S s5,  TASK_THREAD_S5_RA(a3)
	REG_S s6,  TASK_THREAD_S6_RA(a3)
	REG_S s7,  TASK_THREAD_S7_RA(a3)
	REG_S s8,  TASK_THREAD_S8_RA(a3)
	REG_S s9,  TASK_THREAD_S9_RA(a3)
	REG_S s10, TASK_THREAD_S10_RA(a3)
	REG_S s11, TASK_THREAD_S11_RA(a3)
	/* Restore context from next->thread */
	REG_L ra,  TASK_THREAD_RA_RA(a4)
	REG_L sp,  TASK_THREAD_SP_RA(a4)
	REG_L s0,  TASK_THREAD_S0_RA(a4)
	REG_L s1,  TASK_THREAD_S1_RA(a4)
	REG_L s2,  TASK_THREAD_S2_RA(a4)
	REG_L s3,  TASK_THREAD_S3_RA(a4)
	REG_L s4,  TASK_THREAD_S4_RA(a4)
	REG_L s5,  TASK_THREAD_S5_RA(a4)
	REG_L s6,  TASK_THREAD_S6_RA(a4)
	REG_L s7,  TASK_THREAD_S7_RA(a4)
	REG_L s8,  TASK_THREAD_S8_RA(a4)
	REG_L s9,  TASK_THREAD_S9_RA(a4)
	REG_L s10, TASK_THREAD_S10_RA(a4)
	REG_L s11, TASK_THREAD_S11_RA(a4)
	/* The offset of thread_info in task_struct is zero. */
	move tp, a1
	ret
SYM_FUNC_END(__switch_to)

#ifndef CONFIG_MMU
#define do_page_fault do_trap_unknown
#endif

	.section ".rodata"
	.align LGREG
	/* Exception vector table */
SYM_CODE_START(excp_vect_table)
	RISCV_PTR do_trap_insn_misaligned
	ALT_INSN_FAULT(RISCV_PTR do_trap_insn_fault)
	RISCV_PTR do_trap_insn_illegal
	RISCV_PTR do_trap_break
	RISCV_PTR do_trap_load_misaligned
	RISCV_PTR do_trap_load_fault
	RISCV_PTR do_trap_store_misaligned
	RISCV_PTR do_trap_store_fault
	RISCV_PTR do_trap_ecall_u /* system call */
	RISCV_PTR do_trap_ecall_s
	RISCV_PTR do_trap_unknown
	RISCV_PTR do_trap_ecall_m
	/* instruciton page fault */
	ALT_PAGE_FAULT(RISCV_PTR do_page_fault)
	RISCV_PTR do_page_fault   /* load page fault */
	RISCV_PTR do_trap_unknown
	RISCV_PTR do_page_fault   /* store page fault */
excp_vect_table_end:
SYM_CODE_END(excp_vect_table)

#ifndef CONFIG_MMU
SYM_CODE_START(__user_rt_sigreturn)
	li a7, __NR_rt_sigreturn
	ecall
SYM_CODE_END(__user_rt_sigreturn)
#endif

sse_panic_string:
    .ascii "SSE TP is invalid, last state %px"

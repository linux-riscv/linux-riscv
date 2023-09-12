// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 * Copyright (C) 2017 Linaro Ltd. <ard.biesheuvel@linaro.org>
 * Copyright (C) 2021 SiFive
 */
#include <linux/compiler.h>
#include <linux/irqflags.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/types.h>
#include <linux/slab.h>

#include <asm/vector.h>
#include <asm/switch_to.h>
#include <asm/simd.h>

DEFINE_PER_CPU(bool, vector_context_busy);

/*
 * Claim ownership of the CPU vector context for use by the calling context.
 *
 * The caller may freely manipulate the vector context metadata until
 * put_cpu_vector_context() is called.
 */
static void get_cpu_vector_context(void)
{
	bool busy;

	preempt_disable();
	busy = __this_cpu_xchg(vector_context_busy, true);

	WARN_ON(busy);
}

/*
 * Release the CPU vector context.
 *
 * Must be called from a context in which get_cpu_vector_context() was
 * previously called, with no call to put_cpu_vector_context() in the
 * meantime.
 */
static void put_cpu_vector_context(void)
{
	bool busy = __this_cpu_xchg(vector_context_busy, false);

	WARN_ON(!busy);
	preempt_enable();
}

#ifdef CONFIG_RISCV_ISA_V_PREEMPTIVE
void kernel_vector_allow_preemption(void)
{
	current->thread.vstate_ctrl |= RISCV_V_VSTATE_CTRL_PREEMPTIBLE;
}

static bool kernel_vector_preemptible(void)
{
	return !!(current->thread.vstate_ctrl & RISCV_V_VSTATE_CTRL_PREEMPTIBLE);
}

static int riscv_v_start_kernel_context(void)
{
	struct __riscv_v_ext_state *vstate;

	vstate = &current->thread.kernel_vstate;
	if (!vstate->datap) {
		vstate->datap = kmalloc(riscv_v_vsize, GFP_KERNEL);
		if (!vstate->datap)
			return -ENOMEM;
	}

	current->thread.trap_pt_regs = NULL;
	WARN_ON(test_and_set_thread_flag(TIF_RISCV_V_KERNEL_MODE));
	return 0;
}

static void riscv_v_stop_kernel_context(void)
{
	WARN_ON(!test_and_clear_thread_flag(TIF_RISCV_V_KERNEL_MODE));
	current->thread.trap_pt_regs = NULL;
}
#else
#define kernel_vector_preemptible()	(false)
#define riscv_v_start_kernel_context()	(0)
#define riscv_v_stop_kernel_context()	do {} while (0)
#endif /* CONFIG_RISCV_ISA_V_PREEMPTIVE */

/*
 * kernel_vector_begin(): obtain the CPU vector registers for use by the calling
 * context
 *
 * Must not be called unless may_use_simd() returns true.
 * Task context in the vector registers is saved back to memory as necessary.
 *
 * A matching call to kernel_vector_end() must be made before returning from the
 * calling context.
 *
 * The caller may freely use the vector registers until kernel_vector_end() is
 * called.
 */
void kernel_vector_begin(void)
{
	if (WARN_ON(!has_vector()))
		return;

	BUG_ON(!may_use_simd());

	riscv_v_vstate_save(&current->thread.vstate, task_pt_regs(current));

	if (!preemptible() || !kernel_vector_preemptible()) {
		get_cpu_vector_context();
	} else {
		if (riscv_v_start_kernel_context())
			get_cpu_vector_context();
	}

	riscv_v_enable();
}
EXPORT_SYMBOL_GPL(kernel_vector_begin);

/*
 * kernel_vector_end(): give the CPU vector registers back to the current task
 *
 * Must be called from a context in which kernel_vector_begin() was previously
 * called, with no call to kernel_vector_end() in the meantime.
 *
 * The caller must not use the vector registers after this function is called,
 * unless kernel_vector_begin() is called again in the meantime.
 */
void kernel_vector_end(void)
{
	if (WARN_ON(!has_vector()))
		return;

	riscv_v_vstate_set_restore(current, task_pt_regs(current));

	riscv_v_disable();

	if (!test_thread_flag(TIF_RISCV_V_KERNEL_MODE))
		put_cpu_vector_context();
	else
		riscv_v_stop_kernel_context();
}
EXPORT_SYMBOL_GPL(kernel_vector_end);

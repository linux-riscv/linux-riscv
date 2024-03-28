// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2008 ARM Limited
 * Copyright (C) 2014 Regents of the University of California
 */

#include <linux/export.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>
#include <linux/stacktrace.h>
#include <linux/ftrace.h>

#include <asm/stacktrace.h>

struct unwind_state {
	unsigned long fp;
	unsigned long sp;
	unsigned long pc;
	struct pt_regs *regs;
	struct task_struct *task;
};

typedef bool (*unwind_consume_fn)(void *cookie, const struct unwind_state *state);

#ifdef CONFIG_FRAME_POINTER

extern asmlinkage void ret_from_exception(void);

static __always_inline void
walk_stackframe(struct task_struct *task, struct pt_regs *regs,
		unwind_consume_fn fn, void *arg)
{
	unsigned long fp, sp, pc;
	struct unwind_state state;
	int level = 0;

	if (regs) {
		fp = frame_pointer(regs);
		sp = user_stack_pointer(regs);
		pc = instruction_pointer(regs);
	} else if (task == NULL || task == current) {
		fp = (unsigned long)__builtin_frame_address(0);
		sp = current_stack_pointer;
		pc = (unsigned long)walk_stackframe;
		level = -1;
	} else {
		/* task blocked in __switch_to */
		fp = task->thread.s[0];
		sp = task->thread.sp;
		pc = task->thread.ra;
	}
	state.task = task;
	state.regs = regs;

	for (;;) {
		unsigned long low, high;
		struct stackframe *frame;

		state.sp = sp;
		state.fp = fp;
		state.pc = pc;
		if (unlikely(!__kernel_text_address(pc) || (level++ >= 0 && !fn(arg, &state))))
			break;

		/* Validate frame pointer */
		low = sp + sizeof(struct stackframe);
		high = ALIGN(sp, THREAD_SIZE);
		if (unlikely(fp < low || fp > high || fp & 0x7))
			break;
		/* Unwind stack frame */
		frame = (struct stackframe *)fp - 1;
		sp = fp;
		if (regs && (regs->epc == pc) && (frame->fp & 0x7)) {
			fp = frame->ra;
			pc = regs->ra;
		} else {
			fp = frame->fp;
			pc = ftrace_graph_ret_addr(current, NULL, frame->ra,
						   &frame->ra);
			if (pc == (unsigned long)ret_from_exception) {
				state.sp = sp;
				state.fp = fp;
				state.pc = pc;
				if (unlikely(!__kernel_text_address(pc) || !fn(arg, &state)))
					break;

				pc = ((struct pt_regs *)sp)->epc;
				fp = ((struct pt_regs *)sp)->s0;
			}
		}

	}
}

#else /* !CONFIG_FRAME_POINTER */

static __always_inline void
walk_stackframe(struct task_struct *task, struct pt_regs *regs,
		unwind_consume_fn fn, void *arg)
{
	unsigned long sp, pc;
	struct unwind_state state;
	unsigned long *ksp;

	if (regs) {
		sp = user_stack_pointer(regs);
		pc = instruction_pointer(regs);
	} else if (task == NULL || task == current) {
		sp = current_stack_pointer;
		pc = (unsigned long)walk_stackframe;
	} else {
		/* task blocked in __switch_to */
		sp = task->thread.sp;
		pc = task->thread.ra;
	}

	if (unlikely(sp & 0x7))
		return;

	state.task = task;
	state.regs = regs;
	state.sp = sp;
	state.fp = 0;
	ksp = (unsigned long *)sp;
	while (!kstack_end(ksp)) {
		state.pc = pc;
		if (__kernel_text_address(pc) && unlikely(!fn(arg, &state)))
			break;
		pc = READ_ONCE_NOCHECK(*ksp++) - 0x4;
	}
}

#endif /* CONFIG_FRAME_POINTER */

struct unwind_consume_entry_data {
	stack_trace_consume_fn consume_entry;
	void *cookie;
};

static __always_inline bool
arch_unwind_consume_entry(void *cookie, const struct unwind_state *state)
{
	struct unwind_consume_entry_data *data = cookie;

	return data->consume_entry(data->cookie, state->pc);
}

noinline noinstr void arch_stack_walk(stack_trace_consume_fn consume_entry, void *cookie,
				      struct task_struct *task, struct pt_regs *regs)
{
	struct unwind_consume_entry_data data = {
		.consume_entry = consume_entry,
		.cookie = cookie,
	};

	walk_stackframe(task, regs, arch_unwind_consume_entry, &data);
}

static bool print_trace_address(void *arg, unsigned long pc)
{
	const char *loglvl = arg;

	print_ip_sym(loglvl, pc);
	return true;
}

noinline void dump_backtrace(struct pt_regs *regs, struct task_struct *task,
		    const char *loglvl)
{
	arch_stack_walk(print_trace_address, (void *)loglvl, task, regs);
}

void show_stack(struct task_struct *task, unsigned long *sp, const char *loglvl)
{
	pr_cont("%sCall Trace:\n", loglvl);
	dump_backtrace(NULL, task, loglvl);
}

static bool save_wchan(void *arg, unsigned long pc)
{
	if (!in_sched_functions(pc)) {
		unsigned long *p = arg;
		*p = pc;
		return false;
	}
	return true;
}

unsigned long __get_wchan(struct task_struct *task)
{
	unsigned long pc = 0;

	if (!try_get_task_stack(task))
		return 0;
	arch_stack_walk(save_wchan, &pc, task, NULL);
	put_task_stack(task);
	return pc;
}

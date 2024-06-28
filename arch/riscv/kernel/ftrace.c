// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2013 Linaro Limited
 * Author: AKASHI Takahiro <takahiro.akashi@linaro.org>
 * Copyright (C) 2017 Andes Technology Corporation
 */

#include <linux/ftrace.h>
#include <linux/uaccess.h>
#include <linux/memory.h>
#include <linux/stop_machine.h>
#include <asm/cacheflush.h>
#include <asm/patch.h>

#ifdef CONFIG_DYNAMIC_FTRACE
void arch_ftrace_update_code(int command)
{
	mutex_lock(&text_mutex);
	command |= FTRACE_MAY_SLEEP;
	ftrace_modify_all_code(command);
	mutex_unlock(&text_mutex);
	flush_icache_all();
}

static int ftrace_check_current_call(unsigned long hook_pos,
				     unsigned int *expected)
{
	unsigned int replaced[2];
	unsigned int nops[2] = {NOP4, NOP4};

	/* we expect nops at the hook position */
	if (!expected)
		expected = nops;

	/*
	 * Read the text we want to modify;
	 * return must be -EFAULT on read error
	 */
	if (copy_from_kernel_nofault(replaced, (void *)hook_pos,
			MCOUNT_INSN_SIZE))
		return -EFAULT;

	/*
	 * Make sure it is what we expect it to be;
	 * return must be -EINVAL on failed comparison
	 */
	if (memcmp(expected, replaced, sizeof(replaced))) {
		pr_err("%p: expected (%08x %08x) but got (%08x %08x)\n",
		       (void *)hook_pos, expected[0], expected[1], replaced[0],
		       replaced[1]);
		return -EINVAL;
	}

	return 0;
}

static int __ftrace_modify_call(unsigned long hook_pos, unsigned long target, bool validate)
{
	unsigned int call[2];
	unsigned int replaced[2];

	make_call_t0(hook_pos, target, call);

	if (validate) {
		/*
		 * Read the text we want to modify;
		 * return must be -EFAULT on read error
		 */
		if (copy_from_kernel_nofault(replaced, (void *)hook_pos,
					     MCOUNT_INSN_SIZE))
			return -EFAULT;

		if (replaced[0] != call[0]) {
			pr_err("%p: expected (%08x) but got (%08x)\n",
			       (void *)hook_pos, call[0], replaced[0]);
			return -EINVAL;
		}
	}

	/* Replace the jalr at once. Return -EPERM on write error. */
	if (patch_insn_write((void *)(hook_pos + MCOUNT_AUIPC_SIZE), call + 1, MCOUNT_JALR_SIZE))
		return -EPERM;

	return 0;
}

static int __ftrace_modify_call_site(ftrace_func_t *hook_pos, ftrace_func_t target, bool enable)
{
	ftrace_func_t call = target;
	ftrace_func_t nops = &ftrace_stub;

	WRITE_ONCE(*hook_pos, enable ? call : nops);

	return 0;
}

int ftrace_make_call(struct dyn_ftrace *rec, unsigned long addr)
{
	unsigned long distance, orig_addr;

	orig_addr = (unsigned long)&ftrace_caller;
	distance = addr > orig_addr ? addr - orig_addr : orig_addr - addr;
	if (distance > JALR_RANGE)
		return -EINVAL;

	return __ftrace_modify_call(rec->ip, addr, false);
}

int ftrace_make_nop(struct module *mod, struct dyn_ftrace *rec,
		    unsigned long addr)
{
	unsigned int nops[1] = {NOP4};

	if (patch_insn_write((void *)(rec->ip + MCOUNT_AUIPC_SIZE), nops, MCOUNT_NOP4_SIZE))
		return -EPERM;

	return 0;
}

/*
 * This is called early on, and isn't wrapped by
 * ftrace_arch_code_modify_{prepare,post_process}() and therefor doesn't hold
 * text_mutex, which triggers a lockdep failure.  SMP isn't running so we could
 * just directly poke the text, but it's simpler to just take the lock
 * ourselves.
 */
int ftrace_init_nop(struct module *mod, struct dyn_ftrace *rec)
{
	unsigned int nops[2];
	int out;

	make_call_t0(rec->ip, &ftrace_caller, nops);
	nops[1] = NOP4;

	mutex_lock(&text_mutex);
	out = patch_insn_write((void *)rec->ip, nops, MCOUNT_INSN_SIZE);
	mutex_unlock(&text_mutex);

	return out;
}

ftrace_func_t ftrace_call_dest = ftrace_stub;
int ftrace_update_ftrace_func(ftrace_func_t func)
{
	return __ftrace_modify_call_site(&ftrace_call_dest, func, true);
}

#endif

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS
int ftrace_modify_call(struct dyn_ftrace *rec, unsigned long old_addr,
		       unsigned long addr)
{
	unsigned int call[2];
	unsigned long caller = rec->ip;
	int ret;

	make_call_t0(caller, old_addr, call);
	ret = ftrace_check_current_call(caller, call);

	if (ret)
		return ret;

	return __ftrace_modify_call(caller, addr, true);
}
#endif

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
/*
 * Most of this function is copied from arm64.
 */
void prepare_ftrace_return(unsigned long *parent, unsigned long self_addr,
			   unsigned long frame_pointer)
{
	unsigned long return_hooker = (unsigned long)&return_to_handler;
	unsigned long old;

	if (unlikely(atomic_read(&current->tracing_graph_pause)))
		return;

	/*
	 * We don't suffer access faults, so no extra fault-recovery assembly
	 * is needed here.
	 */
	old = *parent;

	if (!function_graph_enter(old, self_addr, frame_pointer, parent))
		*parent = return_hooker;
}

#ifdef CONFIG_DYNAMIC_FTRACE
#ifdef CONFIG_DYNAMIC_FTRACE_WITH_ARGS
void ftrace_graph_func(unsigned long ip, unsigned long parent_ip,
		       struct ftrace_ops *op, struct ftrace_regs *fregs)
{
	prepare_ftrace_return(&fregs->ra, ip, fregs->s0);
}
#else /* CONFIG_DYNAMIC_FTRACE_WITH_ARGS */
ftrace_func_t ftrace_graph_call_dest = ftrace_stub;
int ftrace_enable_ftrace_graph_caller(void)
{
	return __ftrace_modify_call_site(&ftrace_graph_call_dest,
					 &prepare_ftrace_return, true);
}

int ftrace_disable_ftrace_graph_caller(void)
{
	return __ftrace_modify_call_site(&ftrace_graph_call_dest,
					 &prepare_ftrace_return, false);
}
#endif /* CONFIG_DYNAMIC_FTRACE_WITH_ARGS */
#endif /* CONFIG_DYNAMIC_FTRACE */
#endif /* CONFIG_FUNCTION_GRAPH_TRACER */

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Tracepoints for RISC-V exceptions
 *
 * Copyright (C) 2024 ISCAS. All rights reserved
 *
 */

#if !defined(_TRACE_PAGE_FAULT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_PAGE_FAULT_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM exceptions

TRACE_EVENT(page_fault_user,
	TP_PROTO(struct pt_regs *regs),
	TP_ARGS(regs),

	TP_STRUCT__entry(
		__field(unsigned long, address)
		__field(unsigned long, epc)
		__field(unsigned long, cause)
	),

	TP_fast_assign(
		__entry->address	= regs->badaddr;
		__entry->epc		= regs->epc;
		__entry->cause		= regs->cause;
	),

	TP_printk("user page fault, address=%ps epc=%ps cause=0x%lx",
			(void *)__entry->address, (void *)__entry->epc,
			__entry->cause)
);

TRACE_EVENT(page_fault_kernel,
	TP_PROTO(struct pt_regs *regs),
	TP_ARGS(regs),

	TP_STRUCT__entry(
		__field(unsigned long, address)
		__field(unsigned long, epc)
		__field(unsigned long, cause)
	),

	TP_fast_assign(
		__entry->address	= regs->badaddr;
		__entry->epc		= regs->epc;
		__entry->cause		= regs->cause;
	),

	TP_printk("kernel page fault, address=%ps epc=%ps cause=0x%lx",
			(void *)__entry->address, (void *)__entry->epc,
			__entry->cause)
);

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH asm/trace/
#define TRACE_INCLUDE_FILE exceptions
#endif /*  _TRACE_PAGE_FAULT_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

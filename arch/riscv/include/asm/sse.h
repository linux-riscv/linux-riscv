/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2023 Rivos Inc.
 */
#ifndef __ASM_SSE_H
#define __ASM_SSE_H

#include <linux/riscv_sse.h>


struct sse_interrupted_state {
	unsigned long pc;
	unsigned long ra;
	unsigned long sp;
	unsigned long gp;
	unsigned long tp;
	unsigned long t0;
	unsigned long t1;
	unsigned long t2;
	unsigned long s0;
	unsigned long s1;
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
	unsigned long s2;
	unsigned long s3;
	unsigned long s4;
	unsigned long s5;
	unsigned long s6;
	unsigned long s7;
	unsigned long s8;
	unsigned long s9;
	unsigned long s10;
	unsigned long s11;
	unsigned long t3;
	unsigned long t4;
	unsigned long t5;
	unsigned long t6;
	unsigned long exec_mode;
};

struct sse_entry_state {
	unsigned long pc;
	unsigned long ra;
	unsigned long sp;
	unsigned long gp;
	unsigned long tp;
	unsigned long t0;
	unsigned long t1;
	unsigned long t2;
	unsigned long s0;
	unsigned long s1;
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
	unsigned long s2;
	unsigned long s3;
	unsigned long s4;
	unsigned long s5;
	unsigned long s6;
	unsigned long s7;
	unsigned long s8;
	unsigned long s9;
	unsigned long s10;
	unsigned long s11;
	unsigned long t3;
	unsigned long t4;
	unsigned long t5;
	unsigned long t6;
};

struct sse_handler_context {
	struct sse_entry_state e_state;
	struct sse_interrupted_state i_state;
};

unsigned long *sse_stack_alloc(unsigned int cpu, unsigned int size);
void sse_stack_free(unsigned long *stack);

struct sse_handler_context;
void sse_handler_context_init(struct sse_handler_context *ctx, void *stack,
			      u32 evt, sse_event_handler *handler, void *arg);

#endif

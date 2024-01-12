/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Rivos Inc.
 */

#ifndef __LINUX_RISCV_SSE_H
#define __LINUX_RISCV_SSE_H

#include <linux/types.h>
#include <linux/linkage.h>

struct sse_event;
struct pt_regs;

typedef int (sse_event_handler)(u32 event_num, void *arg, struct pt_regs *regs);

#ifdef CONFIG_RISCV_SSE

struct sse_event_state {
	unsigned long mode;
	unsigned long pc;
	unsigned long a0;
	unsigned long a6;
	unsigned long a7;
};

struct sse_registered_event {
	struct sse_event_state state;
	unsigned long state_phys;
	void *stack;
	void *shadow_stack;
	unsigned long attr_buf;
	u32 evt_id;
	struct sse_event *evt;
};

void sse_handle_event(struct sse_registered_event *reg_evt,
			       struct pt_regs *regs);

struct sse_event *sse_event_register(u32 event_num, u32 priority,
				     sse_event_handler *handler, void *arg);

void sse_event_unregister(struct sse_event *evt);

int sse_event_set_target_cpu(struct sse_event *sse_evt, unsigned int cpu);

int sse_event_enable(struct sse_event *sse_evt);

void sse_event_disable(struct sse_event *sse_evt);

#else
static inline int sse_event_register(struct sse_event *evt, u32 priority,
				     sse_event_handler *handler, void *arg)
{
	return -EOPNOTSUPP;
}

static inline void sse_event_unregister(struct sse_event *evt) {}

static inline int sse_event_set_target_cpu(struct sse_event *sse_evt,
					   unsigned int cpu)
{
	return -EOPNOTSUPP;
}

static inline int sse_event_enable(struct sse_event *sse_evt)
{
	return -EOPNOTSUPP;
}

static inline void sse_event_disable(struct sse_event *sse_evt) {}


#endif

#endif /* __LINUX_RISCV_SSE_H */

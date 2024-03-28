// SPDX-License-Identifier: GPL-2.0
/*
 * Tracepoints for RISC-V KVM
 *
 * Copyright 2024 Beijing ESWIN Computing Technology Co., Ltd.
 *
 */
#if !defined(_TRACE_RSICV_KVM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_RSICV_KVM_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm

TRACE_EVENT(kvm_entry,
	TP_PROTO(struct kvm_vcpu *vcpu),
	TP_ARGS(vcpu),

	TP_STRUCT__entry(
		__field(unsigned long, pc)
	),

	TP_fast_assign(
		__entry->pc	= vcpu->arch.guest_context.sepc;
	),

	TP_printk("PC: 0x%016lx", __entry->pc)
);

TRACE_EVENT(kvm_exit,
	TP_PROTO(struct kvm_vcpu *vcpu, unsigned long exit_reason,
			unsigned long scause),
	TP_ARGS(vcpu, exit_reason, scause),

	TP_STRUCT__entry(
		__field(unsigned long, pc)
		__field(unsigned long, exit_reason)
		__field(unsigned long, scause)
	),

	TP_fast_assign(
		__entry->pc		= vcpu->arch.guest_context.sepc;
		__entry->exit_reason	= exit_reason;
		__entry->scause		= scause;
	),

	TP_printk("EXIT_REASON:0x%lx,PC: 0x%016lx,SCAUSE:0x%lx",
			__entry->exit_reason, __entry->pc, __entry->scause)
);

#endif /* _TRACE_RSICV_KVM_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace_riscv

/* This part must be outside protection */
#include <trace/define_trace.h>

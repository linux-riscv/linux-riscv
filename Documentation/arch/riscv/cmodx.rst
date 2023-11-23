.. SPDX-License-Identifier: GPL-2.0

==============================================================================
Concurrent Modification and Execution of Instructions (CMODX) for RISC-V Linux
==============================================================================

CMODX is a programming technique where a program executes instructions that were
modified by the program itself. Instruction storage and the instruction cache
(icache) is not guaranteed to be synchronized on RISC-V hardware. Therefore, the
program must enforce its own synchonization with the unprivileged fence.i
instruction.

However, the default Linux ABI prohibits the use of fence.i in userspace
applications. At any point the scheduler may migrate a task onto a new hart. If
migration occurs after the userspace synchronized the icache and instruction
storage with fence.i, the icache will no longer be clean. This is due to the
behavior of fence.i only affecting the hart that it is called on. Thus, the hart
that the task has been migrated to, may not have synchronized instruction
storage and icache.

There are two ways to solve this problem: use the riscv_flush_icache() syscall,
or use the ``PR_RISCV_SET_ICACHE_FLUSH_CTX`` prctl(). The syscall should be used
when the application very rarely needs to flush the icache. If the icache will
need to be flushed many times in the lifetime of the application, the prctl
should be used.

The prctl informs the kernel that it must emit synchronizing instructions upon
task migration. The program itself must emit synchonizing instructions when
necessary as well.

1.  prctl() Interface
---------------------

Before the program emits their first icache flushing instruction, the program
must call this prctl().

* prctl(PR_RISCV_SET_ICACHE_FLUSH_CTX, unsigned long ctx, unsigned long per_thread)

	Sets the icache flushing context. If per_thread is 0, context will be
	applied per process, otherwise if per_thread is 1 context will be
	per-thread. Any other number will have undefined behavior.

	* :c:macro:`PR_RISCV_CTX_SW_FENCEI`: Allow fence.i to be called in
	  userspace.

Example usage:

The following files are meant to be compiled and linked with each other. The
modify_instruction() function replaces an add with 0 with an add with one,
causing the instruction sequence in get_value() to change from returning a zero
to returning a one.

cmodx.c::

	#include <stdio.h>
	#include <sys/prctl.h>

	extern int get_value();
	extern void modify_instruction();

	int main()
	{
		int value = get_value();
		printf("Value before cmodx: %d\n", value);

		// Call prctl before first fence.i is called inside modify_instruction
		prctl(PR_RISCV_SET_ICACHE_FLUSH_CTX, PR_RISCV_CTX_SW_FENCEI, 0);
		modify_instruction();

		value = get_value();
		printf("Value after cmodx: %d\n", value);
		return 0;
	}

cmodx.S::

	.option norvc

	.text
	.global modify_instruction
	modify_instruction:
	lw a0, new_insn
	lui a5,%hi(old_insn)
	sw  a0,%lo(old_insn)(a5)
	fence.i
	ret

	.section modifiable, "awx"
	.global get_value
	get_value:
	li a0, 0
	old_insn:
	addi a0, a0, 0
	ret

	.data
	new_insn:
	addi a0, a0, 1

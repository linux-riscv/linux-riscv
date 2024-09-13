.. SPDX-License-Identifier: GPL-2.0

:Author: Deepak Gupta <debug@rivosinc.com>
:Date:   12 January 2024

====================================================
Tracking indirect control transfers on RISC-V Linux
====================================================

This document briefly describes the interface provided to userspace by Linux
to enable indirect branch tracking for user mode applications on RISV-V

1. Feature Overview
--------------------

Memory corruption issues usually result in to crashes, however when in hands of
an adversary and if used creatively can result into variety security issues.

One of those security issues can be code re-use attacks on program where adversary
can use corrupt function pointers and chain them together to perform jump oriented
programming (JOP) or call oriented programming (COP) and thus compromising control
flow integrity (CFI) of the program.

Function pointers live in read-write memory and thus are susceptible to corruption
and allows an adversary to reach any program counter (PC) in address space. On
RISC-V zicfilp extension enforces a restriction on such indirect control transfers

	- indirect control transfers must land on a landing pad instruction `lpad`.
	  There are two exception to this rule
		- rs1 = x1 or rs1 = x5, i.e. a return from a function and returns are
		  protected using shadow stack (see zicfiss.rst)

		- rs1 = x7. On RISC-V compiler usually does below to reach function
		  which is beyond the offset possible J-type instruction.

			"auipc x7, <imm>"
			"jalr (x7)"

		  Such form of indirect control transfer are still immutable and don't rely
		  on memory and thus rs1=x7 is exempted from tracking and considered software
		  guarded jumps.

`lpad` instruction is pseudo of `auipc rd, <imm_20bit>` with `rd=x0`` and is a HINT
nop. `lpad` instruction must be aligned on 4 byte boundary and compares 20 bit
immediate withx7. If `imm_20bit` == 0, CPU don't perform any comparision with x7. If
`imm_20bit` != 0, then `imm_20bit` must match x7 else CPU will raise
`software check exception` (cause=18)with `*tval = 2`.

Compiler can generate a hash over function signatures and setup them (truncated
to 20bit) in x7 at callsites and function prologues can have `lpad` with same
function hash. This further reduces number of program counters a call site can
reach.

2. ELF and psABI
-----------------

Toolchain sets up `GNU_PROPERTY_RISCV_FEATURE_1_FCFI` for property
`GNU_PROPERTY_RISCV_FEATURE_1_AND` in notes section of the object file.

3. Linux enabling
------------------

User space programs can have multiple shared objects loaded in its address space
and it's a difficult task to make sure all the dependencies have been compiled
with support of indirect branch. Thus it's left to dynamic loader to enable
indirect branch tracking for the program.

4. prctl() enabling
--------------------

`PR_SET_INDIR_BR_LP_STATUS` / `PR_GET_INDIR_BR_LP_STATUS` /
`PR_LOCK_INDIR_BR_LP_STATUS` are three prctls added to manage indirect branch
tracking. prctls are arch agnostic and returns -EINVAL on other arches.

`PR_SET_INDIR_BR_LP_STATUS`: If arg1 `PR_INDIR_BR_LP_ENABLE` and if CPU supports
`zicfilp` then kernel will enabled indirect branch tracking for the task.
Dynamic loader can issue this `prctl` once it has determined that all the objects
loaded in address space support indirect branch tracking. Additionally if there is
a `dlopen` to an object which wasn't compiled with `zicfilp`, dynamic loader can
issue this prctl with arg1 set to 0 (i.e. `PR_INDIR_BR_LP_ENABLE` being clear)

`PR_GET_INDIR_BR_LP_STATUS`: Returns current status of indirect branch tracking.
If enabled it'll return `PR_INDIR_BR_LP_ENABLE`

`PR_LOCK_INDIR_BR_LP_STATUS`: Locks current status of indirect branch tracking on
the task. User space may want to run with strict security posture and wouldn't want
loading of objects without `zicfilp` support in it and thus would want to disallow
disabling of indirect branch tracking. In that case user space can use this prctl
to lock current settings.

5. violations related to indirect branch tracking
--------------------------------------------------

Pertaining to indirect branch tracking, CPU raises software check exception in
following conditions
	- missing `lpad` after indirect call / jmp
	- `lpad` not on 4 byte boundary
	- `imm_20bit` embedded in `lpad` instruction doesn't match with `x7`

In all 3 cases, `*tval = 2` is captured and software check exception is raised
(cause=18)

Linux kernel will treat this as `SIGSEV`` with code = `SEGV_CPERR` and follow
normal course of signal delivery.

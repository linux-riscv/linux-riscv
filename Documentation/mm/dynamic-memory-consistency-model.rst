.. SPDX-License-Identifier: GPL-2.0

================================
Dynamic memory consistency model
================================

This document gives an overview of the userspace interface to change memory
consistency model at run-time.


What is a memory consistency model?
===================================

The memory consistency model is a set of guarantees a CPU architecture
provides about (re-)ordering memory accesses. Each architecture defines
its own model and set of rules within that, which are carefully specified.
The provided guarantees have consequences for the microarchitectures (e.g.,
some memory consistency models allow reordering stores after loads) and
the software executed within this model (memory consistency models that
allow reordering memory accesses provide memory barrier instructions
to enforce additional guarantees when needed explicitly).

Details about the architecture-independent memory consistency model abstraction
in the Linux kernel and the use of the different types of memory barriers
can be found here:

	Documentation/memory-barriers.txt

Two models can be in a weaker/stronger relation. I.e., a consistency
model A is weaker/stronger than another model B if A provides a subset/superset
of the constraints that B provides.

Some architectures define more than one memory consistency model.
On such architectures, switching the memory consistency model at run-time
to a stronger one is possible because software written for the weaker model is
compatible with the constraints of the stronger model.

If two models are not in a weaker/stronger relation, switching between
them will violate the consistency assumptions that the software was
written under (i.e., causing subtle bugs that are very hard to debug).

User API via prctl
==================

Two prctl calls are defined to get/set the active memory consistency model:

* prctl(PR_GET_MEMORY_CONSISTENCY_MODEL)

    Returns the active memory consistency model for the calling process/thread.
    If the architecture does not support dynamic memory consistency models,
    then -1 is returned, and errno is set to EINVAL.

* prctl(PR_SET_MEMORY_CONSISTENCY_MODEL, unsigned long new_model)

    Switches the memory consistency model for the calling process/thread
    to the given model. If the architecture does not support dynamic
    memory consistency models or does not support the provided model, then
    -1 is returned, and errno is set to EINVAL.

Supported memory consistency models
===================================

This section defines the memory consistency models which are supported
by the prctl interface.

RISC-V
------

RISC-V uses RVWMO (RISC-V weak memory ordering) as default memory consistency
model. TSO (total store ordering) is another specified model and provides
additional ordering guarantees. Switching from RVWMO to TSO (and back) is
possible when the Ssdtso extension is available.

* :c:macro:`PR_MEMORY_CONSISTENCY_MODEL_RISCV_WMO`: RISC-V weak memory ordering (default).

* :c:macro:`PR_MEMORY_CONSISTENCY_MODEL_RISCV_TSO`: RISC-V total store ordering.

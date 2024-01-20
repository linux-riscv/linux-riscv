.. SPDX-License-Identifier: GPL-2.0

=====================================
Virtual Memory Layout on RISC-V Linux
=====================================

:Author: Alexandre Ghiti <alex@ghiti.fr>
:Date: 12 February 2021

This document describes the virtual memory layout used by the RISC-V Linux
Kernel.

RISC-V Linux Kernel 32bit
=========================

RISC-V Linux Kernel SV32
------------------------

TODO

RISC-V Linux Kernel 64bit
=========================

The RISC-V privileged architecture document states that the 64bit addresses
"must have bits 63–48 all equal to bit 47, or else a page-fault exception will
occur.": that splits the virtual address space into 2 halves separated by a very
big hole, the lower half is where the userspace resides, the upper half is where
the RISC-V Linux Kernel resides.

RISC-V Linux Kernel SV39
------------------------

::

  ========================================================================================================================
      Start addr    |   Offset   |     End addr     |  Size   | VM area description
  ========================================================================================================================
                    |            |                  |         |
   0000000000000000 |    0       | 0000003fffffffff |  256 GB | user-space virtual memory, different per mm
  __________________|____________|__________________|_________|___________________________________________________________
                    |            |                  |         |
   0000004000000000 | +256    GB | ffffffbfffffffff | ~16M TB | ... huge, almost 64 bits wide hole of non-canonical
                    |            |                  |         |     virtual memory addresses up to the -256 GB
                    |            |                  |         |     starting offset of kernel mappings.
  __________________|____________|__________________|_________|___________________________________________________________
                                                              |
                                                              | Kernel-space virtual memory, shared between all processes:
  ____________________________________________________________|___________________________________________________________
                    |            |                  |         |
   ffffffc6fea00000 | -228    GB | ffffffc6feffffff |    6 MB | fixmap
   ffffffc6ff000000 | -228    GB | ffffffc6ffffffff |   16 MB | PCI io
   ffffffc700000000 | -228    GB | ffffffc7ffffffff |    4 GB | vmemmap
   ffffffc800000000 | -224    GB | ffffffd7ffffffff |   64 GB | vmalloc/ioremap space
   ffffffd800000000 | -160    GB | fffffff6ffffffff |  124 GB | direct mapping of all physical memory
   fffffff700000000 |  -36    GB | fffffffeffffffff |   32 GB | kasan
  __________________|____________|__________________|_________|____________________________________________________________
                                                              |
                                                              |
  ____________________________________________________________|____________________________________________________________
                    |            |                  |         |
   ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | modules, BPF
   ffffffff80000000 |   -2    GB | ffffffffffffffff |    2 GB | kernel
  __________________|____________|__________________|_________|____________________________________________________________


RISC-V Linux Kernel SV48
------------------------

::

 ========================================================================================================================
      Start addr    |   Offset   |     End addr     |  Size   | VM area description
 ========================================================================================================================
                    |            |                  |         |
   0000000000000000 |    0       | 00007fffffffffff |  128 TB | user-space virtual memory, different per mm
  __________________|____________|__________________|_________|___________________________________________________________
                    |            |                  |         |
   0000800000000000 | +128    TB | ffff7fffffffffff | ~16M TB | ... huge, almost 64 bits wide hole of non-canonical
                    |            |                  |         | virtual memory addresses up to the -128 TB
                    |            |                  |         | starting offset of kernel mappings.
  __________________|____________|__________________|_________|___________________________________________________________
                                                              |
                                                              | Kernel-space virtual memory, shared between all processes:
  ____________________________________________________________|___________________________________________________________
                    |            |                  |         |
   ffff8d7ffea00000 |  -114.5 TB | ffff8d7ffeffffff |    6 MB | fixmap
   ffff8d7fff000000 |  -114.5 TB | ffff8d7fffffffff |   16 MB | PCI io
   ffff8d8000000000 |  -114.5 TB | ffff8f7fffffffff |    2 TB | vmemmap
   ffff8f8000000000 |  -112.5 TB | ffffaf7fffffffff |   32 TB | vmalloc/ioremap space
   ffffaf8000000000 |  -80.5  TB | ffffef7fffffffff |   64 TB | direct mapping of all physical memory
   ffffef8000000000 |  -16.5  TB | fffffffeffffffff | 16.5 TB | kasan
  __________________|____________|__________________|_________|____________________________________________________________
                                                              |
                                                              | Identical layout to the 39-bit one from here on:
  ____________________________________________________________|____________________________________________________________
                    |            |                  |         |
   ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | modules, BPF
   ffffffff80000000 |   -2    GB | ffffffffffffffff |    2 GB | kernel
  __________________|____________|__________________|_________|____________________________________________________________


RISC-V Linux Kernel SV57
------------------------

::

 ========================================================================================================================
      Start addr    |   Offset   |     End addr     |  Size   | VM area description
 ========================================================================================================================
                    |            |                  |         |
   0000000000000000 |   0        | 00ffffffffffffff |   64 PB | user-space virtual memory, different per mm
  __________________|____________|__________________|_________|___________________________________________________________
                    |            |                  |         |
   0100000000000000 | +64     PB | feffffffffffffff | ~16K PB | ... huge, almost 64 bits wide hole of non-canonical
                    |            |                  |         | virtual memory addresses up to the -64 PB
                    |            |                  |         | starting offset of kernel mappings.
  __________________|____________|__________________|_________|___________________________________________________________
                                                              |
                                                              | Kernel-space virtual memory, shared between all processes:
  ____________________________________________________________|___________________________________________________________
                    |            |                  |         |
   ff1bfffffea00000 | -57     PB | ff1bfffffeffffff |    6 MB | fixmap
   ff1bffffff000000 | -57     PB | ff1bffffffffffff |   16 MB | PCI io
   ff1c000000000000 | -57     PB | ff1fffffffffffff |    1 PB | vmemmap
   ff20000000000000 | -56     PB | ff5fffffffffffff |   16 PB | vmalloc/ioremap space
   ff60000000000000 | -40     PB | ffdeffffffffffff |   32 PB | direct mapping of all physical memory
   ffdf000000000000 |  -8     PB | fffffffeffffffff |    8 PB | kasan
  __________________|____________|__________________|_________|____________________________________________________________
                                                              |
                                                              | Identical layout to the 39-bit one from here on:
  ____________________________________________________________|____________________________________________________________
                    |            |                  |         |
   ffffffff00000000 |  -4     GB | ffffffff7fffffff |    2 GB | modules, BPF
   ffffffff80000000 |  -2     GB | ffffffffffffffff |    2 GB | kernel
  __________________|____________|__________________|_________|____________________________________________________________


User-space and large virtual address space
==========================================
On RISC-V, Sv57 paging enables 56-bit userspace virtual address space.
Not all user space is ready to handle wide addresses. It's known that
at least some JIT compilers use higher bits in pointers to encode their
information. It collides with valid pointers with Sv57 paging and leads
to crashes.

To mitigate this, we are not going to allocate virtual address space
above 47-bit by default. And on kernel v6.6-v6.7, that is 38-bit by
default.

But userspace can ask for allocation from full address space by
specifying hint address (with or without MAP_FIXED) above 47-bits, or
hint address + size above 47-bits with MAP_FIXED.

If hint address set above 47-bit, but MAP_FIXED is not specified, we try
to look for unmapped area by specified address. If it's already
occupied, we look for unmapped area in *full* address space, rather than
from 47-bit window.

A high hint address would only affect the allocation in question, but not
any future mmap()s.

Specifying high hint address without MAP_FIXED on older kernel or on
machine without Sv57 paging support is safe. On kernel v6.6-v6.7, the
hint will be treated as the upper bound of the address space to search,
but this was removed in the future version of kernels. On kernel older
than v6.6 or on machine without Sv57 paging support, the kernel will
fall back to allocation from the supported address space.

This approach helps to easily make application's memory allocator aware
about large address space without manually tracking allocated virtual
address space.

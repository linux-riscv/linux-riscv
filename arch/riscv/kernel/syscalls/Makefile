# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the RISC-V syscall tables
#

CFLAGS_syscall_table.o        += $(call cc-option,-Wno-override-init,)
CFLAGS_compat_syscall_table.o += $(call cc-option,-Wno-override-init,)

obj-y                += syscall_table.o
obj-$(CONFIG_COMPAT) += compat_syscall_table.o

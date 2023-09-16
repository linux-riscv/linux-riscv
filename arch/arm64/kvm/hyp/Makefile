# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Kernel-based Virtual Machine module, HYP part
#

incdir := $(srctree)/$(src)/include
subdir-asflags-y := -I$(incdir) -I$(srctree)/arch/arm64/kvm
subdir-ccflags-y := -I$(incdir) -I$(srctree)/arch/arm64/kvm

obj-$(CONFIG_KVM) += vhe/ nvhe/ pgtable.o

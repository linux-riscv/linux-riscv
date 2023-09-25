# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the RISC-V syscall tables
#

ifndef CONFIG_TRIM_UNUSED_SYSCALLS

CFLAGS_syscall_table.o        += $(call cc-option,-Wno-override-init,)
CFLAGS_compat_syscall_table.o += $(call cc-option,-Wno-override-init,)

obj-y                += syscall_table.o
obj-$(CONFIG_COMPAT) += compat_syscall_table.o
else # CONFIG_TRIM_UNUSED_SYSCALLS

include $(srctree)/scripts/Makefile.syscalls

CFLAGS_syscall_table_used.o        += $(call cc-option,-Wno-override-init,)
CFLAGS_compat_syscall_table_used.o += $(call cc-option,-Wno-override-init,)

obj-y                += syscall_table_used.o
obj-$(CONFIG_COMPAT) += compat_syscall_table_used.o

# comment the unused syscalls
quiet_cmd_used = USED    $@
      cmd_used = sed -E -e '/^\[([0-9]+|\([0-9]+ \+ [0-9]+\))\] = /{/= *__riscv_(__sys_|sys_|compat_)*($(used_syscalls)),/!{s%^%/* %g;s%$$% */%g}}' -i $@;

$(obj)/syscall_table_used.c: $(src)/syscall_table.c
	$(Q)cp $< $@

$(obj)/syscall_table_used.i: $(src)/syscall_table_used.c $(used_syscalls_deps) FORCE
	$(call if_changed_dep,cpp_i_c)
	$(call cmd,used)

$(obj)/syscall_table_used.o: $(obj)/syscall_table_used.i FORCE
	$(call if_changed,cc_o_c)

$(obj)/compat_syscall_table_used.c: $(src)/compat_syscall_table.c
	$(Q)cp $< $@

$(obj)/compat_syscall_table_used.i: $(src)/compat_syscall_table_used.c $(used_syscalls_deps) FORCE
	$(call if_changed_dep,cpp_i_c)
	$(call cmd,used)

$(obj)/compat_syscall_table_used.o: $(obj)/compat_syscall_table_used.i FORCE
	$(call if_changed,cc_o_c)

endif # CONFIG_TRIM_UNUSED_SYSCALLS

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

# calculate syscalls total from $(obj)/syscall_table_used.i
ifneq ($(used_syscalls),)
  NR_syscalls := $$(($$(sed -E -n -e '/^\[([0-9]+|\([0-9]+ \+ [0-9]+\))\] = /{s/^\[(.*)\].*/\1/gp}' $(obj)/syscall_table_used.i | bc | sort -g | tail -1 | grep '[0-9]' || echo -1) + 1))
else
  NR_syscalls := 0
endif

CFLAGS_traps_used.o                += -DNR_syscalls=$(NR_syscalls)
CFLAGS_syscall_table_used.o        += $(call cc-option,-Wno-override-init,)
CFLAGS_compat_syscall_table_used.o += $(call cc-option,-Wno-override-init,)

obj-y                += traps_used.o
obj-y                += syscall_table_used.o
obj-$(CONFIG_COMPAT) += compat_syscall_table_used.o

# comment the unused syscalls
quiet_cmd_used = USED    $@
      cmd_used = sed -E -e '/^\[([0-9]+|\([0-9]+ \+ [0-9]+\))\] = /{/= *__riscv_(__sys_|sys_|compat_)*($(used_syscalls)),/!{s%^%/* %g;s%$$% */%g}}' -i $@;

# update the syscalls total
quiet_cmd_snr = SNR     $@
      cmd_snr = snr=$(NR_syscalls); if [ $$snr -ne 0 ]; then \
		sed -i -e "s/sys_call_table\[.*\] =/sys_call_table[($$snr)] =/g;s/\[0 ... (.*) - 1\] = __riscv_sys_ni_syscall/[0 ... ($$snr) - 1] = __riscv_sys_ni_syscall/g" $@; \
		fi;

$(obj)/traps_used.c: $(src)/../traps.c $(obj)/syscall_table_used.i FORCE
	$(Q)cp $< $@

$(obj)/syscall_table_used.c: $(src)/syscall_table.c
	$(Q)cp $< $@

$(obj)/syscall_table_used.i: $(src)/syscall_table_used.c $(used_syscalls_deps) FORCE
	$(call if_changed_dep,cpp_i_c)
	$(call cmd,used)
	$(call cmd,snr)

$(obj)/syscall_table_used.o: $(obj)/syscall_table_used.i FORCE
	$(call if_changed,cc_o_c)
	$(call cmd,force_checksrc)

$(obj)/compat_syscall_table_used.c: $(src)/compat_syscall_table.c
	$(Q)cp $< $@

$(obj)/compat_syscall_table_used.i: $(src)/compat_syscall_table_used.c $(used_syscalls_deps) FORCE
	$(call if_changed_dep,cpp_i_c)
	$(call cmd,used)
	$(call cmd,snr)

$(obj)/compat_syscall_table_used.o: $(obj)/compat_syscall_table_used.i FORCE
	$(call if_changed,cc_o_c)
	$(call cmd,force_checksrc)

endif # CONFIG_TRIM_UNUSED_SYSCALLS

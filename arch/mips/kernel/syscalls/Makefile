# SPDX-License-Identifier: GPL-2.0
kapi := arch/$(SRCARCH)/include/generated/asm
uapi := arch/$(SRCARCH)/include/generated/uapi/asm

$(shell mkdir -p $(uapi) $(kapi))

syshdr := $(srctree)/scripts/syscallhdr.sh
sysnr := $(srctree)/$(src)/syscallnr.sh
systbl := $(srctree)/scripts/syscalltbl.sh

quiet_cmd_syshdr = SYSHDR  $@
      cmd_syshdr = $(CONFIG_SHELL) $(syshdr) --offset __NR_Linux $< $@

quiet_cmd_sysnr = SYSNR   $@
      cmd_sysnr = $(CONFIG_SHELL) '$(sysnr)' '$<' '$@'		\
		  '$(sysnr_abis_$(basetarget))'			\
		  '$(sysnr_pfx_$(basetarget))'

quiet_cmd_systbl = SYSTBL  $@
      cmd_systbl = $(CONFIG_SHELL) $(systbl) $< $@

$(uapi)/unistd_%.h: $(src)/syscall_%.tbl $(syshdr) FORCE
	$(call if_changed,syshdr)

sysnr_pfx_unistd_nr_n32 := N32
sysnr_pfx_unistd_nr_n64 := 64
sysnr_pfx_unistd_nr_o32 := O32

ifndef CONFIG_TRIM_UNUSED_SYSCALLS
tbl = $(src)/syscall_%.tbl
else

include $(srctree)/scripts/Makefile.syscalls

orig_tbl = $(src)/syscall_%.tbl
 tbl_dir = arch/$(SRCARCH)/include/generated/tbl
     tbl = $(tbl_dir)/syscall_used_%.tbl

quiet_cmd_used = USED    $@
      cmd_used = sed -E -e "/^[0-9]*[[:space:]]/{/(^($(used_syscalls))[[:space:]]|[[:space:]]($(used_syscalls))[[:space:]]|[[:space:]]($(used_syscalls))$$)/!{s/^/\#/g}}" $< > $@;

$(tbl): $(orig_tbl) $(used_syscalls_deps) FORCE
	$(Q)mkdir -p $(tbl_dir)
	$(call cmd,used)

endif

$(kapi)/unistd_nr_%.h: $(tbl) $(sysnr) FORCE
	$(call if_changed,sysnr)

$(kapi)/syscall_table_%.h: $(tbl) $(systbl) FORCE
	$(call if_changed,systbl)

uapisyshdr-y		+= unistd_n32.h			\
			   unistd_n64.h			\
			   unistd_o32.h
kapisyshdr-y		+= syscall_table_n32.h		\
			   syscall_table_n64.h		\
			   syscall_table_o32.h		\
			   unistd_nr_n32.h		\
			   unistd_nr_n64.h		\
			   unistd_nr_o32.h

uapisyshdr-y	:= $(addprefix $(uapi)/, $(uapisyshdr-y))
kapisyshdr-y	:= $(addprefix $(kapi)/, $(kapisyshdr-y))
targets		+= $(addprefix ../../../../, $(uapisyshdr-y) $(kapisyshdr-y))

PHONY += all
all: $(uapisyshdr-y) $(kapisyshdr-y)
	@:

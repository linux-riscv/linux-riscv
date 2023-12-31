# SPDX-License-Identifier: GPL-2.0-only
#
# linux/arch/riscv/crypto/Makefile
#

obj-$(CONFIG_CRYPTO_AES_RISCV64) += aes-riscv64.o
aes-riscv64-y := aes-riscv64-glue.o aes-riscv64-zvkned.o

quiet_cmd_perlasm = PERLASM $@
      cmd_perlasm = $(PERL) $(<) void $(@)

$(obj)/aes-riscv64-zvkned.S: $(src)/aes-riscv64-zvkned.pl
	$(call cmd,perlasm)

clean-files += aes-riscv64-zvkned.S

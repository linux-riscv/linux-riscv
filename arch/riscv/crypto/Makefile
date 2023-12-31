# SPDX-License-Identifier: GPL-2.0-only
#
# linux/arch/riscv/crypto/Makefile
#

obj-$(CONFIG_CRYPTO_AES_RISCV64) += aes-riscv64.o
aes-riscv64-y := aes-riscv64-glue.o aes-riscv64-zvkned.o

obj-$(CONFIG_CRYPTO_AES_BLOCK_RISCV64) += aes-block-riscv64.o
aes-block-riscv64-y := aes-riscv64-block-mode-glue.o aes-riscv64-zvkned-zvbb-zvkg.o aes-riscv64-zvkned-zvkb.o

obj-$(CONFIG_CRYPTO_GHASH_RISCV64) += ghash-riscv64.o
ghash-riscv64-y := ghash-riscv64-glue.o ghash-riscv64-zvkg.o

obj-$(CONFIG_CRYPTO_SHA256_RISCV64) += sha256-riscv64.o
sha256-riscv64-y := sha256-riscv64-glue.o sha256-riscv64-zvknha_or_zvknhb-zvkb.o

obj-$(CONFIG_CRYPTO_SHA512_RISCV64) += sha512-riscv64.o
sha512-riscv64-y := sha512-riscv64-glue.o sha512-riscv64-zvknhb-zvkb.o

obj-$(CONFIG_CRYPTO_SM3_RISCV64) += sm3-riscv64.o
sm3-riscv64-y := sm3-riscv64-glue.o sm3-riscv64-zvksh.o

obj-$(CONFIG_CRYPTO_SM4_RISCV64) += sm4-riscv64.o
sm4-riscv64-y := sm4-riscv64-glue.o sm4-riscv64-zvksed.o

quiet_cmd_perlasm = PERLASM $@
      cmd_perlasm = $(PERL) $(<) void $(@)

$(obj)/aes-riscv64-zvkned.S: $(src)/aes-riscv64-zvkned.pl
	$(call cmd,perlasm)

$(obj)/aes-riscv64-zvkned-zvbb-zvkg.S: $(src)/aes-riscv64-zvkned-zvbb-zvkg.pl
	$(call cmd,perlasm)

$(obj)/aes-riscv64-zvkned-zvkb.S: $(src)/aes-riscv64-zvkned-zvkb.pl
	$(call cmd,perlasm)

$(obj)/ghash-riscv64-zvkg.S: $(src)/ghash-riscv64-zvkg.pl
	$(call cmd,perlasm)

$(obj)/sha256-riscv64-zvknha_or_zvknhb-zvkb.S: $(src)/sha256-riscv64-zvknha_or_zvknhb-zvkb.pl
	$(call cmd,perlasm)

$(obj)/sha512-riscv64-zvknhb-zvkb.S: $(src)/sha512-riscv64-zvknhb-zvkb.pl
	$(call cmd,perlasm)

$(obj)/sm3-riscv64-zvksh.S: $(src)/sm3-riscv64-zvksh.pl
	$(call cmd,perlasm)

$(obj)/sm4-riscv64-zvksed.S: $(src)/sm4-riscv64-zvksed.pl
	$(call cmd,perlasm)

clean-files += aes-riscv64-zvkned.S
clean-files += aes-riscv64-zvkned-zvbb-zvkg.S
clean-files += aes-riscv64-zvkned-zvkb.S
clean-files += ghash-riscv64-zvkg.S
clean-files += sha256-riscv64-zvknha_or_zvknhb-zvkb.S
clean-files += sha512-riscv64-zvknhb-zvkb.S
clean-files += sm3-riscv64-zvksh.S
clean-files += sm4-riscv64-zvksed.S

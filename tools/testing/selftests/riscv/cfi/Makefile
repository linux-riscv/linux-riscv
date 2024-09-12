CFLAGS += -I$(top_srcdir)/tools/include

CFLAGS += -march=rv64gc_zicfilp_zicfiss

TEST_GEN_PROGS := cfitests

include ../../lib.mk

$(OUTPUT)/cfitests: riscv_cfi_test.c shadowstack.c
	$(CC) -o$@ $(CFLAGS) $(LDFLAGS) $^

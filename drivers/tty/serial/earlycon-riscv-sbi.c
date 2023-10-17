// SPDX-License-Identifier: GPL-2.0
/*
 * RISC-V SBI based earlycon
 *
 * Copyright (C) 2018 Anup Patel <anup@brainfault.org>
 */
#include <linux/kernel.h>
#include <linux/console.h>
#include <linux/init.h>
#include <linux/serial_core.h>
#include <asm/sbi.h>

#ifdef CONFIG_RISCV_SBI_V01
static void sbi_putc(struct uart_port *port, unsigned char c)
{
	sbi_console_putchar(c);
}

static void sbi_0_1_console_write(struct console *con,
				  const char *s, unsigned n)
{
	struct earlycon_device *dev = con->data;
	uart_console_write(&dev->port, s, n, sbi_putc);
}
#endif

static void sbi_dbcn_console_write(struct console *con,
				   const char *s, unsigned n)
{
	phys_addr_t pa = __pa(s);

	sbi_ecall(SBI_EXT_DBCN, SBI_EXT_DBCN_CONSOLE_WRITE,
#ifdef CONFIG_32BIT
		  n, pa, (u64)pa >> 32,
#else
		  n, pa, 0,
#endif
		  0, 0, 0);
}

static int __init early_sbi_setup(struct earlycon_device *device,
				  const char *opt)
{
	int ret = 0;

	/* TODO: Check for SBI debug console (DBCN) extension */
	if ((sbi_spec_version >= sbi_mk_version(1, 0)) &&
	    (sbi_probe_extension(SBI_EXT_DBCN) > 0))
		device->con->write = sbi_dbcn_console_write;
	else
#ifdef CONFIG_RISCV_SBI_V01
		device->con->write = sbi_0_1_console_write;
#else
		ret = -ENODEV;
#endif

	return ret;
}
EARLYCON_DECLARE(sbi, early_sbi_setup);

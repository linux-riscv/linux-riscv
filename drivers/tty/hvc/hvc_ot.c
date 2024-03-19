/* SPDX-License-Identifier: GPL-2.0 */
/* Trivial HVC "driver" for an OpenTitan-like UART,
 * exposed in DT with "opentitan,uart"; polling.
 *
 * Copyright (c) 2022-2024 Rivos Inc.
 *
 * Based on hvc_riscv_sbi.c which is: 
 * Copyright (C) 2008 David Gibson, IBM Corporation
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 */

#include <linux/console.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/serial_core.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/of.h>
#include <linux/of_address.h>

#include "hvc_console.h"

static volatile u32 *ot_uart_base = 0;

#define OT_UART_CTRL   (0x10/4)
#define OT_UART_CTRL_TXEN 0x01
#define OT_UART_CTRL_RXEN 0x02

#define OT_UART_STATUS (0x14/4)
#define OT_UART_STATUS_TXFULL 0x01

#define OT_UART_FIFO_STATUS (0x24/4)
#define OT_UART_FIFO_STATUS_TXLVL_MASK 0x3f
#define OT_UART_FIFO_STATUS_RXLVL_MASK 0x3f0000

#define OT_UART_RDATA  (0x18/4)
#define OT_UART_WDATA  (0x1c/4)


static void ot_putch_blocking(volatile u32 *base, char c)
{
	while (base[OT_UART_STATUS] & OT_UART_STATUS_TXFULL)
		cpu_relax();

	base[OT_UART_WDATA] = c;
}

static ssize_t hvc_ot_tty_put(uint32_t vtermno, const u8 *buf, size_t count)
{
	ssize_t i;

	if (!ot_uart_base) {
		return 0;
	}

	for (i = 0; i < count; i++) {
		ot_putch_blocking(ot_uart_base, buf[i]);
	}

	return i;
}

static ssize_t hvc_ot_tty_get(uint32_t vtermno, u8 *buf, size_t count)
{
	ssize_t i;
	for (i = 0; i < count; i++) {
		if (ot_uart_base[OT_UART_FIFO_STATUS] & OT_UART_FIFO_STATUS_RXLVL_MASK)
			// Char pending
			buf[i] = ot_uart_base[OT_UART_RDATA];
		else
			break;
	}
	return i;
}

static const struct hv_ops hvc_ot_ops = {
	.get_chars = hvc_ot_tty_get,
	.put_chars = hvc_ot_tty_put,
};

static int __init hvc_ot_init(void)
{
	return PTR_ERR_OR_ZERO(hvc_alloc(0, 0, &hvc_ot_ops, 16));
}
device_initcall(hvc_ot_init);

static int __init hvc_ot_console_init(void)
{
	struct device_node *np;

	np = of_find_compatible_node(NULL, NULL, "opentitan,uart");
	ot_uart_base = of_iomap(np, 0);
	ot_uart_base[OT_UART_CTRL] = OT_UART_CTRL_TXEN | OT_UART_CTRL_RXEN;
	hvc_instantiate(0, 0, &hvc_ot_ops);

	return 0;
}
console_initcall(hvc_ot_console_init);

static void early_ot_early_putc(struct uart_port *port, unsigned char c)
{
	ot_putch_blocking((volatile u32 *)port->membase, c);
}

static void hvc_ot_early_write(struct console *con, const char *s, unsigned int n)
{
	struct earlycon_device *dev = con->data;
	uart_console_write(&dev->port, s, n, early_ot_early_putc);
}

static int __init hvc_ot_console_setup(struct earlycon_device *device,
				       const char *opt)
{
	if (!device->port.membase)
		return -ENODEV;

	((volatile u32 *)device->port.membase)[OT_UART_CTRL] = OT_UART_CTRL_TXEN | OT_UART_CTRL_RXEN;

	device->con->write = hvc_ot_early_write;
	return 0;
}
EARLYCON_DECLARE(ot, hvc_ot_console_setup);

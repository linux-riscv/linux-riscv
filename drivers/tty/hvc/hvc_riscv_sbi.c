/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2008 David Gibson, IBM Corporation
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 */

#include <linux/console.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/types.h>

#include <asm/sbi.h>

#include "hvc_console.h"

#ifdef CONFIG_RISCV_SBI_V01
static int hvc_sbi_tty_put(uint32_t vtermno, const char *buf, int count)
{
	int i;

	for (i = 0; i < count; i++)
		sbi_console_putchar(buf[i]);

	return i;
}

static int hvc_sbi_tty_get(uint32_t vtermno, char *buf, int count)
{
	int i, c;

	for (i = 0; i < count; i++) {
		c = sbi_console_getchar();
		if (c < 0)
			break;
		buf[i] = c;
	}

	return i;
}

static const struct hv_ops hvc_sbi_v01_ops = {
	.get_chars = hvc_sbi_tty_get,
	.put_chars = hvc_sbi_tty_put,
};
#endif

static int hvc_sbi_dbcn_tty_put(uint32_t vtermno, const char *buf, int count)
{
	phys_addr_t pa;
	struct sbiret ret;

	if (is_vmalloc_addr(buf))
		pa = page_to_phys(vmalloc_to_page(buf)) + offset_in_page(buf);
	else
		pa = __pa(buf);

	ret = sbi_ecall(SBI_EXT_DBCN, SBI_EXT_DBCN_CONSOLE_WRITE,
#ifdef CONFIG_32BIT
		  count, pa, (u64)pa >> 32,
#else
		  count, pa, 0,
#endif
		  0, 0, 0);

	if (ret.error)
		return 0;

	return count;
}

static int hvc_sbi_dbcn_tty_get(uint32_t vtermno, char *buf, int count)
{
	phys_addr_t pa;
	struct sbiret ret;

	if (is_vmalloc_addr(buf))
		pa = page_to_phys(vmalloc_to_page(buf)) + offset_in_page(buf);
	else
		pa = __pa(buf);

	ret = sbi_ecall(SBI_EXT_DBCN, SBI_EXT_DBCN_CONSOLE_READ,
#ifdef CONFIG_32BIT
		  count, pa, (u64)pa >> 32,
#else
		  count, pa, 0,
#endif
		  0, 0, 0);

	if (ret.error)
		return 0;

	return ret.value;
}

static const struct hv_ops hvc_sbi_dbcn_ops = {
	.put_chars = hvc_sbi_dbcn_tty_put,
	.get_chars = hvc_sbi_dbcn_tty_get,
};

static int __init hvc_sbi_init(void)
{
	int err;

	if ((sbi_spec_version >= sbi_mk_version(1, 0)) &&
	    (sbi_probe_extension(SBI_EXT_DBCN) > 0)) {
		err = PTR_ERR_OR_ZERO(hvc_alloc(0, 0, &hvc_sbi_dbcn_ops, 16));
		if (err)
			return err;
		hvc_instantiate(0, 0, &hvc_sbi_dbcn_ops);
	} else {
#ifdef CONFIG_RISCV_SBI_V01
		err = PTR_ERR_OR_ZERO(hvc_alloc(0, 0, &hvc_sbi_v01_ops, 16));
		if (err)
			return err;
		hvc_instantiate(0, 0, &hvc_sbi_v01_ops);
#else
		return -ENODEV;
#endif
	}

	return 0;
}
device_initcall(hvc_sbi_init);

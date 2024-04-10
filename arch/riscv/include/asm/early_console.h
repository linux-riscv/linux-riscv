/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _ASM_EARLY_CONSOLE_H
#define _ASM_EARLY_CONSOLE_H
#ifdef __KERNEL__

#include <linux/compiler.h>
#include <linux/init.h>

void __init early_console_init(void);

/* early_console libs */
void early_console_puts(const char *s);
int early_console_write(const char *s, int n);
void early_console_printf(const char *fmt, ...);
void early_console_progress(char *s, unsigned short hex);

#ifdef CONFIG_RISCV_EARLY_CONSOLE_SBI
void __init hvc_sbi_early_init(void (**putc)(char c));
#endif /* CONFIG_HVC_RISCV_SBI */

#endif /* __KERNEL__ */
#endif /* _ASM_EARLY_CONSOLE_H */

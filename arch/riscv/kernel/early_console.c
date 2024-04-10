// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Early console support for RISCV
 */

#include <linux/stdarg.h>
#include <linux/types.h>
#include <linux/console.h>
#include <asm/sbi.h>
#include <asm/early_console.h>

/* interface for early console output characters */
void (*riscv_early_console_putc)(char c);

void early_console_puts(const char *s)
{
	if (riscv_early_console_putc) {
		char c;

		if (s && *s != '\0') {
			while ((c = *s++) != '\0')
				riscv_early_console_putc(c);
		}
	}
}

int early_console_write(const char *s, int n)
{
	int remain = n;
	char c;

	if (!riscv_early_console_putc)
		return 0;

	if (s && *s != '\0') {
		while (((c = *s++) != '\0') && (remain-- > 0))
			riscv_early_console_putc(c);
	}

	return n - remain;
}

#define EARLY_CONSOLE_BUFSIZE 256
void early_console_printf(const char *fmt, ...)
{
	if (riscv_early_console_putc) {
		char buf[EARLY_CONSOLE_BUFSIZE];
		va_list args;

		va_start(args, fmt);
		vsnprintf(buf, EARLY_CONSOLE_BUFSIZE, fmt, args);
		early_console_puts(buf);
		va_end(args);
	}
}

void __init early_console_progress(char *s, unsigned short hex)
{
	early_console_puts(s);
	early_console_puts("\n");
}

/*
 * Console based on early console
 */
static void riscv_early_console_write(struct console *con, const char *s,
		unsigned int n)
{
	early_console_write(s, n);
}

static struct console riscv_early_console = {
	.name	= "riscv_early_con",
	.write	= riscv_early_console_write,
	.flags	= CON_PRINTBUFFER | CON_ENABLED | CON_BOOT | CON_ANYTIME,
	.index	= 0,
};

static void __init register_early_console(void)
{
	if (!riscv_early_console_putc)
		return;

	add_preferred_console("riscv_early_con", 0, NULL);
	register_console(&riscv_early_console);
}

/*
 * This is called after sbi_init.
 */
void __init early_console_init(void)
{
	/*
	 * Set riscv_early_console_putc.
	 * If there are other output interfaces, you can add corresponding code
	 * to initialize riscv_early_console_putc.
	 */
#if defined(CONFIG_RISCV_EARLY_CONSOLE_SBI)
	/* using the sbi */
	hvc_sbi_early_init(&riscv_early_console_putc);
#else
	/* using other */
#endif

	console_loglevel = CONSOLE_LOGLEVEL_MOTORMOUTH;
	register_early_console();
}


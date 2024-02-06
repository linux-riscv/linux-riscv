// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023, Ventana Micro Systems Inc
 *	Author: Sunil V L <sunilvl@ventanamicro.com>
 *
 */

#include <linux/acpi.h>
#include "init.h"

void __init acpi_riscv_init(void)
{
	riscv_acpi_aplic_platform_init();
	riscv_acpi_plic_platform_init();
}

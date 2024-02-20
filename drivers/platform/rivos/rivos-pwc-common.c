// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Rivos Inc.
 * Author: Clément Léger <cleger@rivosinc.com>
 */

#include <linux/auxiliary_bus.h>
#include <linux/hwmon.h>

#include "rivos-pwc-common.h"

struct device *rivos_pwc_hwmon_probe(struct rivos_pwc_hwmon_init *init)
{
	struct device *hwmon_dev;
	struct hwmon_chip_info *chip;
	const char *name;

	chip = devm_kzalloc(init->dev, sizeof(*chip), GFP_KERNEL);
	if (!chip)
		return ERR_PTR(-ENOMEM);

	chip->ops = init->ops;
	chip->info = init->info;
	name = strchr(init->id->name, '.') + 1;
	if (!name)
		return ERR_PTR(-EINVAL);

	hwmon_dev = devm_hwmon_device_register_with_info(init->dev, name,
							 init->drv_data, chip,
							 init->drv_groups);

	return hwmon_dev;
}

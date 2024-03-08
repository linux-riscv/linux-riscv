// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Rivos Inc.
 * Author: Clément Léger <cleger@rivosinc.com>
 */

#include <linux/auxiliary_bus.h>
#include <linux/bitfield.h>
#include <linux/hwmon.h>
#include <linux/module.h>

#include "rivos-pwc-thermal.h"

/* Custom DPA fields in TEMP_STATUS register */
#define TEMP_STATUS_DPA_MAX_ABS_TEMP		GENMASK(7, 0)

static const struct rivos_pwc_thermal_chan dpa_thermal_chans[] = {
	{"dpa_max", TEMP_STATUS_OFFSET, TEMP_STATUS_DPA_MAX_ABS_TEMP, 0}
};

static const struct hwmon_channel_info *dpa_thermal_info[] = {
	HWMON_CHANNEL_INFO(temp,
			   /* DPA MAX */
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_FAULT |
			   HWMON_T_MAX | HWMON_T_MAX_HYST | HWMON_T_MAX_ALARM |
			   HWMON_T_CRIT | HWMON_T_CRIT_HYST | HWMON_T_CRIT_ALARM
			   ),
	NULL
};

static int dpa_thermal_probe(struct auxiliary_device *auxdev,
			     const struct auxiliary_device_id *id)
{
	struct rivos_pwc_thermal *data;
	struct rivos_pwc_hwmon_init init;

	data = rivos_pwc_thermal_get_data(auxdev, 0);
	if (IS_ERR(data))
		return PTR_ERR(data);

	data->chans = dpa_thermal_chans;
	init.info = dpa_thermal_info;
	init.id = id;

	return rivos_pwc_thermal_probe(data, &init);
}

static const struct auxiliary_device_id dpa_thermal_id_table[] = {
	{ .name = "rivos_pwc.dpa_thermal" },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, dpa_thermal_id_table);

static struct auxiliary_driver dpa_thermal_driver = {
	.id_table	= dpa_thermal_id_table,
	.probe		= dpa_thermal_probe,
};
module_auxiliary_driver(dpa_thermal_driver);

MODULE_AUTHOR("Clément Léger <cleger@rivosinc.com>");
MODULE_DESCRIPTION("Rivos DPA thermal driver");
MODULE_LICENSE("GPL");

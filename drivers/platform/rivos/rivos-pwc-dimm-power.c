// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Rivos Inc.
 * Author: Clément Léger <cleger@rivosinc.com>
 */

#include <linux/auxiliary_bus.h>
#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/hwmon.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/stringify.h>
#include <linux/sysfs.h>

#include "rivos-pwc-power.h"

#define POWER_INFO_1_OFFSET			0x0
#define  POWER_INFO_1_TDP			GENMASK(15, 0)

#define POWER_INFO_2_OFFSET			0x8
#define  POWER_INFO_2_POWER_UNIT		GENMASK(15, 0)
#define  POWER_INFO_2_ENERGY_UNIT		GENMASK(31, 16)

struct rivos_pwc_dimm_power {
	u32 tdp;
};

#define DIMM_CHAN(__dimm) \
	{"dimm" __stringify(__dimm), (0x10 + (__dimm) * 8)}

static const struct rivos_pwc_power_chan dimm_power_chan[] = {
	DIMM_CHAN(0),
	DIMM_CHAN(1),
	DIMM_CHAN(2),
};

static int dimm_power_read(struct device *dev, enum hwmon_sensor_types type,
			   u32 attr, int channel, long *val)
{
	struct rivos_pwc_power *priv = dev_get_drvdata(dev);
	struct rivos_pwc_dimm_power *drv = priv->drv_data;

	switch (type) {
	case hwmon_power:
		switch (attr) {
		case hwmon_power_max:
			*val = drv->tdp;
			return 0;
		}
		break;
	default:
		break;
	}
	return -EOPNOTSUPP;
}

static int dimm_power_is_visible(const void *data,
				     enum hwmon_sensor_types type, u32 attr,
				     int channel, umode_t *mode)
{
	switch (type) {
	case hwmon_power:
		switch (attr) {
		case hwmon_power_label:
			*mode = 0444;
			return 0;
		}
		break;
	default:
		break;
	}

	return -EOPNOTSUPP;
}

static int dimm_power_read_string(struct device *dev,
				 enum hwmon_sensor_types type,
				 u32 attr, int channel, const char **str)
{
	switch (type) {
	case hwmon_power:
		switch (attr) {
		case hwmon_power_label:
			*str = "dimm_tdp";
			return 0;
		}
	default:
		break;
	}

	return -EOPNOTSUPP;
}

static const struct rivos_pwc_hwmon_ops dimm_power_hwmon_ops = {
	.is_visible = dimm_power_is_visible,
	.read = dimm_power_read,
	.read_string = dimm_power_read_string,
};

static const struct hwmon_channel_info *dimm_power_info[] = {
	HWMON_CHANNEL_INFO(power,
			   HWMON_P_MAX | HWMON_P_LABEL
			   ),
	HWMON_CHANNEL_INFO(energy,
			   HWMON_E_INPUT | HWMON_E_LABEL,
			   HWMON_E_INPUT | HWMON_E_LABEL,
			   HWMON_E_INPUT | HWMON_E_LABEL
			   ),
	NULL
};

static int dimm_power_probe(struct auxiliary_device *auxdev,
				 const struct auxiliary_device_id *id)
{
	u32 reg;
	struct rivos_pwc_power *data;
	struct rivos_pwc_dimm_power *drv;
	struct rivos_pwc_hwmon_init init;

	data = rivos_pwc_power_get_data(auxdev, sizeof(*drv));
	if (IS_ERR(data))
		return PTR_ERR(data);

	data->chans = dimm_power_chan;
	data->drv_ops = &dimm_power_hwmon_ops;
	init.info = dimm_power_info;
	init.id = id;

	drv = data->drv_data;
	reg = readl(data->base + POWER_INFO_1_OFFSET);
	drv->tdp = FIELD_GET(POWER_INFO_1_TDP, reg) << data->power_unit;
	drv->tdp *= 1000000L;

	return rivos_pwc_power_probe(data, &init);
}

static const struct auxiliary_device_id dimm_power_id_table[] = {
	{ .name = "rivos_pwc.dimm_power" },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, dimm_power_id_table);

static struct auxiliary_driver dimm_power_driver = {
	.id_table	= dimm_power_id_table,
	.probe		= dimm_power_probe,
};
module_auxiliary_driver(dimm_power_driver);

MODULE_AUTHOR("Clément Léger <cleger@rivosinc.com>");
MODULE_DESCRIPTION("Rivos DIMM power driver");
MODULE_LICENSE("GPL");

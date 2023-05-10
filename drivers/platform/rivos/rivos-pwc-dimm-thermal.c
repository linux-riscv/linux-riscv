// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Rivos Inc.
 * Author: Clément Léger <cleger@rivosinc.com>
 */

#include <linux/auxiliary_bus.h>
#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/hwmon.h>
#include <linux/module.h>
#include <linux/stringify.h>
#include <linux/sysfs.h>

#include "rivos-pwc-thermal.h"

/* Custom DIMM fields in TEMP_STATUS register */
#define TEMP_STATUS_DIMM_MAX_ABS_TEMP		GENMASK(7, 0)
#define TEMP_STATUS_DRAM_MAX_SLOT_ID		GENMASK(31, 16)

#define DIMM_TEMP_STATUS_OFFSET(__dimm)		(0x20 + (__dimm) * 0x8)
#define  DIMM_TEMP_STATUS_ABS_TEMP		GENMASK(7, 0)
#define  DIMM_TEMP_STATUS_ABS_TEMP_SHIFT	0
#define  DIMM_TEMP_STATUS_DRAM_DEV_ABS_TEMP	GENMASK(15, 8)
#define  DIMM_TEMP_STATUS_DRAM_DEV_ABS_TEMP_SHIFT	8

struct rivos_pwc_dimm_thermal {
	int max_temp_slot;
};

#define DIMM_TEMP_SLOT(__dimm) \
	{ \
		"dimm" __stringify(__dimm), \
		DIMM_TEMP_STATUS_OFFSET(__dimm), \
		DIMM_TEMP_STATUS_ABS_TEMP, \
		DIMM_TEMP_STATUS_ABS_TEMP_SHIFT \
	},\
	{ \
		"dimm_dram" __stringify(__dimm), \
		DIMM_TEMP_STATUS_OFFSET(__dimm), \
		DIMM_TEMP_STATUS_DRAM_DEV_ABS_TEMP, \
		DIMM_TEMP_STATUS_DRAM_DEV_ABS_TEMP_SHIFT \
	}

static struct rivos_pwc_thermal_chan dimm_thermal_chans[] = {
	{"dimm_max", TEMP_STATUS_OFFSET, TEMP_STATUS_DIMM_MAX_ABS_TEMP, 0},
	DIMM_TEMP_SLOT(0),
	DIMM_TEMP_SLOT(1),
	DIMM_TEMP_SLOT(2)
};

static ssize_t temp1_slot_id_show(struct device *dev,
				       struct device_attribute *devattr,
				       char *buf)
{
	struct rivos_pwc_dimm_thermal *priv = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", priv->max_temp_slot);
}

static DEVICE_ATTR_RO(temp1_slot_id);

static struct attribute *rivos_pwc_dimm_thermal_attrs[] = {
	&dev_attr_temp1_slot_id.attr,
	NULL
};

ATTRIBUTE_GROUPS(rivos_pwc_dimm_thermal);

static void dimm_thermal_read_max_slot_temp(struct rivos_pwc_thermal *priv,
					    int channel, long *val, bool *valid)
{
	struct rivos_pwc_dimm_thermal *drv = priv->drv_data;

	u32 reg = rivos_pwc_thermal_read_temp(priv, channel, val, valid);

	/* First channel is the DIMM Max temperature, store slot id for later
	 * retrieval, this way it is associated to the temp reading and latch on
	 * sysfs temp read.
	 */
	if (channel == 0)
		drv->max_temp_slot = FIELD_GET(TEMP_STATUS_DRAM_MAX_SLOT_ID,
					       reg);
}

static int dimm_thermal_read(struct device *dev, enum hwmon_sensor_types type,
			     u32 attr, int channel, long *val)
{
	struct rivos_pwc_thermal *priv = dev_get_drvdata(dev);
	bool valid;

	switch (type) {
	case hwmon_temp:
		switch (attr) {
		case hwmon_temp_fault:
			dimm_thermal_read_max_slot_temp(priv, channel, val, &valid);
			*val = !valid;
			return 0;
		case hwmon_temp_input:
			dimm_thermal_read_max_slot_temp(priv, channel, val, &valid);
			return 0;
		}
		break;
	default:
		break;
	}

	return -EOPNOTSUPP;

}

static int dimm_thermal_is_visible(const void *data,
					 enum hwmon_sensor_types type,
					 u32 attr, int channel, umode_t *mode)
{
	struct rivos_pwc_thermal *priv = (struct rivos_pwc_thermal *) data;
	bool valid;
	long val;

	switch (type) {
	case hwmon_temp:
		switch (attr) {
		case hwmon_temp_input:
		case hwmon_temp_fault:
		case hwmon_temp_label:
			/* DIMM Max channel is always available */
			if (channel == 0) {
				*mode = 0444;
				return 0;
			}

			dimm_thermal_read_max_slot_temp(priv, channel, &val,
							&valid);
			/* DIMM slot is unpopulated, hide it */
			if (!val && !valid)
				*mode = 0;
			else
				*mode = 0444;

			return 0;
		}
		break;
	default:
		break;
	}

	return -EOPNOTSUPP;
}

static const struct rivos_pwc_hwmon_ops dimm_thermal_hwmon_ops = {
	.is_visible = dimm_thermal_is_visible,
	.read = dimm_thermal_read,
};

static const struct hwmon_channel_info *dimm_thermal_info[] = {
	HWMON_CHANNEL_INFO(temp,
			   /* Dimm MAX */
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_FAULT |
			   HWMON_T_MAX | HWMON_T_MAX_HYST | HWMON_T_MAX_ALARM |
			   HWMON_T_CRIT | HWMON_T_CRIT_HYST | HWMON_T_CRIT_ALARM,
			   /* DIMM Slots */
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_FAULT
			   ),
	NULL
};

static int dimm_thermal_probe(struct auxiliary_device *auxdev,
			      const struct auxiliary_device_id *id)
{
	struct rivos_pwc_thermal *data;
	struct rivos_pwc_hwmon_init init;
	struct rivos_pwc_dimm_thermal *drv;

	data = rivos_pwc_thermal_get_data(auxdev, sizeof(*drv));
	if (IS_ERR(data))
		return PTR_ERR(data);

	data->chans = dimm_thermal_chans;
	data->drv_ops = &dimm_thermal_hwmon_ops;
	init.info = dimm_thermal_info;
	init.drv_groups = rivos_pwc_dimm_thermal_groups;
	init.id = id;

	drv = data->drv_data;

	return rivos_pwc_thermal_probe(data, &init);
}


static const struct auxiliary_device_id dimm_thermal_id_table[] = {
	{ .name = "rivos_pwc.dimm_thermal" },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, dimm_thermal_id_table);

static struct auxiliary_driver dimm_thermal_driver = {
	.id_table	= dimm_thermal_id_table,
	.probe		= dimm_thermal_probe,
};
module_auxiliary_driver(dimm_thermal_driver);

MODULE_AUTHOR("Clément Léger <cleger@rivosinc.com>");
MODULE_DESCRIPTION("Rivos DIMM thermal driver");
MODULE_LICENSE("GPL");

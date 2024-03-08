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

#include "rivos-pwc-thermal.h"

/* Custom chiplet field in TEMP_INFO register */
#define TEMP_INFO_OFFSET			0x0
#define TEMP_INFO_TJMAX				GENMASK(7, 0)
#define TEMP_INFO_T_SD				GENMASK(15, 8)

#define TEMP_INFO_CONTROL			0x8
#define TEMP_INFO_TJMAX_REDUCTION		GENMASK(3, 0)

#define TEMP_STATUS_CLUSTER_COUNT		8
#define TEMP_STATUS_CLUSTER_OFFSET(__clus)	(0x30 + (__clus) * 0x8)

#define TEMP_STATUS_HART_COUNT			32
#define TEMP_STATUS_HART_OFFSET(__hart)		(0x70 + (__hart) * 0x8)

#define TEMP_MASK				GENMASK(7, 0)

#define TEMP_CHAN_CLUSTER(__clus) \
	{"cluster" __stringify(__clus), TEMP_STATUS_CLUSTER_OFFSET(__clus), TEMP_MASK, 0}
#define TEMP_CHAN_HART(__hart) \
	{"hart" __stringify(__hart), TEMP_STATUS_HART_OFFSET(__hart), TEMP_MASK, 0}

struct rivos_pwc_chiplet_thermal {
	long t_sd;
	long tjmax;
};

static struct rivos_pwc_thermal_chan chiplet_thermal_chans[] = {
	{ "chiplet", TEMP_STATUS_OFFSET, TEMP_MASK, 0},
	TEMP_CHAN_CLUSTER(0),
	TEMP_CHAN_CLUSTER(1),
	TEMP_CHAN_CLUSTER(2),
	TEMP_CHAN_CLUSTER(3),
	TEMP_CHAN_CLUSTER(4),
	TEMP_CHAN_CLUSTER(5),
	TEMP_CHAN_CLUSTER(6),
	TEMP_CHAN_CLUSTER(7),
	TEMP_CHAN_HART(0),
	TEMP_CHAN_HART(1),
	TEMP_CHAN_HART(2),
	TEMP_CHAN_HART(3),
	TEMP_CHAN_HART(4),
	TEMP_CHAN_HART(5),
	TEMP_CHAN_HART(6),
	TEMP_CHAN_HART(7),
	TEMP_CHAN_HART(8),
	TEMP_CHAN_HART(9),
	TEMP_CHAN_HART(10),
	TEMP_CHAN_HART(11),
	TEMP_CHAN_HART(12),
	TEMP_CHAN_HART(13),
	TEMP_CHAN_HART(14),
	TEMP_CHAN_HART(15),
	TEMP_CHAN_HART(16),
	TEMP_CHAN_HART(17),
	TEMP_CHAN_HART(18),
	TEMP_CHAN_HART(19),
	TEMP_CHAN_HART(20),
	TEMP_CHAN_HART(21),
	TEMP_CHAN_HART(22),
	TEMP_CHAN_HART(23),
	TEMP_CHAN_HART(24),
	TEMP_CHAN_HART(25),
	TEMP_CHAN_HART(26),
	TEMP_CHAN_HART(27),
	TEMP_CHAN_HART(28),
	TEMP_CHAN_HART(29),
	TEMP_CHAN_HART(30),
	TEMP_CHAN_HART(31),
};

static ssize_t temp1_shutdown_show(struct device *dev,
				struct device_attribute *devattr,
				char *buf)
{
	struct rivos_pwc_thermal *priv = dev_get_drvdata(dev);
	struct rivos_pwc_chiplet_thermal *drv = priv->drv_data;

	return sprintf(buf, "%ld\n", drv->t_sd);
}
static DEVICE_ATTR_RO(temp1_shutdown);

static struct attribute *rivos_pwc_chiplet_thermal_attrs[] = {
	&dev_attr_temp1_shutdown.attr,
	NULL
};
ATTRIBUTE_GROUPS(rivos_pwc_chiplet_thermal);

static int chiplet_thermal_read(struct device *dev, enum hwmon_sensor_types type,
				u32 attr, int channel, long *val)
{
	struct rivos_pwc_thermal *priv = dev_get_drvdata(dev);
	struct rivos_pwc_chiplet_thermal *drv = priv->drv_data;
	u32 reg;

	if (channel != 0)
		return -EOPNOTSUPP;

	if (type == hwmon_temp && attr == hwmon_temp_emergency) {
		reg = rivos_pwc_thermal_readl(priv, TEMP_INFO_CONTROL);
		reg = FIELD_GET(TEMP_INFO_TJMAX_REDUCTION, reg);
		*val = drv->tjmax - reg;
		return 0;
	}

	return -EOPNOTSUPP;
}

static int chiplet_thermal_write(struct device *dev, enum hwmon_sensor_types type,
				 u32 attr, int channel, long val)
{
	struct rivos_pwc_thermal *priv = dev_get_drvdata(dev);
	struct rivos_pwc_chiplet_thermal *drv = priv->drv_data;
	u32 tjmax_tmp;
	u32 reg;

	if (channel != 0)
		return -EOPNOTSUPP;

	if (type == hwmon_temp && attr == hwmon_temp_emergency) {
		tjmax_tmp = drv->tjmax - FIELD_MAX(TEMP_INFO_TJMAX_REDUCTION);
		tjmax_tmp = clamp_val(val, tjmax_tmp, drv->tjmax);

		/* tjmax_reduction is actually a delta from the fixed tjmax */
		tjmax_tmp = drv->tjmax - val;
		reg = FIELD_PREP(TEMP_INFO_TJMAX_REDUCTION, tjmax_tmp);
		rivos_pwc_thermal_writel(priv, reg, TEMP_INFO_CONTROL);

		return 0;
	}

	return -EOPNOTSUPP;
}

static int chiplet_thermal_is_visible(const void *data,
					 enum hwmon_sensor_types type,
					 u32 attr, int channel, umode_t *mode)
{
	if (type == hwmon_temp && attr == hwmon_temp_emergency) {
		*mode = 0644;
		return 0;
	}

	return -EOPNOTSUPP;
}

static const struct rivos_pwc_hwmon_ops chiplet_thermal_hwmon_ops = {
	.is_visible = chiplet_thermal_is_visible,
	.read = chiplet_thermal_read,
	.write = chiplet_thermal_write,
};

static const struct hwmon_channel_info *chiplet_thermal_info[] = {
	HWMON_CHANNEL_INFO(temp,
			   /* Chiplet */
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT |
			   HWMON_T_MAX | HWMON_T_MAX_HYST | HWMON_T_MAX_ALARM |
			   HWMON_T_CRIT | HWMON_T_CRIT_HYST | HWMON_T_CRIT_ALARM |
			   HWMON_T_EMERGENCY,
			   /* Clusters */
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   /* Harts */
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT,
			   HWMON_T_INPUT | HWMON_T_TYPE | HWMON_T_LABEL | HWMON_T_FAULT
			   ),
	NULL
};

static int chiplet_thermal_probe(struct auxiliary_device *auxdev,
				 const struct auxiliary_device_id *id)
{
	u32 reg;
	struct rivos_pwc_thermal *data;
	struct rivos_pwc_hwmon_init init;
	struct rivos_pwc_chiplet_thermal *drv;

	data = rivos_pwc_thermal_get_data(auxdev, sizeof(*drv));
	if (IS_ERR(data))
		return PTR_ERR(data);

	data->chans = chiplet_thermal_chans;
	data->drv_ops = &chiplet_thermal_hwmon_ops;
	init.info = chiplet_thermal_info;
	init.id = id;
	init.drv_groups = rivos_pwc_chiplet_thermal_groups;

	drv = data->drv_data;
	reg = rivos_pwc_thermal_readl(data, TEMP_INFO_OFFSET);

	drv->t_sd = FIELD_GET(TEMP_INFO_T_SD, reg) * 1000L;
	drv->tjmax = FIELD_GET(TEMP_INFO_TJMAX, reg) * 1000L;

	return rivos_pwc_thermal_probe(data, &init);
}

static const struct auxiliary_device_id chiplet_thermal_id_table[] = {
	{ .name = "rivos_pwc.chiplet_thermal" },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, chiplet_thermal_id_table);

static struct auxiliary_driver chiplet_thermal_driver = {
	.id_table	= chiplet_thermal_id_table,
	.probe		= chiplet_thermal_probe,
};
module_auxiliary_driver(chiplet_thermal_driver);

MODULE_AUTHOR("Clément Léger <cleger@rivosinc.com>");
MODULE_DESCRIPTION("Rivos chiplet thermal driver");
MODULE_LICENSE("GPL");

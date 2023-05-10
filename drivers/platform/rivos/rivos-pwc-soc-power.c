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
#include <linux/mutex.h>
#include <linux/sysfs.h>

#include "rivos-pwc-power.h"

#define POWER_INFO_1_LO_OFFSET			0x0
#define  POWER_INFO_1_LO_TDP			GENMASK(15, 0)
#define  POWER_INFO_1_LO_ICC_MAX		GENMASK(31, 16)

#define POWER_INFO_1_HI_OFFSET			0x4
#define  POWER_INFO_1_HI_MIN_POWER_LIMIT	GENMASK(15, 0)
#define  POWER_INFO_1_HI_MAX_POWER_LIMIT	GENMASK(31, 16)

#define POWER_INFO_2_HI_OFFSET			0xC
#define  POWER_INFO_2_HI_CURRENT_UNIT		GENMASK(15, 0)

#define SOC_ENERGY_STATUS_OFFSET		0x10

#define SOC_POWER_LIMIT_HOST_OFFSET		0x18
#define  SOC_POWER_LIMIT_LONG_LIMIT		GENMASK(15, 0)
#define  SOC_POWER_LIMIT_SHORT_LIMIT		GENMASK(31, 16)

struct rivos_pwc_soc_power {
	u16 current_unit;
	u32 tdp;
	u32 icc_max;
	u32 max_power_limit;
	u32 min_power_limit;
	u32 short_power_limit;
	u32 long_power_limit;
	struct mutex lock;
};

static const struct rivos_pwc_power_chan soc_power_chans[] = {
	{"energy", SOC_ENERGY_STATUS_OFFSET}
};

static void soc_power_rmw_limits(struct rivos_pwc_power *priv, u32 mask, u32 val)
{
	struct rivos_pwc_soc_power *drv = priv->drv_data;
	u32 reg;

	mutex_lock(&drv->lock);
	reg = readl(priv->base + SOC_POWER_LIMIT_HOST_OFFSET);
	reg &= ~mask;
	reg |= val;
	writel(reg, priv->base + SOC_POWER_LIMIT_HOST_OFFSET);
	mutex_unlock(&drv->lock);
}

static long uwatt_to_reg(struct rivos_pwc_power *priv, long uwatt)
{
	uwatt /= 1000000L;
	uwatt >>= priv->power_unit;

	return uwatt;
}

static void soc_power_set_long_limit(struct rivos_pwc_power *priv, long uwatt)
{
	struct rivos_pwc_soc_power *drv = priv->drv_data;
	long watt;

	uwatt = clamp_val(uwatt, drv->min_power_limit, drv->tdp);

	drv->long_power_limit = uwatt;
	watt = uwatt_to_reg(priv, uwatt);

	soc_power_rmw_limits(priv, SOC_POWER_LIMIT_LONG_LIMIT,
			     FIELD_PREP(SOC_POWER_LIMIT_LONG_LIMIT, watt));
}

static void soc_power_set_short_limit(struct rivos_pwc_power *priv, long uwatt)
{
	struct rivos_pwc_soc_power *drv = priv->drv_data;
	long watt;

	uwatt = clamp_val(uwatt, drv->tdp, drv->max_power_limit);

	drv->short_power_limit = uwatt;
	watt = uwatt_to_reg(priv, uwatt);

	soc_power_rmw_limits(priv, SOC_POWER_LIMIT_SHORT_LIMIT,
			     FIELD_PREP(SOC_POWER_LIMIT_SHORT_LIMIT, watt));
}

#define DRV_SHOW_ATTR(__name, __field) \
static ssize_t __name ## _show(struct device *dev, \
			       struct device_attribute *devattr, char *buf) \
{ \
	struct rivos_pwc_power *priv = dev_get_drvdata(dev); \
	struct rivos_pwc_soc_power *drv = priv->drv_data; \
	\
	return sprintf(buf, "%d\n", drv->__field); \
}

DRV_SHOW_ATTR(power1_short_cap_min, tdp);
DRV_SHOW_ATTR(power1_short_cap_max, max_power_limit);
DRV_SHOW_ATTR(power1_short_cap, short_power_limit);

static ssize_t power1_short_cap_store(struct device *dev,
			       struct device_attribute *attr,
			       const char *buf, size_t count)
{
	struct rivos_pwc_power *priv = dev_get_drvdata(dev);
	long val;
	int ret;

	ret = kstrtol(buf, 10, &val);
	if (ret < 0)
		return ret;

	soc_power_set_short_limit(priv, val);

	return count;
}

static DEVICE_ATTR_RO(power1_short_cap_min);
static DEVICE_ATTR_RO(power1_short_cap_max);
static DEVICE_ATTR_RW(power1_short_cap);

static struct attribute *rivos_pwc_soc_power_attrs[] = {
	&dev_attr_power1_short_cap_min.attr,
	&dev_attr_power1_short_cap_max.attr,
	&dev_attr_power1_short_cap.attr,
	NULL
};

ATTRIBUTE_GROUPS(rivos_pwc_soc_power);

static int soc_power_read(struct device *dev, enum hwmon_sensor_types type,
			  u32 attr, int channel, long *val)
{
	struct rivos_pwc_power *priv = dev_get_drvdata(dev);
	struct rivos_pwc_soc_power *drv = priv->drv_data;

	switch (type) {
	case hwmon_curr:
		switch (attr) {
		case hwmon_curr_max:
			*val = drv->icc_max;
			return 0;
		}
		break;
	case hwmon_power:
		switch (attr) {
		case hwmon_power_cap_max:
		case hwmon_power_max:
			*val = drv->tdp;
			return 0;
		case hwmon_power_crit:
			*val = drv->max_power_limit;
			return 0;
		case hwmon_power_cap_min:
		case hwmon_power_min:
			*val = drv->min_power_limit;
			return 0;
		case hwmon_power_cap:
			*val = drv->long_power_limit;
			return 0;
		}
		break;
	default:
		break;
	}
	return -EOPNOTSUPP;
}

static int soc_power_write(struct device *dev, enum hwmon_sensor_types type,
			   u32 attr, int channel, long val)
{
	struct rivos_pwc_power *priv = dev_get_drvdata(dev);

	switch (type) {
	case hwmon_power:
		switch (attr) {
		case hwmon_power_cap:
			soc_power_set_long_limit(priv, val);
			return 0;
		}
		break;
	default:
		break;
	}
	return -EOPNOTSUPP;
}


static int soc_power_is_visible(const void *data,
					 enum hwmon_sensor_types type,
					 u32 attr, int channel, umode_t *mode)
{
	switch (type) {
	case hwmon_curr:
		switch (attr) {
		case hwmon_curr_max:
		case hwmon_curr_label:
			*mode = 0444;
			return 0;
		}
		break;
	case hwmon_power:
		switch (attr) {
		case hwmon_power_crit:
		case hwmon_power_max:
		case hwmon_power_min:
		case hwmon_power_cap_min:
		case hwmon_power_cap_max:
		case hwmon_power_label:
			*mode = 0444;
			return 0;
		case hwmon_power_cap:
			*mode = 0644;
			return 0;
		}
		break;
	default:
		break;
	}
	return -EOPNOTSUPP;
}

static int soc_power_read_string(struct device *dev,
				 enum hwmon_sensor_types type,
				 u32 attr, int channel, const char **str)
{
	switch (type) {
	case hwmon_curr:
		switch (attr) {
		case hwmon_curr_label:
			*str = "soc_icc";
			return 0;
		}
		break;
	case hwmon_power:
		switch (attr) {
		case hwmon_power_label:
			*str = "soc_power";
			return 0;
		}
		break;
	default:
		break;
	}

	return -EOPNOTSUPP;
}

static const struct rivos_pwc_hwmon_ops soc_power_hwmon_ops = {
	.is_visible = soc_power_is_visible,
	.read = soc_power_read,
	.write = soc_power_write,
	.read_string = soc_power_read_string,
};

static const struct hwmon_channel_info *soc_power_info[] = {
	HWMON_CHANNEL_INFO(curr,
			   HWMON_C_MAX | HWMON_C_LABEL
			   ),
	HWMON_CHANNEL_INFO(power,
			   HWMON_P_CRIT | HWMON_P_MAX | HWMON_P_MIN |
			   HWMON_P_CAP | HWMON_P_CAP_MAX | HWMON_P_CAP_MIN |
			   HWMON_P_LABEL
			   ),
	HWMON_CHANNEL_INFO(energy,
			   HWMON_E_INPUT | HWMON_E_LABEL
			   ),
	NULL
};

static void soc_power_init(struct rivos_pwc_power *priv)
{
	struct rivos_pwc_soc_power *drv = priv->drv_data;
	u32 reg, val;

	reg = readl(priv->base + POWER_INFO_2_HI_OFFSET);
	drv->current_unit = FIELD_GET(POWER_INFO_2_HI_CURRENT_UNIT, reg);

	reg = readl(priv->base + POWER_INFO_1_LO_OFFSET);
	val = FIELD_GET(POWER_INFO_1_LO_TDP, reg) << priv->power_unit;
	drv->tdp = val * 1000000L;

	val =  FIELD_GET(POWER_INFO_1_LO_ICC_MAX, reg) <<
			 drv->current_unit;
	drv->icc_max = val * 1000L;

	reg = readl(priv->base + POWER_INFO_1_HI_OFFSET);
	val = FIELD_GET(POWER_INFO_1_HI_MIN_POWER_LIMIT, reg) <<
	      priv->power_unit;
	drv->min_power_limit = val * 1000000L;
	val = FIELD_GET(POWER_INFO_1_HI_MAX_POWER_LIMIT, reg) <<
	      priv->power_unit;
	drv->max_power_limit = val * 1000000L;

	reg = readl(priv->base + SOC_POWER_LIMIT_HOST_OFFSET);
	val =  FIELD_GET(SOC_POWER_LIMIT_LONG_LIMIT, reg) << priv->power_unit;
	drv->long_power_limit = val * 1000000L;
	val =  FIELD_GET(SOC_POWER_LIMIT_SHORT_LIMIT, reg) << priv->power_unit;
	drv->short_power_limit = val * 1000000L;
}

static int soc_power_probe(struct auxiliary_device *auxdev,
				 const struct auxiliary_device_id *id)
{
	struct rivos_pwc_power *data;
	struct rivos_pwc_soc_power *drv;
	struct rivos_pwc_hwmon_init init;

	data = rivos_pwc_power_get_data(auxdev, sizeof(*drv));
	if (IS_ERR(data))
		return PTR_ERR(data);

	data->chans = soc_power_chans;
	data->drv_ops = &soc_power_hwmon_ops;
	init.drv_groups = rivos_pwc_soc_power_groups;
	init.info = soc_power_info;
	init.id = id;

	drv = data->drv_data;
	mutex_init(&drv->lock);

	soc_power_init(data);

	return rivos_pwc_power_probe(data, &init);
}

static const struct auxiliary_device_id soc_power_id_table[] = {
	{ .name = "rivos_pwc.soc_power" },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, soc_power_id_table);

static struct auxiliary_driver soc_power_driver = {
	.id_table	= soc_power_id_table,
	.probe		= soc_power_probe,
};
module_auxiliary_driver(soc_power_driver);

MODULE_AUTHOR("Clément Léger <cleger@rivosinc.com>");
MODULE_DESCRIPTION("Rivos SoC power driver");
MODULE_LICENSE("GPL");

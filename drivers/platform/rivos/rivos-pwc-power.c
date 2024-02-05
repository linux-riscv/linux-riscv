// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Rivos Inc.
 * Author: Clément Léger <cleger@rivosinc.com>
 */

#include <linux/bitfield.h>
#include <linux/hwmon.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/sysfs.h>

#include "rivos-pwc.h"
#include "rivos-pwc-power.h"

#define rivos_pwc_power_drv_op(__priv, __type, __err, __op, ...) \
({ \
	__type ret; \
	if (__priv->drv_ops && __priv->drv_ops->__op) \
		ret = __priv->drv_ops->__op(__VA_ARGS__); \
	else \
		ret = __err; \
	ret; \
})

static long rivos_pwc_power_read_energy(struct rivos_pwc_power *priv, int chan)
{
	u32 reg_offset = priv->chans[chan].reg_offset;
	u32 low, hi;
	long val, energy;

	do {
		hi = readl(priv->base + reg_offset + 0x4);
		low = readl(priv->base + reg_offset);
	} while (hi != readl(priv->base + reg_offset + 0x4));

	/* energy is stored in a long, avoid overflowing it and going signed */
	if (hi & BIT(31))
		hi &= ~BIT(31);

	energy = (((u64)hi << 32) | low) << priv->energy_unit;

	/* hwmon expect micro-joules report, check that we do not overflow */
	if (unlikely(check_mul_overflow(energy, 1000000L, &val)))
		val = LONG_MAX;

	return val;
}

static int pwc_power_read(struct device *dev, enum hwmon_sensor_types type,
			      u32 attr, int channel, long *val)
{
	struct rivos_pwc_power *priv = dev_get_drvdata(dev);
	int ret;

	ret = rivos_pwc_power_drv_op(priv, int, -EOPNOTSUPP, read, dev, type,
				       attr, channel, val);
	if (ret != -EOPNOTSUPP)
		return ret;

	switch (type) {
	case hwmon_energy:
		switch (attr) {
		case hwmon_energy_input:
			*val = rivos_pwc_power_read_energy(priv, channel);
			return 0;
		}
		break;
	default:
		break;
	}
	return -EOPNOTSUPP;
}

static int rivos_pwc_power_write(struct device *dev, enum hwmon_sensor_types type,
			 u32 attr, int channel, long val)
{
	struct rivos_pwc_power *priv = dev_get_drvdata(dev);

	return rivos_pwc_power_drv_op(priv, int, -EOPNOTSUPP, write, dev,
					type, attr, channel, val);
}

static umode_t pwc_power_is_visible(const void *data,
					 enum hwmon_sensor_types type,
					 u32 attr, int channel)
{
	struct rivos_pwc_power *priv = (void *)data;
	umode_t mode;
	int ret;

	ret = rivos_pwc_power_drv_op(priv, int, -EOPNOTSUPP, is_visible, data, type,
				       attr, channel, &mode);
	if (ret == 0)
		return mode;

	switch (type) {
	case hwmon_energy:
		switch (attr) {
		case hwmon_energy_input:
		case hwmon_energy_label:
			return 0444;
		}
		break;
	default:
		break;
	}
	return 0;
}

static int pwc_power_read_string(struct device *dev,
				 enum hwmon_sensor_types type,
				 u32 attr, int channel, const char **str)
{
	struct rivos_pwc_power *priv = dev_get_drvdata(dev);
	int ret;

	ret = rivos_pwc_power_drv_op(priv, int, -EOPNOTSUPP, read_string, dev,
				       type, attr, channel, str);
	if (ret != -EOPNOTSUPP)
		return ret;

	switch (type) {
	case hwmon_energy:
		switch (attr) {
		case hwmon_energy_label:
			*str = priv->chans[channel].label;
			return 0;
		}
		break;
	default:
		break;
	}

	return -EOPNOTSUPP;
}

static const struct hwmon_ops rivos_pwc_power_ops = {
	.is_visible = pwc_power_is_visible,
	.read = pwc_power_read,
	.read_string = pwc_power_read_string,
	.write = rivos_pwc_power_write,
};

struct rivos_pwc_power *
rivos_pwc_power_get_data(struct auxiliary_device *auxdev, int priv_size)
{
	struct rivos_pwc_dvsec_dev *rpd_dev = auxdev_to_rpd_dev(auxdev);
	struct device *dev = &auxdev->dev;
	struct rivos_pwc_power *data;
	u32 info_2;

	data = devm_kzalloc(dev, sizeof(*data) + priv_size, GFP_KERNEL);
	if (!data)
		return ERR_PTR(-ENOMEM);

	if (priv_size)
		data->drv_data = data + 1;

	data->dev = dev;
	auxiliary_set_drvdata(auxdev, data);

	data->base = devm_ioremap_resource(dev, &rpd_dev->resource);
	if (IS_ERR(data->base))
		return ERR_CAST(data->base);

	info_2 = readl(data->base + POWER_INFO_2_OFFSET);
	data->energy_unit = FIELD_GET(POWER_INFO_2_ENERGY_UNIT, info_2);
	data->power_unit = FIELD_GET(POWER_INFO_2_POWER_UNIT, info_2);

	return data;
}

int rivos_pwc_power_probe(struct rivos_pwc_power *data,
			  struct rivos_pwc_hwmon_init *init)
{
	struct device *hwmon_dev;

	init->drv_data = data;
	init->dev = data->dev;
	init->ops = &rivos_pwc_power_ops;

	hwmon_dev = rivos_pwc_hwmon_probe(init);
	if (IS_ERR_OR_NULL(hwmon_dev))
		return PTR_ERR(hwmon_dev);

	return 0;
}


// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Rivos Inc.
 * Author: Clément Léger <cleger@rivosinc.com>
 */

#include <linux/auxiliary_bus.h>
#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/hwmon.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/limits.h>

#include "rivos-pwc.h"
#include "rivos-pwc-thermal.h"

#define rivos_pwc_thermal_drv_op(__priv, __type, __err, __op, ...) \
({ \
	__type ret; \
	if (__priv->drv_ops && __priv->drv_ops->__op) \
		ret = __priv->drv_ops->__op(__VA_ARGS__); \
	else \
		ret = __err; \
	ret; \
})

u32 rivos_pwc_thermal_readl(struct rivos_pwc_thermal *priv, u32 offset)
{
	return readl(priv->base + offset);
}

void rivos_pwc_thermal_writel(struct rivos_pwc_thermal *priv, u32 val,
			      u32 offset)
{
	return writel(val, priv->base + offset);
}

void rivos_pwc_thermal_rmw(struct rivos_pwc_thermal *priv, u32 off, u32 mask,
			   u32 val)
{
	u32 reg;

	reg = rivos_pwc_thermal_readl(priv, off);
	reg &= ~mask;
	reg |= val;
	rivos_pwc_thermal_writel(priv, reg, off);
}

u32 rivos_pwc_thermal_read_temp(struct rivos_pwc_thermal *priv, int channel,
				long *val, bool *valid)
{
	const struct rivos_pwc_thermal_chan *chan = &priv->chans[channel];
	u32 reg = rivos_pwc_thermal_readl(priv, chan->reg);

	*valid = !!(reg & TEMP_STATUS_VALID);

	/* hwmon expect milli-degrees */
	*val = ((reg >> chan->shift) & chan->mask) * 1000L;

	return reg;
}

static u8 get_thres_offset(int thres_id)
{
	return thres_id ? TEMP_THRES_OFFSET : 0;
}

static int rivos_pwc_thermal_set_thres_up(struct rivos_pwc_thermal *priv,
					   int thres_id, long millidegrees)
{
	long degrees;
	u32 reg, mask;
	u8 offset = get_thres_offset(thres_id);

	degrees = millidegrees / 1000;
	if (degrees < S8_MIN || degrees > S8_MAX)
		return -EINVAL;

	reg = FIELD_PREP(TEMP_THRES_INT_UP, degrees) << offset;
	reg |= (TEMP_THRES_INT_IE | TEMP_THRES_INT_EN) << offset;
	mask = (TEMP_THRES_INT_IE | TEMP_THRES_INT_EN | TEMP_THRES_INT_UP) <<
	       offset;

	mutex_lock(&priv->lock);
	rivos_pwc_thermal_rmw(priv, TEMP_THRES_INT_LO_OFFSET, mask, reg);
	mutex_unlock(&priv->lock);

	return 0;
}

static void rivos_pwc_thermal_get_thres_up(struct rivos_pwc_thermal *priv,
					     int thres_id, long *millidegrees)
{
	u32 reg = rivos_pwc_thermal_readl(priv, TEMP_THRES_INT_LO_OFFSET);
	u8 offset = get_thres_offset(thres_id);

	*millidegrees = FIELD_GET(TEMP_THRES_INT_UP, reg >> offset) * 1000;
}

static void rivos_pwc_thermal_get_thres_down(struct rivos_pwc_thermal *priv,
					     int thres_id,
					     long *millidegrees)
{
	u32 reg = rivos_pwc_thermal_readl(priv, TEMP_THRES_INT_LO_OFFSET);
	u8 offset = get_thres_offset(thres_id);
	u8 delta;

	reg >>= offset;
	delta = FIELD_GET(TEMP_THRES_INT_DELTA_DOWN, reg);
	*millidegrees = (FIELD_GET(TEMP_THRES_INT_UP, reg) - delta) * 1000;
}

static int rivos_pwc_thermal_set_thres_down(struct rivos_pwc_thermal *priv,
					    int thres_id, long millidegrees)
{
	u8 offset = get_thres_offset(thres_id);
	u32 delta_down;
	long degrees;
	s8 thres_up;
	u32 reg;

	degrees = millidegrees / 1000;
	if (degrees < S8_MIN || degrees > S8_MAX)
		return -EINVAL;

	mutex_lock(&priv->lock);

	reg = rivos_pwc_thermal_readl(priv, TEMP_THRES_INT_LO_OFFSET);
	thres_up = FIELD_GET(TEMP_THRES_INT_UP, reg >> offset);

	/* Check that we fit in the expected delta down ranges (15°C max) */
	delta_down = thres_up - degrees;
	if (delta_down > FIELD_MAX(TEMP_THRES_INT_DELTA_DOWN)) {
		mutex_unlock(&priv->lock);
		return -EINVAL;
	}

	reg &= ~(TEMP_THRES_INT_DELTA_DOWN << offset);
	reg |= FIELD_PREP(TEMP_THRES_INT_DELTA_DOWN, delta_down) << offset;

	rivos_pwc_thermal_writel(priv, reg, TEMP_THRES_INT_LO_OFFSET);

	mutex_unlock(&priv->lock);

	return 0;
}

static int rivos_pwc_thermal_read(struct device *dev, enum hwmon_sensor_types type,
			     u32 attr, int channel, long *val)
{
	struct rivos_pwc_thermal *priv = dev_get_drvdata(dev);
	bool valid;
	int ret;
	u32 reg;

	ret = rivos_pwc_thermal_drv_op(priv, int, -EOPNOTSUPP, read, dev, type,
				       attr, channel, val);
	if (ret != -EOPNOTSUPP)
		return ret;

	switch (type) {
	case hwmon_temp:
		switch (attr) {
		case hwmon_temp_fault:
			rivos_pwc_thermal_read_temp(priv, channel, val, &valid);
			*val = !valid;
			return 0;
		case hwmon_temp_input:
			rivos_pwc_thermal_read_temp(priv, channel, val, &valid);
			return 0;
		case hwmon_temp_max:
			if (channel != 0)
				break;
			rivos_pwc_thermal_get_thres_up(priv, 0, val);
			return 0;
		case hwmon_temp_max_hyst:
			if (channel != 0)
				break;
			rivos_pwc_thermal_get_thres_down(priv, 0, val);
			return 0;
		case hwmon_temp_max_alarm:
			if (channel != 0)
				break;
			reg = rivos_pwc_thermal_readl(priv, TEMP_STATUS_OFFSET);
			*val = FIELD_GET(TEMP_STATUS_T1UL, reg);
			return 0;
		case hwmon_temp_crit:
			if (channel != 0)
				break;
			rivos_pwc_thermal_get_thres_up(priv, 1, val);
			return 0;
		case hwmon_temp_crit_hyst:
			if (channel != 0)
				break;
			rivos_pwc_thermal_get_thres_down(priv, 1, val);
			return 0;
		case hwmon_temp_crit_alarm:
			if (channel != 0)
				break;
			reg = rivos_pwc_thermal_readl(priv, TEMP_STATUS_OFFSET);
			*val = FIELD_GET(TEMP_STATUS_T2UL, reg);
			return 0;
		}
		break;
	default:
		return -EOPNOTSUPP;
	}

	return -EOPNOTSUPP;
}

static int rivos_pwc_thermal_write(struct device *dev, enum hwmon_sensor_types type,
			 u32 attr, int channel, long val)
{
	struct rivos_pwc_thermal *priv = dev_get_drvdata(dev);
	int ret;

	ret = rivos_pwc_thermal_drv_op(priv, int, -EOPNOTSUPP, write, dev, type,
				       attr, channel, val);
	if (ret != -EOPNOTSUPP)
		return ret;

	/* We only support limits writing on channel 0 */
	if (channel != 0)
		return -EOPNOTSUPP;

	switch (type) {
	case hwmon_temp:
		switch (attr) {
		case hwmon_temp_max:
			return rivos_pwc_thermal_set_thres_up(priv, 0, val);
		case hwmon_temp_max_hyst:
			return rivos_pwc_thermal_set_thres_down(priv, 0, val);
		case hwmon_temp_crit:
			return rivos_pwc_thermal_set_thres_up(priv, 1, val);
		case hwmon_temp_crit_hyst:
			return rivos_pwc_thermal_set_thres_down(priv, 1, val);
		}
		break;
	default:
		break;
	}

	return -EOPNOTSUPP;
}

static umode_t rivos_pwc_thermal_is_visible(const void *data,
					 enum hwmon_sensor_types type,
					 u32 attr, int channel)
{
	struct rivos_pwc_thermal *priv = (void *)data;
	umode_t mode;
	int ret;

	ret = rivos_pwc_thermal_drv_op(priv, int, -EOPNOTSUPP, is_visible, data, type,
				       attr, channel, &mode);
	if (ret == 0)
		return mode;

	switch (type) {
	case hwmon_temp:
		switch (attr) {
		case hwmon_temp_label:
		case hwmon_temp_input:
		case hwmon_temp_fault:
		case hwmon_temp_crit_alarm:
		case hwmon_temp_max_alarm:
			return 0444;
		case hwmon_temp_crit:
		case hwmon_temp_crit_hyst:
		case hwmon_temp_max:
		case hwmon_temp_max_hyst:
			return 0644;
		}
		break;
	default:
		break;
	}

	return 0;
}

static int rivos_pwc_thermal_read_string(struct device *dev,
				 enum hwmon_sensor_types type,
				 u32 attr, int channel, const char **str)
{
	struct rivos_pwc_thermal *priv = dev_get_drvdata(dev);
	int ret;

	ret = rivos_pwc_thermal_drv_op(priv, int, -EOPNOTSUPP, read_string, dev,
				       type, attr, channel, str);
	if (ret != -EOPNOTSUPP)
		return ret;

	switch (type) {
	case hwmon_temp:
		switch (attr) {
		case hwmon_temp_label:
			*str = priv->chans[channel].label;
			return 0;
		}
		break;
	default:
		break;
	}

	return -EOPNOTSUPP;
}

static const struct hwmon_ops rivos_pwc_thermal_ops = {
	.is_visible = rivos_pwc_thermal_is_visible,
	.read = rivos_pwc_thermal_read,
	.read_string = rivos_pwc_thermal_read_string,
	.write = rivos_pwc_thermal_write,
};

static irqreturn_t rivos_pwc_thermal_irq(int irq, void *data)
{
	struct rivos_pwc_thermal *priv = data;
	u32 sts = rivos_pwc_thermal_readl(priv, TEMP_STATUS_OFFSET);

	if (priv->drv_irq)
		sts = priv->drv_irq(priv, sts);

	if (sts & TEMP_STATUS_T1UL)
		hwmon_notify_event(priv->hwmon_dev, hwmon_temp, hwmon_temp_max_alarm, 0);
	if (sts & TEMP_STATUS_T2UL)
		hwmon_notify_event(priv->hwmon_dev, hwmon_temp, hwmon_temp_crit_alarm, 0);

	/* Clear alarms now that we went below the hysteresis */
	if (sts & TEMP_STATUS_T1DL)
		sts &= ~(TEMP_STATUS_T1UL | TEMP_STATUS_T1DL);
	if (sts & TEMP_STATUS_T2DL)
		sts &= ~(TEMP_STATUS_T2UL | TEMP_STATUS_T2DL);

	rivos_pwc_thermal_writel(priv, sts, TEMP_STATUS_OFFSET);

	rivos_pwc_irq_ack(priv->rpd_dev);

	return IRQ_HANDLED;
}

struct rivos_pwc_thermal *
rivos_pwc_thermal_get_data(struct auxiliary_device *auxdev,
			   int priv_size)
{
	struct rivos_pwc_dvsec_dev *rpd_dev = auxdev_to_rpd_dev(auxdev);
	struct device *dev = &auxdev->dev;
	struct rivos_pwc_thermal *data;

	data = devm_kzalloc(dev, sizeof(*data) + priv_size, GFP_KERNEL);
	if (!data)
		return ERR_PTR(-ENOMEM);

	if (priv_size)
		data->drv_data = data + 1;

	mutex_init(&data->lock);

	data->dev = dev;
	data->rpd_dev = rpd_dev;
	auxiliary_set_drvdata(auxdev, data);

	data->base = devm_ioremap_resource(dev, &rpd_dev->resource);
	if (IS_ERR(data->base))
		return ERR_CAST(data->base);

	return data;
}

int rivos_pwc_thermal_probe(struct rivos_pwc_thermal *data,
			    struct rivos_pwc_hwmon_init *init)
{
	struct rivos_pwc_dvsec_dev *rpd_dev = data->rpd_dev;
	const char *name;
	int ret;

	name = strchr(init->id->name, '.') + 1;
	if (!name)
		return -EINVAL;

	/* Request the IRQ once everything has been registered  */
	if (rpd_dev->irq >= 0) {
		ret = devm_request_irq(data->dev, rpd_dev->irq,
				       rivos_pwc_thermal_irq, 0, name, data);
		if (ret)
			return ret;
	}

	init->drv_data = data;
	init->dev = data->dev;
	init->ops = &rivos_pwc_thermal_ops;
	data->hwmon_dev = rivos_pwc_hwmon_probe(init);
	if (IS_ERR_OR_NULL(data->hwmon_dev))
		return PTR_ERR(data->hwmon_dev);

	return 0;
}

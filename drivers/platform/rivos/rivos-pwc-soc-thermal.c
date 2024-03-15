// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Rivos Inc.
 * Author: Clément Léger <cleger@rivosinc.com>
 */

#include <linux/bitfield.h>
#include <linux/hwmon.h>
#include <linux/io.h>
#include <linux/module.h>
#include "rivos-pwc.h"
#include "rivos-pwc-thermal.h"

#define TEMP_INFO_OFFSET			0x0
#define  TEMP_INFO_TJMAX			GENMASK(7, 0)
#define  TEMP_INFO_T_SD				GENMASK(15, 8)

/* Custom SOC fields in TEMP_STATUS register */
#define TEMP_STATUS_SOC_MAX_ABS_TEMP		GENMASK(7, 0)
#define TEMP_STATUS_PH_S			BIT(16)
#define TEMP_STATUS_TC_S			BIT(17)
#define TEMP_STATUS_VR_S			BIT(18)
#define TEMP_STATUS_EP_S			BIT(19)
#define TEMP_STATUS_PH_L			BIT(20)
#define TEMP_STATUS_TC_L			BIT(21)
#define TEMP_STATUS_VR_L			BIT(22)
#define TEMP_STATUS_EP_L			BIT(23)

#define TEMP_THRES_INT_HI_OFFSET		0x1C
#define  TEMP_THRES_INT_PH_IE			BIT(0)
#define  TEMP_THRES_INT_TC_IE			BIT(1)
#define  TEMP_THRES_INT_VR_IE			BIT(2)
#define  TEMP_THRES_INT_EP_IE			BIT(3)

/* Custom DPA fields in TEMP_STATUS register */
#define TEMP_STATUS_SOC_MAX_ABS_TEMP		GENMASK(7, 0)

struct rivos_pwc_soc_thermal {
	s8 t_sd;
	s8 tjmax;
};

static const struct rivos_pwc_thermal_chan soc_thermal_chans[] = {
	{"soc_max", TEMP_STATUS_OFFSET, TEMP_STATUS_SOC_MAX_ABS_TEMP, 0}
};

static ssize_t temp1_shutdown_show(struct device *dev,
			       struct device_attribute *devattr, char *buf)
{
	struct rivos_pwc_thermal *priv = dev_get_drvdata(dev);
	struct rivos_pwc_soc_thermal *drv = priv->drv_data;

	return sprintf(buf, "%d\n", drv->t_sd);
}
static DEVICE_ATTR_RO(temp1_shutdown);

static struct attribute *rivos_pwc_soc_thermal_attrs[] = {
	&dev_attr_temp1_shutdown.attr,
	NULL
};
ATTRIBUTE_GROUPS(rivos_pwc_soc_thermal);

static int soc_thermal_read(struct device *dev, enum hwmon_sensor_types type,
				u32 attr, int channel, long *val)
{
	struct rivos_pwc_thermal *priv = dev_get_drvdata(dev);
	struct rivos_pwc_soc_thermal *drv = priv->drv_data;
	u32 reg;

	switch (type) {
	case hwmon_temp:
		switch (attr) {
		case hwmon_temp_emergency:
			*val = drv->tjmax;
			return 0;
		case hwmon_temp_emergency_alarm:
			reg = rivos_pwc_thermal_readl(priv, TEMP_STATUS_OFFSET);
			*val = FIELD_GET(TEMP_STATUS_PH_S, reg);
			return 0;
		}
		break;
	default:
		break;
	}

	return -EOPNOTSUPP;
}

static int soc_thermal_is_visible(const void *data,
					 enum hwmon_sensor_types type,
					 u32 attr, int channel, umode_t *mode)
{

	if (type == hwmon_temp && (attr == hwmon_temp_emergency ||
				   attr == hwmon_temp_emergency_alarm)) {
		*mode = 0444;
		return 0;
	}

	return -EOPNOTSUPP;
}

static const struct rivos_pwc_hwmon_ops soc_thermal_hwmon_ops = {
	.is_visible = soc_thermal_is_visible,
	.read = soc_thermal_read,
};

static const struct hwmon_channel_info *soc_thermal_info[] = {
	HWMON_CHANNEL_INFO(temp,
			   /* SOC MAX */
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_FAULT |
			   HWMON_T_MAX | HWMON_T_MAX_HYST | HWMON_T_MAX_ALARM |
			   HWMON_T_CRIT | HWMON_T_CRIT_HYST | HWMON_T_CRIT_ALARM |
			   HWMON_T_EMERGENCY | HWMON_T_EMERGENCY_ALARM
			   ),
	NULL
};

static u32 soc_thermal_irq(struct rivos_pwc_thermal *priv, u32 status)
{
	if (status & TEMP_STATUS_PH_L) {
		hwmon_notify_event(priv->hwmon_dev, hwmon_temp,
				   hwmon_temp_emergency_alarm, 0);
		status &= ~TEMP_STATUS_PH_L;
	}

	return status;
}

static int soc_thermal_probe(struct auxiliary_device *auxdev,
			     const struct auxiliary_device_id *id)
{
	u32 reg;
	struct rivos_pwc_thermal *data;
	struct rivos_pwc_hwmon_init init;
	struct rivos_pwc_soc_thermal *drv;

	data = rivos_pwc_thermal_get_data(auxdev, sizeof(*drv));
	if (IS_ERR(data))
		return PTR_ERR(data);

	data->chans = soc_thermal_chans;
	data->drv_ops = &soc_thermal_hwmon_ops;
	data->drv_irq = &soc_thermal_irq;
	init.info = soc_thermal_info;
	init.drv_groups = rivos_pwc_soc_thermal_groups;
	init.id = id;

	drv = data->drv_data;
	reg = rivos_pwc_thermal_readl(data, TEMP_INFO_OFFSET);

	drv->t_sd = FIELD_GET(TEMP_INFO_T_SD, reg) * 1000L;
	drv->tjmax = FIELD_GET(TEMP_INFO_TJMAX, reg) * 1000L;

	reg = TEMP_THRES_INT_PH_IE;
	rivos_pwc_thermal_writel(data, reg, TEMP_THRES_INT_HI_OFFSET);

	return rivos_pwc_thermal_probe(data, &init);
}

static const struct auxiliary_device_id soc_thermal_id_table[] = {
	{ .name = "rivos_pwc.soc_thermal" },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, soc_thermal_id_table);

static struct auxiliary_driver soc_thermal_driver = {
	.id_table	= soc_thermal_id_table,
	.probe		= soc_thermal_probe,
};
module_auxiliary_driver(soc_thermal_driver);

MODULE_AUTHOR("Clément Léger <cleger@rivosinc.com>");
MODULE_DESCRIPTION("Rivos SOC thermal driver");
MODULE_LICENSE("GPL");

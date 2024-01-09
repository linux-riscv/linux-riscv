// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Rivos Inc.
 * Author: Clément Léger <cleger@rivosinc.com>
 */

#include <linux/auxiliary_bus.h>
#include <linux/bitmap.h>
#include <linux/device.h>
#include <linux/hwmon.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sysfs.h>

#include "rivos-pwc-thermal.h"

/* Custom HBM fields in TEMP_STATUS register */
#define TEMP_STATUS_HBM_MAX_ABS_TEMP		GENMASK(7, 0)

#define TEMP_STATUS_T_HI_S			BIT(20)
#define TEMP_STATUS_T_U_HI_S			BIT(21)
#define TEMP_STATUS_T_HI_L			BIT(22)
#define TEMP_STATUS_T_U_HI_L			BIT(23)

struct rivos_pwc_hbm_thermal {
	struct mutex lock;
};

static const struct rivos_pwc_thermal_chan hbm_thermal_chans[] = {
	{"hbm_max", TEMP_STATUS_OFFSET, TEMP_STATUS_HBM_MAX_ABS_TEMP, 0}
};

static const struct hwmon_channel_info *hbm_thermal_info[] = {
	HWMON_CHANNEL_INFO(temp,
			   /* HBM MAX */
			   HWMON_T_INPUT | HWMON_T_LABEL | HWMON_T_FAULT |
			   HWMON_T_MAX | HWMON_T_MAX_HYST | HWMON_T_MAX_ALARM |
			   HWMON_T_CRIT | HWMON_T_CRIT_HYST | HWMON_T_CRIT_ALARM
			   ),
	NULL
};

#define HBM_STATUS_ATTR_SHOW(__name, __bit) \
static ssize_t  __name ## _show(struct device *dev, \
				struct device_attribute *devattr, \
				char *buf) \
{ \
	struct rivos_pwc_thermal *priv = dev_get_drvdata(dev); \
	u32 reg = rivos_pwc_thermal_readl(priv, TEMP_STATUS_OFFSET); \
\
	return sprintf(buf, "%d\n", !!(reg & __bit)); \
}

#define HBM_STATUS_ATTR_STORE(__name, __bit) \
static ssize_t  __name ## _store(struct device *dev, \
			       struct device_attribute *attr, \
			       const char *buf, size_t count) \
{ \
	struct rivos_pwc_thermal *priv = dev_get_drvdata(dev); \
	struct rivos_pwc_hbm_thermal *drv = priv->drv_data; \
	u32 reg; \
	long val; \
	int ret; \
\
	ret = kstrtol(buf, 10, &val); \
	if (ret < 0) \
		return ret; \
	/* Clear only register */ \
	if (val != 0) \
		return -EINVAL; \
\
	mutex_lock(&drv->lock); \
	reg = rivos_pwc_thermal_readl(priv, TEMP_STATUS_OFFSET); \
	reg &= ~__bit; \
	rivos_pwc_thermal_writel(priv, reg, TEMP_STATUS_OFFSET); \
	mutex_unlock(&drv->lock); \
\
	return count; \
}

#define HBM_STATUS_ATTR_RO(__name, __bit) \
	HBM_STATUS_ATTR_SHOW(__name, __bit) \
	static DEVICE_ATTR_RO(__name)

#define HBM_STATUS_ATTR_RW(__name, __bit) \
	HBM_STATUS_ATTR_SHOW(__name, __bit) \
	HBM_STATUS_ATTR_STORE(__name, __bit) \
	static DEVICE_ATTR_RW(__name)

HBM_STATUS_ATTR_RO(temp1_hi_status, TEMP_STATUS_T_HI_S);
HBM_STATUS_ATTR_RO(temp1_ultra_hi_status, TEMP_STATUS_T_U_HI_S);
HBM_STATUS_ATTR_RW(temp1_hi_status_log, TEMP_STATUS_T_HI_L);
HBM_STATUS_ATTR_RW(temp1_ultra_hi_status_log, TEMP_STATUS_T_U_HI_L);

static struct attribute *rivos_pwc_hbm_thermal_attrs[] = {
	&dev_attr_temp1_hi_status.attr,
	&dev_attr_temp1_ultra_hi_status.attr,
	&dev_attr_temp1_hi_status_log.attr,
	&dev_attr_temp1_ultra_hi_status_log.attr,
	NULL
};
ATTRIBUTE_GROUPS(rivos_pwc_hbm_thermal);

static int hbm_thermal_probe(struct auxiliary_device *auxdev,
				 const struct auxiliary_device_id *id)
{
	struct rivos_pwc_thermal *data;
	struct rivos_pwc_hwmon_init init;
	struct rivos_pwc_hbm_thermal *drv;

	data = rivos_pwc_thermal_get_data(auxdev, sizeof(*drv));
	if (IS_ERR(data))
		return PTR_ERR(data);

	data->chans = hbm_thermal_chans;
	init.info = hbm_thermal_info;
	init.drv_groups = rivos_pwc_hbm_thermal_groups;
	init.id = id;

	drv = data->drv_data;
	mutex_init(&drv->lock);

	return rivos_pwc_thermal_probe(data, &init);
}

static const struct auxiliary_device_id hbm_thermal_id_table[] = {
	{ .name = "rivos_pwc.hbm_thermal" },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, hbm_thermal_id_table);

static struct auxiliary_driver hbm_thermal_driver = {
	.id_table	= hbm_thermal_id_table,
	.probe		= hbm_thermal_probe,
};
module_auxiliary_driver(hbm_thermal_driver);

MODULE_AUTHOR("Clément Léger <cleger@rivosinc.com>");
MODULE_DESCRIPTION("Rivos HBM thermal driver");
MODULE_LICENSE("GPL");

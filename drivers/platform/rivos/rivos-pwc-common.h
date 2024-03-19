/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _RIVOS_PWC_COMMON_H
#define _RIVOS_PWC_COMMON_H

#include <linux/auxiliary_bus.h>
#include <linux/device.h>
#include <linux/hwmon.h>

struct rivos_pwc_hwmon_ops {
	int (*is_visible)(const void *drvdata, enum hwmon_sensor_types type,
			      u32 attr, int channel, umode_t *mode);
	int (*read)(struct device *dev, enum hwmon_sensor_types type,
		    u32 attr, int channel, long *val);
	int (*read_string)(struct device *dev, enum hwmon_sensor_types type,
		    u32 attr, int channel, const char **str);
	int (*write)(struct device *dev, enum hwmon_sensor_types type,
		     u32 attr, int channel, long val);
};

struct rivos_pwc_hwmon_init {
	const struct attribute_group **drv_groups;
	const struct hwmon_channel_info **info;
	const struct auxiliary_device_id *id;
	const struct hwmon_ops *ops;
	struct device *dev;
	void *drv_data;
};

struct device *rivos_pwc_hwmon_probe(struct rivos_pwc_hwmon_init *init);

#endif /* _RIVOS_PWC_COMMON_H */

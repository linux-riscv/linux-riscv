/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Copyright (C) 2023 Rivos Inc.
 * Author: Clément Léger <cleger@rivosinc.com>
 */

#ifndef _RIVOS_PWC_POWER_H
#define _RIVOS_PWC_POWER_H

#include <linux/auxiliary_bus.h>
#include <linux/compiler_types.h>
#include <linux/device.h>
#include <linux/hwmon.h>
#include <linux/sysfs.h>

#include "rivos-pwc-common.h"

/* Cluster/DPA/DIMM DVSEC registers */
#define POWER_INFO_2_OFFSET			0x8
#define  POWER_INFO_2_POWER_UNIT		GENMASK(15, 0)
#define  POWER_INFO_2_ENERGY_UNIT		GENMASK(31, 16)

struct rivos_pwc_power_chan {
	const char *label;
	u32 reg_offset;
};

struct rivos_pwc_power {
	void __iomem *base;
	u16 energy_unit;
	u16 power_unit;
	struct device *dev;
	const struct rivos_pwc_hwmon_ops *drv_ops;
	const struct rivos_pwc_power_chan *chans;
	void *drv_data;
};

struct rivos_pwc_power *
rivos_pwc_power_get_data(struct auxiliary_device *auxdev, int priv_size);

int rivos_pwc_power_probe(struct rivos_pwc_power *drv_data,
			  struct rivos_pwc_hwmon_init *init);

#endif /* _RIVOS_PWC_POWER_H */

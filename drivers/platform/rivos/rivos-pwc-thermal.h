/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _RIVOS_PWC_THERMAL_H
#define _RIVOS_PWC_THERMAL_H

#include <linux/auxiliary_bus.h>
#include <linux/compiler_types.h>
#include <linux/device.h>
#include <linux/hwmon.h>
#include <linux/sysfs.h>

#include "rivos-pwc-common.h"

/* Registers definitions that are common to all thermal DVSEC functions */
#define TEMP_STATUS_OFFSET		0x10
#define  TEMP_STATUS_T1US		BIT(8)
#define  TEMP_STATUS_T1DS		BIT(9)
#define  TEMP_STATUS_T2US		BIT(10)
#define  TEMP_STATUS_T2DS		BIT(11)
#define  TEMP_STATUS_T1UL		BIT(12)
#define  TEMP_STATUS_T1DL		BIT(13)
#define  TEMP_STATUS_T2UL		BIT(14)
#define  TEMP_STATUS_T2DL		BIT(15)

#define TEMP_THRES_INT_LO_OFFSET	0x18
#define  TEMP_THRES_INT_UP		GENMASK(7, 0)
#define  TEMP_THRES_INT_DELTA_DOWN	GENMASK(11, 8)
#define  TEMP_THRES_INT_IE		BIT(12)
#define  TEMP_THRES_INT_EN		BIT(13)
#define  TEMP_THRES_OFFSET		16

#define TEMP_STATUS_VALID		BIT(31)

struct rivos_pwc_thermal_chan {
	const char *label;
	u32 reg;
	u32 mask;
	u8 shift;
};

struct rivos_pwc_thermal {
	void __iomem *base;
	struct device *dev;
	const struct rivos_pwc_hwmon_ops *drv_ops;
	u32 (*drv_irq)(struct rivos_pwc_thermal *priv, u32 status);
	struct device *hwmon_dev;
	const struct rivos_pwc_thermal_chan *chans;
	void *drv_data;
	struct mutex lock;
	int irq;
	struct rivos_pwc_dvsec_dev *rpd_dev;
};

u32 rivos_pwc_thermal_readl(struct rivos_pwc_thermal *priv, u32 offset);

void rivos_pwc_thermal_writel(struct rivos_pwc_thermal *priv, u32 val,
			      u32 offset);

u32 rivos_pwc_thermal_read_temp(struct rivos_pwc_thermal *priv, int channel,
				long *val, bool *valid);

struct rivos_pwc_thermal *
rivos_pwc_thermal_get_data(struct auxiliary_device *auxdev, int priv_size);

int rivos_pwc_thermal_probe(struct rivos_pwc_thermal *drv_data,
			    struct rivos_pwc_hwmon_init *init);

#endif /* _RIVOS_PWC_THERMAL_H */

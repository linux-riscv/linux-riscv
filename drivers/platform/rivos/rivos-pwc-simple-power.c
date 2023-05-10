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

#include "rivos-pwc-power.h"

#define DPA_HBM_ENERGY_OFFSET			0x10

#define CHIPLET_ENERGY_STATUS_OFFSET		0x20

#define ENERGY_STATUS_CLUSTER_OFFSET(__clus)	(0x28 + (__clus) * 8)

struct rivos_pwc_simple_power_data {
	const struct rivos_pwc_power_chan *chans;
	const struct hwmon_channel_info **info;
};

#define ENERGY_CHAN_CLUSTER(__clus) \
	{"cluster" __stringify(__clus), ENERGY_STATUS_CLUSTER_OFFSET(__clus)}

static const struct rivos_pwc_power_chan chiplet_power_chans[] = {
	{ "chiplet", CHIPLET_ENERGY_STATUS_OFFSET},
	ENERGY_CHAN_CLUSTER(0),
	ENERGY_CHAN_CLUSTER(1),
	ENERGY_CHAN_CLUSTER(2),
	ENERGY_CHAN_CLUSTER(3),
	ENERGY_CHAN_CLUSTER(4),
	ENERGY_CHAN_CLUSTER(5),
	ENERGY_CHAN_CLUSTER(6),
	ENERGY_CHAN_CLUSTER(7),
};

static const struct hwmon_channel_info *chiplet_power_info[] = {
	HWMON_CHANNEL_INFO(energy,
			   /* Chiplet */
			   HWMON_E_INPUT | HWMON_E_LABEL,
			   /* Clusters */
			   HWMON_E_INPUT | HWMON_E_LABEL,
			   HWMON_E_INPUT | HWMON_E_LABEL,
			   HWMON_E_INPUT | HWMON_E_LABEL,
			   HWMON_E_INPUT | HWMON_E_LABEL,
			   HWMON_E_INPUT | HWMON_E_LABEL,
			   HWMON_E_INPUT | HWMON_E_LABEL,
			   HWMON_E_INPUT | HWMON_E_LABEL,
			   HWMON_E_INPUT | HWMON_E_LABEL
			   ),
	NULL
};

static const struct rivos_pwc_power_chan dpa_hbm_power_chans[] = {
	{"energy", DPA_HBM_ENERGY_OFFSET}
};

static const struct hwmon_channel_info *dpa_hbm_power_info[] = {
	HWMON_CHANNEL_INFO(energy,
			   HWMON_E_INPUT | HWMON_E_LABEL
			   ),
	NULL
};

static int simple_power_probe(struct auxiliary_device *auxdev,
			      const struct auxiliary_device_id *id)
{
	struct rivos_pwc_simple_power_data *drv_data = (void *) id->driver_data;
	struct rivos_pwc_hwmon_init init;
	struct rivos_pwc_power *data;

	data = rivos_pwc_power_get_data(auxdev, 0);
	if (IS_ERR(data))
		return PTR_ERR(data);

	data->chans = drv_data->chans;
	init.info = drv_data->info;
	init.id = id;

	return rivos_pwc_power_probe(data, &init);
}

struct rivos_pwc_simple_power_data dpa_hbm_drv_data = {
	.chans = dpa_hbm_power_chans,
	.info = dpa_hbm_power_info,
};

struct rivos_pwc_simple_power_data chiplet_drv_data = {
	.chans = chiplet_power_chans,
	.info = chiplet_power_info,
};

static const struct auxiliary_device_id simple_power_id_table[] = {
	{
		.name = "rivos_pwc.dpa_power",
		.driver_data = (kernel_ulong_t)&dpa_hbm_drv_data
	},
	{
		.name = "rivos_pwc.hbm_power",
		.driver_data = (kernel_ulong_t)&dpa_hbm_drv_data
	},
	{
		.name = "rivos_pwc.chiplet_power",
		.driver_data = (kernel_ulong_t)&chiplet_drv_data
	},
	{}
};
MODULE_DEVICE_TABLE(auxiliary, simple_power_id_table);

static struct auxiliary_driver simple_power_driver = {
	.id_table	= simple_power_id_table,
	.probe		= simple_power_probe,
};
module_auxiliary_driver(simple_power_driver);

MODULE_AUTHOR("Clément Léger <cleger@rivosinc.com>");
MODULE_DESCRIPTION("Rivos simple power driver");
MODULE_LICENSE("GPL");

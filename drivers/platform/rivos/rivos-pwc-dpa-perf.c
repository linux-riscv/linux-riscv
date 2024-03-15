// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2023 Rivos Inc.
 * Author: Clément Léger <cleger@rivosinc.com>
 */

#include <linux/bitfield.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/sysfs.h>
#include "rivos-pwc.h"

#define INFO_LO_OFFSET		0x0
#define  INFO_LO_HIGH_PERF	GENMASK(15, 0)
#define  INFO_LO_LOW_PERF	GENMASK(31, 16)

#define CTRL_LO_OFFSET		0x8
#define  CTRL_LO_MAX_PERF	GENMASK(15, 0)
#define  CTRL_LO_MIN_PERF	GENMASK(31, 16)

#define CTRL_HI_OFFSET		0xA
#define  CTRL_HI_DES_PERF	GENMASK(15, 0)
#define  CTRL_HI_EPP		GENMASK(21, 16)

#define PERF_STATUS_LO_OFFSET	0x10
#define PERF_STATUS_D_L		BIT(0)
#define PERF_STATUS_M_L		BIT(1)
#define PERF_STATUS_T_L		BIT(16)
#define PERF_STATUS_ET_L	BIT(17)
#define PERF_STATUS_VRT_L	BIT(18)
#define PERF_STATUS_LPL_L	BIT(19)
#define PERF_STATUS_SPL_L	BIT(20)
#define PERF_STATUS_ICCL_L	BIT(21)
#define PERF_STATUS_CPPC_L	BIT(22)
#define PERF_STATUS_PQOS_L	BIT(23)
#define PERF_STATUS_VRC_L	BIT(24)

enum rivos_dpa_epp_profile {
	EPP_INDEX_PERFORMANCE,
	EPP_INDEX_EFFICIENCY,
	EPP_INDEX_BALANCED,
};

static const char * const energy_perf_strings[] = {
	[EPP_INDEX_PERFORMANCE] = "performance",
	[EPP_INDEX_EFFICIENCY] = "efficiency",
	[EPP_INDEX_BALANCED] = "balanced",
	NULL
};

static u8 epp_values[] = {
	[EPP_INDEX_PERFORMANCE] = 0x0,
	[EPP_INDEX_EFFICIENCY] = 0xFF,
	[EPP_INDEX_BALANCED] = 0x80,
};

struct rivos_dpa_perf {
	u16 cpuinfo_min_freq;
	u16 cpuinfo_max_freq;
	u16 scaling_max_freq;
	u16 scaling_min_freq;
	u16 scaling_desired_freq;
	u8 epp;
	struct mutex lock;
	void __iomem *base;
};

static ssize_t dpa_perf_show_l_attr(struct device *dev, char *buf, u32 bit)
{
	struct rivos_dpa_perf *rdp = dev_get_drvdata(dev);
	u32 reg;

	mutex_lock(&rdp->lock);
	reg = readl(rdp->base + PERF_STATUS_LO_OFFSET);
	mutex_unlock(&rdp->lock);

	return sysfs_emit(buf, "%d\n", !!(reg & bit));
}

static ssize_t dpa_perf_store_l_attr(struct device *dev, const char *buf,
				     size_t count, u32 bit)
{
	struct rivos_dpa_perf *rdp = dev_get_drvdata(dev);
	u16 value;
	u32 reg;
	int rc;

	rc = kstrtou16(buf, 0, &value);
	if (rc || value != 0)
		return -EINVAL;

	mutex_lock(&rdp->lock);
	reg = readl(rdp->base + PERF_STATUS_LO_OFFSET);
	reg &= ~bit;
	writel(reg, rdp->base + PERF_STATUS_LO_OFFSET);
	mutex_unlock(&rdp->lock);

	return count;
}

#define DPA_PERF_L_ATTR(__define, _name) \
static ssize_t _name ## _show(struct device *dev, \
			      struct device_attribute *attr, char *buf) \
{ \
	return dpa_perf_show_l_attr(dev, buf, PERF_STATUS_## __define ##_L); \
} \
static ssize_t _name ## _store(struct device *dev, \
			       struct device_attribute *attr, const char *buf, \
			       size_t count) \
{ \
	return dpa_perf_store_l_attr(dev, buf, count, \
				     PERF_STATUS_## __define ##_L); \
} \
static DEVICE_ATTR_RW(_name);

#define DPA_PERF_SHOW(_name) \
static ssize_t _name ## _show(struct device *dev, struct device_attribute *attr, char *buf) \
{ \
	struct rivos_dpa_perf *rdp = dev_get_drvdata(dev); \
	return sysfs_emit(buf, "%d\n", rdp->_name); \
}

static int dpa_get_epp_index(u8 epp)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(epp_values); i++) {
		if (epp_values[i] == epp)
			return i;
	}

	return -1;
}

static const char *dpa_get_epp_string(u8 epp)
{
	int epp_index = dpa_get_epp_index(epp);

	if (epp_index < 0)
		return NULL;

	return energy_perf_strings[epp_index];
}

static void dpa_perf_update_ctrl_hi(struct rivos_dpa_perf *rdp)
{

	u32 val = FIELD_PREP(CTRL_HI_DES_PERF, rdp->scaling_desired_freq) |
		  FIELD_PREP(CTRL_HI_EPP, rdp->scaling_min_freq);

	writel(val, rdp->base + CTRL_HI_OFFSET);
}

static ssize_t energy_performance_preference_store(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	struct rivos_dpa_perf *rdp = dev_get_drvdata(dev);
	char str_preference[21];
	ssize_t ret;

	ret = sscanf(buf, "%20s", str_preference);
	if (ret != 1)
		return -EINVAL;

	ret = match_string(energy_perf_strings, -1, str_preference);
	if (ret < 0)
		return -EINVAL;

	rdp->epp = epp_values[ret];

	dpa_perf_update_ctrl_hi(rdp);

	return count;
}
static ssize_t energy_performance_preference_show(struct device *dev,
						  struct device_attribute *attr,
						  char *buf)
{
	struct rivos_dpa_perf *rdp = dev_get_drvdata(dev);
	const char *str = dpa_get_epp_string(rdp->epp);

	if (!str)
		return -EINVAL;

	return sysfs_emit(buf, "%s\n", str);
}

static DEVICE_ATTR_RW(energy_performance_preference);

static ssize_t energy_performance_available_preferences_show(struct device *dev,
						  struct device_attribute *attr,
						  char *buf)
{
	int i = 0;
	int offset = 0;

	while (energy_perf_strings[i] != NULL)
		offset += sysfs_emit_at(buf, offset, "%s ", energy_perf_strings[i++]);

	sysfs_emit_at(buf, offset, "\n");

	return offset;
}
static DEVICE_ATTR_RO(energy_performance_available_preferences);

static ssize_t scaling_desired_freq_store(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	struct rivos_dpa_perf *rdp = dev_get_drvdata(dev);
	int rc;
	u16 value;

	rc = kstrtou16(buf, 0, &value);
	if (rc)
		return -EINVAL;

	if (value > rdp->cpuinfo_max_freq || value < rdp->cpuinfo_min_freq ||
	    value != 0)
		return -EINVAL;

	rdp->scaling_desired_freq = value;

	dpa_perf_update_ctrl_hi(rdp);

	return count;
}

DPA_PERF_SHOW(scaling_desired_freq);
static DEVICE_ATTR_RW(scaling_desired_freq);

static void dpa_perf_update_ctrl_lo(struct rivos_dpa_perf *rdp)
{

	u32 val = FIELD_PREP(CTRL_LO_MAX_PERF, rdp->scaling_max_freq) |
		  FIELD_PREP(CTRL_LO_MIN_PERF, rdp->scaling_min_freq);

	writel(val, rdp->base + CTRL_LO_OFFSET);
}

static ssize_t scaling_max_freq_store(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	struct rivos_dpa_perf *rdp = dev_get_drvdata(dev);
	int rc;
	u16 value;

	rc = kstrtou16(buf, 0, &value);
	if (rc)
		return -EINVAL;

	if (value > rdp->cpuinfo_max_freq)
		return -EINVAL;

	rdp->scaling_max_freq = value;

	dpa_perf_update_ctrl_lo(rdp);

	return count;
}

DPA_PERF_SHOW(scaling_max_freq);
static DEVICE_ATTR_RW(scaling_max_freq);

static ssize_t scaling_min_freq_store(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	struct rivos_dpa_perf *rdp = dev_get_drvdata(dev);
	int rc;
	u16 value;

	rc = kstrtou16(buf, 0, &value);
	if (rc)
		return -EINVAL;

	if (value < rdp->cpuinfo_min_freq)
		return -EINVAL;

	rdp->scaling_min_freq = value;

	dpa_perf_update_ctrl_lo(rdp);

	return count;
}

DPA_PERF_SHOW(scaling_min_freq);
static DEVICE_ATTR_RW(scaling_min_freq);

DPA_PERF_SHOW(cpuinfo_min_freq);
static DEVICE_ATTR_RO(cpuinfo_min_freq);

DPA_PERF_SHOW(cpuinfo_max_freq);
static DEVICE_ATTR_RO(cpuinfo_max_freq);

DPA_PERF_L_ATTR(D, desired_performance_excursion);
DPA_PERF_L_ATTR(M, minimum_performance_excursion);
DPA_PERF_L_ATTR(T, thermal_throttle_limit);
DPA_PERF_L_ATTR(ET, external_platform_hot_assertion);
DPA_PERF_L_ATTR(VRT, vr_hot_assertion);
DPA_PERF_L_ATTR(LPL, long_power_limit_excursion);
DPA_PERF_L_ATTR(SPL, short_power_limit_excursion);
DPA_PERF_L_ATTR(ICCL, icc_limit_excursion);
DPA_PERF_L_ATTR(CPPC, cppc_bounds_status);
DPA_PERF_L_ATTR(PQOS, power_qos_limit);
DPA_PERF_L_ATTR(VRC, vr_current_excursion);

static struct attribute *dpa_perf_attrs[] = {
	&dev_attr_cpuinfo_min_freq.attr,
	&dev_attr_cpuinfo_max_freq.attr,
	&dev_attr_scaling_min_freq.attr,
	&dev_attr_scaling_max_freq.attr,
	&dev_attr_scaling_desired_freq.attr,
	&dev_attr_energy_performance_preference.attr,
	&dev_attr_energy_performance_available_preferences.attr,
	&dev_attr_desired_performance_excursion.attr,
	&dev_attr_minimum_performance_excursion.attr,
	&dev_attr_thermal_throttle_limit.attr,
	&dev_attr_external_platform_hot_assertion.attr,
	&dev_attr_vr_hot_assertion.attr,
	&dev_attr_long_power_limit_excursion.attr,
	&dev_attr_short_power_limit_excursion.attr,
	&dev_attr_icc_limit_excursion.attr,
	&dev_attr_cppc_bounds_status.attr,
	&dev_attr_power_qos_limit.attr,
	&dev_attr_vr_current_excursion.attr,
	NULL
};

static const struct attribute_group dpa_perf_group = {
	.attrs = dpa_perf_attrs,
};
__ATTRIBUTE_GROUPS(dpa_perf);

static int dpa_perf_probe(struct auxiliary_device *auxdev, const struct auxiliary_device_id *id)
{
	struct rivos_pwc_dvsec_dev *rpd_dev = auxdev_to_rpd_dev(auxdev);
	struct rivos_dpa_perf *rdp;
	u64 perf_info;

	rdp = devm_kzalloc(&auxdev->dev, sizeof(*rdp), GFP_KERNEL);
	if (!rdp)
		return -ENOMEM;

	mutex_init(&rdp->lock);
	auxiliary_set_drvdata(auxdev, rdp);

	rdp->base = devm_ioremap_resource(&auxdev->dev, &rpd_dev->resource);
	if (IS_ERR(rdp->base))
		return PTR_ERR(rdp->base);

	perf_info = readl(rdp->base + INFO_LO_OFFSET);
	rdp->cpuinfo_max_freq = FIELD_GET(INFO_LO_HIGH_PERF, perf_info);
	rdp->cpuinfo_min_freq = FIELD_GET(INFO_LO_LOW_PERF, perf_info);

	return 0;
}

static const struct auxiliary_device_id dpa_perf_id_table[] = {
	{ .name = "rivos_pwc.dpa_perf" },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, dpa_perf_id_table);

static struct auxiliary_driver dpa_perf_driver = {
	.driver = {
		.dev_groups = dpa_perf_groups,
	},
	.id_table	= dpa_perf_id_table,
	.probe		= dpa_perf_probe,
};
module_auxiliary_driver(dpa_perf_driver);

MODULE_AUTHOR("Clément Léger <cleger@rivosinc.com>");
MODULE_DESCRIPTION("Rivos DPA Perf driver");
MODULE_LICENSE("GPL");

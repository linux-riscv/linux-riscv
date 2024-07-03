// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024 Inochi Amaoto <inochiama@outlook.com>
 *
 * Sophgo power control mcu for SG2042
 */

#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/i2c.h>
#include <linux/err.h>
#include <linux/hwmon.h>

/* fixed MCU registers */
#define REG_BOARD_TYPE				0x00
#define REG_MCU_FIRMWARE_VERSION		0x01
#define REG_PCB_VERSION				0x02
#define REG_PWR_CTRL				0x03
#define REG_SOC_TEMP				0x04
#define REG_BOARD_TEMP				0x05
#define REG_RST_COUNT				0x0a
#define REG_UPTIME				0x0b
#define REG_RESET_REASON			0x0d
#define REG_MCU_TYPE				0x18
#define REG_CRITICAL_ACTIONS			0x65
#define REG_CRITICAL_TEMP			0x66
#define REG_REPOWER_TEMP			0x67

#define CRITICAL_ACTION_REBOOT			0x1
#define CRITICAL_ACTION_POWEROFF		0x2

#define DEFAULT_REPOWER_TEMP			60
#define MAX_REPOWER_TEMP			100

#define sg2042_mcu_read_byte(client, reg)			\
	i2c_smbus_read_byte_data(client, reg)
#define sg2042_mcu_write_byte(client, reg, value)		\
	i2c_smbus_write_byte_data(client, reg, value)
#define sg2042_mcu_read_block(client, reg, array)		\
	i2c_smbus_read_i2c_block_data(client, reg, sizeof(array), array)

#define DEFINE_MCU_ATTR_READ_FUNC(_name, _type, _format)		\
	static ssize_t _name##_show(struct device *dev,			\
				    struct device_attribute *attr,	\
				    char *buf)				\
	{								\
		struct sg2042_mcu_data *mcu = dev_get_drvdata(dev);	\
		_type ret;						\
		ret = sg2042_mcu_get_##_name(mcu->client);		\
		if (ret < 0)						\
			return ret;					\
		return sprintf(buf, _format "\n", ret);			\
	}

#define DEFINE_MCU_DEBUG_ATTR_READ_FUNC(_name, _type, _format)		\
	static int _name##_show(struct seq_file *seqf,			\
				    void *unused)			\
	{								\
		struct sg2042_mcu_data *mcu = seqf->private;		\
		_type ret;						\
		ret = sg2042_mcu_get_##_name(mcu->client);		\
		if (ret < 0)						\
			return ret;					\
		seq_printf(seqf, _format "\n", ret);			\
		return 0;						\
	}

#define _CREATE_DEBUG_ENTRY(name, perm, d, data)			\
	debugfs_create_file(#name, perm, d, data, &name##_fops)

struct sg2042_mcu_board_data {
	u8		id;
	const char	*name;
};

struct sg2042_mcu_data {
	struct i2c_client			*client;
	const struct sg2042_mcu_board_data	*board_info;
	struct dentry				*debugfs;
};

static const struct sg2042_mcu_board_data sg2042_boards_data[] = {
	{
		.id = 0x80,
		.name = "SG2042 evb x8",
	},
	{
		.id = 0x81,
		.name = "SG2042R evb",
	},
	{
		.id = 0x83,
		.name = "SG2042 evb x4",
	},
	{
		.id = 0x90,
		.name = "Milk-V Pioneer",
	},
};

static const char *sg2042_mcu_reset_reason[8] = {
	"Power supply overheat",
	"Power supply failure",
	"12V power supply failure",
	"Reset commant",
	"Unknown",
	"Unknown",
	"Unknown",
	"SoC overheat",
};

static struct dentry *sgmcu_debugfs;

static int sg2042_mcu_get_board_type(struct i2c_client *client)
{
	return sg2042_mcu_read_byte(client, REG_BOARD_TYPE);
}

static int sg2042_mcu_get_firmware_version(struct i2c_client *client)
{
	return sg2042_mcu_read_byte(client, REG_MCU_FIRMWARE_VERSION);
}

static int sg2042_mcu_get_pcb_version(struct i2c_client *client)
{
	return sg2042_mcu_read_byte(client, REG_PCB_VERSION);
}

static int sg2042_mcu_get_soc_temp(struct i2c_client *client)
{
	return sg2042_mcu_read_byte(client, REG_SOC_TEMP);
}

static int sg2042_mcu_get_board_temp(struct i2c_client *client)
{
	return sg2042_mcu_read_byte(client, REG_BOARD_TEMP);
}

static int sg2042_mcu_get_reset_count(struct i2c_client *client)
{
	return sg2042_mcu_read_byte(client, REG_RST_COUNT);
}

static s32 sg2042_mcu_get_uptime(struct i2c_client *client)
{
	int ret;
	u8 time_val[2];

	ret = sg2042_mcu_read_block(client, REG_UPTIME, time_val);
	if (ret < 0)
		return ret;

	return (s32)(time_val[0]) + ((s32)(time_val[1]) << 8);
}

static int sg2042_mcu_get_reset_reason(struct i2c_client *client)
{
	return sg2042_mcu_read_byte(client, REG_RESET_REASON);
}

static int sg2042_mcu_get_mcu_type(struct i2c_client *client)
{
	return sg2042_mcu_read_byte(client, REG_MCU_TYPE);
}

static int sg2042_mcu_get_soc_crit_action(struct i2c_client *client)
{
	return sg2042_mcu_read_byte(client, REG_CRITICAL_ACTIONS);
}

static int sg2042_mcu_get_soc_crit_temp(struct i2c_client *client)
{
	return sg2042_mcu_read_byte(client, REG_CRITICAL_TEMP);
}

static int sg2042_mcu_get_soc_hyst_temp(struct i2c_client *client)
{
	return sg2042_mcu_read_byte(client, REG_REPOWER_TEMP);
}

static int sg2042_mcu_set_soc_crit_action(struct i2c_client *client,
					  u8 value)
{
	return sg2042_mcu_write_byte(client, REG_CRITICAL_ACTIONS, value);
}

static int sg2042_mcu_set_soc_crit_temp(struct i2c_client *client,
					u8 value)
{
	return sg2042_mcu_write_byte(client, REG_CRITICAL_TEMP, value);
}

static int sg2042_mcu_set_soc_hyst_temp(struct i2c_client *client,
					u8 value)
{
	return sg2042_mcu_write_byte(client, REG_REPOWER_TEMP, value);
}

DEFINE_MCU_ATTR_READ_FUNC(reset_count, int, "%d");
DEFINE_MCU_ATTR_READ_FUNC(uptime, s32, "%d");

static ssize_t reset_reason_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct sg2042_mcu_data *mcu = dev_get_drvdata(dev);
	int ret, val, i;

	val = sg2042_mcu_get_reset_reason(mcu->client);
	if (val < 0)
		return val;

	ret = sprintf(buf, "Reason: 0x%02x\n", val);

	for (i = 0; i < ARRAY_SIZE(sg2042_mcu_reset_reason); i++) {
		if (val & BIT(i))
			ret += sprintf(buf + ret, "bit %d: %s\n", i,
						  sg2042_mcu_reset_reason[i]);
	}

	return ret;
}

static ssize_t critical_action_show(struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	struct sg2042_mcu_data *mcu = dev_get_drvdata(dev);
	int ret;
	const char *action;

	ret = sg2042_mcu_get_soc_crit_action(mcu->client);
	if (ret < 0)
		return ret;

	if (ret == CRITICAL_ACTION_REBOOT)
		action = "reboot";
	else if (ret == CRITICAL_ACTION_POWEROFF)
		action = "poweroff";
	else
		action = "unknown";

	return sprintf(buf, "%s\n", action);
}

static ssize_t critical_action_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct sg2042_mcu_data *mcu = dev_get_drvdata(dev);
	int value;

	if (sysfs_streq("reboot", buf))
		value = CRITICAL_ACTION_REBOOT;
	else if (sysfs_streq("poweroff", buf))
		value = CRITICAL_ACTION_POWEROFF;
	else
		return -EINVAL;

	return sg2042_mcu_set_soc_crit_action(mcu->client, value);
}

static DEVICE_ATTR_RO(reset_count);
static DEVICE_ATTR_RO(uptime);
static DEVICE_ATTR_RO(reset_reason);
static DEVICE_ATTR_RW(critical_action);

DEFINE_MCU_DEBUG_ATTR_READ_FUNC(firmware_version, int, "0x%02x");
DEFINE_MCU_DEBUG_ATTR_READ_FUNC(pcb_version, int, "0x%02x");

static int board_type_show(struct seq_file *seqf, void *unused)
{
	struct sg2042_mcu_data *mcu = seqf->private;

	seq_printf(seqf, "%s\n", mcu->board_info->name ?: "Unknown");

	return 0;
}

static int mcu_type_show(struct seq_file *seqf, void *unused)
{
	struct sg2042_mcu_data *mcu = seqf->private;
	int ret;

	ret = sg2042_mcu_get_mcu_type(mcu->client);
	if (ret < 0)
		return ret;

	seq_puts(seqf, ret ? "GD32\n" : "STM32\n");

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(firmware_version);
DEFINE_SHOW_ATTRIBUTE(pcb_version);
DEFINE_SHOW_ATTRIBUTE(mcu_type);
DEFINE_SHOW_ATTRIBUTE(board_type);

// TODO: to debugfs

static struct attribute *sg2042_mcu_attrs[] = {
	&dev_attr_reset_count.attr,
	&dev_attr_uptime.attr,
	&dev_attr_reset_reason.attr,
	&dev_attr_critical_action.attr,
	NULL
};

static const struct attribute_group sg2042_mcu_attr_group = {
	.attrs	= sg2042_mcu_attrs,
};

static const struct hwmon_channel_info * const sg2042_mcu_info[] = {
	HWMON_CHANNEL_INFO(chip, HWMON_C_REGISTER_TZ | HWMON_C_UPDATE_INTERVAL),
	HWMON_CHANNEL_INFO(temp, HWMON_T_INPUT | HWMON_T_CRIT |
					HWMON_T_CRIT_HYST,
				 HWMON_T_INPUT),
	NULL
};

static int sg2042_mcu_read_temp(struct device *dev,
				u32 attr, int channel,
				long *val)
{
	struct sg2042_mcu_data *mcu = dev_get_drvdata(dev);
	long tmp;

	switch (attr) {
	case hwmon_temp_input:
		switch (channel) {
		case 0:
			tmp = sg2042_mcu_get_soc_temp(mcu->client);
			if (tmp < 0)
				return tmp;
			*val = tmp * 1000;
			break;
		case 1:
			tmp = sg2042_mcu_get_board_temp(mcu->client);
			if (tmp < 0)
				return tmp;
			*val = tmp * 1000;
			break;
		default:
			return -EOPNOTSUPP;
		}
		break;
	case hwmon_temp_crit:
		if (channel)
			return -EOPNOTSUPP;

		tmp = sg2042_mcu_get_soc_crit_temp(mcu->client);
		if (tmp < 0)
			return tmp;
		*val = tmp * 1000;
		break;
	case hwmon_temp_crit_hyst:
		if (channel)
			return -EOPNOTSUPP;

		tmp = sg2042_mcu_get_soc_hyst_temp(mcu->client);
		if (tmp < 0)
			return tmp;
		*val = tmp * 1000;
		break;
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

static int sg2042_mcu_read(struct device *dev,
			   enum hwmon_sensor_types type,
			   u32 attr, int channel, long *val)
{
	switch (type) {
	case hwmon_chip:
		if (attr != hwmon_chip_update_interval)
			return -EOPNOTSUPP;
		*val = 1000;
		break;
	case hwmon_temp:
		return sg2042_mcu_read_temp(dev, attr, channel, val);
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

static int sg2042_mcu_write(struct device *dev,
			    enum hwmon_sensor_types type,
			    u32 attr, int channel, long val)
{
	struct sg2042_mcu_data *mcu = dev_get_drvdata(dev);
	u8 down_temp, repower_temp;
	int ret;

	if (type != hwmon_temp || attr != hwmon_temp_crit || !channel)
		return -EOPNOTSUPP;

	switch (attr) {
	case hwmon_temp_crit:
		ret = sg2042_mcu_get_soc_hyst_temp(mcu->client);
		if (ret < 0)
			repower_temp = DEFAULT_REPOWER_TEMP;
		else
			repower_temp = ret;

		down_temp = val / 1000;
		if (down_temp < repower_temp)
			return -EINVAL;

		return sg2042_mcu_set_soc_crit_temp(mcu->client,
						    (u8)(val / 1000));
	case hwmon_temp_crit_hyst:
		ret = sg2042_mcu_get_soc_crit_temp(mcu->client);
		if (ret < 0)
			return -ENODEV;

		down_temp = ret;
		repower_temp = val / 1000;
		if (down_temp < repower_temp)
			return -EINVAL;

		return sg2042_mcu_set_soc_hyst_temp(mcu->client,
						    (u8)(val / 1000));
	default:
		return -EOPNOTSUPP;
	}
}

static umode_t sg2042_mcu_is_visible(const void *_data,
				     enum hwmon_sensor_types type,
				     u32 attr, int channel)
{
	switch (type) {
	case hwmon_chip:
		if (attr == hwmon_chip_update_interval)
			return 0444;
		break;
	case hwmon_temp:
		switch (attr) {
		case hwmon_temp_input:
			if (channel < 2)
				return 0444;
			break;
		case hwmon_temp_crit:
		case hwmon_temp_crit_hyst:
			if (channel == 0)
				return 0664;
			break;
		default:
			return 0;
		}
		break;
	default:
		return 0;
	}
	return 0;
}

static const struct hwmon_ops sg2042_mcu_ops = {
	.is_visible = sg2042_mcu_is_visible,
	.read = sg2042_mcu_read,
	.write = sg2042_mcu_write,
};

static const struct hwmon_chip_info sg2042_mcu_chip_info = {
	.ops = &sg2042_mcu_ops,
	.info = sg2042_mcu_info,
};

static void sg2042_mcu_debugfs_init(struct sg2042_mcu_data *mcu,
				    struct device *dev)
{
	mcu->debugfs = debugfs_create_dir(dev_name(dev), sgmcu_debugfs);
	if (mcu->debugfs) {
		_CREATE_DEBUG_ENTRY(firmware_version, 0444, mcu->debugfs, mcu);
		_CREATE_DEBUG_ENTRY(pcb_version, 0444, mcu->debugfs, mcu);
		_CREATE_DEBUG_ENTRY(mcu_type, 0444, mcu->debugfs, mcu);
		_CREATE_DEBUG_ENTRY(board_type, 0444, mcu->debugfs, mcu);
	}
}

static int sg2042_mcu_check_board(u8 id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sg2042_boards_data); i++) {
		if (sg2042_boards_data[i].id == id)
			return i;
	}

	return -ENODEV;
}

static int sg2042_mcu_i2c_probe(struct i2c_client *client)
{
	int ret;
	struct device *dev = &client->dev;
	struct sg2042_mcu_data *mcu;
	struct device *hwmon_dev;

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_SMBUS_BYTE_DATA |
						I2C_FUNC_SMBUS_BLOCK_DATA))
		return -EIO;

	ret = sg2042_mcu_get_board_type(client);
	if (ret < 0)
		return ret;

	ret = sg2042_mcu_check_board(ret);
	if (ret < 0)
		return ret;

	mcu = devm_kmalloc(dev, sizeof(*mcu), GFP_KERNEL);
	if (!mcu)
		return -ENOMEM;

	mcu->client = client;
	mcu->board_info = &sg2042_boards_data[ret];

	ret = sysfs_create_group(&dev->kobj, &sg2042_mcu_attr_group);
	if (ret < 0)
		return ret;

	i2c_set_clientdata(client, mcu);

	hwmon_dev = devm_hwmon_device_register_with_info(dev, client->name,
							 mcu,
							 &sg2042_mcu_chip_info,
							 NULL);

	sg2042_mcu_debugfs_init(mcu, dev);

	return PTR_ERR_OR_ZERO(hwmon_dev);
}

static void sg2042_mcu_i2c_remove(struct i2c_client *client)
{
	struct device *dev = &client->dev;

	sysfs_remove_group(&dev->kobj, &sg2042_mcu_attr_group);
}

static const struct i2c_device_id sg2042_mcu_id[] = {
	{ "sg2042_hwmon_mcu", 0 },
	{},
};
MODULE_DEVICE_TABLE(i2c, sg2042_mcu_id);

static const struct of_device_id sg2042_mcu_of_id[] = {
	{ .compatible = "sophgo,sg2042-hwmon-mcu" },
	{},
};
MODULE_DEVICE_TABLE(of, sg2042_mcu_of_id);

static struct i2c_driver sg2042_mcu_driver = {
	.driver = {
		.name = "sg2042-mcu",
		.of_match_table = sg2042_mcu_of_id,
	},
	.probe = sg2042_mcu_i2c_probe,
	.remove = sg2042_mcu_i2c_remove,
	.id_table = sg2042_mcu_id,
};

static int __init sg2042_mcu_init(void)
{
	sgmcu_debugfs = debugfs_create_dir("sgmcu", NULL);
	return i2c_add_driver(&sg2042_mcu_driver);
}

static void __exit sg2042_mcu_exit(void)
{
	debugfs_remove_recursive(sgmcu_debugfs);
	i2c_del_driver(&sg2042_mcu_driver);
}

module_init(sg2042_mcu_init);
module_exit(sg2042_mcu_exit);

MODULE_AUTHOR("Inochi Amaoto <inochiama@outlook.com>");
MODULE_DESCRIPTION("MCU I2C driver for SG2042 soc platform");
MODULE_LICENSE("GPL");

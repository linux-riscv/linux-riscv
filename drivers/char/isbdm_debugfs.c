/*
 * ISBDM debugfs support
 *
 * SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * 20 Jun 2023 evan@rivosinc.com
 */

#include <linux/debugfs.h>
#include <linux/pci.h>

#include "isbdmex.h"

#define ISBDM_DEBUGFS_BUFFER_SIZE 4096

/* A pointer to the ISBDM directory right off the root of debugfs. */
static struct dentry *isbdm_debugfs_dir;

static int isbdm_add_stat(char *start, int offset, const char *name, u64 value)
{
	int written;

	written = scnprintf(start + offset,
			    ISBDM_DEBUGFS_BUFFER_SIZE - offset,
			    "%s: %llu\n",
			    name,
			    value);

	return offset + written;
}

static ssize_t isbdm_debug_rxstats_read(struct file *filp, char __user *buffer,
					size_t usr_buf_len, loff_t *ppos)
{
	struct isbdm *ii = filp->private_data;
	char *mem;
	ssize_t status = 0;
	ssize_t size = 0;

	/* No partial reads */
	if (*ppos != 0)
		return 0;

	mutex_lock(&ii->rx_ring.lock);
	mem = kzalloc(ISBDM_DEBUGFS_BUFFER_SIZE, GFP_KERNEL);
	if (!mem) {
		status = -ENOMEM;
		goto exit;
	}

	size = isbdm_add_stat(mem, size, "rx_msg_count",
			      ii->rx_stats.msg_count);

	size = isbdm_add_stat(mem, size, "rx_byte_count",
			      ii->rx_stats.byte_count);

	size = isbdm_add_stat(mem, size, "rx_sequence_errors",
			      ii->rx_sequence_errors);

	if ((size == ISBDM_DEBUGFS_BUFFER_SIZE) || (usr_buf_len < size)) {
		status = -ENOSPC;
		goto exit;
	}

	status = simple_read_from_buffer(buffer, usr_buf_len, ppos, mem,
					 size + 1);
exit:
	mutex_unlock(&ii->rx_ring.lock);
	kfree(mem);
	return status;
}

static const char *isbdm_cmd_name[ISBDM_COMMAND_COUNT] = {
	[ISBDM_COMMAND_READ] = "read",
	[ISBDM_COMMAND_WRITE] = "write",
	[ISBDM_COMMAND_CAS] = "cas",
	[ISBDM_COMMAND_FETCH_ADD] = "add",
	[ISBDM_COMMAND_HOST_READ] = "host_read",
	[ISBDM_COMMAND_HOST_WRITE] = "host_write",
	[ISBDM_COMMAND_HOST_CAS] = "host_cas",
	[ISBDM_COMMAND_HOST_FETCH_ADD] = "host_add",
};

static ssize_t isbdm_debug_cmdstats_read(struct file *filp, char __user *buffer,
					size_t usr_buf_len, loff_t *ppos)
{
	struct isbdm *ii = filp->private_data;
	char *mem;
	ssize_t status = 0;
	ssize_t size = 0;
	int cmd;

	/* No partial reads */
	if (*ppos != 0)
		return 0;

	mutex_lock(&ii->cmd_ring.lock);
	mem = kzalloc(ISBDM_DEBUGFS_BUFFER_SIZE, GFP_KERNEL);
	if (!mem) {
		status = -ENOMEM;
		goto exit;
	}

	size = isbdm_add_stat(mem, size, "rdma_total",
			      ii->cmd_stats.rdma_total);

	size = isbdm_add_stat(mem, size, "rdma_read_bytes",
			      ii->cmd_stats.read_bytes);

	size = isbdm_add_stat(mem, size, "rdma_write_bytes",
			      ii->cmd_stats.write_bytes);

	if ((size == ISBDM_DEBUGFS_BUFFER_SIZE) || (usr_buf_len < size)) {
		status = -ENOSPC;
		goto exit;
	}

	for (cmd = ISBDM_COMMAND_READ; cmd < ISBDM_COMMAND_COUNT; cmd++) {
		const char *name = isbdm_cmd_name[cmd];
		char name_buf[20];

		if (!name)
			continue;

		scnprintf(name_buf, sizeof(name_buf), "rdma_count_%s", name);
		size = isbdm_add_stat(mem, size, name_buf,
				      ii->cmd_stats.rdma_count[cmd]);
	}

	status = simple_read_from_buffer(buffer, usr_buf_len, ppos, mem,
					 size + 1);
exit:
	mutex_unlock(&ii->cmd_ring.lock);
	kfree(mem);
	return status;
}

static ssize_t isbdm_debug_txstats_read(struct file *filp, char __user *buffer,
					size_t usr_buf_len, loff_t *ppos)
{
	struct isbdm *ii = filp->private_data;
	char *mem;
	ssize_t status = 0;
	ssize_t size = 0;

	/* No partial reads */
	if (*ppos != 0)
		return 0;

	mutex_lock(&ii->tx_ring.lock);
	mem = kzalloc(ISBDM_DEBUGFS_BUFFER_SIZE, GFP_KERNEL);
	if (!mem) {
		status = -ENOMEM;
		goto exit;
	}

	size = isbdm_add_stat(mem, size, "tx_msg_count",
			      ii->tx_stats.msg_count);

	size = isbdm_add_stat(mem, size, "tx_byte_count",
			      ii->tx_stats.byte_count);

	if ((size == ISBDM_DEBUGFS_BUFFER_SIZE) || (usr_buf_len < size)) {
		status = -ENOSPC;
		goto exit;
	}

	status = simple_read_from_buffer(buffer, usr_buf_len, ppos, mem,
					 size + 1);
exit:
	mutex_unlock(&ii->tx_ring.lock);
	kfree(mem);
	return status;
}

static ssize_t isbdm_debug_ring_size_read(struct file *filp,
					  char __user *buffer,
					  size_t usr_buf_len, loff_t *ppos)
{
	char buf[64];

	/* No partial reads */
	if (*ppos != 0)
		return 0;

	snprintf(buf, sizeof(buf), "%u", ISBDMEX_RING_SIZE);
	buf[sizeof(buf) - 1] = '\0';
	return simple_read_from_buffer(buffer, usr_buf_len, ppos, buf,
				       strlen(buf) + 1);
}

static const struct file_operations isbdm_debug_rxstats_ops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = isbdm_debug_rxstats_read,
};

static const struct file_operations isbdm_debug_txstats_ops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = isbdm_debug_txstats_read,
};

static const struct file_operations isbdm_debug_cmdstats_ops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = isbdm_debug_cmdstats_read,
};

static const struct file_operations isbdm_debug_ring_size_ops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = isbdm_debug_ring_size_read,
};

void isbdm_debugfs_init(struct isbdm *ii)
{
	struct dentry *dir;

	if (!isbdm_debugfs_dir)
		return;

	dir = debugfs_create_dir(dev_name(&ii->pdev->dev), isbdm_debugfs_dir);
	ii->debugfs_dir = dir;
	debugfs_create_file("rx_stats", S_IRUSR, dir,
			    ii, &isbdm_debug_rxstats_ops);

	debugfs_create_file("tx_stats", S_IRUSR, dir,
			    ii, &isbdm_debug_txstats_ops);

	debugfs_create_file("cmd_stats", S_IRUSR, dir,
			    ii, &isbdm_debug_cmdstats_ops);

	debugfs_create_file("ring_size", S_IRUSR, dir,
			    ii, &isbdm_debug_ring_size_ops);
}

void isbdm_debugfs_cleanup(struct isbdm *ii)
{
	debugfs_remove_recursive(ii->debugfs_dir);
}

void isbdm_init_debugfs(void)
{
	/* Create base dir in debugfs root dir */
	isbdm_debugfs_dir = debugfs_create_dir("isbdm", NULL);
}

void isbdm_remove_debugfs(void)
{
	debugfs_remove_recursive(isbdm_debugfs_dir);
}

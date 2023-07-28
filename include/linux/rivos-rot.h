/*
 * SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __RIVOS_ROT_H
#define __RIVOS_ROT_H

#include <linux/device.h>
#include <linux/rivos-doe.h>

struct rivos_rot_device;

struct rivos_rot_device *get_rivos_rot(void);
void put_rivos_rot(struct rivos_rot_device *rrs);
void rivos_rot_init_fidl_msg(struct rivos_fidl_header *hdr, u64 ordinal);
int rivos_fidl_doe(struct rivos_rot_device *rot, const void *request,
		   size_t request_sz, void *response, size_t response_sz);

#endif /* __RIVOS_ROT_H */


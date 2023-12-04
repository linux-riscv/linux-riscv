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
int rivos_rot_isbdm_update_status(struct rivos_rot_device *rot,
				  uint32_t rid,
				  enum isbdm_connection_state state);

#endif /* __RIVOS_ROT_H */


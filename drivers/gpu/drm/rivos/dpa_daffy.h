/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Rivos DPA device driver
 *
 * Copyright (C) 2022-2023 Rivos Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _DPA_DRM_DAFFY_H_
#define _DPA_DRM_DAFFY_H_

#include <linux/completion.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "duc_structs.h"

#define DPA_FW_QUEUE_SIZE 16

struct dpa_fwq {
	struct daffy_queue_desc desc;
	struct daffy_queue_pkt h_ring[DPA_FW_QUEUE_SIZE];
	struct daffy_queue_pkt d_ring[DPA_FW_QUEUE_SIZE];
};

struct dpa_fwq_waiter {
	struct daffy_queue_pkt *pkt;
	struct completion done;

	struct list_head node;
};

struct dpa_daffy {
	spinlock_t h_lock;
	wait_queue_head_t h_full_wq;
	u64 h_retire_index;
	struct list_head h_waiters;

	struct dpa_fwq *fwq;
	dma_addr_t fwq_dma_addr;
};

struct dpa_device;
struct dpa_process;

int daffy_init(struct dpa_device *dpa_dev);
void daffy_free(struct dpa_device *dpa_dev);
irqreturn_t daffy_handle_irq(int irq, void *dpa_dev);

int daffy_get_info_cmd(struct dpa_device *dpa,
		       struct drm_dpa_get_info *args);
int daffy_register_pasid_cmd(struct dpa_device *dpa, u32 pasid,
			     u32 *db_offset,
			     u32 *db_size);
int daffy_unregister_pasid_cmd(struct dpa_device *dpa, u32 pasid);
int daffy_create_queue_cmd(struct dpa_device *dpa,
			   struct dpa_process *p,
			   struct drm_dpa_create_queue *args);
int daffy_destroy_queue_cmd(struct dpa_device *dpa, u32 queue_id);
int daffy_set_signal_pages_cmd(struct dpa_device *dpa, struct dpa_process *p,
			       struct drm_dpa_set_signal_pages *args,
			       u32 num_pages);
int daffy_set_notification_queue_cmd(struct dpa_device *dpa,
				     struct dpa_process *p,
				     struct drm_dpa_set_notification_queue *args);

#endif /* _DPA_DRM_DAFFY_H_ */

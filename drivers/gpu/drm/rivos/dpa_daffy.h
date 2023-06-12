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

#include "dpa_drm.h"

// don't assume the value of PAGE_SIZE
#define DPA_FW_QUEUE_PAGE_SIZE (4 * 1024)

#define DPA_FWQ_PKT_SIZE (64)

// number of packets in a queue (fixed), 16 packets or 1Kb
#define DPA_FW_QUEUE_SIZE (DPA_FW_QUEUE_PAGE_SIZE / (DPA_FWQ_PKT_SIZE * 4))

// allocate one page with this structure at the beginning
// and send it to the DPA
struct dpa_fw_queue_desc {
	#define DPA_FW_QUEUE_MAGIC (0xF00FADE5)
	u32 magic;
#define DPA_FW_QUEUE_DESC_VERSION (0x1)
	u32 version;
	u32 h_qsize; // expected to be power of 2
	u32 d_qsize; // expected to be power of 2

	// read index points to the next packet id to read
	u64 h_read_index;
	// write index points to the next packet id to allocate
	u64 h_write_index;
	u64 d_read_index;
	u64 d_write_index;
//#define DPA_FWQ_RING_OFFSET (sizeof(struct dpa_fw_queue_pkt))
	u64 h_ring_base_ptr;
	u64 d_ring_base_ptr;
};

// DUC-to-Host MSI vectors
enum host_msi_id {
	FW_QUEUE_H2D = 0,
	FW_QUEUE_D2H = 1,
	FW_FATAL = 2,
	PERF_MON = 3,
};

// FW_QUEUE_H2D MSI vector cause offsets
enum msi_causes_fw_queue_h2d {
	PACKET_COMPLETE = 0,
	BAD_PACKET = 1,
	H2D_DMA_ERROR = 2,
};

// FW_QUEUE_D2H MSI vector cause offsets
enum msi_causes_fw_queue_d2h {
	NEW_PACKET = 0,
	OVERFLOW = 1,
	D2H_DMA_ERROR = 2,
};

enum daffy_command {
	INVALID = 1,
	GET_INFO = 2,
	CREATE_QUEUE = 3,
	MODIFY_QUEUE = 4,
	PAUSE_QUEUE = 5,
	QUIESCE_QUEUE = 6,
	DESTROY_QUEUE = 7,
	REGISTER_SIGNAL_PAGES = 8,
	UNREGISTER_SIGNAL_PAGES = 9,
	SUBSCRIBE_SIGNAL = 10,
	UPDATE_SIGNAL = 11,
};

// Unused for now
enum signal_type {
	SIGNAL = 1,
	EXCEPTION = 2,
};

enum daffy_response {
	SUCCESS = 1,
	ERROR = 2,
	ALREADY_SIGNALED = 3,
};

struct daffy_pkt_header {
	u64 id;
	u16 command;
	u16 response;
};

struct daffy_get_info_cmd {
	u32 pe_grid_dim_x;
	u32 pe_grid_dim_y;
};

struct daffy_create_queue_cmd {
	u64 ring_base_address;
	u64 write_pointer_address;
	u64 read_pointer_address;

	u32 ring_size;
	u32 queue_priority;
	u32 queue_type;
	u32 pasid;

	u32 queue_id; // from DPA
	u32 doorbell_offset; // from DPA
};

struct daffy_modify_queue_cmd {
	u32 queue_id;
	u64 ring_base_address;
	u64 write_pointer_address;
	u64 read_pointer_address;

	u32 queue_priority;
};

struct daffy_pause_queue_cmd {
	u32 queue_id;
};

struct daffy_quiesce_queue_cmd {
	u32 queue_id;
};

struct daffy_destroy_queue_cmd {
	u32 queue_id;
};

struct daffy_register_signal_pages_cmd {
	u64 base_address;
	u32 num_pages;
	u32 type;
	u32 pasid;
};

struct daffy_unregister_signal_pages_cmd {
	u32 pasid;
};

struct daffy_subscribe_signal_cmd {
	u64 signal_idx;
	u32 pasid;
};

struct daffy_update_signal_cmd {
	u64 signal_idx;
	u32 pasid;
};

// placeholder for the packet to calculate max size
struct dpa_fw_queue_pkt {
	struct daffy_pkt_header hdr;
	union {
		struct daffy_get_info_cmd dgic;
		struct daffy_create_queue_cmd dcqc;
		struct daffy_modify_queue_cmd dmqc;
		struct daffy_pause_queue_cmd dpqc;
		struct daffy_quiesce_queue_cmd dqqc;
		struct daffy_destroy_queue_cmd ddqc;
		struct daffy_register_signal_pages_cmd drspc;
		struct daffy_unregister_signal_pages_cmd durspc;
		struct daffy_subscribe_signal_cmd dssc;
		struct daffy_update_signal_cmd dusc;
		u8 buf[DPA_FWQ_PKT_SIZE - sizeof(struct daffy_pkt_header)];
	} u;
};

struct dpa_device;
struct dpa_process;

int daffy_alloc_fw_queue(struct dpa_device *dpa_dev);
void daffy_free_fw_queue(struct dpa_device *dpa_dev);
int daffy_get_info_cmd(struct dpa_device *dev,
					struct dpa_process *p,
					struct drm_dpa_get_info *args);
int daffy_create_queue_cmd(struct dpa_device *dev,
			   struct dpa_process *p,
			   struct drm_dpa_create_queue *args);
int daffy_destroy_queue_cmd(struct dpa_device *dev,
			    struct dpa_process *p, u32 queue_id);
int daffy_register_signal_pages_cmd(struct dpa_device *dpa_dev,
				struct dpa_process *p,
				struct drm_dpa_create_signal_pages *args,
				u32 num_pages);
int daffy_unregister_signal_pages_cmd(struct dpa_device *dpa_dev,
				struct dpa_process *p);
int daffy_subscribe_signal_cmd(struct dpa_device *dpa_dev,
				struct dpa_process *p, u64 event_id);



#endif /* _DPA_DRM_DAFFY_H_ */

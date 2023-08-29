/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _DPA_DAFFY_DEFS_H_
#define _DPA_DAFFY_DEFS_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define DAFFY_QUEUE_PKT_SIZE		64
#define DAFFY_QUEUE_MAGIC		0xF00FADE5
#define DAFFY_QUEUE_DESC_VERSION	0x1

/* FW queue descriptor shared with the DUC. */
struct daffy_queue_desc {
	uint32_t magic;
	uint32_t version;

	/* Must be power of 2. */
	uint32_t h_qsize;
	uint32_t d_qsize;

	/*
	 * read_index is the next packet ID to be read by the consumer,
	 * write_index is the next packet ID to be allocated by the producer.
	 */
	uint64_t h_read_index;
	uint64_t h_write_index;
	uint64_t d_read_index;
	uint64_t d_write_index;

	/* Must be 64B-aligned. */
	uint64_t h_ring_base_ptr;
	uint64_t d_ring_base_ptr;
};

/* DUC-to-host MSI vectors. */
enum {
	DPA_MSI_FW_QUEUE_H2D = 0,
	DPA_MSI_FW_QUEUE_D2H = 1,
	DPA_MSI_FW_FATAL = 2,
	DPA_MSI_PERF_MON = 3,

	DPA_NUM_MSI = 8,
};

/* DPA_MSI_FW_QUEUE_H2D causes. */
enum {
	FW_QUEUE_H2D_PACKET_COMPLETE = 0,
	FW_QUEUE_H2D_BAD_PACKET = 1,
	FW_QUEUE_H2D_DMA_ERROR = 2,
};

/* DPA_MSI_FW_QUEUE_D2H causes. */
enum {
	FW_QUEUE_D2H_NEW_PACKET = 0,
	FW_QUEUE_D2H_OVERFLOW = 1,
	FW_QUEUE_D2H_DMA_ERROR = 2,
};

enum {
	DAFFY_CMD_INVALID = 1,
	DAFFY_CMD_GET_INFO = 2,
	DAFFY_CMD_REGISTER_PASID = 3,
	DAFFY_CMD_UNREGISTER_PASID = 4,
	DAFFY_CMD_CREATE_QUEUE = 5,
	DAFFY_CMD_MODIFY_QUEUE = 6,
	DAFFY_CMD_PAUSE_QUEUE = 7,
	DAFFY_CMD_QUIESCE_QUEUE = 8,
	DAFFY_CMD_DESTROY_QUEUE = 9,
	DAFFY_CMD_SET_SIGNAL_PAGES = 10,
	DAFFY_CMD_SET_NOTIFICATION_QUEUE = 11,
	DAFFY_CMD_UPDATE_SIGNAL = 13,
};

enum {
	DAFFY_RESP_SUCCESS = 1,
	DAFFY_RESP_ERROR = 2,
};

struct daffy_pkt_header {
	uint64_t id;
	uint16_t command;
	uint16_t response;
};

struct daffy_get_info_cmd {
	/* out */
	uint64_t pe_enable_mask[2];
};

struct daffy_register_pasid_cmd {
	/* in */
	uint32_t pasid;
	/* out */
	uint32_t doorbell_offset;
	uint32_t doorbell_size;
};

struct daffy_unregister_pasid_cmd {
	uint32_t pasid;
};

struct daffy_create_queue_cmd {
	/* in */
	uint64_t ring_base_address;
	uint32_t ring_size;
	uint32_t queue_priority;
	uint32_t pasid;

	/* out */
	uint32_t queue_id;
	uint32_t doorbell_offset;
};

struct daffy_modify_queue_cmd {
	uint32_t queue_id;
	uint64_t ring_base_address;
	uint64_t write_pointer_address;
	uint64_t read_pointer_address;

	uint32_t queue_priority;
};

struct daffy_pause_queue_cmd {
	uint32_t queue_id;
};

struct daffy_quiesce_queue_cmd {
	uint32_t queue_id;
};

struct daffy_destroy_queue_cmd {
	uint32_t queue_id;
};

struct daffy_set_signal_pages_cmd {
	uint64_t base_address;
	uint32_t num_pages;
	uint32_t pasid;
};

struct daffy_set_notification_queue_cmd {
	uint64_t base_address;
	uint32_t ring_size;
	uint32_t pasid;
	uint8_t signal_id;
};

struct daffy_update_signal_cmd {
	uint64_t signal_idx;
	uint32_t pasid;
};

struct daffy_queue_pkt {
	struct daffy_pkt_header hdr;
	union {
		struct daffy_get_info_cmd dgic;
		struct daffy_register_pasid_cmd drpc;
		struct daffy_unregister_pasid_cmd durpc;
		struct daffy_create_queue_cmd dcqc;
		struct daffy_modify_queue_cmd dmqc;
		struct daffy_pause_queue_cmd dpqc;
		struct daffy_quiesce_queue_cmd dqqc;
		struct daffy_destroy_queue_cmd ddqc;
		struct daffy_set_signal_pages_cmd dsspc;
		struct daffy_set_notification_queue_cmd dsnqc;
		struct daffy_update_signal_cmd dusc;

		uint8_t buf[DAFFY_QUEUE_PKT_SIZE - sizeof(struct daffy_pkt_header)];
	} u;
};

#endif

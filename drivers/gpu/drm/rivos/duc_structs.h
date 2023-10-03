/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef _DPA_DUC_STRUCTS_H_
#define _DPA_DUC_STRUCTS_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/*
 * Work submission queue
 */

#define DUC_QUEUE_PACKET_SIZE	64

struct queue_index {
	uint64_t value;
	uint64_t reserved[7];
} __attribute__((aligned(64)));

/*
 * Work queue metadata. This structure must immediately precede the packet
 * ring in memory.
 */
struct queue_metadata {
	struct queue_index read_index;
	struct queue_index write_index;
};

struct duc_signal {
	uint64_t signal_value;
	uint64_t timestamp_us;
	uint64_t pad[6];
} __attribute__((aligned(64)));

enum duc_signal_flags {
	/* Set if the signal handle is valid. */
	DUC_SIGNAL_VALID = (1 << 0),
	/* Set if the DUC should notify the host when the DUC writes the signal. */
	DUC_SIGNAL_NOTIFY_ON_WRITE = (1 << 1),
};

struct duc_signal_handle {
	uint8_t index;
	uint8_t reserved[3];
	uint32_t flags;
};

enum duc_packet_type {
	DUC_PACKET_TYPE_INVALID = 1,
	DUC_PACKET_TYPE_KERNEL_DISPATCH = 2,
	DUC_PACKET_TYPE_BARRIER_AND = 3,
	DUC_PACKET_TYPE_MEMCPY = 6,
	DUC_PACKET_TYPE_MEMSET = 7,
	DUC_PACKET_TYPE_PREFETCH = 8,
};

struct duc_kernel_dispatch_packet {
	uint16_t header;
	uint16_t workgroup_size_x;
	uint16_t workgroup_size_y;
	uint16_t workgroup_size_z;
	uint32_t quilt_size_x;
	uint16_t quilt_size_y;
	uint16_t quilt_size_z;
	uint64_t kernel_code_entry;
	uint64_t kernarg_address;
	uint32_t private_segment_size_log2;  // This could be uint8.
	uint32_t kernarg_size;
	uint64_t private_mem_ptr;
	uint8_t num_pg_barriers;
	uint8_t num_gprs_blocks;
	uint8_t scratch_mem_allocs;
	// TODO: Add size, qlet/fifo mem and barriers and start offset when needed
	uint8_t qlet;
	uint8_t reserved[4];
	struct duc_signal_handle completion_signal;
} __attribute__((aligned(64)));

struct duc_barrier_and_packet {
	uint16_t header;
	uint16_t reserved0;
	uint32_t reserved1;
	struct duc_signal_handle dep_signal[5];
	uint64_t reserved2;
	struct duc_signal_handle completion_signal;
} __attribute__((aligned(64)));

struct duc_dma_packet {
	uint16_t header;
	uint16_t reserved0;
	uint32_t size;
	uint64_t reserved1[3];
	uint64_t src; /* Pattern for memset, address for memcpy */
	uint64_t dst;
	uint64_t reserved2;
	struct duc_signal_handle completion_signal;
} __attribute__((aligned(64)));

union duc_queue_packet {
	struct duc_kernel_dispatch_packet kernel_dispatch;
	struct duc_barrier_and_packet barrier_and;
	struct duc_dma_packet dma;
	struct {
		uint16_t header;
		uint8_t pad[DUC_QUEUE_PACKET_SIZE - sizeof(uint16_t)];
	} header;
} __attribute__((aligned(64)));

/*
 * Notification queue
 */

enum duc_notification_type {
	DUC_NOTIFICATION_BAD_PACKET = 0,
	DUC_NOTIFICATION_PE_EXCEPTION = 1,
};

enum bad_packet_error {
	PACKET_ERROR_UNKNOWN = 0,
	PACKET_ERROR_UNSUPPORTED = 1,
	PACKET_ERROR_INVALID_SIGNAL = 2,
	PACKET_ERROR_INVALID_LAUNCH_ARGS = 3,
};

struct bad_packet_notification {
	uint16_t header;
	uint16_t queue_id;
	uint16_t packet_header;
	uint16_t error;
	uint64_t packet_index;
	uint64_t reserved1[6];
};

enum pe_exception_type {
	PE_EXCEPTION_MC = (1 << 0),
	PE_EXCEPTION_LS = (1 << 1),
	PE_EXCEPTION_PEMH = (1 << 2),
	PE_EXCEPTION_MMUL = (1 << 3),
};

struct pe_exception_notification {
	uint16_t header;
	uint16_t pe_id;
	uint16_t exceptions;
	uint16_t reserved0;
	uint64_t mc_exception_info;
	uint64_t ls_exception_info;
	uint64_t pemh_exception_info;
	uint64_t mmul_exception_info;
	uint64_t reserved1[3];
};

union duc_notification {
	struct bad_packet_notification bad_packet;
	struct pe_exception_notification pe_exception;
	struct {
		uint16_t header;
		uint8_t pad[DUC_QUEUE_PACKET_SIZE - sizeof(uint16_t)];
	} header;
} __attribute__((aligned(64)));

/*
 * Daffy queue
 */

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
} __attribute__((aligned(64)));

/* DUC-to-host MSI vectors. */
enum duc_msi {
	DPA_MSI_FW_QUEUE_H2D = 0,
	DPA_MSI_FW_QUEUE_D2H = 1,
	DPA_MSI_FW_FATAL = 2,
	DPA_MSI_PERF_MON = 3,

	DPA_NUM_MSI = 8,
};

/* DPA_MSI_FW_QUEUE_H2D causes. */
enum fw_queue_h2d_cause {
	FW_QUEUE_H2D_PACKET_COMPLETE = 0,
	FW_QUEUE_H2D_BAD_PACKET = 1,
	FW_QUEUE_H2D_DMA_ERROR = 2,
};

/* DPA_MSI_FW_QUEUE_D2H causes. */
enum fw_queue_d2h_cause {
	FW_QUEUE_D2H_NEW_PACKET = 0,
	FW_QUEUE_D2H_OVERFLOW = 1,
	FW_QUEUE_D2H_DMA_ERROR = 2,
};

/* DPA_MSI_FW_FATAL causes. */
enum fw_fatal_cause {
	FW_FATAL_PANIC = 0,
	FW_FATAL_UNHANDLED_TRAP = 1,
	FW_FATAL_WATCHDOG = 2,
};

enum daffy_cmd_type {
	DAFFY_CMD_INVALID = 1,
	DAFFY_CMD_GET_INFO = 2,
	DAFFY_CMD_REGISTER_PASID = 3,
	DAFFY_CMD_UNREGISTER_PASID = 4,
	DAFFY_CMD_CREATE_QUEUE = 5,
	DAFFY_CMD_DESTROY_QUEUE = 9,
	DAFFY_CMD_SET_SIGNAL_PAGES = 10,
	DAFFY_CMD_SET_NOTIFICATION_QUEUE = 11,
	DAFFY_CMD_UPDATE_SIGNAL = 13,
	DAFFY_CMD_FLUSH_LLCH = 14,
};

enum daffy_response {
	DAFFY_RESP_SUCCESS = 1,
	DAFFY_RESP_ERROR = 2,
};

enum daffy_create_queue_flags {
	DAFFY_CREATE_QUEUE_DEBUG = (1 << 0),
};

struct daffy_pkt_header {
	uint64_t id;
	uint16_t command;
	uint16_t response;
	uint32_t reserved;
};

struct daffy_get_info_cmd {
	/* out */
	uint64_t pe_enable_mask[2];

	uint64_t reserved[4];
};

struct daffy_register_pasid_cmd {
	/* in */
	uint32_t pasid;
	/* out */
	uint32_t doorbell_offset;
	uint32_t doorbell_size;

	uint32_t reserved[9];
};

struct daffy_unregister_pasid_cmd {
	uint32_t pasid;

	uint32_t reserved[11];
};

struct daffy_create_queue_cmd {
	/* in */
	uint64_t ring_base_address;
	uint32_t ring_size;
	uint32_t flags;
	uint32_t pasid;

	/* out */
	uint32_t queue_id;
	uint32_t doorbell_offset;

	uint32_t reserved[5];
};

struct daffy_destroy_queue_cmd {
	uint32_t queue_id;

	uint32_t reserved[11];
};

struct daffy_set_signal_pages_cmd {
	uint64_t base_address;
	uint32_t num_pages;
	uint32_t pasid;

	uint64_t reserved[4];
};

struct daffy_set_notification_queue_cmd {
	uint64_t base_address;
	uint32_t ring_size;
	uint32_t pasid;
	uint8_t signal_id;

	uint8_t reserved[31];
};

struct daffy_update_signal_cmd {
	uint64_t signal_idx;
	uint32_t pasid;

	uint32_t reserved[9];
};

struct daffy_queue_pkt {
	struct daffy_pkt_header hdr;
	union {
		struct daffy_get_info_cmd get_info;
		struct daffy_register_pasid_cmd register_pasid;
		struct daffy_unregister_pasid_cmd unregister_pasid;
		struct daffy_create_queue_cmd create_queue;
		struct daffy_destroy_queue_cmd destroy_queue;
		struct daffy_set_signal_pages_cmd set_signal_pages;
		struct daffy_set_notification_queue_cmd set_notification_queue;
		struct daffy_update_signal_cmd update_signal;
	} u;
} __attribute__((aligned(64)));

#endif

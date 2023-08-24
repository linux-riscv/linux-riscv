// Copyright (c) 2022 by Rivos Inc.
// Licensed under the 3-Clause BSD License License, see LICENSE for details.
// SPDX-License-Identifier: BSD-3-Clause

#pragma once

#include <stdint.h>

// This file defines the format of DUC queue packets and signals.

typedef struct queue_index {
  uint64_t value;
  uint64_t reserved[7];
} queue_index_t;

/*
 * Work queue metadata. This structure must immediately precede the packet
 * ring in memory.
 */
typedef struct queue_metadata {
  queue_index_t read_index;
  queue_index_t write_index;
} queue_metadata_t;

typedef enum {
  /* Set if the signal handle is valid. */
  DUC_SIGNAL_VALID = (1 << 0),
  /* Set if the DUC should notify the host when the DUC writes the signal. */
  DUC_SIGNAL_NOTIFY_ON_WRITE = (1 << 1),
} duc_signal_flags_t;

typedef struct duc_signal_handle_s {
  uint8_t index;
  uint8_t reserved[3];
  uint32_t flags;
} duc_signal_handle_t;

typedef enum {
  /* Keep these in sync with HSA for now. */
  HSA_PACKET_TYPE_VENDOR_SPECIFIC = 0,
  HSA_PACKET_TYPE_INVALID = 1,
  HSA_PACKET_TYPE_KERNEL_DISPATCH = 2,
  HSA_PACKET_TYPE_BARRIER_AND = 3,
  HSA_PACKET_TYPE_AGENT_DISPATCH = 4,
  HSA_PACKET_TYPE_BARRIER_OR = 5,
  DUC_PACKET_TYPE_MEMCPY = 6,
  DUC_PACKET_TYPE_MEMSET = 7,
  DUC_PACKET_TYPE_PREFETCH = 8,
} hsa_packet_type_t;

typedef struct hsa_kernel_dispatch_packet_s {
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
  duc_signal_handle_t completion_signal;
} hsa_kernel_dispatch_packet_t;

typedef struct hsa_barrier_and_packet_s {
  uint16_t header;
  uint16_t reserved0;
  uint32_t reserved1;
  duc_signal_handle_t dep_signal[5];
  uint64_t reserved2;
  duc_signal_handle_t completion_signal;
} hsa_barrier_and_packet_t;

typedef struct duc_dma_packet_s {
  uint16_t header;
  uint16_t reserved0;
  uint32_t size;
  uint64_t reserved1[3];
  uint64_t src; /* Pattern for memset, address for memcpy */
  uint64_t dst;
  uint64_t reserved2;
  duc_signal_handle_t completion_signal;
} duc_dma_packet_t;

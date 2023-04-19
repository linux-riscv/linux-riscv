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

#ifndef __DRM_DPA_H__
#define __DRM_DPA_H__

#include <drm/drm.h>
#include <linux/ioctl.h>

#define DRM_DPA_GET_VERSION						0x1
#define DRM_DPA_CREATE_QUEUE					0x2
#define DRM_DPA_DESTROY_QUEUE					0x3
#define DRM_DPA_SET_MEMORY_POLICY				0x4
#define DRM_DPA_GET_CLOCK_COUNTERS				0x5
#define DRM_DPA_GET_PROCESS_APERTURES			0x6
#define DRM_DPA_UPDATE_QUEUE					0x7
#define DRM_DPA_DBG_REGISTER_DEPRECATED			0xd
#define DRM_DPA_DBG_UNREGISTER_DEPRECATED		0xe
#define DRM_DPA_DBG_ADDRESS_WATCH_DEPRECATED	0xf
#define DRM_DPA_DBG_WAVE_CONTROL_DEPRECATED		0x10
#define DRM_DPA_SET_SCRATCH_BACKING_VA			0x11
#define DRM_DPA_GET_TILE_CONFIG					0x12
#define DRM_DPA_SET_TRAP_HANDLER				0x13
#define DRM_DPA_GET_PROCESS_APERTURES_NEW		0x14
#define DRM_DPA_ACQUIRE_VM						0x15
#define DRM_DPA_ALLOC_MEMORY_OF_GPU				0x16
#define DRM_DPA_FREE_MEMORY_OF_GPU				0x17
#define DRM_DPA_MAP_MEMORY_TO_GPU				0x18
#define DRM_DPA_UNMAP_MEMORY_FROM_GPU			0x19
#define DRM_DPA_GET_INFO						0x1a
#define DRM_DPA_CREATE_SIGNAL_PAGES				0x1b
#define DRM_DPA_WAIT_SIGNAL						0x1c

#define NUM_OF_SUPPORTED_GPUS 7

#define DPA_IOCTL(dir, name, str) \
DRM_##dir(DRM_COMMAND_BASE + DRM_DPA_##name, struct drm_dpa_##str)

struct drm_dpa_get_version {
	__u32 major_version;
	__u32 minor_version;
};

struct drm_dpa_create_queue {
	__u64 ring_base_address;	/* to DPA */
	__u64 write_pointer_address;	/* from DPA */
	__u64 read_pointer_address;	/* from DPA */
	__u64 doorbell_offset;	/* from DPA */

	__u32 ring_size;		/* to DPA */
	__u32 gpu_id;		/* to DPA */
	__u32 queue_type;		/* to DPA */
	__u32 queue_percentage;	/* to DPA */
	__u32 queue_priority;	/* to DPA */
	__u32 queue_id;		/* from DPA */

	__u64 eop_buffer_address;	/* to DPA */
	__u64 eop_buffer_size;	/* to DPA */
	__u64 ctx_save_restore_address; /* to DPA */
	__u32 ctx_save_restore_size;	/* to DPA */
	__u32 ctl_stack_size;		/* to DPA */
};

struct drm_dpa_destroy_queue {
	__u32 queue_id;		/* to DPA */
	__u32 pad;
};

struct drm_dpa_update_queue {
	__u64 ring_base_address;	/* to DPA */

	__u32 queue_id;		/* to DPA */
	__u32 ring_size;		/* to DPA */
	__u32 queue_percentage;	/* to DPA */
	__u32 queue_priority;	/* to DPA */
};

struct drm_dpa_set_memory_policy {
	__u64 alternate_aperture_base;	/* to DPA */
	__u64 alternate_aperture_size;	/* to DPA */

	__u32 gpu_id;			/* to DPA */
	__u32 default_policy;		/* to DPA */
	__u32 alternate_policy;		/* to DPA */
	__u32 pad;
};

struct drm_dpa_get_clock_counters {
	__u64 gpu_clock_counter;	/* from DPA */
	__u64 cpu_clock_counter;	/* from DPA */
	__u64 system_clock_counter;	/* from DPA */
	__u64 system_clock_freq;	/* from DPA */

	__u32 gpu_id;		/* to DPA */
	__u32 pad;
};

struct drm_dpa_process_device_apertures {
	__u64 lds_base;		/* from DPA */
	__u64 lds_limit;		/* from DPA */
	__u64 scratch_base;		/* from DPA */
	__u64 scratch_limit;		/* from DPA */
	__u64 gpuvm_base;		/* from DPA */
	__u64 gpuvm_limit;		/* from DPA */
	__u32 gpu_id;		/* from DPA */
	__u32 pad;
};

struct drm_dpa_get_process_apertures {
	struct drm_dpa_process_device_apertures
			process_apertures[NUM_OF_SUPPORTED_GPUS];/* from DPA */

	/* from DPA, should be in the range [1 - NUM_OF_SUPPORTED_GPUS] */
	__u32 num_of_nodes;
	__u32 pad;
};

struct drm_dpa_get_process_apertures_new {
	/* User allocated. Pointer to struct DPA_process_device_apertures
	 * filled in by Kernel
	 */
	__u64 drm_dpa_process_device_apertures_ptr;
	/* to DPA - indicates amount of memory present in
	 *  DPA_process_device_apertures_ptr
	 * from DPA - Number of entries filled by DPA.
	 */
	__u32 num_of_nodes;
	__u32 pad;
};

struct drm_dpa_acquire_vm {
	__u32 drm_fd;	/* to DPA */
	__u32 gpu_id;	/* to DPA */
};

struct drm_dpa_alloc_memory_of_gpu {
	__u64 va_addr;		/* to DPA */
	__u64 size;		/* to DPA */
	__u64 handle;		/* from DPA */
	__u64 mmap_offset;	/* to DPA (userptr), from DPA (mmap offset) */
	__u32 gpu_id;		/* to DPA */
	__u32 flags;
};

/* Free memory allocated with drm_dpa_alloc_memory_of_gpu
 *
 * @handle: memory handle returned by alloc
 */
struct drm_dpa_free_memory_of_gpu {
	__u64 handle;		/* to DPA */
};

struct drm_dpa_map_memory_to_gpu {
	__u64 handle;			/* to DPA */
	__u64 device_ids_array_ptr;	/* to DPA */
	__u32 n_devices;		/* to DPA */
	__u32 n_success;		/* to/from DPA */
};

struct drm_dpa_get_info {
	__u32 pe_grid_dim_x;
	__u32 pe_grid_dim_y;
};

/* each signal takes one 64B cacheline */
struct drm_dpa_signal {
	__u64 signal_value;
	__u64 pad[7];
};

#define DPA_DRM_MAX_SIGNAL_PAGES (4)
#define DPA_DRM_SIGNALS_PER_PAGE (PAGE_SIZE / sizeof(struct drm_dpa_signal))

struct drm_dpa_create_signal_pages {
	__u64 va;	/* in to be passed to mmap, must be page aligned */
	__u32 size;	/* in multiple of page size */
	__u32 type;	/* ignored for now, eventually different types */
};

struct drm_dpa_wait_signal {
	__u64 signal_idx;	/* in signal index, offset in 64B from start */
	__u64 timeout_ns;	/* in timeout in nano seconds */
};

/* Unmap memory from one or more GPUs
 *
 * same arguments as for mapping
 */
struct drm_dpa_unmap_memory_from_gpu {
	__u64 handle;			/* to DPA */
	__u64 device_ids_array_ptr;	/* to DPA */
	__u32 n_devices;		/* to DPA */
	__u32 n_success;		/* to/from DPA */
};

#define DRM_IOCTL_DPA_GET_VERSION \
	DPA_IOCTL(IOWR, GET_VERSION, get_version)
#define DRM_IOCTL_DPA_CREATE_QUEUE \
	DPA_IOCTL(IOWR, CREATE_QUEUE, create_queue)
#define DRM_IOCTL_DPA_DESTROY_QUEUE \
	DPA_IOCTL(IOWR, DESTROY_QUEUE, destroy_queue)
#define DRM_IOCTL_DPA_SET_MEMORY_POLICY \
	DPA_IOCTL(IOWR, SET_MEMORY_POLICY, set_memory_policy)
#define DRM_IOCTL_DPA_GET_CLOCK_COUNTERS \
	DPA_IOCTL(IOWR, GET_CLOCK_COUNTERS, get_clock_counters)
#define DRM_IOCTL_DPA_GET_PROCESS_APERTURES \
	DPA_IOCTL(IOWR, GET_PROCESS_APERTURES, get_process_apertures)
#define DRM_IOCTL_DPA_UPDATE_QUEUE \
	DPA_IOCTL(IOWR, UPDATE_QUEUE, update_queue)
#define DRM_IOCTL_DPA_GET_PROCESS_APERTURES_NEW \
	DPA_IOCTL(IOWR, GET_PROCESS_APERTURES_NEW, get_process_apertures_new)
#define DRM_IOCTL_DPA_ACQUIRE_VM \
	DPA_IOCTL(IOWR, ACQUIRE_VM, acquire_vm)
#define DRM_IOCTL_DPA_ALLOC_MEMORY_OF_GPU \
	DPA_IOCTL(IOWR, ALLOC_MEMORY_OF_GPU, alloc_memory_of_gpu)
#define DRM_IOCTL_DPA_FREE_MEMORY_OF_GPU \
	DPA_IOCTL(IOWR, FREE_MEMORY_OF_GPU, free_memory_of_gpu)
#define DRM_IOCTL_DPA_MAP_MEMORY_TO_GPU \
	DPA_IOCTL(IOWR, MAP_MEMORY_TO_GPU, map_memory_to_gpu)
#define DRM_IOCTL_DPA_UNMAP_MEMORY_FROM_GPU \
	DPA_IOCTL(IOWR, UNMAP_MEMORY_FROM_GPU, unmap_memory_from_gpu)
#define DRM_IOCTL_DPA_GET_INFO \
	DPA_IOCTL(IOWR, GET_INFO, get_info)
#define DRM_IOCTL_DPA_CREATE_SIGNAL_PAGES \
	DPA_IOCTL(IOWR, CREATE_SIGNAL_PAGES, create_signal_pages)
#define DRM_IOCTL_DPA_WAIT_SIGNAL \
	DPA_IOCTL(IOWR, WAIT_SIGNAL, wait_signal)

/* Allocation flags: memory types */
#define DPA_IOC_ALLOC_MEM_FLAGS_VRAM		(1 << 0)
#define DPA_IOC_ALLOC_MEM_FLAGS_GTT		(1 << 1)
#define DPA_IOC_ALLOC_MEM_FLAGS_USERPTR		(1 << 2)
#define DPA_IOC_ALLOC_MEM_FLAGS_DOORBELL	(1 << 3)
#define DPA_IOC_ALLOC_MEM_FLAGS_MMIO_REMAP	(1 << 4)
/* Allocation flags: attributes/access options */
#define DPA_IOC_ALLOC_MEM_FLAGS_WRITABLE	(1 << 31)
#define DPA_IOC_ALLOC_MEM_FLAGS_EXECUTABLE	(1 << 30)
#define DPA_IOC_ALLOC_MEM_FLAGS_PUBLIC		(1 << 29)
#define DPA_IOC_ALLOC_MEM_FLAGS_NO_SUBSTITUTE	(1 << 28)
#define DPA_IOC_ALLOC_MEM_FLAGS_AQL_QUEUE_MEM	(1 << 27)
#define DPA_IOC_ALLOC_MEM_FLAGS_COHERENT	(1 << 26)

#define DPA_IOC_QUEUE_TYPE_COMPUTE		0x0
#define DPA_IOC_QUEUE_TYPE_SDMA			0x1
#define DPA_IOC_QUEUE_TYPE_COMPUTE_AQL		0x2
#define DPA_IOC_QUEUE_TYPE_SDMA_XGMI		0x3

#define DPA_MAX_QUEUE_PERCENTAGE	100
#define DPA_MAX_QUEUE_PRIORITY		15

#endif /* __DRM_DPA_H__ */

/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2022-2023 Rivos Inc.
 * Rivos DPA device driver
 */

#ifndef __DRM_DPA_H__
#define __DRM_DPA_H__

#include <linux/time_types.h>
#include "drm.h"

#define DRM_DPA_GET_INFO					0x1
#define DRM_DPA_CREATE_QUEUE					0x2
#define DRM_DPA_DESTROY_QUEUE					0x3
#define DRM_DPA_UPDATE_QUEUE					0x4
#define DRM_DPA_SET_SIGNAL_PAGES				0x7
#define DRM_DPA_WAIT_SIGNAL					0x8

#define DPA_IOCTL(dir, name, str) \
	DRM_##dir(DRM_COMMAND_BASE + DRM_DPA_##name, struct drm_dpa_##str)

struct drm_dpa_get_info {
	__u64 pe_enable_mask[2];
	__u32 doorbell_size;
	__u32 pad;
};

struct drm_dpa_create_queue {
	__u64 ring_base_address;	/* to DPA */
	__u64 doorbell_offset;		/* from DPA */

	__u32 ring_size;		/* to DPA */
	__u32 queue_priority;		/* to DPA */
	__u32 queue_id;			/* from DPA */
};

struct drm_dpa_destroy_queue {
	__u32 queue_id;		/* to DPA */
	__u32 pad;
};

struct drm_dpa_update_queue {
	__u64 ring_base_address;	/* to DPA */

	__u32 queue_id;			/* to DPA */
	__u32 ring_size;		/* to DPA */
	__u32 queue_percentage;		/* to DPA */
	__u32 queue_priority;		/* to DPA */
};

/*
 * Registers the virtual address range to be used to store signals shared
 * with the DPA. Both va and size must be page-aligned.
 */
struct drm_dpa_set_signal_pages {
	__u64 va;
	__u32 size;
	__u32 reserved;
};

/* The maximum number of signals that can be waited on simultaneously. */
#define DPA_DRM_MAX_WAIT_SIGNALS	4

/* Waits for any of the signals in signal_ids to be set. */
struct drm_dpa_wait_signal {
	__u8 signal_ids[DPA_DRM_MAX_WAIT_SIGNALS];
	__u32 num_signals;
	struct __kernel_timespec timeout;
};

#define DRM_IOCTL_DPA_GET_INFO \
	DPA_IOCTL(IOWR, GET_INFO, get_info)
#define DRM_IOCTL_DPA_CREATE_QUEUE \
	DPA_IOCTL(IOWR, CREATE_QUEUE, create_queue)
#define DRM_IOCTL_DPA_DESTROY_QUEUE \
	DPA_IOCTL(IOWR, DESTROY_QUEUE, destroy_queue)
#define DRM_IOCTL_DPA_UPDATE_QUEUE \
	DPA_IOCTL(IOWR, UPDATE_QUEUE, update_queue)
#define DRM_IOCTL_DPA_SET_SIGNAL_PAGES \
	DPA_IOCTL(IOWR, SET_SIGNAL_PAGES, set_signal_pages)
#define DRM_IOCTL_DPA_WAIT_SIGNAL \
	DPA_IOCTL(IOWR, WAIT_SIGNAL, wait_signal)


/* Each signal takes one 64B cacheline */
struct drm_dpa_signal {
	__u64 signal_value;
	__u64 timestamp_us;
	__u64 pad[6];
};

#define DPA_DRM_MAX_SIGNAL_PAGES (4)
#define DPA_DRM_SIGNALS_PER_PAGE (PAGE_SIZE / sizeof(struct drm_dpa_signal))
#define DPA_DRM_MAX_SIGNALS_PER_PASID (DPA_DRM_MAX_SIGNAL_PAGES * \
	DPA_DRM_SIGNALS_PER_PAGE)

#define DPA_MAX_QUEUE_PRIORITY		15

#endif /* __DRM_DPA_H__ */

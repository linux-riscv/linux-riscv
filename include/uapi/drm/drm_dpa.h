#ifndef __DRM_DPA_H__
#define __DRM_DPA_H__

#define DRM_DPA_GET_VERSION 				0x1
#define DRM_DPA_CREATE_QUEUE 				0x2
#define DRM_DPA_DESTROY_QUEUE 				0x3
#define DRM_DPA_SET_MEMORY_POLICY 			0x4
#define DRM_DPA_GET_CLOCK_COUNTERS 			0x5
#define DRM_DPA_GET_PROCESS_APERTURES 			0x6
#define DRM_DPA_UPDATE_QUEUE 				0x7
#define DRM_DPA_CREATE_EVENT 				0x8
#define DRM_DPA_DESTROY_EVENT 				0x9
#define DRM_DPA_SET_EVENT 				0xa
#define DRM_DPA_RESET_EVENT 				0xb
#define DRM_DPA_WAIT_EVENTS 				0xc
#define DRM_DPA_DBG_REGISTER_DEPRECATED 		0xd
#define DRM_DPA_DBG_UNREGISTER_DEPRECATED 		0xe
#define DRM_DPA_DBG_ADDRESS_WATCH_DEPRECATED 		0xf
#define DRM_DPA_DBG_WAVE_CONTROL_DEPRECATED 		0x10
#define DRM_DPA_SET_SCRATCH_BACKING_VA			0x11
#define DRM_DPA_GET_TILE_CONFIG 			0x12
#define DRM_DPA_SET_TRAP_HANDLER 			0x13
#define DRM_DPA_GET_PROCESS_APERTURES_NEW 		0x14
#define DRM_DPA_ACQUIRE_VM 				0x15
#define DRM_DPA_ALLOC_MEMORY_OF_GPU			0x16
#define DRM_DPA_FREE_MEMORY_OF_GPU 			0x17
#define DRM_DPA_MAP_MEMORY_TO_GPU 			0x18
#define DRM_DPA_UNMAP_MEMORY_FROM_GPU 			0x19

#define DPA_IOCTL(dir, name, str) \
DRM_##dir(DRM_COMMAND_BASE + DRM_DPA_##name, struct drm_dpa_##str)

struct drm_dpa_get_version {
	__u32 major_version;
	__u32 minor_version;
};

struct drm_dpa_create_queue {
	__u64 ring_base_address;	/* to KFD */
	__u64 write_pointer_address;	/* from KFD */
	__u64 read_pointer_address;	/* from KFD */
	__u64 doorbell_offset;	/* from KFD */

	__u32 ring_size;		/* to KFD */
	__u32 gpu_id;		/* to KFD */
	__u32 queue_type;		/* to KFD */
	__u32 queue_percentage;	/* to KFD */
	__u32 queue_priority;	/* to KFD */
	__u32 queue_id;		/* from KFD */

	__u64 eop_buffer_address;	/* to KFD */
	__u64 eop_buffer_size;	/* to KFD */
	__u64 ctx_save_restore_address; /* to KFD */
	__u32 ctx_save_restore_size;	/* to KFD */
	__u32 ctl_stack_size;		/* to KFD */
};

struct drm_dpa_destroy_queue {
	__u32 queue_id;		/* to KFD */
	__u32 pad;
};

struct drm_dpa_update_queue {
	__u64 ring_base_address;	/* to KFD */

	__u32 queue_id;		/* to KFD */
	__u32 ring_size;		/* to KFD */
	__u32 queue_percentage;	/* to KFD */
	__u32 queue_priority;	/* to KFD */
};

struct drm_dpa_set_memory_policy {
	__u64 alternate_aperture_base;	/* to KFD */
	__u64 alternate_aperture_size;	/* to KFD */

	__u32 gpu_id;			/* to KFD */
	__u32 default_policy;		/* to KFD */
	__u32 alternate_policy;		/* to KFD */
	__u32 pad;
};

struct drm_dpa_get_clock_counters {
	__u64 gpu_clock_counter;	/* from KFD */
	__u64 cpu_clock_counter;	/* from KFD */
	__u64 system_clock_counter;	/* from KFD */
	__u64 system_clock_freq;	/* from KFD */

	__u32 gpu_id;		/* to KFD */
	__u32 pad;
};

struct drm_dpa_get_process_apertures {
	struct kfd_process_device_apertures
			process_apertures[NUM_OF_SUPPORTED_GPUS];/* from KFD */

	/* from KFD, should be in the range [1 - NUM_OF_SUPPORTED_GPUS] */
	__u32 num_of_nodes;
	__u32 pad;
};

struct drm_dpa_get_process_apertures_new {
	/* User allocated. Pointer to struct kfd_process_device_apertures
	 * filled in by Kernel
	 */
	__u64 kfd_process_device_apertures_ptr;
	/* to KFD - indicates amount of memory present in
	 *  kfd_process_device_apertures_ptr
	 * from KFD - Number of entries filled by KFD.
	 */
	__u32 num_of_nodes;
	__u32 pad;
};

struct drm_dpa_create_event {
	__u64 event_page_offset;	/* from KFD */
	__u32 event_trigger_data;	/* from KFD - signal events only */
	__u32 event_type;		/* to KFD */
	__u32 auto_reset;		/* to KFD */
	__u32 node_id;		/* to KFD - only valid for certain
							event types */
	__u32 event_id;		/* from KFD */
	__u32 event_slot_index;	/* from KFD */
};

struct drm_dpa_destroy_event {
	__u32 event_id;		/* to KFD */
	__u32 pad;
};

struct drm_dpa_set_event {
	__u32 event_id;		/* to KFD */
	__u32 pad;
};

struct drm_dpa_reset_event {
	__u32 event_id;		/* to KFD */
	__u32 pad;
};

struct drm_dpa_wait_events {
	__u64 events_ptr;		/* pointed to struct
					   kfd_event_data array, to KFD */
	__u32 num_events;		/* to KFD */
	__u32 wait_for_all;		/* to KFD */
	__u32 timeout;		/* to KFD */
	__u32 wait_result;		/* from KFD */
};
struct drm_dpa_acquire_vm {
	__u32 drm_fd;	/* to KFD */
	__u32 gpu_id;	/* to KFD */
};

struct drm_dpa_alloc_memory_of_gpu {
	__u64 va_addr;		/* to KFD */
	__u64 size;		/* to KFD */
	__u64 handle;		/* from KFD */
	__u64 mmap_offset;	/* to KFD (userptr), from KFD (mmap offset) */
	__u32 gpu_id;		/* to KFD */
	__u32 flags;
};

/* Free memory allocated with drm_dpa_alloc_memory_of_gpu
 *
 * @handle: memory handle returned by alloc
 */
struct drm_dpa_free_memory_of_gpu {
	__u64 handle;		/* to KFD */
};

struct drm_dpa_map_memory_to_gpu {
	__u64 handle;			/* to KFD */
	__u64 device_ids_array_ptr;	/* to KFD */
	__u32 n_devices;		/* to KFD */
	__u32 n_success;		/* to/from KFD */
};

/* Unmap memory from one or more GPUs
 *
 * same arguments as for mapping
 */
struct drm_dpa_unmap_memory_from_gpu {
	__u64 handle;			/* to KFD */
	__u64 device_ids_array_ptr;	/* to KFD */
	__u32 n_devices;		/* to KFD */
	__u32 n_success;		/* to/from KFD */
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
#define DRM_IOCTL_DPA_CREATE_EVENT \
	DPA_IOCTL(IOWR, CREATE_EVENT, create_event)
#define DRM_IOCTL_DPA_DESTROY_EVENT \
	DPA_IOCTL(IOWR, DESTROY_EVENT, destroy_event)
#define DRM_IOCTL_DPA_SET_EVENT \
	DPA_IOCTL(IOWR, SET_EVENT, set_event)
#define DRM_IOCTL_DPA_RESET_EVENT \
	DPA_IOCTL(IOWR, RESET_EVENT, reset_event)
#define DRM_IOCTL_DPA_WAIT_EVENTS \
	DPA_IOCTL(IOWR, WAIT_EVENTS, wait_events)
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

#endif
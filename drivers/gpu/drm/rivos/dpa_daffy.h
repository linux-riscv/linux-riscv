#ifndef _DPA_KFD_DAFFY_H_
#define _DPA_KFD_DAFFY_H_

// don't assume the value of PAGE_SIZE
#define DPA_FW_QUEUE_PAGE_SIZE (4 * 1024)

#define DPA_FWQ_PKT_SIZE (64)

// number of packets in a queue (fixed), 16 packets or 1Kb
#define DPA_FW_QUEUE_SIZE (DPA_FW_QUEUE_PAGE_SIZE / ( DPA_FWQ_PKT_SIZE * 4))

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

enum daffy_command {
	INVALID = 1,
	GET_VERSION,
	CREATE_QUEUE,
	MODIFY_QUEUE,
	PAUSE_QUEUE,
	QUIESCE_QUEUE,
	DESTROY_QUEUE,
};

struct daffy_pkt_header {
	u64 id;
	u16 command;
	u16 response;
};

struct daffy_get_version_cmd {
	u32 version; // from DPA
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

// placeholder for the packet to calculate max size
struct dpa_fw_queue_pkt {
	struct daffy_pkt_header hdr;
	union {
		struct daffy_get_version_cmd dgvc;
		struct daffy_create_queue_cmd dcqc;
		struct daffy_modify_queue_cmd dmqc;
		struct daffy_pause_queue_cmd dpqc;
		struct daffy_quiesce_queue_cmd dqqc;
		struct daffy_destroy_queue_cmd ddqc;
		u8 buf[DPA_FWQ_PKT_SIZE - sizeof(struct daffy_pkt_header)];
	} u;
};

struct dpa_device;
struct dpa_kfd_process;

int daffy_alloc_fw_queue(struct dpa_device *dpa_dev);
void daffy_free_fw_queue(struct dpa_device *dpa_dev);
int daffy_get_version_cmd(struct dpa_device *dev, u32 *version);
int daffy_create_queue_cmd(struct dpa_device *dev,
			   struct dpa_kfd_process *p,
			   struct kfd_ioctl_create_queue_args *args);
int daffy_destroy_queue_cmd(struct dpa_device *dev,
			    struct dpa_kfd_process *p, u32 queue_id);



#endif

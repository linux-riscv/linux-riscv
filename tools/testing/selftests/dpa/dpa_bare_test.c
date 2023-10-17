// from selftests dir: make CROSS_COMPILE=riscv64-linux-gnu- TARGETS=dpa

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <drm/drm.h>
#include <drm_dpa.h>

#include "../../../../drivers/gpu/drm/rivos/duc_structs.h"

// Doorbells are 8B long, 64B aligned, 64 per doorbell page
struct Doorbell {
	uint64_t doorbell_write_offset;
	uint8_t padding[56];
};

#define ALIGN_UP_PGSZ(addr, page_size) (((uint64_t)(addr) +	\
					 (uint64_t)(page_size))		\
					& ~((uint64_t)(page_size)	\
					    - 1ULL))

// hack until DPA kernel driver exposes this somehow
#define DRM_DEV "/dev/dri/renderD128"
static int drm_fd;

// keep read and write indices one CL apart
#define CACHELINE_SIZE (64)

static void get_info(size_t *doorbell_size)
{
	struct drm_dpa_get_info args;
	int ret = ioctl(drm_fd, DRM_IOCTL_DPA_GET_INFO, &args);

	if (ret) {
		perror("ioctl get info");
		exit(1);
	}
	*doorbell_size = args.doorbell_size;
}

static void open_render_fd(void)
{
	drm_fd = open(DRM_DEV, O_RDWR);
	if (drm_fd < 0) {
		perror("open drm_fd");
		exit(1);
	}
}

static void alloc_aligned_host_memory(void **ptr, size_t size)
{
	size_t aligned_size = ALIGN_UP_PGSZ(size, getpagesize());
	void *ret = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (ret == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}
	*ptr = ret;
	memset(ret, 0xff, aligned_size);
}

static void alloc_gpu_memory(void **ptr, size_t size)
{
	/* TODO: Find the NUMA node of the DPA device and mbind() to it. */
	alloc_aligned_host_memory(ptr, size);
}

static struct duc_signal *get_signal_page()
{
	int ret;
	struct drm_dpa_set_signal_pages args;
	struct duc_signal *event_page;

	alloc_aligned_host_memory((void **)&event_page, getpagesize());
	memset(&args, 0, sizeof(args));
	args.va = (uint64_t)event_page;
	args.size = getpagesize();

	ret = ioctl(drm_fd, DRM_IOCTL_DPA_SET_SIGNAL_PAGES, &args);
	if (ret) {
		perror("ioctl register signal pages");
		exit(1);
	}

	return event_page;
}

static int wait_signal(uint8_t index, uint64_t timeout_sec,
		       uint64_t timeout_ns)
{
	struct drm_dpa_wait_signal args;
	int ret;

	args.signal_ids[0] = index;
	args.num_signals = 1;
	args.timeout.tv_sec = timeout_sec;
	args.timeout.tv_nsec = timeout_ns;

	ret = ioctl(drm_fd, DRM_IOCTL_DPA_WAIT_SIGNAL, &args);
	if (ret) {
		perror("wait signal ioctl");
		exit(1);
	}

	return ret;
}

static void destroy_queue(uint32_t q_id)
{
	struct drm_dpa_destroy_queue args;
	int ret;

	fprintf(stderr, "%s: id %u\n", __func__, q_id);
	args.queue_id = q_id;
	ret = ioctl(drm_fd, DRM_IOCTL_DPA_DESTROY_QUEUE, &args);
	if (ret) {
		perror("ioctl destroy queue");
		exit(1);
	}
}

static void create_queue(void *queue_base, uint32_t num_packets,
			 uint64_t *doorbell_offset, uint32_t *q_id)
{
	int ret;
	struct drm_dpa_create_queue args;

	memset(&args, 0, sizeof(args));
	args.ring_base_address = (uint64_t)queue_base;
	args.ring_size = num_packets;

	ret = ioctl(drm_fd, DRM_IOCTL_DPA_CREATE_QUEUE, &args);
	if (ret) {
		perror("ioctl create queue");
		exit(1);
	}
	fprintf(stderr, "%s: q 0x%llx id %d doorbell offset 0x%llx\n",
		__func__, args.ring_base_address, args.queue_id,
		args.doorbell_offset);
	*doorbell_offset = args.doorbell_offset;
	*q_id = args.queue_id;
}

static void print_aql_packet(struct duc_kernel_dispatch_packet *pkt)
{
	fprintf(stderr, "\nPrinting AQL packet....\n");
	fprintf(stderr, "header: 0x%x\n", pkt->header);
	fprintf(stderr, "workgroup_size_x: 0x%x\n", pkt->workgroup_size_x);
	fprintf(stderr, "workgroup_size_y: 0x%x\n", pkt->workgroup_size_y);
	fprintf(stderr, "workgroup_size_z: 0x%x\n", pkt->workgroup_size_z);
	fprintf(stderr, "quilt_size_x: 0x%x\n", pkt->quilt_size_x);
	fprintf(stderr, "quilt_size_y: 0x%x\n", pkt->quilt_size_x);
	fprintf(stderr, "quilt_size_z: 0x%x\n", pkt->quilt_size_x);
	fprintf(stderr, "kernel_code_entry: 0x%lx\n", pkt->kernel_code_entry);
	fprintf(stderr, "kernarg_address: 0x%lx\n", pkt->kernarg_address);
	fprintf(stderr, "private_segment_size_log2: 0x%x\n", pkt->private_segment_size_log2);
	fprintf(stderr, "kernarg_size: 0x%x\n", pkt->kernarg_size);
	fprintf(stderr, "private_mem_ptr: 0x%lx\n", pkt->private_mem_ptr);
	fprintf(stderr, "num_pg_barriers: 0x%x\n\n", pkt->num_pg_barriers);
	fprintf(stderr, "num_gprs_blocks: 0x%x\n\n", pkt->num_gprs_blocks);
	fprintf(stderr, "scratch_mem_allocs: 0x%x\n\n", pkt->scratch_mem_allocs);
}

#define RIG64_EXIT_INSTRUCTION (0x0000000000080073ULL)

static int init_null_kernel(void **kern_ptr, size_t *kernel_size)
{
	uint64_t *kern_data;

	*kernel_size = getpagesize();
	*kern_ptr = mmap(NULL, *kernel_size, PROT_READ | PROT_WRITE,
			 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (*kern_ptr == MAP_FAILED) {
		perror("mmap kernel");
		return 1;
	}
	kern_data = *kern_ptr;
	memset(kern_data, -1, *kernel_size);

	// just one instruction, exit
	kern_data[0] = RIG64_EXIT_INSTRUCTION;
	return 0;
}

static uint64_t *mmap_doorbell(size_t size)
{
	uint64_t *map = mmap(NULL, size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, drm_fd, 0);
	if (map == MAP_FAILED) {
		perror("mmap doorbell");
		exit(1);
	}

	return map;
}


int main(int argc, char *argv[])
{
	void *kern_ptr, *queue_ptr = NULL;
	size_t doorbell_size;
	size_t queue_packets = 64;
	size_t queue_size = sizeof(struct queue_metadata) +
		queue_packets * sizeof(union duc_queue_packet);
	size_t kernel_size = 0;

	uint64_t doorbell_offset;
	uint32_t queue_id;

	struct queue_metadata *meta = NULL;
	union duc_queue_packet *ring = NULL;

	void *doorbell_map;
	volatile struct Doorbell *doorbell;

	struct duc_kernel_dispatch_packet *aql_packet;
	struct duc_barrier_and_packet *aql_barrier_packet;

	struct duc_signal *signal_page, *signal;
	int ret = 0;

	if (init_null_kernel(&kern_ptr, &kernel_size)) {
		fprintf(stderr, "null kernel init failed\n");
		exit(1);
	}

	open_render_fd();
	get_info(&doorbell_size);
	fprintf(stderr, "Mapping doorbell page\n");
	doorbell_map = mmap_doorbell(doorbell_size);

	signal_page = get_signal_page();
	signal = &signal_page[0];

	// initialize first signal to unset
	signal->signal_value = 1;

	// allocate a user buffer for the queue
	alloc_gpu_memory(&queue_ptr, queue_size);
	fprintf(stderr, "queue_ptr: 0x%lx\n", (unsigned long)queue_ptr);

	meta = queue_ptr;
	ring = queue_ptr + sizeof(*meta);

	// set all packets to invalid -- 1
	memset(ring, 1, queue_packets * sizeof(*ring));

	meta->read_index.value = 0;
	meta->write_index.value = 0;
	create_queue(queue_ptr, queue_packets, &doorbell_offset, &queue_id);

	doorbell = (struct Doorbell *)(doorbell_map + doorbell_offset);

	fprintf(stderr, "AQL Queue create succeeded, got queue id %u offset 0x%lx\n",
		queue_id, doorbell_offset);
	if (kernel_size) {
		int wait_count = 0;

		fprintf(stderr, "kern_ptr: 0x%lx\n", (unsigned long)kern_ptr);

		// send an empty barrier packet first to test multiple packets
		aql_barrier_packet = &ring[0].barrier_and;
		memset(aql_barrier_packet, 0, sizeof(*aql_barrier_packet));
		aql_barrier_packet->header = DUC_PACKET_TYPE_BARRIER_AND;

		// this is the kernel dispatch packet
		aql_packet = &ring[1].kernel_dispatch;
		memset(aql_packet, 0, sizeof(*aql_packet));

		// Stub these fields for now
		aql_packet->header = DUC_PACKET_TYPE_KERNEL_DISPATCH;
		aql_packet->workgroup_size_x = 32;
		aql_packet->workgroup_size_y = 1;
		aql_packet->workgroup_size_z = 1;
		aql_packet->quilt_size_x = 1;
		aql_packet->quilt_size_y = 1;
		aql_packet->quilt_size_z = 1;
		aql_packet->kernel_code_entry = (uint64_t) kern_ptr;
		aql_packet->kernarg_address = 0;
		aql_packet->private_segment_size_log2 = 0; // It means no private.
		aql_packet->kernarg_size = 0;
		aql_packet->private_mem_ptr = 0;
		aql_packet->num_pg_barriers = 0;
		aql_packet->num_gprs_blocks = 1;  // Min 1 for r-mode.
		aql_packet->scratch_mem_allocs = 0;

		print_aql_packet(aql_packet);

		fprintf(stderr, "AQL packet address: 0x%lx\n", (unsigned long)aql_packet);
		fprintf(stderr, "Size of AQL packet: %lu\n", sizeof(*aql_packet));
		fprintf(stderr, "Current read index: %lu write index: %lu\n",
			meta->read_index.value, meta->write_index.value);
		meta->write_index.value += 2;
		fprintf(stderr, "Incremented write index: %lu\n",
			meta->write_index.value);
		doorbell->doorbell_write_offset = 1;
		fprintf(stderr, "Rang the doorbell\n");
		while (wait_count < 10 && meta->read_index.value == 0) {
			fprintf(stderr, "Waiting for read index to increment: %lu\n",
				meta->read_index.value);
			sleep(1);
			wait_count++;
		}
		if (meta->read_index.value > 0) {
			fprintf(stderr, "DUC read AQL Packet! read index %lu\n",
				meta->read_index.value);
		} else {
			fprintf(stderr, "Read index failed to increment, DUC is likely stuck parsing AQL packet\n");
			munmap(doorbell_map, doorbell_size);
			exit(1);
		}

		// Add another barrier packet with a signal attached so we can wait on that
		aql_barrier_packet = &ring[2].barrier_and;
		memset(aql_barrier_packet, 0, sizeof(*aql_barrier_packet));
		aql_barrier_packet->completion_signal.index = 0;
		aql_barrier_packet->completion_signal.flags =
			DUC_SIGNAL_VALID | DUC_SIGNAL_NOTIFY_ON_WRITE;
		aql_barrier_packet->header = DUC_PACKET_TYPE_BARRIER_AND;
		meta->write_index.value += 1;
		doorbell->doorbell_write_offset = 1;
		// wait 1 second
		fprintf(stderr, "waiting for signal back on barrier\n");
		if ((ret = wait_signal(0, 1, 0))) {
			fprintf(stderr, "wait for signal returned %d\n", ret);
		}
		fprintf(stderr, "signal value is now %" PRIu64 "\n",
			(uint64_t)signal->signal_value);
		// 0 means it was completed
		ret = (int)signal->signal_value;
		destroy_queue(queue_id);
	} else {
		fprintf(stderr, "No kernel to launch, exiting\n");
	}

	munmap(doorbell_map, doorbell_size);
	close(drm_fd);
	return ret;
}

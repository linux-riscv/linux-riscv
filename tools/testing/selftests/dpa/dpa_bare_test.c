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

#include "duc_packets.h"

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

static void get_info(void)
{
	struct drm_dpa_get_info args;
	int ret = ioctl(drm_fd, DRM_IOCTL_DPA_GET_INFO, &args);

	if (ret) {
		perror("ioctl get info");
		exit(1);
	}
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
	void *ret = mmap(NULL, size, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (ret == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}
	*ptr = ret;
	memset(ret, 0xff, size);
}

static void alloc_gpu_memory(void **ptr, size_t size)
{
	/* TODO: Find the NUMA node of the DPA device and mbind() to it. */
	alloc_aligned_host_memory(ptr, size);
}

static struct drm_dpa_signal *get_signal_page()
{
	int ret;
	struct drm_dpa_create_signal_pages args;
	struct drm_dpa_signal *event_page;

	alloc_aligned_host_memory((void **)&event_page, getpagesize());
	memset(&args, 0, sizeof(args));
	args.va = (uint64_t)event_page;
	args.size = getpagesize();

	ret = ioctl(drm_fd, DRM_IOCTL_DPA_CREATE_SIGNAL_PAGES, &args);
	if (ret) {
		perror("ioctl create signal pages");
		exit(1);
	}

	return event_page;
}

static int wait_signal(uint32_t index, uint32_t timeout)
{
	struct drm_dpa_wait_signal args;
	int ret;

	args.signal_idx = index;
	args.timeout_ns = timeout;

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

static void create_queue(void *ring_base, uint32_t ring_size, void *ctx_scratch,
			 uint32_t ctx_scratch_size, uint32_t stack_size,
			 uint64_t *read_ptr, uint64_t *write_ptr,
			 uint64_t *doorbell_offset,
			 uint32_t *q_id)
{
	int ret;
	struct drm_dpa_create_queue args;

	args.ring_base_address = (uint64_t)ring_base;
	args.ring_size = (uint32_t)ring_size;
	args.queue_priority = DPA_MAX_QUEUE_PRIORITY;
	args.write_pointer_address = (uint64_t)write_ptr;
	args.read_pointer_address = (uint64_t)read_ptr;

	// This is only used for some specific AMD GPU
	args.eop_buffer_address = 0;
	args.eop_buffer_size = 0;
	args.ctx_save_restore_address = (uint64_t)ctx_scratch;
	args.ctx_save_restore_size = ctx_scratch_size;
	args.ctl_stack_size = stack_size;

	ret = ioctl(drm_fd, DRM_IOCTL_DPA_CREATE_QUEUE, &args);
	if (ret) {
		perror("ioctl create queue");
		exit(1);
	}
	fprintf(stderr, "%s: q 0x%llx wptr 0x%llx rptr 0x%llx q id %d doorbell offset 0x%llx\n",
		__func__, args.ring_base_address, args.write_pointer_address, args.read_pointer_address,
		args.queue_id, args.doorbell_offset);
	*doorbell_offset = args.doorbell_offset;
	*q_id = args.queue_id;

}

static void print_aql_packet(hsa_kernel_dispatch_packet_t *pkt)
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

static uint64_t *mmap_doorbell(uint64_t doorbell_offset, size_t size)
{
	uint64_t *map = mmap(NULL, size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, drm_fd, doorbell_offset);

	if (map == MAP_FAILED) {
		perror("mmap doorbell");
		exit(1);
	}

	return map;
}


int main(int argc, char *argv[])
{
	void *kern_ptr, *rw_ptr, *queue_ptr = NULL;
	//size_t doorbell_size = getpagesize() * 2; // this AMD gpu expects 2 pages
	size_t doorbell_size = getpagesize();
	size_t queue_size = getpagesize();
	size_t aql_queue_size = getpagesize();
	size_t rwptr_size = getpagesize();
	size_t kernel_size = 0;

	uint64_t *q_read_ptr;
	uint64_t *q_write_ptr;

	uint64_t doorbell_offset;
	uint32_t queue_id;

	struct Doorbell *doorbell_map = NULL;

	hsa_kernel_dispatch_packet_t *aql_packet;
	hsa_barrier_and_packet_t *aql_barrier_packet;

	struct drm_dpa_signal *signal_page, *signal;
	int ret = 0;

	if (init_null_kernel(&kern_ptr, &kernel_size)) {
		fprintf(stderr, "null kernel init failed\n");
		exit(1);
	}

	open_render_fd();
	get_info();
	signal_page = get_signal_page();
	signal = &signal_page[0];

	// initialize first signal to unset
	signal->signal_value = 1;

	// allocate a user buffer for the queue
	alloc_gpu_memory(&queue_ptr, queue_size);
	fprintf(stderr, "queue_ptr: 0x%lx\n", (unsigned long)queue_ptr);

	alloc_gpu_memory(&rw_ptr, rwptr_size);
	fprintf(stderr, "rw_ptr: 0x%lx\n", (unsigned long)rw_ptr);

	// set read and write pointers to memory inside the queue space
	q_read_ptr = rw_ptr;
	q_write_ptr = q_read_ptr + (CACHELINE_SIZE/sizeof(uint64_t));

	// set all packets to invalid -- 1
	memset(queue_ptr, 1, aql_queue_size);

	*q_read_ptr = *q_write_ptr = 0;
	create_queue(queue_ptr, aql_queue_size, NULL, 0, 0, q_read_ptr, q_write_ptr,
			&doorbell_offset, &queue_id);

	fprintf(stderr, "Mapping doorbell page\n");
	doorbell_map = (struct Doorbell*) mmap_doorbell(doorbell_offset, doorbell_size);

	fprintf(stderr, "AQL Queue create succeeded, got queue id %u\n", queue_id);
	if (kernel_size) {
		int wait_count = 0;

		fprintf(stderr, "kern_ptr: 0x%lx\n", (unsigned long)kern_ptr);

		// send an empty barrier packet first to test multiple packets
		aql_barrier_packet = (hsa_barrier_and_packet_t *)queue_ptr;
		memset(aql_barrier_packet, 0, sizeof(*aql_barrier_packet));
		aql_barrier_packet->header = HSA_PACKET_TYPE_BARRIER_AND;

		// this is the kernel dispatch packet
		aql_packet = (hsa_kernel_dispatch_packet_t *) (queue_ptr +
							       sizeof(hsa_kernel_dispatch_packet_t));

		// Stub these fields for now
		aql_packet->header = HSA_PACKET_TYPE_KERNEL_DISPATCH;
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
		aql_packet->completion_signal.handle = 0;		
		aql_packet->num_pg_barriers = 0;
		aql_packet->num_gprs_blocks = 1;  // Min 1 for r-mode.
		aql_packet->scratch_mem_allocs = 0;

		print_aql_packet(aql_packet);

		fprintf(stderr, "AQL packet address: 0x%lx\n", (unsigned long)aql_packet);
		fprintf(stderr, "Size of AQL packet: %lu\n", sizeof(*aql_packet));
		fprintf(stderr, "Current read index: %lu write index: %lu\n",
			*q_read_ptr, *q_write_ptr);
		*q_write_ptr += 2;
		fprintf(stderr, "Incremented write index: %lu\n", *q_write_ptr);
		doorbell_map[queue_id].doorbell_write_offset = *q_write_ptr;
		fprintf(stderr, "Rang the doorbell\n");
		while ((wait_count < 10) && (*q_read_ptr == 0)) {
			fprintf(stderr, "Waiting for read index to increment: %lu\n",
				*q_read_ptr);
			sleep(1);
			wait_count++;
		}
		if (*q_read_ptr > 0) {
			fprintf(stderr, "DUC read AQL Packet! read index %lu\n", *q_read_ptr);
		} else {
			fprintf(stderr, "Read index failed to increment, DUC is likely stuck parsing AQL packet\n");
			munmap(doorbell_map, doorbell_size);
			exit(1);
		}

		// Add another barrier packet with a signal attached so we can wait on that
		aql_barrier_packet = (hsa_barrier_and_packet_t *)(queue_ptr +
								  (*q_write_ptr *
								   sizeof(*aql_barrier_packet)));
		memset(aql_barrier_packet, 0, sizeof(*aql_barrier_packet));
		aql_barrier_packet->completion_signal.handle = (uint64_t)signal;
		aql_barrier_packet->header = HSA_PACKET_TYPE_BARRIER_AND;
		*q_write_ptr += 1;
		doorbell_map[queue_id].doorbell_write_offset = *q_write_ptr;
		// wait 1 second
		fprintf(stderr, "waiting for signal back on barrier\n");
		if ((ret = wait_signal(0, 1000000000))) {
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

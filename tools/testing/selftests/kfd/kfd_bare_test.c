// gcc -O2 -Werror -o kfd_bare_test kfd_bare_test.c
// riscv64-linux-gnu-gcc-10 -O2 -Werror -o kfd_bare_test_riscv kfd_bare_test.c

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
#include <linux/kfd_ioctl.h>
#include <elf.h>

#define LITTLEENDIAN_CPU
#include "hsa.h"

#define KFD_DEV "/dev/kfd"
static int kfd;

// hack until DPA kernel driver exposes this somehow
#define DRM_DEV "/dev/dri/renderD128"
static int drm_fd;

static uint32_t gpu_id;

#define NUM_DEV_APERTURES NUM_OF_SUPPORTED_GPUS
struct kfd_process_device_apertures dev_apertures[NUM_DEV_APERTURES];

// ELF Section Header type values
#define SYMTAB 0x2
#define STRTAB 0x3

// keep read and write indices one CL apart
#define CACHELINE_SIZE (64)

// hardcoded arguments for axpy kernel
#define AXPY_X_DIM (4)
#define AXPY_Y_DIM (1)
#define AXPY_Z_DIM (1)

static void open_kfd(void)
{
	kfd = open(KFD_DEV, O_RDWR);
	if (kfd < 0) {
		perror("open");
		exit(1);
	}
}

static void get_version(void)
{
	struct kfd_ioctl_get_version_args args;
	int ret = ioctl(kfd, AMDKFD_IOC_GET_VERSION, &args);
	if (ret) {
		perror("ioctl get version");
		exit(1);
	}
	fprintf(stderr, "version: major %d minor %d\n",
		args.major_version, args.minor_version);
}

static void get_process_apertures_new(void)
{
	struct kfd_ioctl_get_process_apertures_new_args args;
	int i, ret;

	memset(&dev_apertures, 0, sizeof(dev_apertures));
	args.kfd_process_device_apertures_ptr = (uint64_t)
		&dev_apertures;
	args.num_of_nodes = NUM_DEV_APERTURES;

	ret = ioctl(kfd, AMDKFD_IOC_GET_PROCESS_APERTURES_NEW, &args);
	if (ret) {
		perror("ioctl get process apertures new");
		exit(1);
	}
	fprintf(stderr,"aperture nodes filled: %d\n", args.num_of_nodes);
	for (i = 0; i < args.num_of_nodes; i++) {
		fprintf(stderr, "aperture[%d]:\n"
			"\t lds_base 0x%" PRIx64 "\n"
			"\t lds_limit 0x%" PRIx64 "\n"
			"\t scratch_base 0x%" PRIx64 "\n"
			"\t scratch_limit 0x%" PRIx64 "\n"
			"\t gpuvm_base 0x%" PRIx64 "\n"
			"\t gpuvm_limit 0x%" PRIx64 "\n"
			"\t gpu_id 0x%" PRIx32 "\n",
			i,
			(uint64_t) dev_apertures[i].lds_base,
			(uint64_t) dev_apertures[i].lds_limit,
			(uint64_t) dev_apertures[i].scratch_base,
			(uint64_t) dev_apertures[i].scratch_limit,
			(uint64_t) dev_apertures[i].gpuvm_base,
			(uint64_t) dev_apertures[i].gpuvm_limit,
			dev_apertures[i].gpu_id);
		gpu_id = dev_apertures[i].gpu_id;
	}
}

int amdgpu_device_initialize(int fd,
			     uint32_t *major_version,
			     uint32_t *minor_version,
			     void *device_handle);

// necessary for acquire vm
static void open_render_fd(void)
{
	drm_fd = open(DRM_DEV, O_RDWR);
	// non fatal for now
	// DPA doesn't have DRM yet, so just use DPA KFD
	if (drm_fd < 0) {
		perror("open drm_fd");
		drm_fd = -1;
		drm_fd = kfd;
	}
}

// necessary for allocations to work
static void acquire_vm(void)
{
	struct kfd_ioctl_acquire_vm_args args;
	int ret;

	args.drm_fd = drm_fd;
	args.gpu_id = gpu_id;

	ret = ioctl(kfd,  AMDKFD_IOC_ACQUIRE_VM, &args);
	if (ret) {
		perror("ioctl aquire vm");
		exit(1);
	}

}

static void set_memory_policy(void)
{
	struct kfd_ioctl_set_memory_policy_args args;
	int ret;

	args.alternate_aperture_base = dev_apertures[0].gpuvm_base;
	args.alternate_aperture_size = dev_apertures[0].gpuvm_limit -
		dev_apertures[0].gpuvm_base;
	args.gpu_id = gpu_id;
	args.default_policy = KFD_IOC_CACHE_POLICY_NONCOHERENT;
	args.alternate_policy = KFD_IOC_CACHE_POLICY_COHERENT;

	ret = ioctl(kfd, AMDKFD_IOC_SET_MEMORY_POLICY, &args);
	if (ret) {
		perror("ioctl set memory policy");
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

typedef enum {
	MMIO,
	DEVICE,
	USER,
	DOORBELL,
} gpu_memory_t;

static void alloc_memory_of_gpu(void *user_ptr, size_t size, gpu_memory_t gpu_mem_type,
				uint64_t *mmap_offset, uint64_t *handle)
{
	struct kfd_ioctl_alloc_memory_of_gpu_args args;
	int ret;

	args.gpu_id = gpu_id;
	args.va_addr = (uint64_t)user_ptr;
	args.size = size;
	args.mmap_offset = (uint64_t)user_ptr;
	args.flags =
		KFD_IOC_ALLOC_MEM_FLAGS_COHERENT |
		KFD_IOC_ALLOC_MEM_FLAGS_WRITABLE |
		KFD_IOC_ALLOC_MEM_FLAGS_NO_SUBSTITUTE;

	if (gpu_mem_type == MMIO) {
		args.flags |= KFD_IOC_ALLOC_MEM_FLAGS_MMIO_REMAP;
		args.mmap_offset = 0;
	} else if (gpu_mem_type == USER) {
		args.flags |= KFD_IOC_ALLOC_MEM_FLAGS_USERPTR;
		args.flags |= KFD_IOC_ALLOC_MEM_FLAGS_EXECUTABLE; // needs to for the queue
	} else if (gpu_mem_type == DEVICE) {
		args.flags |= KFD_IOC_ALLOC_MEM_FLAGS_VRAM;
		// allow host access
		args.flags |= KFD_IOC_ALLOC_MEM_FLAGS_PUBLIC;
	} else if (gpu_mem_type == DOORBELL) {
		args.flags |= KFD_IOC_ALLOC_MEM_FLAGS_DOORBELL;
	} else {
		fprintf(stderr, "%s: Invalid memory type\n", __func__);
		exit(1);
	}

	ret = ioctl(kfd, AMDKFD_IOC_ALLOC_MEMORY_OF_GPU, &args);
	if (ret) {
		perror("ioctl alloc memory of gpu");
		exit(1);
	}

	fprintf(stderr, "%s: user_ptr 0x%" PRIx64 " mmap_offset 0x%" PRIx64
		" handle 0x%" PRIx64 " va 0x%" PRIx64 "\n",
		__func__, (uint64_t)user_ptr, (uint64_t)args.mmap_offset,
		(uint64_t)args.handle, (uint64_t)args.va_addr);
	if (mmap_offset)
		*mmap_offset = args.mmap_offset;

	*handle = args.handle;
}

#if 0
static void mmap_gpu_obj(int fd, void *user_ptr, size_t size, uint64_t mmap_offset)
{
	// this set of flags is good for anything the host needs to access
	// otherwise it would be PROT_NONE, MAP_PRIVATE | MAP_FIXED
	void *ret = mmap(user_ptr, size, PROT_READ | PROT_WRITE,
			 MAP_SHARED | MAP_FIXED, fd, mmap_offset);
	if (ret == MAP_FAILED) {
		perror("mmap gpu obj");
		exit(1);
	}
}

static void mmap_kfd(void *user_ptr, size_t size, uint64_t mmap_offset)
{
	return mmap_gpu_obj(kfd, user_ptr, size, mmap_offset);
}

// not used yet
static void mmap_dev_mem(void *user_ptr, size_t size, uint64_t mmap_offset)
{
	// device memory is mapped through the DRM fd apparently
	return mmap_gpu_obj(drm_fd, user_ptr, size, mmap_offset);
}

static void map_memory_to_gpu(uint64_t handle)
{
	struct kfd_ioctl_map_memory_to_gpu_args args;
	int ret;
	uint32_t gpu_ids[1] = { gpu_id };

	args.handle = handle;
	args.device_ids_array_ptr = (uint64_t)&gpu_ids;
	args.n_devices = 1;
	args.n_success = 0;

	ret = ioctl(kfd, AMDKFD_IOC_MAP_MEMORY_TO_GPU, &args);
	fprintf(stderr, "%s: gpu_id 0x%x args.handle = 0x%lx n_success = %d\n",
		__func__, gpu_id, (uint64_t)args.handle, args.n_success);

	if (ret) {
		perror("ioctl map memory of gpu");
		exit(1);
	}
	if (!args.n_success)
		exit(1);

}
#endif

static void parse_kernels(void *elf_base, unsigned int *kern_start_offset)
{
    if (elf_base == NULL) {
        perror("Missing ELF header");
        exit(1);
    }

    Elf64_Ehdr *e_header = (Elf64_Ehdr *) elf_base;
    Elf64_Off sh_off = e_header->e_shoff;
    uint64_t sh_num = e_header->e_shnum;
    uint64_t sh_entrysize = e_header->e_shentsize;

    Elf64_Shdr *sh_header = (Elf64_Shdr *) (elf_base + sh_off);
    Elf64_Shdr *sh_end = (Elf64_Shdr *) (elf_base + sh_off + (sh_num * sh_entrysize));
    Elf64_Off symtab_off = 0, strtab_off = 0;
    uint64_t sh_size = 0;
    if (sh_header == NULL) {
        perror("Missing section header table");
        exit(1);
    }

    while (sh_header < sh_end) {
        switch (sh_header->sh_type) {
            case SYMTAB:
                symtab_off = sh_header->sh_offset;
                sh_size = sh_header->sh_size;

            case STRTAB:
                strtab_off = sh_header->sh_offset;
        }
        sh_header++;
    }

    Elf64_Sym *sym_entry = (Elf64_Sym *) (elf_base + symtab_off);
    Elf64_Sym *symtab_end = (Elf64_Sym *) (elf_base + symtab_off + sh_size);
    if (sym_entry == NULL) {
        perror("Missing symbol table");
        exit(1);
    }

	// Extract the kernel offset
    while (sym_entry < symtab_end) {
        char *str_addr = (char *) (elf_base + strtab_off + sym_entry->st_name);
        if (!strncmp(str_addr, "_Z", 2)) {
            *kern_start_offset = sym_entry->st_value + 4096;
            return;
        }
        sym_entry++;
    }

    perror("No kernel offset found\n");
    exit(1);
}

#if 0
static void create_signal_event(uint64_t *page_offset, uint32_t *trigger_data,
				uint32_t *event_id, uint32_t *event_slot_index)
{
	int ret;
	struct kfd_ioctl_create_event_args args;

	memset(&args, 0, sizeof(args));
	args.event_type = KFD_IOC_EVENT_SIGNAL;


	ret = ioctl(kfd, AMDKFD_IOC_CREATE_EVENT, &args);
	if (ret) {
		perror("ioctl create event");
		exit(1);
	}
	if (page_offset)
		*page_offset = args.event_page_offset;
	if (trigger_data)
		*trigger_data = args.event_trigger_data;
	if (event_id)
		*event_id = args.event_id;
	if (event_slot_index)
		*event_slot_index = args.event_slot_index;

	fprintf(stderr, "%s: page_offset 0x%lx trigger_data 0x%x event_id 0x%x "
		"event_slot_index 0x%x\n", __func__, (uint64_t)args.event_page_offset,
		args.event_trigger_data, args.event_id, args.event_slot_index);
}
#endif

static void destroy_queue(uint32_t q_id)
{
	struct kfd_ioctl_destroy_queue_args args;
	int ret;

	fprintf(stderr, "%s: id %u\n", __func__, q_id);
	args.queue_id = q_id;
	ret = ioctl(kfd, AMDKFD_IOC_DESTROY_QUEUE, &args);
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
	struct kfd_ioctl_create_queue_args args;

	args.ring_base_address = (uint64_t)ring_base;
	args.ring_size = (uint32_t)ring_size;
	args.gpu_id = gpu_id;
	args.queue_type = KFD_IOC_QUEUE_TYPE_COMPUTE_AQL;
	args.queue_percentage = KFD_MAX_QUEUE_PERCENTAGE;
	args.queue_priority = KFD_MAX_QUEUE_PRIORITY;
	args.write_pointer_address = (uint64_t)write_ptr;
	args.read_pointer_address = (uint64_t)read_ptr;

	// This is only used for some specific AMD GPU
	args.eop_buffer_address = 0;
	args.eop_buffer_size = 0;
	args.ctx_save_restore_address = (uint64_t)ctx_scratch;
	args.ctx_save_restore_size = ctx_scratch_size;
	args.ctl_stack_size = stack_size;

	ret = ioctl(kfd, AMDKFD_IOC_CREATE_QUEUE, &args);
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
	fprintf(stderr, "setup: 0x%x\n", pkt->setup);
	fprintf(stderr, "workgroup_size_x: 0x%x\n", pkt->workgroup_size_x);
	fprintf(stderr, "workgroup_size_y: 0x%x\n", pkt->workgroup_size_y);
	fprintf(stderr, "workgroup_size_z: 0x%x\n", pkt->workgroup_size_z);
	fprintf(stderr, "reserved0: 0x%x\n", pkt->reserved0);
	fprintf(stderr, "grid_size_x: 0x%x\n", pkt->grid_size_x);
	fprintf(stderr, "grid_size_y: 0x%x\n", pkt->grid_size_y);
	fprintf(stderr, "grid_size_z: 0x%x\n", pkt->grid_size_z);
	fprintf(stderr, "private_segment_size: 0x%x\n", pkt->private_segment_size);
	fprintf(stderr, "group_segment_size: 0x%x\n", pkt->group_segment_size);
	fprintf(stderr, "kernel_object: 0x%lx\n", pkt->kernel_object);
	fprintf(stderr, "kernarg_address: 0x%lx\n", (unsigned long)pkt->kernarg_address);
	fprintf(stderr, "reserved2: 0x%lx\n", pkt->reserved2);
	fprintf(stderr, "completion_signal: 0x%lx\n\n", pkt->completion_signal.handle);
}

static void dump_buffer_u64(uint64_t *buf, unsigned length)
{
	int i;
	for (i = 0; i < length; i++) {
		fprintf(stderr, "%08lx\n", buf[i]);
	}
}

static void dump_buffer_f32(float *buf, unsigned length)
{
	int i;
	for (i = 0; i < length; i++) {
		fprintf(stderr, "%f\n", buf[i]);
	}
}

#define ARG0_LOC (24)
#define ARG1_LOC (32)
#define ARG2_LOC (40)
const size_t axpy_x_offset = CACHELINE_SIZE;
const size_t axpy_y_offset = CACHELINE_SIZE * 2;

#define AXPY_XY_BUFSIZE (4)

// set up kernel arguments for a specific instance of axpy
static void init_axpy_kern_args(uint8_t *kern_args_ptr, size_t size)
{
	// copied from axpy.cu
	// 3 arguments a, x, y
	float a = 2.0f;
	float host_x[AXPY_XY_BUFSIZE] = {1.0f, 2.0f, 3.0f, 4.0f};
	float host_y[AXPY_XY_BUFSIZE] = {0.5f, 1.5f, 2.5f, 3.5f};

	// we're not going to bother allocating separate buffers for x and y
	// arrays, instead just put them somewhere on the kernel arguments page
	

	// layout is:
	// 0 -- pointer to arg 0 (literal)
	// 8 -- pointer to arg 1 (pointer to x array)
	// 16 -- pointer to arg 2 (pointer to y array)

	// 24 -- arg 0 -- 4 byte float
	// 32 -- arg 1 -- pointer to x
	// 40 -- arg 2 -- pointer to y
	
	// 64 -- arg 1 array
	// 128 -- arg 2 array

	void *a_arg_ptr = kern_args_ptr + ARG0_LOC;
	void *x_arg_ptr = kern_args_ptr + ARG1_LOC;
	void *y_arg_ptr = kern_args_ptr + ARG2_LOC;
	void *x_ptr = kern_args_ptr + axpy_x_offset;
	void *y_ptr = kern_args_ptr + axpy_y_offset;

	fprintf(stderr, "launching axpy with: \na = %f\n", a);
	fprintf(stderr, "x array: \n");
	dump_buffer_f32(host_x, AXPY_XY_BUFSIZE);
	fprintf(stderr, "y array: \n");
	dump_buffer_f32(host_y, AXPY_XY_BUFSIZE);
	

	memset(kern_args_ptr, 2, size);

	// pointers to args
	memcpy(kern_args_ptr + 0 * sizeof(uint64_t), &a_arg_ptr, sizeof(a_arg_ptr));
	memcpy(kern_args_ptr + 1 * sizeof(uint64_t), &x_arg_ptr, sizeof(x_arg_ptr));
	memcpy(kern_args_ptr + 2 * sizeof(uint64_t), &y_arg_ptr, sizeof(y_arg_ptr));
	
       	// copy literal first arg is at 24 bytes in
	memcpy(kern_args_ptr + ARG0_LOC, &a, sizeof(a));
	
	// pointers to x and y arrays
	memcpy(kern_args_ptr + ARG1_LOC, &x_ptr, sizeof(x_ptr));
	memcpy(kern_args_ptr + ARG2_LOC, &y_ptr, sizeof(y_ptr));
	
	// copy arrays to their locations
	memcpy(x_ptr, host_x, sizeof(host_x));
	memcpy(y_ptr, host_y, sizeof(host_y));

	fprintf(stderr, "kernargs buffer:\n");
	//dump_buffer_u64((uint64_t*)kern_args_ptr, 48/(sizeof(uint64_t)));
}


// now convert pointers..
static void axpy_kern_args_convert_nopasid(uint8_t *kern_args_ptr, uint64_t device_args_ptr, size_t size)
{
	uint64_t *kaptr = (uint64_t*)kern_args_ptr;
	kaptr[0] = device_args_ptr + ARG0_LOC;
	kaptr[1] = device_args_ptr + ARG1_LOC;
	kaptr[2] = device_args_ptr + ARG2_LOC;
	kaptr[4] = device_args_ptr + CACHELINE_SIZE;
	kaptr[5] = device_args_ptr + 2 * CACHELINE_SIZE;

	fprintf(stderr, "converted kernargs buffer:\n");
	dump_buffer_u64((uint64_t*)kern_args_ptr, 48/(sizeof(uint64_t)));
}

static uint64_t *mmap_doorbell(uint64_t doorbell_offset, size_t size)
{
	uint64_t *map = mmap(NULL, size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, kfd, doorbell_offset);

	if (map == MAP_FAILED) {
		perror("mmap doorbell");
		exit(1);
	}

	return map;
}


int main(int argc, char *argv[])
{
	void *kern_ptr = NULL, *rw_ptr, *queue_ptr;
	//size_t doorbell_size = getpagesize() * 2; // this AMD gpu expects 2 pages
	size_t doorbell_size = getpagesize();
	size_t queue_size = getpagesize();
	size_t aql_queue_size = getpagesize();
	size_t rwptr_size = getpagesize();
	size_t kernel_size = 0;

	uint64_t queue_mmap_offset = 0;
	uint64_t queue_handle = 0;
	uint64_t rwptr_mmap_offset = 0;
	uint64_t rwptr_handle = 0;

	uint64_t *q_read_ptr;
	uint64_t *q_write_ptr;

	uint64_t doorbell_offset;
	uint32_t queue_id;

	uint64_t *doorbell_map = NULL;

	int kern_fd = -1;
	struct stat kstat;
	unsigned int kern_start_offset = 0;
	hsa_kernel_dispatch_packet_t *aql_packet;

	// if we have arguments expect an ELF file with a RIG binary
	// we are only expecting a very specific axpy kernel binary
	if (argc > 1) {
		if (lstat(argv[1], &kstat)) {
			perror("lstat");
			return 1;
		}
		fprintf(stderr, "kernel object size %lu bytes\n",
			kstat.st_size);
		kernel_size = kstat.st_size + 4096;
		kern_fd = open(argv[1], O_RDONLY);
		if (kern_fd < 0) {
			perror("open");
			return 1;
		}
		kern_ptr = mmap(NULL, kernel_size, PROT_READ, MAP_SHARED,
				kern_fd, 0);
		if (kern_ptr == MAP_FAILED) {
			perror("mmap kernel");
			return 1;
		}

		parse_kernels(kern_ptr, &kern_start_offset);
	}

	open_kfd();
	get_version();
	get_process_apertures_new();
	open_render_fd();
	acquire_vm();
	set_memory_policy();

	// allocate a user buffer for the queue
	alloc_aligned_host_memory(&queue_ptr, queue_size);
	alloc_memory_of_gpu(queue_ptr, queue_size, USER, &queue_mmap_offset, &queue_handle);
	fprintf(stderr, "queue_ptr: 0x%lx\n", (unsigned long)queue_ptr);
	fprintf(stderr, "queue_mmap_offset: 0x%lx\n", queue_mmap_offset);

	
	alloc_aligned_host_memory(&rw_ptr, rwptr_size);
	alloc_memory_of_gpu(rw_ptr, rwptr_size, USER, &rwptr_mmap_offset, &rwptr_handle);
	fprintf(stderr, "rw_ptr: 0x%lx\n", (unsigned long)rw_ptr);
	fprintf(stderr, "rwptr_mmap_offset: 0x%lx\n", rwptr_mmap_offset);


	// set read and write pointers to memory inside the queue space
	q_read_ptr = rw_ptr;
	q_write_ptr = q_read_ptr + (CACHELINE_SIZE/sizeof(uint64_t));

	// set all packets to invalid -- 1
	memset(queue_ptr, 1, aql_queue_size);

	*q_read_ptr = *q_write_ptr = 0;
	create_queue(queue_ptr, aql_queue_size, NULL, 0, 0, q_read_ptr, q_write_ptr,
			&doorbell_offset, &queue_id);

	doorbell_map = mmap_doorbell(doorbell_offset, doorbell_size);

	fprintf(stderr, "AQL Queue create succeeded, got queue id %u\n", queue_id);
	if (kernel_size) {
		int wait_count = 0;
		uint64_t kern_mmap_offset = 0;
		uint64_t kern_handle = 0;
		
		uint64_t kern_args_mmap_offset = 0;
		uint64_t kern_args_handle = 0;
		void *kern_args_ptr;

		uint64_t kern_args_size = getpagesize();
		
		alloc_memory_of_gpu(kern_ptr, kernel_size, USER, &kern_mmap_offset, &kern_handle);
		fprintf(stderr, "kern_ptr: 0x%lx\n", (unsigned long)kern_ptr);
		fprintf(stderr, "kern_mmap_offset: 0x%lx\n", kern_mmap_offset);

		alloc_aligned_host_memory(&kern_args_ptr, kern_args_size);
		alloc_memory_of_gpu(kern_args_ptr, kern_args_size, USER, &kern_args_mmap_offset,
				    &kern_args_handle);
		fprintf(stderr, "kern_args_ptr: 0x%lx\n", (unsigned long)kern_args_ptr);
		fprintf(stderr, "kern_args_mmap_offset: 0x%lx\n", (unsigned long)kern_args_mmap_offset);

		// only designed to support axpy kernel
		init_axpy_kern_args(kern_args_ptr, kern_args_size);
		// hack to deal with no pasid
		// axpy_kern_args_convert_nopasid(kern_args_ptr, kern_args_mmap_offset & 0xFFFFFFFFFFFFULL,
		// 			       kern_args_size);


		aql_packet = (hsa_kernel_dispatch_packet_t *) (queue_ptr);

		// Stub these fields for now
		aql_packet->header = HSA_PACKET_TYPE_KERNEL_DISPATCH;
		aql_packet->setup = 0;
		aql_packet->workgroup_size_x = AXPY_X_DIM;
		aql_packet->workgroup_size_y = AXPY_Y_DIM;
		aql_packet->workgroup_size_z = AXPY_Z_DIM;
		aql_packet->reserved0 = 0;
		aql_packet->grid_size_x = AXPY_X_DIM;;
		aql_packet->grid_size_y = AXPY_Y_DIM;;
		aql_packet->grid_size_z = AXPY_Z_DIM;;
		aql_packet->private_segment_size = 0;
		aql_packet->group_segment_size = 0;
		aql_packet->kernel_object = (uint64_t) ((uint8_t*) kern_ptr + kern_start_offset);
		aql_packet->kernarg_address = kern_args_ptr;
		aql_packet->reserved2 = 0;
		aql_packet->completion_signal.handle = 0;

		print_aql_packet(aql_packet);

		fprintf(stderr, "AQL packet address: 0x%lx\n", (unsigned long)aql_packet);
		fprintf(stderr, "Size of AQL packet: %lu\n", sizeof(*aql_packet));
		fprintf(stderr, "Current read index: %lu write index: %lu\n",
			*q_read_ptr, *q_write_ptr);
		*q_write_ptr += 1;
		fprintf(stderr, "Incremented write index: %lu\n", *q_write_ptr);
		doorbell_map[queue_id] = *q_write_ptr;
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
		fprintf(stderr, "axpy y buffer after execution: \n");
		dump_buffer_f32((float *)(kern_args_ptr + axpy_y_offset), AXPY_XY_BUFSIZE);
		destroy_queue(queue_id);
	} else {
		fprintf(stderr, "No kernel to launch, exiting\n");
	}

	munmap(doorbell_map, doorbell_size);
	close(kfd);
	return 0;
}

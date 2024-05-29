// SPDX-License-Identifier: GPL-2.0
/*
 * access_tracking_perf_test
 *
 * Copyright (C) 2021, Google, Inc.
 *
 * This test measures the performance effects of KVM's access tracking.
 * Access tracking is driven by the MMU notifiers test_young, clear_young, and
 * clear_flush_young. These notifiers do not have a direct userspace API,
 * however the clear_young notifier can be triggered by marking a pages as idle
 * in /sys/kernel/mm/page_idle/bitmap. This test leverages that mechanism to
 * enable access tracking on guest memory.
 *
 * To measure performance this test runs a VM with a configurable number of
 * vCPUs that each touch every page in disjoint regions of memory. Performance
 * is measured in the time it takes all vCPUs to finish touching their
 * predefined region.
 *
 * Note that a deterministic correctness test of access tracking is not possible
 * by using page_idle as it exists today. This is for a few reasons:
 *
 * 1. page_idle only issues clear_young notifiers, which lack a TLB flush. This
 *    means subsequent guest accesses are not guaranteed to see page table
 *    updates made by KVM until some time in the future.
 *
 * 2. page_idle only operates on LRU pages. Newly allocated pages are not
 *    immediately allocated to LRU lists. Instead they are held in a "pagevec",
 *    which is drained to LRU lists some time in the future. There is no
 *    userspace API to force this drain to occur.
 *
 * These limitations are worked around in this test by using a large enough
 * region of memory for each vCPU such that the number of translations cached in
 * the TLB and the number of pages held in pagevecs are a small fraction of the
 * overall workload. And if either of those conditions are not true (for example
 * in nesting, where TLB size is unlimited) this test will print a warning
 * rather than silently passing.
 */
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "kvm_util.h"
#include "test_util.h"
#include "memstress.h"
#include "guest_modes.h"
#include "processor.h"
#include "lru_gen_util.h"

static const char *TEST_MEMCG_NAME = "access_tracking_perf_test";
static const int LRU_GEN_ENABLED = 0x1;
static const int LRU_GEN_MM_WALK = 0x2;
static const int LRU_GEN_SECONDARY_MMU_WALK = 0x8;
static const char *CGROUP_PROCS = "cgroup.procs";
/*
 * If using MGLRU, this test assumes a cgroup v2 or cgroup v1 memory hierarchy
 * is mounted at cgroup_root.
 *
 * Can be changed with -r.
 */
static const char *cgroup_root = "/sys/fs/cgroup";

/* Global variable used to synchronize all of the vCPU threads. */
static int iteration;

/* Defines what vCPU threads should do during a given iteration. */
static enum {
	/* Run the vCPU to access all its memory. */
	ITERATION_ACCESS_MEMORY,
	/* Mark the vCPU's memory idle in page_idle. */
	ITERATION_MARK_IDLE,
} iteration_work;

/* The iteration that was last completed by each vCPU. */
static int vcpu_last_completed_iteration[KVM_MAX_VCPUS];

/* The time at which the last iteration was completed */
static struct timespec vcpu_last_completed_time[KVM_MAX_VCPUS];

/* Whether to overlap the regions of memory vCPUs access. */
static bool overlap_memory_access;

struct test_params {
	/* The backing source for the region of memory. */
	enum vm_mem_backing_src_type backing_src;

	/* The amount of memory to allocate for each vCPU. */
	uint64_t vcpu_memory_bytes;

	/* The number of vCPUs to create in the VM. */
	int nr_vcpus;

	/* Whether to use lru_gen aging instead of idle page tracking. */
	bool lru_gen;

	/* Whether to test the performance of aging itself. */
	bool benchmark_lru_gen;
};

static uint64_t pread_uint64(int fd, const char *filename, uint64_t index)
{
	uint64_t value;
	off_t offset = index * sizeof(value);

	TEST_ASSERT(pread(fd, &value, sizeof(value), offset) == sizeof(value),
		    "pread from %s offset 0x%" PRIx64 " failed!",
		    filename, offset);

	return value;

}

static void write_file_long(const char *path, long v)
{
	FILE *f;

	f = fopen(path, "w");
	TEST_ASSERT(f, "fopen(%s) failed", path);
	TEST_ASSERT(fprintf(f, "%ld\n", v) > 0,
		    "fprintf to %s failed", path);
	TEST_ASSERT(!fclose(f), "fclose(%s) failed", path);
}

static char *path_join(const char *parent, const char *child)
{
	char *out = NULL;

	return asprintf(&out, "%s/%s", parent, child) >= 0 ? out : NULL;
}

static char *memcg_path(const char *memcg)
{
	return path_join(cgroup_root, memcg);
}

static char *memcg_file_path(const char *memcg, const char *file)
{
	char *mp = memcg_path(memcg);
	char *fp;

	if (!mp)
		return NULL;
	fp = path_join(mp, file);
	free(mp);
	return fp;
}

static void move_to_memcg(const char *memcg, pid_t pid)
{
	char *procs = memcg_file_path(memcg, CGROUP_PROCS);

	TEST_ASSERT(procs, "Failed to construct cgroup.procs path");
	write_file_long(procs, pid);
	free(procs);
}

#define PAGEMAP_PRESENT (1ULL << 63)
#define PAGEMAP_PFN_MASK ((1ULL << 55) - 1)

static uint64_t lookup_pfn(int pagemap_fd, struct kvm_vm *vm, uint64_t gva)
{
	uint64_t hva = (uint64_t) addr_gva2hva(vm, gva);
	uint64_t entry;
	uint64_t pfn;

	entry = pread_uint64(pagemap_fd, "pagemap", hva / getpagesize());
	if (!(entry & PAGEMAP_PRESENT))
		return 0;

	pfn = entry & PAGEMAP_PFN_MASK;
	__TEST_REQUIRE(pfn, "Looking up PFNs requires CAP_SYS_ADMIN");

	return pfn;
}

static bool is_page_idle(int page_idle_fd, uint64_t pfn)
{
	uint64_t bits = pread_uint64(page_idle_fd, "page_idle", pfn / 64);

	return !!((bits >> (pfn % 64)) & 1);
}

static void mark_page_idle(int page_idle_fd, uint64_t pfn)
{
	uint64_t bits = 1ULL << (pfn % 64);

	TEST_ASSERT(pwrite(page_idle_fd, &bits, 8, 8 * (pfn / 64)) == 8,
		    "Set page_idle bits for PFN 0x%" PRIx64, pfn);
}

static void mark_vcpu_memory_idle(struct kvm_vm *vm,
				  struct memstress_vcpu_args *vcpu_args)
{
	int vcpu_idx = vcpu_args->vcpu_idx;
	uint64_t base_gva = vcpu_args->gva;
	uint64_t pages = vcpu_args->pages;
	uint64_t page;
	uint64_t still_idle = 0;
	uint64_t no_pfn = 0;
	int page_idle_fd;
	int pagemap_fd;

	/* If vCPUs are using an overlapping region, let vCPU 0 mark it idle. */
	if (overlap_memory_access && vcpu_idx)
		return;

	page_idle_fd = open("/sys/kernel/mm/page_idle/bitmap", O_RDWR);
	TEST_ASSERT(page_idle_fd > 0, "Failed to open page_idle.");

	pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
	TEST_ASSERT(pagemap_fd > 0, "Failed to open pagemap.");

	for (page = 0; page < pages; page++) {
		uint64_t gva = base_gva + page * memstress_args.guest_page_size;
		uint64_t pfn = lookup_pfn(pagemap_fd, vm, gva);

		if (!pfn) {
			no_pfn++;
			continue;
		}

		if (is_page_idle(page_idle_fd, pfn)) {
			still_idle++;
			continue;
		}

		mark_page_idle(page_idle_fd, pfn);
	}

	/*
	 * Assumption: Less than 1% of pages are going to be swapped out from
	 * under us during this test.
	 */
	TEST_ASSERT(no_pfn < pages / 100,
		    "vCPU %d: No PFN for %" PRIu64 " out of %" PRIu64 " pages.",
		    vcpu_idx, no_pfn, pages);

	/*
	 * Check that at least 90% of memory has been marked idle (the rest
	 * might not be marked idle because the pages have not yet made it to an
	 * LRU list or the translations are still cached in the TLB). 90% is
	 * arbitrary; high enough that we ensure most memory access went through
	 * access tracking but low enough as to not make the test too brittle
	 * over time and across architectures.
	 *
	 * When running the guest as a nested VM, "warn" instead of asserting
	 * as the TLB size is effectively unlimited and the KVM doesn't
	 * explicitly flush the TLB when aging SPTEs.  As a result, more pages
	 * are cached and the guest won't see the "idle" bit cleared.
	 */
	if (still_idle >= pages / 10) {
#ifdef __x86_64__
		TEST_ASSERT(this_cpu_has(X86_FEATURE_HYPERVISOR),
			    "vCPU%d: Too many pages still idle (%lu out of %lu)",
			    vcpu_idx, still_idle, pages);
#endif
		printf("WARNING: vCPU%d: Too many pages still idle (%lu out of %lu), "
		       "this will affect performance results.\n",
		       vcpu_idx, still_idle, pages);
	}

	close(page_idle_fd);
	close(pagemap_fd);
}

static void assert_ucall(struct kvm_vcpu *vcpu, uint64_t expected_ucall)
{
	struct ucall uc;
	uint64_t actual_ucall = get_ucall(vcpu, &uc);

	TEST_ASSERT(expected_ucall == actual_ucall,
		    "Guest exited unexpectedly (expected ucall %" PRIu64
		    ", got %" PRIu64 ")",
		    expected_ucall, actual_ucall);
}

static bool spin_wait_for_next_iteration(int *current_iteration)
{
	int last_iteration = *current_iteration;

	do {
		if (READ_ONCE(memstress_args.stop_vcpus))
			return false;

		*current_iteration = READ_ONCE(iteration);
	} while (last_iteration == *current_iteration);

	return true;
}

static void vcpu_thread_main(struct memstress_vcpu_args *vcpu_args)
{
	struct kvm_vcpu *vcpu = vcpu_args->vcpu;
	struct kvm_vm *vm = memstress_args.vm;
	int vcpu_idx = vcpu_args->vcpu_idx;
	int current_iteration = 0;

	while (spin_wait_for_next_iteration(&current_iteration)) {
		switch (READ_ONCE(iteration_work)) {
		case ITERATION_ACCESS_MEMORY:
			vcpu_run(vcpu);
			assert_ucall(vcpu, UCALL_SYNC);
			break;
		case ITERATION_MARK_IDLE:
			mark_vcpu_memory_idle(vm, vcpu_args);
			break;
		};

		vcpu_last_completed_iteration[vcpu_idx] = current_iteration;
		clock_gettime(CLOCK_MONOTONIC,
			      &vcpu_last_completed_time[vcpu_idx]);
	}
}

static void spin_wait_for_vcpu(int vcpu_idx, int target_iteration)
{
	while (READ_ONCE(vcpu_last_completed_iteration[vcpu_idx]) !=
	       target_iteration) {
		continue;
	}
}

static bool all_vcpus_done(int target_iteration, int nr_vcpus)
{
	for (int i = 0; i < nr_vcpus; ++i)
		if (READ_ONCE(vcpu_last_completed_iteration[i]) !=
		    target_iteration)
			return false;

	return true;
}

/* The type of memory accesses to perform in the VM. */
enum access_type {
	ACCESS_READ,
	ACCESS_WRITE,
};

static void run_iteration(struct kvm_vm *vm, int nr_vcpus, const char *description,
			  bool wait)
{
	int next_iteration, i;

	/* Kick off the vCPUs by incrementing iteration. */
	next_iteration = ++iteration;

	/* Wait for all vCPUs to finish the iteration. */
	if (wait) {
		struct timespec ts_start;
		struct timespec ts_elapsed;

		clock_gettime(CLOCK_MONOTONIC, &ts_start);

		for (i = 0; i < nr_vcpus; i++)
			spin_wait_for_vcpu(i, next_iteration);

		ts_elapsed = timespec_elapsed(ts_start);

		pr_info("%-30s: %ld.%09lds\n",
			description, ts_elapsed.tv_sec, ts_elapsed.tv_nsec);
	} else
		pr_info("%-30s\n", description);
}

static void _access_memory(struct kvm_vm *vm, int nr_vcpus,
			   enum access_type access, const char *description,
			   bool wait)
{
	memstress_set_write_percent(vm, (access == ACCESS_READ) ? 0 : 100);
	iteration_work = ITERATION_ACCESS_MEMORY;
	run_iteration(vm, nr_vcpus, description, wait);
}

static void access_memory(struct kvm_vm *vm, int nr_vcpus,
			  enum access_type access, const char *description)
{
	return _access_memory(vm, nr_vcpus, access, description, true);
}

static void access_memory_async(struct kvm_vm *vm, int nr_vcpus,
				enum access_type access,
				const char *description)
{
	return _access_memory(vm, nr_vcpus, access, description, false);
}

static void mark_memory_idle(struct kvm_vm *vm, int nr_vcpus)
{
	/*
	 * Even though this parallelizes the work across vCPUs, this is still a
	 * very slow operation because page_idle forces the test to mark one pfn
	 * at a time and the clear_young notifier serializes on the KVM MMU
	 * lock.
	 */
	pr_debug("Marking VM memory idle (slow)...\n");
	iteration_work = ITERATION_MARK_IDLE;
	run_iteration(vm, nr_vcpus, "Mark memory idle", true);
}

static void create_memcg(const char *memcg)
{
	const char *full_memcg_path = memcg_path(memcg);
	int ret;

	TEST_ASSERT(full_memcg_path, "Failed to construct full memcg path");
retry:
	ret = mkdir(full_memcg_path, 0755);
	if (ret && errno == EEXIST) {
		TEST_ASSERT(!rmdir(full_memcg_path),
			    "Found existing memcg at %s, but rmdir failed",
			    full_memcg_path);
		goto retry;
	}
	TEST_ASSERT(!ret, "Creating the memcg failed: mkdir(%s) failed",
		    full_memcg_path);

	pr_info("Created memcg at %s\n", full_memcg_path);
}

/*
 * Test lru_gen aging speed while vCPUs are faulting memory in.
 *
 * This test will run lru_gen aging until the vCPUs have finished all of
 * the faulting work, reporting:
 *  - vcpu wall time (wall time for slowest vCPU)
 *  - average aging pass duration
 *  - total number of aging passes
 *  - total time spent aging
 *
 * This test produces the most useful results when the vcpu wall time and the
 * total time spent aging are similar (i.e., we want to avoid timing aging
 * while the vCPUs aren't doing any work).
 */
static void run_benchmark(enum vm_guest_mode mode, struct kvm_vm *vm,
			  struct test_params *params)
{
	int nr_vcpus = params->nr_vcpus;
	struct memcg_stats stats;
	struct timespec ts_start, ts_max, ts_vcpus_elapsed,
			ts_aging_elapsed, ts_aging_elapsed_avg;
	int num_passes = 0;

	printf("Running lru_gen benchmark...\n");

	clock_gettime(CLOCK_MONOTONIC, &ts_start);
	access_memory_async(vm, nr_vcpus, ACCESS_WRITE,
			    "Populating memory (async)");
	while (!all_vcpus_done(iteration, nr_vcpus)) {
		lru_gen_do_aging_quiet(&stats, TEST_MEMCG_NAME);
		++num_passes;
	}

	ts_aging_elapsed = timespec_elapsed(ts_start);
	ts_aging_elapsed_avg = timespec_div(ts_aging_elapsed, num_passes);

	/* Find out when the slowest vCPU finished. */
	ts_max = ts_start;
	for (int i = 0; i < nr_vcpus; ++i) {
		struct timespec *vcpu_ts = &vcpu_last_completed_time[i];

		if (ts_max.tv_sec < vcpu_ts->tv_sec ||
		    (ts_max.tv_sec == vcpu_ts->tv_sec  &&
		     ts_max.tv_nsec < vcpu_ts->tv_nsec))
			ts_max = *vcpu_ts;
	}

	ts_vcpus_elapsed = timespec_sub(ts_max, ts_start);

	pr_info("%-30s: %ld.%09lds\n", "vcpu wall time",
		ts_vcpus_elapsed.tv_sec, ts_vcpus_elapsed.tv_nsec);

	pr_info("%-30s: %ld.%09lds, (passes:%d, total:%ld.%09lds)\n",
		"lru_gen avg pass duration",
		ts_aging_elapsed_avg.tv_sec,
		ts_aging_elapsed_avg.tv_nsec,
		num_passes,
		ts_aging_elapsed.tv_sec,
		ts_aging_elapsed.tv_nsec);
}

/*
 * Test how much access tracking affects vCPU performance.
 *
 * Supports two modes of access tracking:
 * - idle page tracking
 * - lru_gen aging
 *
 * When using lru_gen, this test additionally verifies that the pages are in
 * fact getting younger and older, otherwise the performance data would be
 * invalid.
 *
 * The forced lru_gen aging can race with aging that occurs naturally.
 */
static void run_test(enum vm_guest_mode mode, struct kvm_vm *vm,
		     struct test_params *params)
{
	int nr_vcpus = params->nr_vcpus;
	bool lru_gen = params->lru_gen;
	struct memcg_stats stats;
	long total_pages = nr_vcpus * params->vcpu_memory_bytes / getpagesize();
	int found_gens[5];

	pr_info("\n");
	access_memory(vm, nr_vcpus, ACCESS_WRITE, "Populating memory");

	/* As a control, read and write to the populated memory first. */
	access_memory(vm, nr_vcpus, ACCESS_WRITE, "Writing to populated memory");
	access_memory(vm, nr_vcpus, ACCESS_READ, "Reading from populated memory");

	/* Repeat on memory that has been marked as idle. */
	if (lru_gen) {
		/* Do an initial page table scan */
		lru_gen_do_aging(&stats, TEST_MEMCG_NAME);
		TEST_ASSERT(sum_memcg_stats(&stats) >= total_pages,
		  "Not all pages tracked in lru_gen stats.\n"
		  "Is lru_gen enabled? Did the memcg get created properly?");

		/* Find the generation we're currently in (probably youngest) */
		found_gens[0] = lru_gen_find_generation(&stats, total_pages);

		/* Do an aging pass now */
		lru_gen_do_aging(&stats, TEST_MEMCG_NAME);

		/* Same generation, but a newer generation has been made */
		found_gens[1] = lru_gen_find_generation(&stats, total_pages);
		TEST_ASSERT(found_gens[1] == found_gens[0],
			    "unexpected gen change: %d vs. %d",
			    found_gens[1], found_gens[0]);
	} else
		mark_memory_idle(vm, nr_vcpus);

	access_memory(vm, nr_vcpus, ACCESS_WRITE, "Writing to idle memory");

	if (lru_gen) {
		/* Scan the page tables again */
		lru_gen_do_aging(&stats, TEST_MEMCG_NAME);

		/* The pages should now be young again, so in a newer generation */
		found_gens[2] = lru_gen_find_generation(&stats, total_pages);
		TEST_ASSERT(found_gens[2] > found_gens[1],
			    "pages did not get younger");

		/* Do another aging pass */
		lru_gen_do_aging(&stats, TEST_MEMCG_NAME);

		/* Same generation; new generation has been made */
		found_gens[3] = lru_gen_find_generation(&stats, total_pages);
		TEST_ASSERT(found_gens[3] == found_gens[2],
			    "unexpected gen change: %d vs. %d",
			    found_gens[3], found_gens[2]);
	} else
		mark_memory_idle(vm, nr_vcpus);

	access_memory(vm, nr_vcpus, ACCESS_READ, "Reading from idle memory");

	if (lru_gen) {
		/* Scan the pages tables again */
		lru_gen_do_aging(&stats, TEST_MEMCG_NAME);

		/* The pages should now be young again, so in a newer generation */
		found_gens[4] = lru_gen_find_generation(&stats, total_pages);
		TEST_ASSERT(found_gens[4] > found_gens[3],
			    "pages did not get younger");
	}
}

static void setup_vm_and_run(enum vm_guest_mode mode, void *arg)
{
	struct test_params *params = arg;
	int nr_vcpus = params->nr_vcpus;
	struct kvm_vm *vm;

	if (params->lru_gen) {
		create_memcg(TEST_MEMCG_NAME);
		move_to_memcg(TEST_MEMCG_NAME, getpid());
	}

	vm = memstress_create_vm(mode, nr_vcpus, params->vcpu_memory_bytes, 1,
				 params->backing_src, !overlap_memory_access);

	memstress_start_vcpu_threads(nr_vcpus, vcpu_thread_main);

	if (params->benchmark_lru_gen)
		run_benchmark(mode, vm, params);
	else
		run_test(mode, vm, params);

	memstress_join_vcpu_threads(nr_vcpus);
	memstress_destroy_vm(vm);
}

static void help(char *name)
{
	puts("");
	printf("usage: %s [-h] [-m mode] [-b vcpu_bytes] [-v vcpus] [-o]"
	       " [-s mem_type] [-l] [-r memcg_root]\n", name);
	puts("");
	printf(" -h: Display this help message.");
	guest_modes_help();
	printf(" -b: specify the size of the memory region which should be\n"
	       "     dirtied by each vCPU. e.g. 10M or 3G.\n"
	       "     (default: 1G)\n");
	printf(" -v: specify the number of vCPUs to run.\n");
	printf(" -o: Overlap guest memory accesses instead of partitioning\n"
	       "     them into a separate region of memory for each vCPU.\n");
	printf(" -l: Use MGLRU aging instead of idle page tracking\n");
	printf(" -p: Benchmark MGLRU aging while faulting memory in\n");
	printf(" -r: The memory cgroup hierarchy root to use (when -l is given)\n");
	backing_src_help("-s");
	puts("");
	exit(0);
}

int main(int argc, char *argv[])
{
	struct test_params params = {
		.backing_src = DEFAULT_VM_MEM_SRC,
		.vcpu_memory_bytes = DEFAULT_PER_VCPU_MEM_SIZE,
		.nr_vcpus = 1,
		.lru_gen = false,
		.benchmark_lru_gen = false,
	};
	int page_idle_fd;
	int opt;

	guest_modes_append_default();

	while ((opt = getopt(argc, argv, "hm:b:v:os:lr:p")) != -1) {
		switch (opt) {
		case 'm':
			guest_modes_cmdline(optarg);
			break;
		case 'b':
			params.vcpu_memory_bytes = parse_size(optarg);
			break;
		case 'v':
			params.nr_vcpus = atoi_positive("Number of vCPUs", optarg);
			break;
		case 'o':
			overlap_memory_access = true;
			break;
		case 's':
			params.backing_src = parse_backing_src_type(optarg);
			break;
		case 'l':
			params.lru_gen = true;
			break;
		case 'p':
			params.benchmark_lru_gen = true;
			break;
		case 'r':
			cgroup_root = strdup(optarg);
			break;
		case 'h':
		default:
			help(argv[0]);
			break;
		}
	}

	if (!params.lru_gen) {
		page_idle_fd = open("/sys/kernel/mm/page_idle/bitmap", O_RDWR);
		__TEST_REQUIRE(page_idle_fd >= 0,
			       "CONFIG_IDLE_PAGE_TRACKING is not enabled");
		close(page_idle_fd);
	} else {
		int lru_gen_fd, lru_gen_debug_fd;
		long mglru_features;
		char mglru_feature_str[8] = {};

		lru_gen_fd = open("/sys/kernel/mm/lru_gen/enabled", O_RDONLY);
		__TEST_REQUIRE(lru_gen_fd >= 0,
			       "CONFIG_LRU_GEN is not enabled");
		TEST_ASSERT(read(lru_gen_fd, &mglru_feature_str, 7) > 0,
				 "couldn't read lru_gen features");
		mglru_features = strtol(mglru_feature_str, NULL, 16);
		__TEST_REQUIRE(mglru_features & LRU_GEN_ENABLED,
			       "lru_gen is not enabled");
		__TEST_REQUIRE(mglru_features & LRU_GEN_MM_WALK,
			       "lru_gen does not support MM_WALK");
		__TEST_REQUIRE(mglru_features & LRU_GEN_SECONDARY_MMU_WALK,
			       "lru_gen does not support SECONDARY_MMU_WALK");

		lru_gen_debug_fd = open(DEBUGFS_LRU_GEN, O_RDWR);
		__TEST_REQUIRE(lru_gen_debug_fd >= 0,
				"Cannot access %s", DEBUGFS_LRU_GEN);
		close(lru_gen_debug_fd);
	}

	TEST_ASSERT(!params.benchmark_lru_gen || params.lru_gen,
		    "-p specified without -l");

	for_each_guest_mode(setup_vm_and_run, &params);

	return 0;
}

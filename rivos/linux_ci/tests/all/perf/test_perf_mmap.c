#include <perf/event.h>
#include <perf/core.h>
#include <perf/evsel.h>
#include <perf/evlist.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int libperf_print(enum libperf_print_level level,
                         const char *fmt, va_list ap)
{
        return vfprintf(stderr, fmt, ap);
}

int main(int argc, char **argv)
{
        int count = 100, err = 0;
        struct perf_evlist *evlist;
        struct perf_evsel *evsel, *evsel1, *evsel2;
        struct perf_thread_map *threads;
        struct perf_counts_values counts;

        struct perf_event_attr attr1 = {
                .type        = PERF_TYPE_HARDWARE,
                .config      = PERF_COUNT_HW_CPU_CYCLES,
                .read_format = PERF_FORMAT_TOTAL_TIME_ENABLED|PERF_FORMAT_TOTAL_TIME_RUNNING,
                .disabled    = 1,
        };

        struct perf_event_attr attr2 = {
                .type        = PERF_TYPE_HW_CACHE,
                .config      = PERF_COUNT_HW_CACHE_DTLB		<<  0  |
			       (PERF_COUNT_HW_CACHE_OP_READ	<<  8) |
			       (PERF_COUNT_HW_CACHE_RESULT_MISS	<< 16),
                .read_format = PERF_FORMAT_TOTAL_TIME_ENABLED|PERF_FORMAT_TOTAL_TIME_RUNNING,
                .disabled    = 0,
        };

        libperf_init(libperf_print);
        threads = perf_thread_map__new_dummy();
        if (!threads) {
                fprintf(stderr, "failed to create threads\n");
                return -1;
        }
        perf_thread_map__set_pid(threads, 0, 0);
        evlist = perf_evlist__new();
        if (!evlist) {
                fprintf(stderr, "failed to create evlist\n");
                goto out_threads;
        }

	/* add evsel1 */
        evsel1 = perf_evsel__new(&attr1);
        if (!evsel1) {
                fprintf(stderr, "failed to create evsel1\n");
                goto out_evlist;
        }

        perf_evlist__add(evlist, evsel1);

	/* add evsel2 */
        evsel2 = perf_evsel__new(&attr2);
        if (!evsel2) {
                fprintf(stderr, "failed to create evsel2\n");
                goto out_evlist;
        }

        perf_evlist__add(evlist, evsel2);

        perf_evlist__set_maps(evlist, NULL, threads);

        err = perf_evlist__open(evlist);
        if (err) {
                fprintf(stderr, "failed to open evsel\n");
                goto out_evlist;
        }
	err = perf_evsel__mmap(evsel1, 0);
	if (err) {
		fprintf(stderr, "failed to mmap evsel\n");
		goto out_evlist;
	}

	err = perf_evsel__mmap(evsel2, 0);
	if (err) {
		fprintf(stderr, "failed to mmap evsel\n");
		goto out_evlist;
	}

        perf_evlist__enable(evlist);
        while (count--);
        perf_evlist__for_each_evsel(evlist, evsel) {
                perf_evsel__read(evsel, 0, 0, &counts);
                fprintf(stdout, "count %llu, enabled %llu, run %llu\n",
                                counts.val, counts.ena, counts.run);
        }
        perf_evlist__disable(evlist);
        perf_evlist__close(evlist);
out_evlist:
        perf_evlist__delete(evlist);
out_threads:
        perf_thread_map__put(threads);
        return err;
}

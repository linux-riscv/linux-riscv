// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include "util/pmu.h"
#include "util/pmus.h"
#include "util/evlist.h"
#include "util/parse-events.h"
#include "util/event.h"
#include "evsel.h"
#include "pmu.h"

static int pmu_update_cpu_stdevents_callback(const struct pmu_event *pe,
					     const struct pmu_events_table *table __maybe_unused,
					     void *vdata)
{
	struct evsel *evsel = vdata;
	struct parse_events_terms terms;
	int err;
	struct perf_pmu *pmu = perf_pmus__find("cpu");

	if (pe->event) {
		parse_events_terms__init(&terms);
		err = parse_events_terms(&terms, pe->event, NULL);
		if (err)
			goto out_free;
		err = perf_pmu__config_terms(pmu, &evsel->core.attr, &terms,
					     /*zero=*/true, /*err=*/NULL);
		if (err)
			goto out_free;
	}

out_free:
	parse_events_terms__exit(&terms);
	return 0;
}

int arch_evlist__override_default_attrs(struct evlist *evlist, const char *pmu_name)
{
	struct evsel *evsel;
	struct perf_pmu *pmu = perf_pmus__find(pmu_name);
	static const char *const overriden_event_arr[] = {"cycles", "instructions",
							  "dTLB-load-misses", "dTLB-store-misses",
							  "iTLB-load-misses"};
	unsigned int i, len = sizeof(overriden_event_arr) / sizeof(char *);

	if (!pmu || !perf_pmu_riscv_cdeleg_present())
		return 0;

	for (i = 0; i < len; i++) {
		if (perf_pmus__have_event(pmu_name, overriden_event_arr[i])) {
			evsel = evlist__find_evsel_by_str(evlist, overriden_event_arr[i]);
			if (!evsel)
				continue;
			pmu_events_table__find_event(pmu->events_table, pmu,
						     overriden_event_arr[i],
						     pmu_update_cpu_stdevents_callback, evsel);
		}
	}

	return 0;
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * IOMMU API for RISC-V architected Ziommu implementations.
 *
 * Copyright © 2023 Rivos Inc.
 *
 * Authors
 *  Pranoy Dutta <prydt@rivosinc.com>
 */

#include <linux/container_of.h>
#include "iommu.h"

static inline struct riscv_iommu_device *pmu_to_riscv_iommu_dev(struct pmu *pmu)
{
	return container_of(pmu, struct riscv_iommu_device, pmu);
}

static inline struct riscv_iommu_device *perf_event_to_riscv_iommu_dev(struct perf_event *event)
{
	struct pmu *pmu = event->pmu;

	return pmu_to_riscv_iommu_dev(pmu);
}

#define RISCV_IOMMU_PMU_ATTR(_name, _format, _filter)			\
	PMU_FORMAT_ATTR(_name, _format);			\
								\
	static struct attribute *_name##_attr[] = {		\
		&format_attr_##_name.attr,			\
		NULL						\
	};							\
								\
	static struct attribute_group _name = {			\
		.name = "format",				\
		.attrs = _name##_attr,				\
	}

/**
 * Filtering Options for HPM (Hardware Performance Monitoring unit)
 *
 * 14:0 event id (what event to count, 0 is no event)
 * 15 DMASK (if partial matching of DID_GSCID is performed in txn)
 * 35:16 PID_PSCID (process_id if IDT==0, else PSCID)
 * 59:36 DID_GSCID (device_id if IDT==0, else GSCID)
 * 60 PV_PSCV (if set only txn with matching process_id/PSCID are counted)
 * 61 DV_GSCV (if set only txn with matching device_id/GSCID are counted)
 * 62 IDT (id type, if set DID_GSCID is GSCID and PID_PSCID is PSCID, else device_id and process_id respectively)
 * 63 OF (overflow status / interrupt disable)
 */
RISCV_IOMMU_PMU_ATTR(event_id, "config:0-14", IOMMU_PMU_FILTER_EVENT_ID);
RISCV_IOMMU_PMU_ATTR(dmask, "config:15", IOMMU_PMU_FILTER_DMASK);
RISCV_IOMMU_PMU_ATTR(pid_pscid, "config:16-35", IOMMU_PMU_FILTER_PID_PSCID);
RISCV_IOMMU_PMU_ATTR(did_gscid, "config:36-59", IOMMU_PMU_FILTER_DID_GSCID);
RISCV_IOMMU_PMU_ATTR(pv_pscv, "config:60", IOMMU_PMU_FILTER_PV_PSCV);
RISCV_IOMMU_PMU_ATTR(dv_gscv, "config:61", IOMMU_PMU_FILTER_DV_GSCV);
RISCV_IOMMU_PMU_ATTR(idt, "config:62", IOMMU_PMU_FILTER_IDT);
RISCV_IOMMU_PMU_ATTR(of, "config:63", IOMMU_PMU_FILTER_OF);

static struct attribute *iommu_pmu_format_attrs[] = {
	&format_attr_event_id.attr,
	&format_attr_dmask.attr,
	&format_attr_pid_pscid.attr,
	&format_attr_did_gscid.attr,
	&format_attr_pv_pscv.attr,
	&format_attr_dv_gscv.attr,
	&format_attr_idt.attr,
	&format_attr_of.attr,
	NULL
};

/* Attribute group for format specifiers */
static struct attribute_group iommu_pmu_format_attr_group = {
	.name = "format",
	.attrs = iommu_pmu_format_attrs,
};

/**
 * Table 17. Standard Events List
 *
 * event id, name
 * 0 do not count
 * 1 untranslated requests
 * 2 translated requests
 * 3 ATS translation requests
 * 4 TLB miss
 * 5 device directory walks
 * 6 process directory walks
 * 7 first-stage page table walks
 * 8 second-stage page table walks
 * 9-16383 reserved
 */

#define RISCV_IOMMU_PMU_EVENT_ATTR(_name, _string)				\
	PMU_EVENT_ATTR_STRING(_name, event_attr_##_name, _string)	\
									\
	static struct attribute *_name##_attr[] = {			\
		&event_attr_##_name.attr.attr, NULL			\
	};								\
									\
	static struct attribute_group _name = {				\
		.name = "events",					\
		.attrs = _name##_attr,					\
	}

RISCV_IOMMU_PMU_EVENT_ATTR(untranslated_requests, "event_id=1");
RISCV_IOMMU_PMU_EVENT_ATTR(translated_requests, "event_id=2");
RISCV_IOMMU_PMU_EVENT_ATTR(ats_translation_requests, "event_id=3");
RISCV_IOMMU_PMU_EVENT_ATTR(tlb_misses, "event_id=4");
RISCV_IOMMU_PMU_EVENT_ATTR(device_directory_walks, "event_id=5");
RISCV_IOMMU_PMU_EVENT_ATTR(process_directory_walks, "event_id=6");
RISCV_IOMMU_PMU_EVENT_ATTR(first_stage_page_table_walks, "event_id=7");
RISCV_IOMMU_PMU_EVENT_ATTR(second_stage_page_table_walks, "event_id=8");

static struct attribute *event_attr[] = {
	&event_attr_untranslated_requests.attr.attr,
	&event_attr_translated_requests.attr.attr,
	&event_attr_ats_translation_requests.attr.attr,
	&event_attr_tlb_misses.attr.attr,
	&event_attr_device_directory_walks.attr.attr,
	&event_attr_process_directory_walks.attr.attr,
	&event_attr_first_stage_page_table_walks.attr.attr,
	&event_attr_second_stage_page_table_walks.attr.attr,
	NULL
};

/* Attribute group of event specifiers */
static struct attribute_group iommu_pmu_events_attr_group = {
	.name = "events",
	.attrs = event_attr,
};

static const struct attribute_group *riscv_iommu_pmu_attr_groups[] = {
	&iommu_pmu_format_attr_group,
	&iommu_pmu_events_attr_group,
	NULL
};

static const struct attribute_group *iommu_pmu_attr_update[] = {
	&event_id,
	NULL
};

/**
 * Returns counter index (0-30). Will return -ENOSPC if no counters are available.
 */
static int get_available_counter(struct riscv_iommu_device *rv_pmu)
{
	int index;
	bool old;

	do {
		index = find_first_zero_bit(&rv_pmu->counters_used, RISCV_IOMMU_IOHPMEVT_CNT);
		if (index >= RISCV_IOMMU_IOHPMEVT_CNT)
			return -ENOSPC;

		old = test_and_set_bit(index, &rv_pmu->counters_used);
	} while (old);

	return index;
}

static void clear_used_counter(struct riscv_iommu_device *rv_pmu, int index)
{
	clear_bit(index, &rv_pmu->counters_used);
}


static int riscv_iommu_pmu_event_init(struct perf_event *event)
{
	struct hw_perf_event *hw = &event->hw;

	/* TODO: Make sure that the event is supported by this PMU. */

	hw->config = event->attr.config;
	local64_set(&event->count, 0);
	perf_event_update_userpage(event);

	return 0;
}

static void riscv_iommu_pmu_event_read(struct perf_event *event)
{
	int index = event->hw.idx;
	struct riscv_iommu_device *iommu_dev = perf_event_to_riscv_iommu_dev(event);
	u64 count_val = riscv_iommu_readq(iommu_dev, RISCV_IOMMU_REG_IOHPMCTR(index));

	local64_add(count_val, &event->count);
	perf_event_update_userpage(event);
}

static void riscv_iommu_pmu_start(struct perf_event *event, int flags)
{
	/* TODO: Make sure the counter is not inhibited (RISC-V IOMMU 5.20)
	 * Currently am just un-inhibiting all registers in iommu.c */

	struct riscv_iommu_device *iommu_dev = perf_event_to_riscv_iommu_dev(event);

	riscv_iommu_writeq(iommu_dev, RISCV_IOMMU_REG_IOHPMCTR(event->hw.idx), 0);
	riscv_iommu_writeq(iommu_dev, RISCV_IOMMU_REG_IOHPMEVT(event->hw.idx), event->hw.config);

	perf_event_update_userpage(event);
}

static void riscv_iommu_pmu_stop(struct perf_event *event, int flags)
{
	struct riscv_iommu_device *iommu_dev = perf_event_to_riscv_iommu_dev(event);

	riscv_iommu_pmu_event_read(event);
	perf_event_update_userpage(event);

	riscv_iommu_writeq(iommu_dev, RISCV_IOMMU_REG_IOHPMEVT(event->hw.idx), 0);
}

static int riscv_iommu_pmu_add(struct perf_event *event, int flags)
{
	struct riscv_iommu_device *rv_pmu = pmu_to_riscv_iommu_dev(event->pmu);

	event->hw.idx = get_available_counter(rv_pmu);
	if (event->hw.idx < 0)
		return event->hw.idx;

	/* TODO: Verify that idx register is writable. */

	if (flags & PERF_EF_START)
		riscv_iommu_pmu_start(event, 0);
	return 0;
}

static void riscv_iommu_pmu_del(struct perf_event *event, int flags)
{
	struct riscv_iommu_device *rv_pmu = pmu_to_riscv_iommu_dev(event->pmu);

	riscv_iommu_pmu_stop(event, PERF_EF_UPDATE);
	clear_used_counter(rv_pmu, event->hw.idx);
	perf_event_update_userpage(event);
}

int riscv_iommu_pmu_register(struct riscv_iommu_device *iommu)
{
	riscv_iommu_writeq(iommu, RISCV_IOMMU_REG_IOCOUNTINH, 0);
	iommu->counters_used = 0;
	iommu->pmu.name = kasprintf(GFP_KERNEL, "riscv_iommu_%llx",
				 iommu->reg_phys);

	iommu->pmu.event_init	= riscv_iommu_pmu_event_init;
	iommu->pmu.add		= riscv_iommu_pmu_add;
	iommu->pmu.del		= riscv_iommu_pmu_del;
	iommu->pmu.start	= riscv_iommu_pmu_start;
	iommu->pmu.stop		= riscv_iommu_pmu_stop;
	iommu->pmu.read		= riscv_iommu_pmu_event_read;
	iommu->pmu.attr_groups	= riscv_iommu_pmu_attr_groups;
	iommu->pmu.module	= THIS_MODULE;

	return perf_pmu_register(&iommu->pmu, iommu->pmu.name, -1);
}

void riscv_iommu_pmu_unregister(struct riscv_iommu_device *iommu)
{
	if (iommu->cap & RISCV_IOMMU_CAP_HPM) {
		kfree(iommu->pmu.name);
		perf_pmu_unregister(&iommu->pmu);
	}
}

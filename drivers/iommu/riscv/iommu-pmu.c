// SPDX-License-Identifier: GPL-2.0-only
/*
 * IOMMU API for RISC-V architected Ziommu implementations.
 *
 * Copyright © 2023 Rivos Inc.
 *
 * Authors
 *  Pranoy Dutta <prydt@rivosinc.com>
 */

#include "iommu.h"
#include "iommu-pmu.h"

#define IOMMU_PMU_ATTR(_name, _format, _filter)			\
	PMU_FORMAT_ATTR(_name, _format);			\
								\
	static struct attribute *_name##_attr[] = {		\
		&format_attr_##_name.attr, 			\
		NULL						\
	};                    					\
								\
	static struct attribute_group _name = {			\
		.name = "format",				\
		.attrs = _name##_attr,				\
	};

/**
 * Filtering Options for HPM (Hardware Performance Monitoring unit)
 * 
 * 14:0 event id (what event to count, 0 is no event)
 * 15 DMASK (if partial matching of DID_GSCID is performed in txn)
 * 35:16 PID_PSCID (process_id if IDT==0, else PSCID)
 * 59:36 DID_GSCID (device_id if IDT==0, else GSCID)
 * 60 PV_PSCV (if set only txn with matching process_id/PSCID are counted)
 * 61 DV_GSCV (if set only txn with matching device_id/GSCID are counted)
 * 62 IDT (id type, if set DID_GSCID is GSCID and PID_PSCID is is PSCID, else device_id and process_id respectively)
 * 63 OF (overflow status / interrupt disable)
 */
IOMMU_PMU_ATTR(event_id, "config:0-14", IOMMU_PMU_FILTER_EVENT_ID)
IOMMU_PMU_ATTR(dmask, "config:15", IOMMU_PMU_FILTER_DMASK)
IOMMU_PMU_ATTR(pid_pscid, "config:16-35", IOMMU_PMU_FILTER_PID_PSCID)
IOMMU_PMU_ATTR(did_gscid, "config:36-59", IOMMU_PMU_FILTER_DID_GSCID)
IOMMU_PMU_ATTR(pv_pscv, "config:60", IOMMU_PMU_FILTER_PV_PSCV)
IOMMU_PMU_ATTR(dv_gscv, "config:61", IOMMU_PMU_FILTER_DV_GSCV)
IOMMU_PMU_ATTR(idt, "config:62", IOMMU_PMU_FILTER_IDT)
IOMMU_PMU_ATTR(of, "config:63", IOMMU_PMU_FILTER_OF)

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

// Attribute group for format specifiers
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

#define IOMMU_PMU_EVENT_ATTR(_name, _string)				\
	PMU_EVENT_ATTR_STRING(_name, event_attr_##_name, _string)	\
									\
	static struct attribute *_name##_attr[] = {			\
		&event_attr_##_name.attr.attr, NULL			\
	};								\
									\
	static struct attribute_group _name = {				\
		.name = "events",					\
		.attrs = _name##_attr,					\
	};

IOMMU_PMU_EVENT_ATTR(do_not_count, "event_id=0")
IOMMU_PMU_EVENT_ATTR(untranslated_requests, "event_id=1")
IOMMU_PMU_EVENT_ATTR(translated_requests, "event_id=2")
IOMMU_PMU_EVENT_ATTR(ats_translation_requests, "event_id=3")
IOMMU_PMU_EVENT_ATTR(tlb_misses, "event_id=4")
IOMMU_PMU_EVENT_ATTR(device_directory_walks, "event_id=5")
IOMMU_PMU_EVENT_ATTR(process_directory_walks, "event_id=6")
IOMMU_PMU_EVENT_ATTR(first_stage_page_table_walks, "event_id=7")
IOMMU_PMU_EVENT_ATTR(second_stage_page_table_walks, "event_id=8")

static struct attribute *event_attr[] = {
	&event_attr_do_not_count.attr.attr,
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

// Attribute group of event specifiers
static struct attribute_group iommu_pmu_events_attr_group = {
	.name = "events",
	.attrs = event_attr,
};

static const struct attribute_group *iommu_pmu_attr_groups[] = {
	&iommu_pmu_format_attr_group,
	&iommu_pmu_events_attr_group,
	NULL
};

static const struct attribute_group *iommu_pmu_attr_update[] = {
	&event_id,
	NULL
};

/* TODO: Implement functions to read from HPM. */
int iommu_pmu_event_init(struct perf_event *event)
{
	return 0;
}
void iommu_pmu_event_update(struct perf_event *event)
{
}

void iommu_pmu_enable(struct pmu *pmu)
{
}
void iommu_pmu_disable(struct pmu *pmu)
{
}

int iommu_pmu_add(struct perf_event *event, int flags)
{
	return -1;
}
void iommu_pmu_del(struct perf_event *event, int flags)
{
}

void iommu_pmu_start(struct perf_event *event, int flags)
{
}
void iommu_pmu_stop(struct perf_event *event, int flags)
{
}

int iommu_pmu_register(struct riscv_iommu_pmu *iommu_pmu)
{
	iommu_pmu->pmu.name = kasprintf(GFP_KERNEL, "riscv_iommu_%llx",
				 iommu_pmu->iommu_dev->reg_phys);
	iommu_pmu->pmu.event_init 	= iommu_pmu_event_init;
	iommu_pmu->pmu.pmu_enable 	= iommu_pmu_enable;
	iommu_pmu->pmu.pmu_disable 	= iommu_pmu_disable;
	iommu_pmu->pmu.add 		= iommu_pmu_add;
	iommu_pmu->pmu.del 		= iommu_pmu_del;
	iommu_pmu->pmu.start 		= iommu_pmu_start;
	iommu_pmu->pmu.stop 		= iommu_pmu_stop;
	iommu_pmu->pmu.read 		= iommu_pmu_event_update;
	iommu_pmu->pmu.attr_groups 	= iommu_pmu_attr_groups;
	iommu_pmu->pmu.module 		= THIS_MODULE;
	/* TODO: set attr_update and capabilities */
	// iommu_pmu->pmu.attr_update = iommu_pmu_attr_update;
	// iommu_pmu->pmu.capabilities

	return perf_pmu_register(&iommu_pmu->pmu, iommu_pmu->pmu.name, -1);
}

void iommu_pmu_unregister(struct riscv_iommu_pmu *iommu_pmu)
{
	kfree(iommu_pmu->pmu.name);
	perf_pmu_unregister(&iommu_pmu->pmu);
}

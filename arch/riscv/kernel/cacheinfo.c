// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017 SiFive
 */

#include <linux/cpu.h>
#include <linux/of.h>
#include <asm/cacheinfo.h>

static struct riscv_cacheinfo_ops *rv_cache_ops;

void riscv_set_cacheinfo_ops(struct riscv_cacheinfo_ops *ops)
{
	rv_cache_ops = ops;
}
EXPORT_SYMBOL_GPL(riscv_set_cacheinfo_ops);

const struct attribute_group *
cache_get_priv_group(struct cacheinfo *this_leaf)
{
	if (rv_cache_ops && rv_cache_ops->get_priv_group)
		return rv_cache_ops->get_priv_group(this_leaf);
	return NULL;
}

static struct cacheinfo *get_cacheinfo(u32 level, enum cache_type type)
{
	/*
	 * Using raw_smp_processor_id() elides a preemptability check, but this
	 * is really indicative of a larger problem: the cacheinfo UABI assumes
	 * that cores have a homonogenous view of the cache hierarchy.  That
	 * happens to be the case for the current set of RISC-V systems, but
	 * likely won't be true in general.  Since there's no way to provide
	 * correct information for these systems via the current UABI we're
	 * just eliding the check for now.
	 */
	struct cpu_cacheinfo *this_cpu_ci = get_cpu_cacheinfo(raw_smp_processor_id());
	struct cacheinfo *this_leaf;
	int index;

	for (index = 0; index < this_cpu_ci->num_leaves; index++) {
		this_leaf = this_cpu_ci->info_list + index;
		if (this_leaf->level == level && this_leaf->type == type)
			return this_leaf;
	}

	return NULL;
}

uintptr_t get_cache_size(u32 level, enum cache_type type)
{
	struct cacheinfo *this_leaf = get_cacheinfo(level, type);

	return this_leaf ? this_leaf->size : 0;
}

uintptr_t get_cache_geometry(u32 level, enum cache_type type)
{
	struct cacheinfo *this_leaf = get_cacheinfo(level, type);

	return this_leaf ? (this_leaf->ways_of_associativity << 16 |
			    this_leaf->coherency_line_size) :
			   0;
}

static void ci_leaf_init(struct cacheinfo *this_leaf,
			 enum cache_type type, unsigned int level)
{
	this_leaf->level = level;
	this_leaf->type = type;
}

int populate_cache_leaves(unsigned int cpu)
{
	struct cpu_cacheinfo *this_cpu_ci = get_cpu_cacheinfo(cpu);
	struct cacheinfo *this_leaf = this_cpu_ci->info_list;
	unsigned int level, idx;

	for (idx = 0, level = 1; level <= this_cpu_ci->num_levels &&
	     idx < this_cpu_ci->num_leaves; idx++, level++) {
		/*
		 * Since the RISC-V architecture doesn't provide any register for detecting the
		 * Cache Level and Cache type, this assumes that:
		 * - There cannot be any split caches (data/instruction) above a unified cache.
		 * - Data/instruction caches come in pairs.
		 * - Significant work is required elsewhere to fully support data/instruction-only
		 *   type caches.
		 * - The above assumptions are based on conventional system design and known
		 *   examples.
		 */
		if (level == 1) {
			ci_leaf_init(this_leaf++, CACHE_TYPE_DATA, level);
			ci_leaf_init(this_leaf++, CACHE_TYPE_INST, level);
		} else {
			ci_leaf_init(this_leaf++, CACHE_TYPE_UNIFIED, level);
		}
	}

	return 0;
}

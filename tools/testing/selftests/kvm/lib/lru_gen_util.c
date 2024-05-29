// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024, Google LLC.
 */

#include <time.h>

#include "lru_gen_util.h"

/*
 * Tracks state while we parse memcg lru_gen stats. The file we're parsing is
 * structured like this (some extra whitespace elided):
 *
 * memcg (id) (path)
 * node (id)
 * (gen_nr) (age_in_ms) (nr_anon_pages) (nr_file_pages)
 */
struct memcg_stats_parse_context {
	bool consumed; /* Whether or not this line was consumed */
	/* Next parse handler to invoke */
	void (*next_handler)(struct memcg_stats *,
			     struct memcg_stats_parse_context *, char *);
	int current_node_idx; /* Current index in nodes array */
	const char *name; /* The name of the memcg we're looking for */
};

static void memcg_stats_handle_searching(struct memcg_stats *stats,
					 struct memcg_stats_parse_context *ctx,
					 char *line);
static void memcg_stats_handle_in_memcg(struct memcg_stats *stats,
					struct memcg_stats_parse_context *ctx,
					char *line);
static void memcg_stats_handle_in_node(struct memcg_stats *stats,
				       struct memcg_stats_parse_context *ctx,
				       char *line);

struct split_iterator {
	char *str;
	char *save;
};

static char *split_next(struct split_iterator *it)
{
	char *ret = strtok_r(it->str, " \t\n\r", &it->save);

	it->str = NULL;
	return ret;
}

static void memcg_stats_handle_searching(struct memcg_stats *stats,
					 struct memcg_stats_parse_context *ctx,
					 char *line)
{
	struct split_iterator it = { .str = line };
	char *prefix = split_next(&it);
	char *memcg_id = split_next(&it);
	char *memcg_name = split_next(&it);
	char *end;

	ctx->consumed = true;

	if (!prefix || strcmp("memcg", prefix))
		return; /* Not a memcg line (maybe empty), skip */

	TEST_ASSERT(memcg_id && memcg_name,
		    "malformed memcg line; no memcg id or memcg_name");

	if (strcmp(memcg_name + 1, ctx->name))
		return; /* Wrong memcg, skip */

	/* Found it! */

	stats->memcg_id = strtoul(memcg_id, &end, 10);
	TEST_ASSERT(*end == '\0', "malformed memcg id '%s'", memcg_id);
	if (!stats->memcg_id)
		return; /* Removed memcg? */

	ctx->next_handler = memcg_stats_handle_in_memcg;
}

static void memcg_stats_handle_in_memcg(struct memcg_stats *stats,
					struct memcg_stats_parse_context *ctx,
					char *line)
{
	struct split_iterator it = { .str = line };
	char *prefix = split_next(&it);
	char *id = split_next(&it);
	long found_node_id;
	char *end;

	ctx->consumed = true;
	ctx->current_node_idx = -1;

	if (!prefix)
		return; /* Skip empty lines */

	if (!strcmp("memcg", prefix)) {
		/* Memcg done, found next one; stop. */
		ctx->next_handler = NULL;
		return;
	} else if (strcmp("node", prefix))
		TEST_ASSERT(false, "found malformed line after 'memcg ...',"
				   "token: '%s'", prefix);

	/* At this point we know we have a node line. Parse the ID. */

	TEST_ASSERT(id, "malformed node line; no node id");

	found_node_id = strtol(id, &end, 10);
	TEST_ASSERT(*end == '\0', "malformed node id '%s'", id);

	ctx->current_node_idx = stats->nr_nodes++;
	TEST_ASSERT(ctx->current_node_idx < MAX_NR_NODES,
		    "memcg has stats for too many nodes, max is %d",
		    MAX_NR_NODES);
	stats->nodes[ctx->current_node_idx].node = found_node_id;

	ctx->next_handler = memcg_stats_handle_in_node;
}

static void memcg_stats_handle_in_node(struct memcg_stats *stats,
				       struct memcg_stats_parse_context *ctx,
				       char *line)
{
	/* Have to copy since we might not consume */
	char *my_line = strdup(line);
	struct split_iterator it = { .str = my_line };
	char *gen, *age, *nr_anon, *nr_file;
	struct node_stats *node_stats;
	struct generation_stats *gen_stats;
	char *end;

	TEST_ASSERT(it.str, "failed to copy input line");

	gen = split_next(&it);

	/* Skip empty lines */
	if (!gen)
		goto out_consume; /* Skip empty lines */

	if (!strcmp("memcg", gen) || !strcmp("node", gen)) {
		/*
		 * Reached next memcg or node section. Don't consume, let the
		 * other handler deal with this.
		 */
		ctx->next_handler = memcg_stats_handle_in_memcg;
		goto out;
	}

	node_stats = &stats->nodes[ctx->current_node_idx];
	TEST_ASSERT(node_stats->nr_gens < MAX_NR_GENS,
		    "found too many generation lines; max is %d",
		    MAX_NR_GENS);
	gen_stats = &node_stats->gens[node_stats->nr_gens++];

	age = split_next(&it);
	nr_anon = split_next(&it);
	nr_file = split_next(&it);

	TEST_ASSERT(age && nr_anon && nr_file,
		    "malformed generation line; not enough tokens");

	gen_stats->gen = (int)strtol(gen, &end, 10);
	TEST_ASSERT(*end == '\0', "malformed generation number '%s'", gen);

	gen_stats->age_ms = strtol(age, &end, 10);
	TEST_ASSERT(*end == '\0', "malformed generation age '%s'", age);

	gen_stats->nr_anon = strtol(nr_anon, &end, 10);
	TEST_ASSERT(*end == '\0', "malformed anonymous page count '%s'",
		    nr_anon);

	gen_stats->nr_file = strtol(nr_file, &end, 10);
	TEST_ASSERT(*end == '\0', "malformed file page count '%s'", nr_file);

out_consume:
	ctx->consumed = true;
out:
	free(my_line);
}

/* Pretty-print lru_gen @stats. */
void print_memcg_stats(const struct memcg_stats *stats, const char *name)
{
	int node, gen;

	fprintf(stderr, "stats for memcg %s (id %lu):\n",
			name, stats->memcg_id);
	for (node = 0; node < stats->nr_nodes; ++node) {
		fprintf(stderr, "\tnode %d\n", stats->nodes[node].node);
		for (gen = 0; gen < stats->nodes[node].nr_gens; ++gen) {
			const struct generation_stats *gstats =
				&stats->nodes[node].gens[gen];

			fprintf(stderr,
				"\t\tgen %d\tage_ms %ld"
				"\tnr_anon %ld\tnr_file %ld\n",
				gstats->gen, gstats->age_ms, gstats->nr_anon,
				gstats->nr_file);
		}
	}
}

/* Re-read lru_gen debugfs information for @memcg into @stats. */
void read_memcg_stats(struct memcg_stats *stats, const char *memcg)
{
	FILE *f;
	ssize_t read = 0;
	char *line = NULL;
	size_t bufsz;
	struct memcg_stats_parse_context ctx = {
		.next_handler = memcg_stats_handle_searching,
		.name = memcg,
	};

	memset(stats, 0, sizeof(struct memcg_stats));

	f = fopen(DEBUGFS_LRU_GEN, "r");
	TEST_ASSERT(f, "fopen(%s) failed", DEBUGFS_LRU_GEN);

	while (ctx.next_handler && (read = getline(&line, &bufsz, f)) > 0) {
		ctx.consumed = false;

		do {
			ctx.next_handler(stats, &ctx, line);
			if (!ctx.next_handler)
				break;
		} while (!ctx.consumed);
	}

	if (read < 0 && !feof(f))
		TEST_ASSERT(false, "getline(%s) failed", DEBUGFS_LRU_GEN);

	TEST_ASSERT(stats->memcg_id > 0, "Couldn't find memcg: %s\n"
		    "Did the memcg get created in the proper mount?",
		    memcg);
	if (line)
		free(line);
	TEST_ASSERT(!fclose(f), "fclose(%s) failed", DEBUGFS_LRU_GEN);
}

/*
 * Find all pages tracked by lru_gen for this memcg in generation @target_gen.
 *
 * If @target_gen is negative, look for all generations.
 */
static long sum_memcg_stats_for_gen(int target_gen,
				    const struct memcg_stats *stats)
{
	int node, gen;
	long total_nr = 0;

	for (node = 0; node < stats->nr_nodes; ++node) {
		const struct node_stats *node_stats = &stats->nodes[node];

		for (gen = 0; gen < node_stats->nr_gens; ++gen) {
			const struct generation_stats *gen_stats =
				&node_stats->gens[gen];

			if (target_gen >= 0 && gen_stats->gen != target_gen)
				continue;

			total_nr += gen_stats->nr_anon + gen_stats->nr_file;
		}
	}

	return total_nr;
}

/* Find all pages tracked by lru_gen for this memcg. */
long sum_memcg_stats(const struct memcg_stats *stats)
{
	return sum_memcg_stats_for_gen(-1, stats);
}

/* Read the memcg stats and optionally print if this is a debug build. */
void read_print_memcg_stats(struct memcg_stats *stats, const char *memcg)
{
	read_memcg_stats(stats, memcg);
#ifdef DEBUG
	print_memcg_stats(stats, memcg);
#endif
}

/*
 * If lru_gen aging should force page table scanning.
 *
 * If you want to set this to false, you will need to do eviction
 * before doing extra aging passes.
 */
static const bool force_scan = true;

static void run_aging_impl(unsigned long memcg_id, int node_id, int max_gen)
{
	FILE *f = fopen(DEBUGFS_LRU_GEN, "w");
	char *command;
	size_t sz;

	TEST_ASSERT(f, "fopen(%s) failed", DEBUGFS_LRU_GEN);
	sz = asprintf(&command, "+ %lu %d %d 1 %d\n",
		      memcg_id, node_id, max_gen, force_scan);
	TEST_ASSERT(sz > 0, "creating aging command failed");

	pr_debug("Running aging command: %s", command);
	if (fwrite(command, sizeof(char), sz, f) < sz) {
		TEST_ASSERT(false, "writing aging command %s to %s failed",
			    command, DEBUGFS_LRU_GEN);
	}

	TEST_ASSERT(!fclose(f), "fclose(%s) failed", DEBUGFS_LRU_GEN);
}

static void _lru_gen_do_aging(struct memcg_stats *stats, const char *memcg,
			      bool verbose)
{
	int node, gen;
	struct timespec ts_start;
	struct timespec ts_elapsed;

	pr_debug("lru_gen: invoking aging...\n");

	/* Must read memcg stats to construct the proper aging command. */
	read_print_memcg_stats(stats, memcg);

	if (verbose)
		clock_gettime(CLOCK_MONOTONIC, &ts_start);

	for (node = 0; node < stats->nr_nodes; ++node) {
		int max_gen = 0;

		for (gen = 0; gen < stats->nodes[node].nr_gens; ++gen) {
			int this_gen = stats->nodes[node].gens[gen].gen;

			max_gen = max_gen > this_gen ? max_gen : this_gen;
		}

		run_aging_impl(stats->memcg_id, stats->nodes[node].node,
			       max_gen);
	}

	if (verbose) {
		ts_elapsed = timespec_elapsed(ts_start);
		pr_info("%-30s: %ld.%09lds\n", "lru_gen: Aging",
			ts_elapsed.tv_sec, ts_elapsed.tv_nsec);
	}

	/* Re-read so callers get updated information */
	read_print_memcg_stats(stats, memcg);
}

/* Do aging, and print how long it took. */
void lru_gen_do_aging(struct memcg_stats *stats, const char *memcg)
{
	return _lru_gen_do_aging(stats, memcg, true);
}

/* Do aging, don't print anything. */
void lru_gen_do_aging_quiet(struct memcg_stats *stats, const char *memcg)
{
	return _lru_gen_do_aging(stats, memcg, false);
}

/*
 * Find which generation contains more than half of @total_pages, assuming that
 * such a generation exists.
 */
int lru_gen_find_generation(const struct memcg_stats *stats,
			    unsigned long total_pages)
{
	int node, gen, gen_idx, min_gen = INT_MAX, max_gen = -1;

	for (node = 0; node < stats->nr_nodes; ++node)
		for (gen_idx = 0; gen_idx < stats->nodes[node].nr_gens;
		     ++gen_idx) {
			gen = stats->nodes[node].gens[gen_idx].gen;
			max_gen = gen > max_gen ? gen : max_gen;
			min_gen = gen < min_gen ? gen : min_gen;
		}

	for (gen = min_gen; gen < max_gen; ++gen)
		/* See if the most pages are in this generation. */
		if (sum_memcg_stats_for_gen(gen, stats) >
				total_pages / 2)
			return gen;

	TEST_ASSERT(false, "No generation includes majority of %lu pages.",
		    total_pages);

	/* unreachable, but make the compiler happy */
	return -1;
}

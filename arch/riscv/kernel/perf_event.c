#include <linux/perf/riscv_pmu.h>
#include <linux/sched_clock.h>

void arch_perf_update_userpage(struct perf_event *event,
                               struct perf_event_mmap_page *userpg, u64 now)
{
        struct riscv_pmu *rvpmu = to_riscv_pmu(event->pmu);
        struct clock_read_data *rd;
        unsigned int seq;
        u64 ns;

        userpg->cap_user_time = 0;
        userpg->cap_user_time_zero = 0;
        userpg->cap_user_time_short = 0;
        userpg->cap_user_rdpmc =
                !!(event->hw.flags & PERF_EVENT_FLAG_USER_READ_CNT);

        /*
         * The counters are 64-bit but the priv spec doesn't mandate all the
         * bits to be implemented: that's why, counter width can vary based on
         * the cpu vendor.
         */
        userpg->pmc_width = rvpmu->ctr_get_width(event->hw.idx);

        do {
                rd = sched_clock_read_begin(&seq);

                userpg->time_mult = rd->mult;
                userpg->time_shift = rd->shift;
                userpg->time_zero = rd->epoch_ns;
                userpg->time_cycles = rd->epoch_cyc;
                userpg->time_mask = rd->sched_clock_mask;

                /*
                 * Subtract the cycle base, such that software that
                 * doesn't know about cap_user_time_short still 'works'
                 * assuming no wraps.
                 */
                ns = mul_u64_u32_shr(rd->epoch_cyc, rd->mult, rd->shift);
                userpg->time_zero -= ns;

        } while (sched_clock_read_retry(seq));

        userpg->time_offset = userpg->time_zero - now;

        /*
         * time_shift is not expected to be greater than 31 due to
         * the original published conversion algorithm shifting a
         * 32-bit value (now specifies a 64-bit value) - refer
         * perf_event_mmap_page documentation in perf_event.h.
         */
        if (userpg->time_shift == 32) {
                userpg->time_shift = 31;
                userpg->time_mult >>= 1;
        }

        /*
         * Internal timekeeping for enabled/running/stopped times
         * is always computed with the sched_clock.
         */
        userpg->cap_user_time = 1;
        userpg->cap_user_time_zero = 1;
        userpg->cap_user_time_short = 1;
}

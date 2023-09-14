/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * timer test specific header
 *
 * Copyright (C) 2018, Google LLC
 */

#ifndef SELFTEST_KVM_TIMER_TEST_H
#define SELFTEST_KVM_TIMER_TEST_H

#include "kvm_util.h"

#define NR_VCPUS_DEF            4
#define NR_TEST_ITERS_DEF       5
#define TIMER_TEST_PERIOD_MS_DEF    10
#define TIMER_TEST_ERR_MARGIN_US    100
#define TIMER_TEST_MIGRATION_FREQ_MS    2

/* Timer test cmdline parameters */
struct test_args {
	int nr_vcpus;
	int nr_iter;
	int timer_period_ms;
	int migration_freq_ms;
	struct kvm_arm_counter_offset offset;
};

/* Shared variables between host and guest */
struct test_vcpu_shared_data {
	int nr_iter;
	int guest_stage;
	uint64_t xcnt;
};

extern struct test_args test_args;
extern struct kvm_vcpu *vcpus[];
extern struct test_vcpu_shared_data vcpu_shared_data[];

struct kvm_vm *test_vm_create(void);
void test_vm_cleanup(struct kvm_vm *vm);

#endif /* SELFTEST_KVM_TIMER_TEST_H */

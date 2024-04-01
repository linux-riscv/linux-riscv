// SPDX-License-Identifier: GPL-2.0
/*
 * sbi_test - SBI API test for KVM's SBI implementation.
 *
 * Copyright (c) 2024 Intel Corporation
 *
 * Test cover the following SBI extentions:
 *  - Base: All functions in this extension should be supported
 */

#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"

/*
 * Test that all functions in the base extension must be supported
 */
static void base_ext_guest_code(void)
{
	struct sbiret ret;

	/*
	 * Since the base extension was introduced in SBI Spec v0.2,
	 * assert if the implemented SBI version is below 0.2.
	 */
	ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_SPEC_VERSION, 0,
			0, 0, 0, 0, 0);
	__GUEST_ASSERT(!ret.error && ret.value >= 2, "Get Spec Version Error: ret.error=%ld, "
			"ret.value=%ld\n", ret.error, ret.value);

	ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_IMP_ID, 0,
			0, 0, 0, 0, 0);
	__GUEST_ASSERT(!ret.error && ret.value == 3, "Get Imp ID Error: ret.error=%ld, "
			"ret.value=%ld\n",
			ret.error, ret.value);

	ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_IMP_VERSION, 0,
			0, 0, 0, 0, 0);
	__GUEST_ASSERT(!ret.error, "Get Imp Version Error: ret.error=%ld\n", ret.error);

	ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_PROBE_EXT, SBI_EXT_BASE,
			0, 0, 0, 0, 0);
	__GUEST_ASSERT(!ret.error && ret.value == 1, "Probe ext Error: ret.error=%ld, "
			"ret.value=%ld\n",
			ret.error, ret.value);

	ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_MVENDORID, 0,
			0, 0, 0, 0, 0);
	__GUEST_ASSERT(!ret.error, "Get Machine Vendor ID Error: ret.error=%ld\n", ret.error);

	ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_MARCHID, 0,
			0, 0, 0, 0, 0);
	__GUEST_ASSERT(!ret.error, "Get Machine Arch ID Error: ret.error=%ld\n", ret.error);

	ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_MIMPID, 0,
			0, 0, 0, 0, 0);
	__GUEST_ASSERT(!ret.error, "Get Machine Imp ID Error: ret.error=%ld\n", ret.error);

	GUEST_DONE();
}

static void sbi_base_ext_test(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct ucall uc;

	vm = vm_create_with_one_vcpu(&vcpu, base_ext_guest_code);
	while (1) {
		vcpu_run(vcpu);
		TEST_ASSERT(vcpu->run->exit_reason == UCALL_EXIT_REASON,
			    "Unexpected exit reason: %u (%s),",
			    vcpu->run->exit_reason, exit_reason_str(vcpu->run->exit_reason));

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_DONE:
			goto done;
		case UCALL_ABORT:
			fprintf(stderr, "Guest assert failed!\n");
			REPORT_GUEST_ASSERT(uc);
		default:
			TEST_FAIL("Unexpected ucall %lu", uc.cmd);
		}
	}

done:
	kvm_vm_free(vm);
}

int main(void)
{
	sbi_base_ext_test();

	return 0;
}

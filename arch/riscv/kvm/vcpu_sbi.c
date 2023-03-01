// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *     Atish Patra <atish.patra@wdc.com>
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <asm/sbi.h>
#include <asm/kvm_vcpu_sbi.h>

static int kvm_linux_err_map_sbi(int err)
{
	switch (err) {
	case 0:
		return SBI_SUCCESS;
	case -EPERM:
		return SBI_ERR_DENIED;
	case -EINVAL:
		return SBI_ERR_INVALID_PARAM;
	case -EFAULT:
		return SBI_ERR_INVALID_ADDRESS;
	case -EOPNOTSUPP:
		return SBI_ERR_NOT_SUPPORTED;
	case -EALREADY:
		return SBI_ERR_ALREADY_AVAILABLE;
	default:
		return SBI_ERR_FAILURE;
	};
}

#ifndef CONFIG_RISCV_SBI_V01
static const struct kvm_vcpu_sbi_extension vcpu_sbi_ext_v01 = {
	.extid_start = -1UL,
	.extid_end = -1UL,
	.handler = NULL,
};
#endif

struct kvm_riscv_sbi_extension_entry {
	enum KVM_RISCV_SBI_EXT_ID dis_idx;
	const struct kvm_vcpu_sbi_extension *ext_ptr;
};

static const struct kvm_riscv_sbi_extension_entry sbi_ext[] = {
	{
		.dis_idx = KVM_RISCV_SBI_EXT_V01,
		.ext_ptr = &vcpu_sbi_ext_v01,
	},
	{
		.dis_idx = KVM_RISCV_SBI_EXT_MAX, /* Can't be disabled */
		.ext_ptr = &vcpu_sbi_ext_base,
	},
	{
		.dis_idx = KVM_RISCV_SBI_EXT_TIME,
		.ext_ptr = &vcpu_sbi_ext_time,
	},
	{
		.dis_idx = KVM_RISCV_SBI_EXT_IPI,
		.ext_ptr = &vcpu_sbi_ext_ipi,
	},
	{
		.dis_idx = KVM_RISCV_SBI_EXT_RFENCE,
		.ext_ptr = &vcpu_sbi_ext_rfence,
	},
	{
		.dis_idx = KVM_RISCV_SBI_EXT_SRST,
		.ext_ptr = &vcpu_sbi_ext_srst,
	},
	{
		.dis_idx = KVM_RISCV_SBI_EXT_HSM,
		.ext_ptr = &vcpu_sbi_ext_hsm,
	},
	{
		.dis_idx = KVM_RISCV_SBI_EXT_EXPERIMENTAL,
		.ext_ptr = &vcpu_sbi_ext_experimental,
	},
	{
		.dis_idx = KVM_RISCV_SBI_EXT_VENDOR,
		.ext_ptr = &vcpu_sbi_ext_vendor,
	},
};

void kvm_riscv_vcpu_sbi_forward(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	struct kvm_cpu_context *cp = &vcpu->arch.guest_context;

	vcpu->arch.sbi_context.return_handled = 0;
	vcpu->stat.ecall_exit_stat++;
	run->exit_reason = KVM_EXIT_RISCV_SBI;
	run->riscv_sbi.extension_id = cp->a7;
	run->riscv_sbi.function_id = cp->a6;
	run->riscv_sbi.args[0] = cp->a0;
	run->riscv_sbi.args[1] = cp->a1;
	run->riscv_sbi.args[2] = cp->a2;
	run->riscv_sbi.args[3] = cp->a3;
	run->riscv_sbi.args[4] = cp->a4;
	run->riscv_sbi.args[5] = cp->a5;
	run->riscv_sbi.ret[0] = cp->a0;
	run->riscv_sbi.ret[1] = cp->a1;
}

void kvm_riscv_vcpu_sbi_system_reset(struct kvm_vcpu *vcpu,
				     struct kvm_run *run,
				     u32 type, u64 reason)
{
	unsigned long i;
	struct kvm_vcpu *tmp;

	kvm_for_each_vcpu(i, tmp, vcpu->kvm)
		tmp->arch.power_off = true;
	kvm_make_all_cpus_request(vcpu->kvm, KVM_REQ_SLEEP);

	memset(&run->system_event, 0, sizeof(run->system_event));
	run->system_event.type = type;
	run->system_event.ndata = 1;
	run->system_event.data[0] = reason;
	run->exit_reason = KVM_EXIT_SYSTEM_EVENT;
}

int kvm_riscv_vcpu_sbi_return(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	struct kvm_cpu_context *cp = &vcpu->arch.guest_context;

	/* Handle SBI return only once */
	if (vcpu->arch.sbi_context.return_handled)
		return 0;
	vcpu->arch.sbi_context.return_handled = 1;

	/* Update return values */
	cp->a0 = run->riscv_sbi.ret[0];
	cp->a1 = run->riscv_sbi.ret[1];

	/* Move to next instruction */
	vcpu->arch.guest_context.sepc += 4;

	return 0;
}

int kvm_riscv_vcpu_set_reg_sbi_ext(struct kvm_vcpu *vcpu,
				   const struct kvm_one_reg *reg)
{
	unsigned long __user *uaddr =
			(unsigned long __user *)(unsigned long)reg->addr;
	unsigned long reg_num = reg->id & ~(KVM_REG_ARCH_MASK |
					    KVM_REG_SIZE_MASK |
					    KVM_REG_RISCV_SBI_EXT);
	unsigned long i, reg_val;
	const struct kvm_riscv_sbi_extension_entry *sext = NULL;
	struct kvm_vcpu_sbi_context *scontext = &vcpu->arch.sbi_context;

	if (KVM_REG_SIZE(reg->id) != sizeof(unsigned long))
		return -EINVAL;

	if (copy_from_user(&reg_val, uaddr, KVM_REG_SIZE(reg->id)))
		return -EFAULT;

	if (reg_num >= KVM_RISCV_SBI_EXT_MAX ||
	    (reg_val != 1 && reg_val != 0))
		return -EINVAL;

	if (vcpu->arch.ran_atleast_once)
		return -EBUSY;

	for (i = 0; i < ARRAY_SIZE(sbi_ext); i++) {
		if (sbi_ext[i].dis_idx == reg_num) {
			sext = &sbi_ext[i];
			break;
		}
	}
	if (!sext)
		return -ENOENT;

	scontext->extension_disabled[sext->dis_idx] = !reg_val;

	return 0;
}

int kvm_riscv_vcpu_get_reg_sbi_ext(struct kvm_vcpu *vcpu,
				   const struct kvm_one_reg *reg)
{
	unsigned long __user *uaddr =
			(unsigned long __user *)(unsigned long)reg->addr;
	unsigned long reg_num = reg->id & ~(KVM_REG_ARCH_MASK |
					    KVM_REG_SIZE_MASK |
					    KVM_REG_RISCV_SBI_EXT);
	unsigned long i, reg_val;
	const struct kvm_riscv_sbi_extension_entry *sext = NULL;
	struct kvm_vcpu_sbi_context *scontext = &vcpu->arch.sbi_context;

	if (KVM_REG_SIZE(reg->id) != sizeof(unsigned long))
		return -EINVAL;

	if (reg_num >= KVM_RISCV_SBI_EXT_MAX)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(sbi_ext); i++) {
		if (sbi_ext[i].dis_idx == reg_num) {
			sext = &sbi_ext[i];
			break;
		}
	}
	if (!sext)
		return -ENOENT;

	reg_val = !scontext->extension_disabled[sext->dis_idx];
	if (copy_to_user(uaddr, &reg_val, KVM_REG_SIZE(reg->id)))
		return -EFAULT;

	return 0;
}

const struct kvm_vcpu_sbi_extension *kvm_vcpu_sbi_find_ext(
				struct kvm_vcpu *vcpu, unsigned long extid)
{
	int i;
	const struct kvm_riscv_sbi_extension_entry *sext;
	struct kvm_vcpu_sbi_context *scontext = &vcpu->arch.sbi_context;

	for (i = 0; i < ARRAY_SIZE(sbi_ext); i++) {
		sext = &sbi_ext[i];
		if (sext->ext_ptr->extid_start <= extid &&
		    sext->ext_ptr->extid_end >= extid) {
			if (sext->dis_idx < KVM_RISCV_SBI_EXT_MAX &&
			    scontext->extension_disabled[sext->dis_idx])
				return NULL;
			return sbi_ext[i].ext_ptr;
		}
	}

	return NULL;
}

int kvm_riscv_vcpu_sbi_ecall(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	int ret = 1;
	bool next_sepc = true;
	bool userspace_exit = false;
	struct kvm_cpu_context *cp = &vcpu->arch.guest_context;
	const struct kvm_vcpu_sbi_extension *sbi_ext;
	struct kvm_cpu_trap utrap = { 0 };
	unsigned long out_val = 0;
	bool ext_is_v01 = false;

	sbi_ext = kvm_vcpu_sbi_find_ext(vcpu, cp->a7);
	if (sbi_ext && sbi_ext->handler) {
#ifdef CONFIG_RISCV_SBI_V01
		if (cp->a7 >= SBI_EXT_0_1_SET_TIMER &&
		    cp->a7 <= SBI_EXT_0_1_SHUTDOWN)
			ext_is_v01 = true;
#endif
		ret = sbi_ext->handler(vcpu, run, &out_val, &utrap, &userspace_exit);
	} else {
		/* Return error for unsupported SBI calls */
		cp->a0 = SBI_ERR_NOT_SUPPORTED;
		goto ecall_done;
	}

	/* Handle special error cases i.e trap, exit or userspace forward */
	if (utrap.scause) {
		/* No need to increment sepc or exit ioctl loop */
		ret = 1;
		utrap.sepc = cp->sepc;
		kvm_riscv_vcpu_trap_redirect(vcpu, &utrap);
		next_sepc = false;
		goto ecall_done;
	}

	/* Exit ioctl loop or Propagate the error code the guest */
	if (userspace_exit) {
		next_sepc = false;
		ret = 0;
	} else {
		/**
		 * SBI extension handler always returns an Linux error code. Convert
		 * it to the SBI specific error code that can be propagated the SBI
		 * caller.
		 */
		ret = kvm_linux_err_map_sbi(ret);
		cp->a0 = ret;
		ret = 1;
	}
ecall_done:
	if (next_sepc)
		cp->sepc += 4;
	if (!ext_is_v01)
		cp->a1 = out_val;

	return ret;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Western Digital Corporation or its affiliates.
 * Copyright (C) 2022 Ventana Micro Systems Inc.
 *
 * Authors:
 *	Anup Patel <apatel@ventanamicro.com>
 */

#include <linux/bitops.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/irqchip/riscv-imsic.h>
#include <linux/kvm_host.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <asm/hwcap.h>

unsigned int kvm_riscv_aia_nr_hgei;
unsigned int kvm_riscv_aia_max_ids;
DEFINE_STATIC_KEY_FALSE(kvm_riscv_aia_available);

static inline void aia_set_hvictl(bool ext_irq_pending)
{
	unsigned long hvictl;

	/*
	 * HVICTL.IID == 9 and HVICTL.IPRIO == 0 represents
	 * no interupt in HVICTL.
	 */

	hvictl = (IRQ_S_EXT << HVICTL_IID_SHIFT) & HVICTL_IID;
	hvictl |= (ext_irq_pending) ? 1 : 0;
	csr_write(CSR_HVICTL, hvictl);
}

void kvm_riscv_aia_enable(void)
{
	if (!kvm_riscv_aia_available())
		return;

	aia_set_hvictl(false);
	csr_write(CSR_HVIPRIO1, 0x0);
	csr_write(CSR_HVIPRIO2, 0x0);
#ifdef CONFIG_32BIT
	csr_write(CSR_HVIPH, 0x0);
	csr_write(CSR_HIDELEGH, 0x0);
	csr_write(CSR_HVIPRIO1H, 0x0);
	csr_write(CSR_HVIPRIO2H, 0x0);
#endif
}

void kvm_riscv_aia_disable(void)
{
	if (!kvm_riscv_aia_available())
		return;

	aia_set_hvictl(false);
}

int kvm_riscv_aia_init(void)
{
	unsigned int imsic_cpu_pages, hgeie_bits;
	const struct imsic_global_config *gc;

	if (!riscv_isa_extension_available(NULL, SxAIA))
		return -ENODEV;
	gc = imsic_get_global_config();

	/* Figure-out number of bits in HGEIE */
	csr_write(CSR_HGEIE, -1UL);
	hgeie_bits = fls_long(csr_read(CSR_HGEIE));
	csr_write(CSR_HGEIE, 0);

	/* Find number of guest files */
	imsic_cpu_pages = (gc) ? BIT(gc->guest_index_bits) : 0;
	kvm_riscv_aia_nr_hgei = min(imsic_cpu_pages, hgeie_bits);
	if (kvm_riscv_aia_nr_hgei)
		kvm_riscv_aia_nr_hgei--;

	/* Find number of guest MSI IDs */
	kvm_riscv_aia_max_ids = IMSIC_MAX_ID;
	if (kvm_riscv_aia_nr_hgei)
		kvm_riscv_aia_max_ids = gc->nr_guest_ids + 1;

	/* Enable KVM AIA support */
	static_branch_enable(&kvm_riscv_aia_available);

	return 0;
}

void kvm_riscv_aia_exit(void)
{
}

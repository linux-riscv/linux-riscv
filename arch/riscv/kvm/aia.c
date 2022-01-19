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

struct aia_hgei_control {
	raw_spinlock_t lock;
	unsigned long free_bitmap;
	struct kvm_vcpu *owners[BITS_PER_LONG];
};
static DEFINE_PER_CPU(struct aia_hgei_control, aia_hgei);
static int hgei_parent_irq;

unsigned int kvm_riscv_aia_nr_hgei;
unsigned int kvm_riscv_aia_max_ids;
DEFINE_STATIC_KEY_FALSE(kvm_riscv_aia_available);

static int aia_find_hgei(struct kvm_vcpu *owner)
{
	int i, hgei;
	unsigned long flags;
	struct aia_hgei_control *hgctrl = this_cpu_ptr(&aia_hgei);

	raw_spin_lock_irqsave(&hgctrl->lock, flags);

	hgei = -1;
	for (i = 1; i <= kvm_riscv_aia_nr_hgei; i++) {
		if (hgctrl->owners[i] == owner) {
			hgei = i;
			break;
		}
	}

	raw_spin_unlock_irqrestore(&hgctrl->lock, flags);

	return hgei;
}

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

int kvm_riscv_aia_alloc_hgei(int cpu, struct kvm_vcpu *owner,
			     void __iomem **hgei_va, phys_addr_t *hgei_pa)
{
	int ret = -ENOENT;
	unsigned long flags;
	const struct imsic_local_config *lc;
	struct aia_hgei_control *hgctrl = per_cpu_ptr(&aia_hgei, cpu);

	if (!kvm_riscv_aia_available())
		return -ENOSYS;
	if (!hgctrl)
		return -ENODEV;

	raw_spin_lock_irqsave(&hgctrl->lock, flags);

	if (hgctrl->free_bitmap) {
		ret = __ffs(hgctrl->free_bitmap);
		hgctrl->free_bitmap &= ~BIT(ret);
		hgctrl->owners[ret] = owner;
	}

	raw_spin_unlock_irqrestore(&hgctrl->lock, flags);

	lc = imsic_get_local_config(cpu);
	if (lc && ret > 0) {
		if (hgei_va)
			*hgei_va = lc->msi_va + (ret * IMSIC_MMIO_PAGE_SZ);
		if (hgei_pa)
			*hgei_pa = lc->msi_pa + (ret * IMSIC_MMIO_PAGE_SZ);
	}

	return ret;
}

void kvm_riscv_aia_free_hgei(int cpu, int hgei)
{
	unsigned long flags;
	struct aia_hgei_control *hgctrl = per_cpu_ptr(&aia_hgei, cpu);

	if (!kvm_riscv_aia_available() || !hgctrl)
		return;

	raw_spin_lock_irqsave(&hgctrl->lock, flags);

	if (0 < hgei && hgei <= kvm_riscv_aia_nr_hgei) {
		if (!(hgctrl->free_bitmap & BIT(hgei))) {
			hgctrl->free_bitmap |= BIT(hgei);
			hgctrl->owners[hgei] = NULL;
		}
	}

	raw_spin_unlock_irqrestore(&hgctrl->lock, flags);
}

void kvm_riscv_aia_wakeon_hgei(struct kvm_vcpu *owner, bool enable)
{
	int hgei;

	if (!kvm_riscv_aia_available())
		return;

	hgei = aia_find_hgei(owner);
	if (hgei > 0) {
		if (enable)
			csr_set(CSR_HGEIE, BIT(hgei));
		else
			csr_clear(CSR_HGEIE, BIT(hgei));
	}
}

static irqreturn_t hgei_interrupt(int irq, void *dev_id)
{
	int i;
	unsigned long hgei_mask, flags;
	struct aia_hgei_control *hgctrl = this_cpu_ptr(&aia_hgei);

	hgei_mask = csr_read(CSR_HGEIP) & csr_read(CSR_HGEIE);
	csr_clear(CSR_HGEIE, hgei_mask);

	raw_spin_lock_irqsave(&hgctrl->lock, flags);

	for_each_set_bit(i, &hgei_mask, BITS_PER_LONG) {
		if (hgctrl->owners[i])
			kvm_vcpu_kick(hgctrl->owners[i]);
	}

	raw_spin_unlock_irqrestore(&hgctrl->lock, flags);

	return IRQ_HANDLED;
}

static int aia_hgei_init(void)
{
	int cpu, rc;
	struct irq_domain *domain;
	struct aia_hgei_control *hgctrl;

	/* Initialize per-CPU guest external interrupt line managment */
	for_each_possible_cpu(cpu) {
		hgctrl = per_cpu_ptr(&aia_hgei, cpu);
		raw_spin_lock_init(&hgctrl->lock);
		if (kvm_riscv_aia_nr_hgei) {
			hgctrl->free_bitmap =
				BIT(kvm_riscv_aia_nr_hgei + 1) - 1;
			hgctrl->free_bitmap &= ~BIT(0);
		} else
			hgctrl->free_bitmap = 0;
	}

	/* Find INTC irq domain */
	domain = irq_find_matching_fwnode(riscv_get_intc_hwnode(),
					  DOMAIN_BUS_ANY);
	if (!domain) {
		kvm_err("unable to find INTC domain\n");
		return -ENOENT;
	}

	/* Map per-CPU SGEI interrupt from INTC domain */
	hgei_parent_irq = irq_create_mapping(domain, IRQ_S_GEXT);
	if (!hgei_parent_irq) {
		kvm_err("unable to map SGEI IRQ\n");
		return -ENOMEM;
	}

	/* Request per-CPU SGEI interrupt */
	rc = request_percpu_irq(hgei_parent_irq, hgei_interrupt,
				"riscv-kvm", &aia_hgei);
	if (rc) {
		kvm_err("failed to request SGEI IRQ\n");
		return rc;
	}

	return 0;
}

static void aia_hgei_exit(void)
{
	/* Free per-CPU SGEI interrupt */
	free_irq(hgei_parent_irq, &aia_hgei);
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

	/* Enable per-CPU SGEI interrupt */
	enable_percpu_irq(hgei_parent_irq,
			  irq_get_trigger_type(hgei_parent_irq));
	csr_set(CSR_HIE, BIT(IRQ_S_GEXT));
}

void kvm_riscv_aia_disable(void)
{
	int i;
	unsigned long flags;
	struct kvm_vcpu *vcpu;
	struct aia_hgei_control *hgctrl = this_cpu_ptr(&aia_hgei);

	if (!kvm_riscv_aia_available())
		return;

	/* Disable per-CPU SGEI interrupt */
	csr_clear(CSR_HIE, BIT(IRQ_S_GEXT));
	disable_percpu_irq(hgei_parent_irq);

	aia_set_hvictl(false);

	raw_spin_lock_irqsave(&hgctrl->lock, flags);

	for (i = 0; i <= kvm_riscv_aia_nr_hgei; i++) {
		vcpu = hgctrl->owners[i];
		if (!vcpu)
			continue;

		/*
		 * We release hgctrl->lock before notifying IMSIC
		 * so that we don't have lock ordering issues.
		 */
		raw_spin_unlock_irqrestore(&hgctrl->lock, flags);

		/* Notify IMSIC */
		kvm_riscv_vcpu_aia_imsic_release(vcpu);

		/*
		 * Wakeup VCPU if it was blocked so that it can
		 * run on other HARTs
		 */
		if (csr_read(CSR_HGEIE) & BIT(i)) {
			csr_clear(CSR_HGEIE, BIT(i));
			kvm_vcpu_kick(vcpu);
		}

		raw_spin_lock_irqsave(&hgctrl->lock, flags);
	}

	raw_spin_unlock_irqrestore(&hgctrl->lock, flags);
}

int kvm_riscv_aia_init(void)
{
	int rc;
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

	/* Initialize guest external interrupt line managment */
	rc = aia_hgei_init();
	if (rc)
		return rc;

	/* Enable KVM AIA support */
	static_branch_enable(&kvm_riscv_aia_available);

	return 0;
}

void kvm_riscv_aia_exit(void)
{
	if (!kvm_riscv_aia_available())
		return;

	/* Cleanup the HGEI state */
	aia_hgei_exit();
}

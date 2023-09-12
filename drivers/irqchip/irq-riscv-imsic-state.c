// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Western Digital Corporation or its affiliates.
 * Copyright (C) 2022 Ventana Micro Systems Inc.
 */

#define pr_fmt(fmt) "riscv-imsic: " fmt
#include <linux/bitmap.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <asm/hwcap.h>

#include "irq-riscv-imsic-state.h"

#define IMSIC_DISABLE_EIDELIVERY		0
#define IMSIC_ENABLE_EIDELIVERY			1
#define IMSIC_DISABLE_EITHRESHOLD		1
#define IMSIC_ENABLE_EITHRESHOLD		0

#define imsic_csr_write(__c, __v)		\
do {						\
	csr_write(CSR_ISELECT, __c);		\
	csr_write(CSR_IREG, __v);		\
} while (0)

#define imsic_csr_read(__c)			\
({						\
	unsigned long __v;			\
	csr_write(CSR_ISELECT, __c);		\
	__v = csr_read(CSR_IREG);		\
	__v;					\
})

#define imsic_csr_set(__c, __v)			\
do {						\
	csr_write(CSR_ISELECT, __c);		\
	csr_set(CSR_IREG, __v);			\
} while (0)

#define imsic_csr_clear(__c, __v)		\
do {						\
	csr_write(CSR_ISELECT, __c);		\
	csr_clear(CSR_IREG, __v);		\
} while (0)

struct imsic_priv *imsic;

const struct imsic_global_config *imsic_get_global_config(void)
{
	return (imsic) ? &imsic->global : NULL;
}
EXPORT_SYMBOL_GPL(imsic_get_global_config);

void __imsic_eix_update(unsigned long base_id,
			unsigned long num_id, bool pend, bool val)
{
	unsigned long i, isel, ireg;
	unsigned long id = base_id, last_id = base_id + num_id;

	while (id < last_id) {
		isel = id / BITS_PER_LONG;
		isel *= BITS_PER_LONG / IMSIC_EIPx_BITS;
		isel += (pend) ? IMSIC_EIP0 : IMSIC_EIE0;

		ireg = 0;
		for (i = id & (__riscv_xlen - 1);
		     (id < last_id) && (i < __riscv_xlen); i++) {
			ireg |= BIT(i);
			id++;
		}

		/*
		 * The IMSIC EIEx and EIPx registers are indirectly
		 * accessed via using ISELECT and IREG CSRs so we
		 * need to access these CSRs without getting preempted.
		 *
		 * All existing users of this function call this
		 * function with local IRQs disabled so we don't
		 * need to do anything special here.
		 */
		if (val)
			imsic_csr_set(isel, ireg);
		else
			imsic_csr_clear(isel, ireg);
	}
}

void imsic_id_set_target(unsigned int id, unsigned int target_cpu)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&imsic->ids_lock, flags);
	imsic->ids_target_cpu[id] = target_cpu;
	raw_spin_unlock_irqrestore(&imsic->ids_lock, flags);
}

unsigned int imsic_id_get_target(unsigned int id)
{
	unsigned int ret;
	unsigned long flags;

	raw_spin_lock_irqsave(&imsic->ids_lock, flags);
	ret = imsic->ids_target_cpu[id];
	raw_spin_unlock_irqrestore(&imsic->ids_lock, flags);

	return ret;
}

void imsic_ids_local_sync(void)
{
	int i;
	unsigned long flags;

	raw_spin_lock_irqsave(&imsic->ids_lock, flags);
	for (i = 1; i <= imsic->global.nr_ids; i++) {
		if (imsic->ipi_id == i)
			continue;

		if (test_bit(i, imsic->ids_enabled_bimap))
			__imsic_id_enable(i);
		else
			__imsic_id_disable(i);
	}
	raw_spin_unlock_irqrestore(&imsic->ids_lock, flags);
}

void imsic_ids_local_delivery(bool enable)
{
	if (enable) {
		imsic_csr_write(IMSIC_EITHRESHOLD, IMSIC_ENABLE_EITHRESHOLD);
		imsic_csr_write(IMSIC_EIDELIVERY, IMSIC_ENABLE_EIDELIVERY);
	} else {
		imsic_csr_write(IMSIC_EIDELIVERY, IMSIC_DISABLE_EIDELIVERY);
		imsic_csr_write(IMSIC_EITHRESHOLD, IMSIC_DISABLE_EITHRESHOLD);
	}
}

int imsic_ids_alloc(unsigned int order)
{
	int ret;
	unsigned long flags;

	raw_spin_lock_irqsave(&imsic->ids_lock, flags);
	ret = bitmap_find_free_region(imsic->ids_used_bimap,
				      imsic->global.nr_ids + 1, order);
	raw_spin_unlock_irqrestore(&imsic->ids_lock, flags);

	return ret;
}

void imsic_ids_free(unsigned int base_id, unsigned int order)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&imsic->ids_lock, flags);
	bitmap_release_region(imsic->ids_used_bimap, base_id, order);
	raw_spin_unlock_irqrestore(&imsic->ids_lock, flags);
}

static int __init imsic_ids_init(void)
{
	int i;
	struct imsic_global_config *global = &imsic->global;

	raw_spin_lock_init(&imsic->ids_lock);

	/* Allocate used bitmap */
	imsic->ids_used_bimap = bitmap_zalloc(global->nr_ids + 1, GFP_KERNEL);
	if (!imsic->ids_used_bimap)
		return -ENOMEM;

	/* Allocate enabled bitmap */
	imsic->ids_enabled_bimap = bitmap_zalloc(global->nr_ids + 1,
						GFP_KERNEL);
	if (!imsic->ids_enabled_bimap) {
		kfree(imsic->ids_used_bimap);
		return -ENOMEM;
	}

	/* Allocate target CPU array */
	imsic->ids_target_cpu = kcalloc(global->nr_ids + 1,
				       sizeof(unsigned int), GFP_KERNEL);
	if (!imsic->ids_target_cpu) {
		bitmap_free(imsic->ids_enabled_bimap);
		bitmap_free(imsic->ids_used_bimap);
		return -ENOMEM;
	}
	for (i = 0; i <= global->nr_ids; i++)
		imsic->ids_target_cpu[i] = UINT_MAX;

	/* Reserve ID#0 because it is special and never implemented */
	bitmap_set(imsic->ids_used_bimap, 0, 1);

	return 0;
}

static void __init imsic_ids_cleanup(void)
{
	kfree(imsic->ids_target_cpu);
	bitmap_free(imsic->ids_enabled_bimap);
	bitmap_free(imsic->ids_used_bimap);
}

static int __init imsic_get_parent_hartid(struct fwnode_handle *fwnode,
					  u32 index, unsigned long *hartid)
{
	int rc;
	struct fwnode_reference_args parent;

	rc = fwnode_property_get_reference_args(fwnode,
			"interrupts-extended", "#interrupt-cells",
			0, index, &parent);
	if (rc)
		return rc;

	/*
	 * Skip interrupts other than external interrupts for
	 * current privilege level.
	 */
	if (parent.args[0] != RV_IRQ_EXT)
		return -EINVAL;

	return riscv_get_intc_hartid(parent.fwnode, hartid);
}

static int __init imsic_get_mmio_resource(struct fwnode_handle *fwnode,
					  u32 index, struct resource *res)
{
	/*
	 * Currently, only OF fwnode is support so extend this function
	 * for other types of fwnode for ACPI support.
	 */
	if (!is_of_node(fwnode))
		return -EINVAL;
	return of_address_to_resource(to_of_node(fwnode), index, res);
}

int __init imsic_setup_state(struct fwnode_handle *fwnode)
{
	int rc, cpu;
	phys_addr_t base_addr;
	void __iomem **mmios_va = NULL;
	struct resource res, *mmios = NULL;
	struct imsic_local_config *local;
	struct imsic_global_config *global;
	unsigned long reloff, hartid;
	u32 i, j, index, nr_parent_irqs, nr_handlers = 0, num_mmios = 0;

	/*
	 * Only one IMSIC instance allowed in a platform for clean
	 * implementation of SMP IRQ affinity and per-CPU IPIs.
	 *
	 * This means on a multi-socket (or multi-die) platform we
	 * will have multiple MMIO regions for one IMSIC instance.
	 */
	if (imsic) {
		pr_err("%pfwP: already initialized hence ignoring\n",
			fwnode);
		return -EALREADY;
	}

	if (!riscv_isa_extension_available(NULL, SxAIA)) {
		pr_err("%pfwP: AIA support not available\n", fwnode);
		return -ENODEV;
	}

	imsic = kzalloc(sizeof(*imsic), GFP_KERNEL);
	if (!imsic)
		return -ENOMEM;
	imsic->fwnode = fwnode;
	global = &imsic->global;

	global->local = alloc_percpu(typeof(*(global->local)));
	if (!global->local) {
		rc = -ENOMEM;
		goto out_free_priv;
	}

	/* Find number of parent interrupts */
	nr_parent_irqs = 0;
	while (!imsic_get_parent_hartid(fwnode, nr_parent_irqs, &hartid))
		nr_parent_irqs++;
	if (!nr_parent_irqs) {
		pr_err("%pfwP: no parent irqs available\n", fwnode);
		rc = -EINVAL;
		goto out_free_local;
	}

	/* Find number of guest index bits in MSI address */
	rc = fwnode_property_read_u32_array(fwnode, "riscv,guest-index-bits",
					    &global->guest_index_bits, 1);
	if (rc)
		global->guest_index_bits = 0;
	i = BITS_PER_LONG - IMSIC_MMIO_PAGE_SHIFT;
	if (i < global->guest_index_bits) {
		pr_err("%pfwP: guest index bits too big\n", fwnode);
		rc = -EINVAL;
		goto out_free_local;
	}

	/* Find number of HART index bits */
	rc = fwnode_property_read_u32_array(fwnode, "riscv,hart-index-bits",
					    &global->hart_index_bits, 1);
	if (rc) {
		/* Assume default value */
		global->hart_index_bits = __fls(nr_parent_irqs);
		if (BIT(global->hart_index_bits) < nr_parent_irqs)
			global->hart_index_bits++;
	}
	i = BITS_PER_LONG - IMSIC_MMIO_PAGE_SHIFT - global->guest_index_bits;
	if (i < global->hart_index_bits) {
		pr_err("%pfwP: HART index bits too big\n", fwnode);
		rc = -EINVAL;
		goto out_free_local;
	}

	/* Find number of group index bits */
	rc = fwnode_property_read_u32_array(fwnode, "riscv,group-index-bits",
					    &global->group_index_bits, 1);
	if (rc)
		global->group_index_bits = 0;
	i = BITS_PER_LONG - IMSIC_MMIO_PAGE_SHIFT -
	    global->guest_index_bits - global->hart_index_bits;
	if (i < global->group_index_bits) {
		pr_err("%pfwP: group index bits too big\n", fwnode);
		rc = -EINVAL;
		goto out_free_local;
	}

	/*
	 * Find first bit position of group index.
	 * If not specified assumed the default APLIC-IMSIC configuration.
	 */
	rc = fwnode_property_read_u32_array(fwnode, "riscv,group-index-shift",
					    &global->group_index_shift, 1);
	if (rc)
		global->group_index_shift = IMSIC_MMIO_PAGE_SHIFT * 2;
	i = global->group_index_bits + global->group_index_shift - 1;
	if (i >= BITS_PER_LONG) {
		pr_err("%pfwP: group index shift too big\n", fwnode);
		rc = -EINVAL;
		goto out_free_local;
	}

	/* Find number of interrupt identities */
	rc = fwnode_property_read_u32_array(fwnode, "riscv,num-ids",
					    &global->nr_ids, 1);
	if (rc) {
		pr_err("%pfwP: number of interrupt identities not found\n",
			fwnode);
		goto out_free_local;
	}
	if ((global->nr_ids < IMSIC_MIN_ID) ||
	    (global->nr_ids >= IMSIC_MAX_ID) ||
	    ((global->nr_ids & IMSIC_MIN_ID) != IMSIC_MIN_ID)) {
		pr_err("%pfwP: invalid number of interrupt identities\n",
			fwnode);
		rc = -EINVAL;
		goto out_free_local;
	}

	/* Find number of guest interrupt identities */
	if (fwnode_property_read_u32_array(fwnode, "riscv,num-guest-ids",
					   &global->nr_guest_ids, 1))
		global->nr_guest_ids = global->nr_ids;
	if ((global->nr_guest_ids < IMSIC_MIN_ID) ||
	    (global->nr_guest_ids >= IMSIC_MAX_ID) ||
	    ((global->nr_guest_ids & IMSIC_MIN_ID) != IMSIC_MIN_ID)) {
		pr_err("%pfwP: invalid number of guest interrupt identities\n",
			fwnode);
		rc = -EINVAL;
		goto out_free_local;
	}

	/* Compute base address */
	rc = imsic_get_mmio_resource(fwnode, 0, &res);
	if (rc) {
		pr_err("%pfwP: first MMIO resource not found\n", fwnode);
		rc = -EINVAL;
		goto out_free_local;
	}
	global->base_addr = res.start;
	global->base_addr &= ~(BIT(global->guest_index_bits +
				   global->hart_index_bits +
				   IMSIC_MMIO_PAGE_SHIFT) - 1);
	global->base_addr &= ~((BIT(global->group_index_bits) - 1) <<
			       global->group_index_shift);

	/* Find number of MMIO register sets */
	while (!imsic_get_mmio_resource(fwnode, num_mmios, &res))
		num_mmios++;

	/* Allocate MMIO resource array */
	mmios = kcalloc(num_mmios, sizeof(*mmios), GFP_KERNEL);
	if (!mmios) {
		rc = -ENOMEM;
		goto out_free_local;
	}

	/* Allocate MMIO virtual address array */
	mmios_va = kcalloc(num_mmios, sizeof(*mmios_va), GFP_KERNEL);
	if (!mmios_va) {
		rc = -ENOMEM;
		goto out_iounmap;
	}

	/* Parse and map MMIO register sets */
	for (i = 0; i < num_mmios; i++) {
		rc = imsic_get_mmio_resource(fwnode, i, &mmios[i]);
		if (rc) {
			pr_err("%pfwP: unable to parse MMIO regset %d\n",
				fwnode, i);
			goto out_iounmap;
		}

		base_addr = mmios[i].start;
		base_addr &= ~(BIT(global->guest_index_bits +
				   global->hart_index_bits +
				   IMSIC_MMIO_PAGE_SHIFT) - 1);
		base_addr &= ~((BIT(global->group_index_bits) - 1) <<
			       global->group_index_shift);
		if (base_addr != global->base_addr) {
			rc = -EINVAL;
			pr_err("%pfwP: address mismatch for regset %d\n",
				fwnode, i);
			goto out_iounmap;
		}

		mmios_va[i] = ioremap(mmios[i].start, resource_size(&mmios[i]));
		if (!mmios_va[i]) {
			rc = -EIO;
			pr_err("%pfwP: unable to map MMIO regset %d\n",
				fwnode, i);
			goto out_iounmap;
		}
	}

	/* Initialize interrupt identity management */
	rc = imsic_ids_init();
	if (rc) {
		pr_err("%pfwP: failed to initialize interrupt management\n",
		       fwnode);
		goto out_iounmap;
	}

	/* Configure handlers for target CPUs */
	for (i = 0; i < nr_parent_irqs; i++) {
		rc = imsic_get_parent_hartid(fwnode, i, &hartid);
		if (rc) {
			pr_warn("%pfwP: hart ID for parent irq%d not found\n",
				fwnode, i);
			continue;
		}

		cpu = riscv_hartid_to_cpuid(hartid);
		if (cpu < 0) {
			pr_warn("%pfwP: invalid cpuid for parent irq%d\n",
				fwnode, i);
			continue;
		}

		/* Find MMIO location of MSI page */
		index = num_mmios;
		reloff = i * BIT(global->guest_index_bits) *
			 IMSIC_MMIO_PAGE_SZ;
		for (j = 0; num_mmios; j++) {
			if (reloff < resource_size(&mmios[j])) {
				index = j;
				break;
			}

			/*
			 * MMIO region size may not be aligned to
			 * BIT(global->guest_index_bits) * IMSIC_MMIO_PAGE_SZ
			 * if holes are present.
			 */
			reloff -= ALIGN(resource_size(&mmios[j]),
			BIT(global->guest_index_bits) * IMSIC_MMIO_PAGE_SZ);
		}
		if (index >= num_mmios) {
			pr_warn("%pfwP: MMIO not found for parent irq%d\n",
				fwnode, i);
			continue;
		}

		local = per_cpu_ptr(global->local, cpu);
		local->msi_pa = mmios[index].start + reloff;
		local->msi_va = mmios_va[index] + reloff;

		nr_handlers++;
	}

	/* If no CPU handlers found then can't take interrupts */
	if (!nr_handlers) {
		pr_err("%pfwP: No CPU handlers found\n", fwnode);
		rc = -ENODEV;
		goto out_ids_cleanup;
	}

	/* We don't need MMIO arrays anymore so let's free-up */
	kfree(mmios_va);
	kfree(mmios);

	return 0;

out_ids_cleanup:
	imsic_ids_cleanup();
out_iounmap:
	for (i = 0; i < num_mmios; i++) {
		if (mmios_va[i])
			iounmap(mmios_va[i]);
	}
	kfree(mmios_va);
	kfree(mmios);
out_free_local:
	free_percpu(imsic->global.local);
out_free_priv:
	kfree(imsic);
	imsic = NULL;
	return rc;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Western Digital Corporation or its affiliates.
 * Copyright (C) 2022 Ventana Micro Systems Inc.
 */

#define pr_fmt(fmt) "riscv-imsic: " fmt
#include <linux/cpu.h>
#include <linux/bitmap.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/seq_file.h>
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

#define imsic_csr_read_clear(__c, __v)		\
({						\
	unsigned long __r;			\
	csr_write(CSR_ISELECT, __c);		\
	__r = csr_read_clear(CSR_IREG, __v);	\
	__r;					\
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
	return imsic ? &imsic->global : NULL;
}
EXPORT_SYMBOL_GPL(imsic_get_global_config);

static bool __imsic_eix_read_clear(unsigned long id, bool pend)
{
	unsigned long isel, imask;

	isel = id / BITS_PER_LONG;
	isel *= BITS_PER_LONG / IMSIC_EIPx_BITS;
	isel += pend ? IMSIC_EIP0 : IMSIC_EIE0;
	imask = BIT(id & (__riscv_xlen - 1));

	return (imsic_csr_read_clear(isel, imask) & imask) ? true : false;
}

#define __imsic_id_read_clear_enabled(__id)		\
	__imsic_eix_read_clear((__id), false)
#define __imsic_id_read_clear_pending(__id)		\
	__imsic_eix_read_clear((__id), true)

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

void imsic_local_sync(void)
{
	struct imsic_local_priv *lpriv = this_cpu_ptr(imsic->lpriv);
	struct imsic_local_config *mlocal;
	struct imsic_vector *mvec;
	unsigned long flags;
	int i;

	raw_spin_lock_irqsave(&lpriv->ids_lock, flags);
	for (i = 1; i <= imsic->global.nr_ids; i++) {
		if (i == IMSIC_IPI_ID)
			continue;

		if (test_bit(i, lpriv->ids_enabled_bitmap))
			__imsic_id_set_enable(i);
		else
			__imsic_id_clear_enable(i);

		mvec = lpriv->ids_move[i];
		lpriv->ids_move[i] = NULL;
		if (mvec) {
			if (__imsic_id_read_clear_pending(i)) {
				mlocal = per_cpu_ptr(imsic->global.local,
						     mvec->cpu);
				writel_relaxed(mvec->local_id, mlocal->msi_va);
			}

			imsic_vector_free(&lpriv->vectors[i]);
		}

	}
	raw_spin_unlock_irqrestore(&lpriv->ids_lock, flags);
}

void imsic_local_delivery(bool enable)
{
	if (enable) {
		imsic_csr_write(IMSIC_EITHRESHOLD, IMSIC_ENABLE_EITHRESHOLD);
		imsic_csr_write(IMSIC_EIDELIVERY, IMSIC_ENABLE_EIDELIVERY);
		return;
	}

	imsic_csr_write(IMSIC_EIDELIVERY, IMSIC_DISABLE_EIDELIVERY);
	imsic_csr_write(IMSIC_EITHRESHOLD, IMSIC_DISABLE_EITHRESHOLD);
}

#ifdef CONFIG_SMP
static void imsic_remote_sync(unsigned int cpu)
{
	/*
	 * We simply inject ID synchronization IPI to a target CPU
	 * if it is not same as the current CPU. The ipi_send_mask()
	 * implementation of IPI mux will inject ID synchronization
	 * IPI only for CPUs that have enabled it so offline CPUs
	 * won't receive IPI. An offline CPU will unconditionally
	 * synchronize IDs through imsic_starting_cpu() when the
	 * CPU is brought up.
	 */
	if (cpu_online(cpu)) {
		if (cpu != smp_processor_id())
			__ipi_send_mask(imsic->ipi_lsync_desc, cpumask_of(cpu));
		else
			imsic_local_sync();
	}
}
#else
static inline void imsic_remote_sync(unsigned int cpu)
{
	imsic_local_sync();
}
#endif

void imsic_vector_mask(struct imsic_vector *vec)
{
	struct imsic_local_priv *lpriv;
	unsigned long flags;

	lpriv = per_cpu_ptr(imsic->lpriv, vec->cpu);
	if (WARN_ON(&lpriv->vectors[vec->local_id] != vec))
		return;

	raw_spin_lock_irqsave(&lpriv->ids_lock, flags);
	bitmap_clear(lpriv->ids_enabled_bitmap, vec->local_id, 1);
	raw_spin_unlock_irqrestore(&lpriv->ids_lock, flags);

	imsic_remote_sync(vec->cpu);
}

void imsic_vector_unmask(struct imsic_vector *vec)
{
	struct imsic_local_priv *lpriv;
	unsigned long flags;

	lpriv = per_cpu_ptr(imsic->lpriv, vec->cpu);
	if (WARN_ON(&lpriv->vectors[vec->local_id] != vec))
		return;

	raw_spin_lock_irqsave(&lpriv->ids_lock, flags);
	bitmap_set(lpriv->ids_enabled_bitmap, vec->local_id, 1);
	raw_spin_unlock_irqrestore(&lpriv->ids_lock, flags);

	imsic_remote_sync(vec->cpu);
}

void imsic_vector_move(struct imsic_vector *old_vec,
			struct imsic_vector *new_vec)
{
	struct imsic_local_priv *old_lpriv, *new_lpriv;
	unsigned long flags, flags1;

	if (WARN_ON(old_vec->cpu == new_vec->cpu))
		return;

	old_lpriv = per_cpu_ptr(imsic->lpriv, old_vec->cpu);
	if (WARN_ON(&old_lpriv->vectors[old_vec->local_id] != old_vec))
		return;

	new_lpriv = per_cpu_ptr(imsic->lpriv, new_vec->cpu);
	if (WARN_ON(&new_lpriv->vectors[new_vec->local_id] != new_vec))
		return;

	raw_spin_lock_irqsave(&old_lpriv->ids_lock, flags);
	raw_spin_lock_irqsave(&new_lpriv->ids_lock, flags1);

	/* Unmask the new vector entry */
	if (test_bit(old_vec->local_id, old_lpriv->ids_enabled_bitmap))
		bitmap_set(new_lpriv->ids_enabled_bitmap,
			   new_vec->local_id, 1);

	/* Mask the old vector entry */
	bitmap_clear(old_lpriv->ids_enabled_bitmap, old_vec->local_id, 1);

	/*
	 * Move and re-trigger the new vector based on the pending
	 * state of the old vector because we might get a device
	 * interrupt on the old vector while device was being moved
	 * to the new vector.
	 */
	old_lpriv->ids_move[old_vec->local_id] = new_vec;

	raw_spin_unlock_irqrestore(&new_lpriv->ids_lock, flags1);
	raw_spin_unlock_irqrestore(&old_lpriv->ids_lock, flags);

	imsic_remote_sync(old_vec->cpu);
	imsic_remote_sync(new_vec->cpu);
}

#ifdef CONFIG_GENERIC_IRQ_DEBUGFS
void imsic_vector_debug_show(struct seq_file *m,
			     struct imsic_vector *vec, int ind)
{
	unsigned int mcpu = 0, mlocal_id = 0;
	struct imsic_local_priv *lpriv;
	bool move_in_progress = false;
	struct imsic_vector *mvec;
	bool is_enabled = false;
	unsigned long flags;

	lpriv = per_cpu_ptr(imsic->lpriv, vec->cpu);
	if (WARN_ON(&lpriv->vectors[vec->local_id] != vec))
		return;

	raw_spin_lock_irqsave(&lpriv->ids_lock, flags);
	if (test_bit(vec->local_id, lpriv->ids_enabled_bitmap))
		is_enabled = true;
	mvec = lpriv->ids_move[vec->local_id];
	if (mvec) {
		move_in_progress = true;
		mcpu = mvec->cpu;
		mlocal_id = mvec->local_id;
	}
	raw_spin_unlock_irqrestore(&lpriv->ids_lock, flags);

	seq_printf(m, "%*starget_cpu      : %5u\n", ind, "", vec->cpu);
	seq_printf(m, "%*starget_local_id : %5u\n", ind, "", vec->local_id);
	seq_printf(m, "%*sis_reserved     : %5u\n", ind, "",
		   (vec->local_id <= IMSIC_IPI_ID) ? 1 : 0);
	seq_printf(m, "%*sis_enabled      : %5u\n", ind, "",
		   (is_enabled) ? 1 : 0);
	seq_printf(m, "%*sis_move_pending : %5u\n", ind, "",
		   (move_in_progress) ? 1 : 0);
	if (move_in_progress) {
		seq_printf(m, "%*smove_cpu        : %5u\n", ind, "", mcpu);
		seq_printf(m, "%*smove_local_id   : %5u\n", ind, "", mlocal_id);
	}
}

void imsic_vector_debug_show_summary(struct seq_file *m, int ind)
{
	irq_matrix_debug_show(m, imsic->matrix, ind);
}
#endif

struct imsic_vector *imsic_vector_from_local_id(unsigned int cpu,
						unsigned int local_id)
{
	struct imsic_local_priv *lpriv = per_cpu_ptr(imsic->lpriv, cpu);

	if (!lpriv || imsic->global.nr_ids < local_id)
		return NULL;

	return &lpriv->vectors[local_id];
}

struct imsic_vector *imsic_vector_alloc(unsigned int hwirq,
					const struct cpumask *mask)
{
	struct imsic_vector *vec = NULL;
	struct imsic_local_priv *lpriv;
	unsigned long flags;
	unsigned int cpu;
	int local_id;

	raw_spin_lock_irqsave(&imsic->matrix_lock, flags);
	local_id = irq_matrix_alloc(imsic->matrix, mask, false, &cpu);
	raw_spin_unlock_irqrestore(&imsic->matrix_lock, flags);
	if (local_id < 0)
		return NULL;

	lpriv = per_cpu_ptr(imsic->lpriv, cpu);
	vec = &lpriv->vectors[local_id];
	vec->hwirq = hwirq;

	return vec;
}

void imsic_vector_free(struct imsic_vector *vec)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&imsic->matrix_lock, flags);
	vec->hwirq = UINT_MAX;
	irq_matrix_free(imsic->matrix, vec->cpu, vec->local_id, false);
	raw_spin_unlock_irqrestore(&imsic->matrix_lock, flags);
}

static void __init imsic_local_cleanup(void)
{
	int cpu;
	struct imsic_local_priv *lpriv;

	for_each_possible_cpu(cpu) {
		lpriv = per_cpu_ptr(imsic->lpriv, cpu);

		bitmap_free(lpriv->ids_enabled_bitmap);
		kfree(lpriv->ids_move);
		kfree(lpriv->vectors);
	}

	free_percpu(imsic->lpriv);
}

static int __init imsic_local_init(void)
{
	struct imsic_global_config *global = &imsic->global;
	struct imsic_local_priv *lpriv;
	struct imsic_vector *vec;
	int cpu, i;

	/* Allocate per-CPU private state */
	imsic->lpriv = alloc_percpu(typeof(*(imsic->lpriv)));
	if (!imsic->lpriv)
		return -ENOMEM;

	/* Setup per-CPU private state */
	for_each_possible_cpu(cpu) {
		lpriv = per_cpu_ptr(imsic->lpriv, cpu);

		raw_spin_lock_init(&lpriv->ids_lock);

		/* Allocate enabled bitmap */
		lpriv->ids_enabled_bitmap = bitmap_zalloc(global->nr_ids + 1,
							  GFP_KERNEL);
		if (!lpriv->ids_enabled_bitmap) {
			imsic_local_cleanup();
			return -ENOMEM;
		}

		/* Allocate move array */
		lpriv->ids_move = kcalloc(global->nr_ids + 1,
					sizeof(*lpriv->ids_move), GFP_KERNEL);
		if (!lpriv->ids_move) {
			imsic_local_cleanup();
			return -ENOMEM;
		}

		/* Allocate vector array */
		lpriv->vectors = kcalloc(global->nr_ids + 1,
					 sizeof(*lpriv->vectors), GFP_KERNEL);
		if (!lpriv->vectors) {
			imsic_local_cleanup();
			return -ENOMEM;
		}

		/* Setup vector array */
		for (i = 0; i <= global->nr_ids; i++) {
			vec = &lpriv->vectors[i];
			vec->cpu = cpu;
			vec->local_id = i;
			vec->hwirq = UINT_MAX;
		}
	}

	return 0;
}

int imsic_hwirq_alloc(void)
{
	int ret;
	unsigned long flags;

	raw_spin_lock_irqsave(&imsic->hwirqs_lock, flags);
	ret = bitmap_find_free_region(imsic->hwirqs_used_bitmap,
				      imsic->nr_hwirqs, 0);
	raw_spin_unlock_irqrestore(&imsic->hwirqs_lock, flags);

	return ret;
}

void imsic_hwirq_free(unsigned int hwirq)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&imsic->hwirqs_lock, flags);
	bitmap_release_region(imsic->hwirqs_used_bitmap, hwirq, 0);
	raw_spin_unlock_irqrestore(&imsic->hwirqs_lock, flags);
}

static int __init imsic_hwirqs_init(void)
{
	struct imsic_global_config *global = &imsic->global;

	imsic->nr_hwirqs = num_possible_cpus() * (global->nr_ids - 1);

	raw_spin_lock_init(&imsic->hwirqs_lock);

	imsic->hwirqs_used_bitmap = bitmap_zalloc(imsic->nr_hwirqs,
						  GFP_KERNEL);
	if (!imsic->hwirqs_used_bitmap)
		return -ENOMEM;

	return 0;
}

static void __init imsic_hwirqs_cleanup(void)
{
	bitmap_free(imsic->hwirqs_used_bitmap);
}

void imsic_state_online(void)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&imsic->matrix_lock, flags);
	irq_matrix_online(imsic->matrix);
	raw_spin_unlock_irqrestore(&imsic->matrix_lock, flags);
}

void imsic_state_offline(void)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&imsic->matrix_lock, flags);
	irq_matrix_offline(imsic->matrix);
	raw_spin_unlock_irqrestore(&imsic->matrix_lock, flags);
}

static int __init imsic_matrix_init(void)
{
	struct imsic_global_config *global = &imsic->global;

	raw_spin_lock_init(&imsic->matrix_lock);
	imsic->matrix = irq_alloc_matrix(global->nr_ids + 1,
					 0, global->nr_ids + 1);
	if (!imsic->matrix)
		return -ENOMEM;

	/* Reserve ID#0 because it is special and never implemented */
	irq_matrix_assign_system(imsic->matrix, 0, false);

	/* Reserve IPI ID because it is special and used internally */
	irq_matrix_assign_system(imsic->matrix, IMSIC_IPI_ID, false);

	return 0;
}

static int __init imsic_get_parent_hartid(struct fwnode_handle *fwnode,
					  u32 index, unsigned long *hartid)
{
	int rc;
	struct of_phandle_args parent;

	/*
	 * Currently, only OF fwnode is supported so extend this
	 * function for ACPI support.
	 */
	if (!is_of_node(fwnode))
		return -EINVAL;

	rc = of_irq_parse_one(to_of_node(fwnode), index, &parent);
	if (rc)
		return rc;

	/*
	 * Skip interrupts other than external interrupts for
	 * current privilege level.
	 */
	if (parent.args[0] != RV_IRQ_EXT)
		return -EINVAL;

	return riscv_of_parent_hartid(parent.np, hartid);
}

static int __init imsic_get_mmio_resource(struct fwnode_handle *fwnode,
					  u32 index, struct resource *res)
{
	/*
	 * Currently, only OF fwnode is supported so extend this
	 * function for ACPI support.
	 */
	if (!is_of_node(fwnode))
		return -EINVAL;

	return of_address_to_resource(to_of_node(fwnode), index, res);
}

static int __init imsic_parse_fwnode(struct fwnode_handle *fwnode,
				     struct imsic_global_config *global,
				     u32 *nr_parent_irqs,
				     u32 *nr_mmios)
{
	unsigned long hartid;
	struct resource res;
	int rc;
	u32 i;

	/*
	 * Currently, only OF fwnode is supported so extend this
	 * function for ACPI support.
	 */
	if (!is_of_node(fwnode))
		return -EINVAL;

	*nr_parent_irqs = 0;
	*nr_mmios = 0;

	/* Find number of parent interrupts */
	*nr_parent_irqs = 0;
	while (!imsic_get_parent_hartid(fwnode, *nr_parent_irqs, &hartid))
		(*nr_parent_irqs)++;
	if (!(*nr_parent_irqs)) {
		pr_err("%pfwP: no parent irqs available\n", fwnode);
		return -EINVAL;
	}

	/* Find number of guest index bits in MSI address */
	rc = of_property_read_u32(to_of_node(fwnode),
				  "riscv,guest-index-bits",
				  &global->guest_index_bits);
	if (rc)
		global->guest_index_bits = 0;

	/* Find number of HART index bits */
	rc = of_property_read_u32(to_of_node(fwnode),
				  "riscv,hart-index-bits",
				  &global->hart_index_bits);
	if (rc) {
		/* Assume default value */
		global->hart_index_bits = __fls(*nr_parent_irqs);
		if (BIT(global->hart_index_bits) < *nr_parent_irqs)
			global->hart_index_bits++;
	}

	/* Find number of group index bits */
	rc = of_property_read_u32(to_of_node(fwnode),
				  "riscv,group-index-bits",
				  &global->group_index_bits);
	if (rc)
		global->group_index_bits = 0;

	/*
	 * Find first bit position of group index.
	 * If not specified assumed the default APLIC-IMSIC configuration.
	 */
	rc = of_property_read_u32(to_of_node(fwnode),
				  "riscv,group-index-shift",
				  &global->group_index_shift);
	if (rc)
		global->group_index_shift = IMSIC_MMIO_PAGE_SHIFT * 2;

	/* Find number of interrupt identities */
	rc = of_property_read_u32(to_of_node(fwnode),
				  "riscv,num-ids",
				  &global->nr_ids);
	if (rc) {
		pr_err("%pfwP: number of interrupt identities not found\n",
			fwnode);
		return rc;
	}

	/* Find number of guest interrupt identities */
	rc = of_property_read_u32(to_of_node(fwnode),
				  "riscv,num-guest-ids",
				  &global->nr_guest_ids);
	if (rc)
		global->nr_guest_ids = global->nr_ids;

	/* Sanity check guest index bits */
	i = BITS_PER_LONG - IMSIC_MMIO_PAGE_SHIFT;
	if (i < global->guest_index_bits) {
		pr_err("%pfwP: guest index bits too big\n", fwnode);
		return -EINVAL;
	}

	/* Sanity check HART index bits */
	i = BITS_PER_LONG - IMSIC_MMIO_PAGE_SHIFT - global->guest_index_bits;
	if (i < global->hart_index_bits) {
		pr_err("%pfwP: HART index bits too big\n", fwnode);
		return -EINVAL;
	}

	/* Sanity check group index bits */
	i = BITS_PER_LONG - IMSIC_MMIO_PAGE_SHIFT -
	    global->guest_index_bits - global->hart_index_bits;
	if (i < global->group_index_bits) {
		pr_err("%pfwP: group index bits too big\n", fwnode);
		return -EINVAL;
	}

	/* Sanity check group index shift */
	i = global->group_index_bits + global->group_index_shift - 1;
	if (i >= BITS_PER_LONG) {
		pr_err("%pfwP: group index shift too big\n", fwnode);
		return -EINVAL;
	}

	/* Sanity check number of interrupt identities */
	if ((global->nr_ids < IMSIC_MIN_ID) ||
	    (global->nr_ids >= IMSIC_MAX_ID) ||
	    ((global->nr_ids & IMSIC_MIN_ID) != IMSIC_MIN_ID)) {
		pr_err("%pfwP: invalid number of interrupt identities\n",
			fwnode);
		return -EINVAL;
	}

	/* Sanity check number of guest interrupt identities */
	if ((global->nr_guest_ids < IMSIC_MIN_ID) ||
	    (global->nr_guest_ids >= IMSIC_MAX_ID) ||
	    ((global->nr_guest_ids & IMSIC_MIN_ID) != IMSIC_MIN_ID)) {
		pr_err("%pfwP: invalid number of guest interrupt identities\n",
			fwnode);
		return -EINVAL;
	}

	/* Compute base address */
	rc = imsic_get_mmio_resource(fwnode, 0, &res);
	if (rc) {
		pr_err("%pfwP: first MMIO resource not found\n", fwnode);
		return -EINVAL;
	}
	global->base_addr = res.start;
	global->base_addr &= ~(BIT(global->guest_index_bits +
				   global->hart_index_bits +
				   IMSIC_MMIO_PAGE_SHIFT) - 1);
	global->base_addr &= ~((BIT(global->group_index_bits) - 1) <<
			       global->group_index_shift);

	/* Find number of MMIO register sets */
	while (!imsic_get_mmio_resource(fwnode, *nr_mmios, &res))
		(*nr_mmios)++;

	return 0;
}

int __init imsic_setup_state(struct fwnode_handle *fwnode)
{
	int rc, cpu;
	phys_addr_t base_addr;
	void __iomem **mmios_va = NULL;
	struct resource *mmios = NULL;
	struct imsic_local_config *local;
	struct imsic_global_config *global;
	unsigned long reloff, hartid;
	u32 i, j, index, nr_parent_irqs, nr_mmios, nr_handlers = 0;

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

	/* Parse IMSIC fwnode */
	rc = imsic_parse_fwnode(fwnode, global, &nr_parent_irqs, &nr_mmios);
	if (rc)
		goto out_free_local;

	/* Allocate MMIO resource array */
	mmios = kcalloc(nr_mmios, sizeof(*mmios), GFP_KERNEL);
	if (!mmios) {
		rc = -ENOMEM;
		goto out_free_local;
	}

	/* Allocate MMIO virtual address array */
	mmios_va = kcalloc(nr_mmios, sizeof(*mmios_va), GFP_KERNEL);
	if (!mmios_va) {
		rc = -ENOMEM;
		goto out_iounmap;
	}

	/* Parse and map MMIO register sets */
	for (i = 0; i < nr_mmios; i++) {
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

	/* Initialize HW interrupt numbers */
	rc = imsic_hwirqs_init();
	if (rc) {
		pr_err("%pfwP: failed to initialize HW interrupts numbers\n",
		       fwnode);
		goto out_iounmap;
	}

	/* Initialize local (or per-CPU )state */
	rc = imsic_local_init();
	if (rc) {
		pr_err("%pfwP: failed to initialize local state\n",
		       fwnode);
		goto out_hwirqs_cleanup;
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
		index = nr_mmios;
		reloff = i * BIT(global->guest_index_bits) *
			 IMSIC_MMIO_PAGE_SZ;
		for (j = 0; nr_mmios; j++) {
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
		if (index >= nr_mmios) {
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
		goto out_local_cleanup;
	}

	/* Initialize matrix allocator */
	rc = imsic_matrix_init();
	if (rc) {
		pr_err("%pfwP: failed to create matrix allocator\n",
		       fwnode);
		goto out_local_cleanup;
	}

	/* We don't need MMIO arrays anymore so let's free-up */
	kfree(mmios_va);
	kfree(mmios);

	return 0;

out_local_cleanup:
	imsic_local_cleanup();
out_hwirqs_cleanup:
	imsic_hwirqs_cleanup();
out_iounmap:
	for (i = 0; i < nr_mmios; i++) {
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

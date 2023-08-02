/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Western Digital Corporation or its affiliates.
 * Copyright (C) 2022 Ventana Micro Systems Inc.
 */

#ifndef _IRQ_RISCV_IMSIC_STATE_H
#define _IRQ_RISCV_IMSIC_STATE_H

#include <linux/irqchip/riscv-imsic.h>
#include <linux/irqdomain.h>
#include <linux/fwnode.h>

/*
 * The IMSIC driver uses 1 IPI for ID synchronization and
 * arch/riscv/kernel/smp.c require 6 IPIs so we fix the
 * total number of IPIs to 8.
 */
#define IMSIC_IPI_ID				1
#define IMSIC_NR_IPI				8

struct imsic_vector {
	/* Fixed details of the vector */
	unsigned int cpu;
	unsigned int local_id;
	/* Details saved by driver in the vector */
	unsigned int hwirq;
};

struct imsic_local_priv {
	/* Local state of interrupt identities */
	raw_spinlock_t ids_lock;
	unsigned long *ids_enabled_bitmap;
	struct imsic_vector **ids_move;

	/* Local vector table */
	struct imsic_vector *vectors;
};

struct imsic_priv {
	/* Device details */
	struct fwnode_handle *fwnode;

	/* Global configuration common for all HARTs */
	struct imsic_global_config global;

	/* Dummy HW interrupt numbers */
	unsigned int nr_hwirqs;
	raw_spinlock_t hwirqs_lock;
	unsigned long *hwirqs_used_bitmap;

	/* Per-CPU state */
	struct imsic_local_priv __percpu *lpriv;

	/* State of IRQ matrix allocator */
	raw_spinlock_t matrix_lock;
	struct irq_matrix *matrix;

	/* IPI interrupt identity and synchronization */
	int ipi_virq;
	struct irq_desc *ipi_lsync_desc;

	/* IRQ domains (created by platform driver) */
	struct irq_domain *base_domain;
	struct irq_domain *plat_domain;
};

extern struct imsic_priv *imsic;

void __imsic_eix_update(unsigned long base_id,
			unsigned long num_id, bool pend, bool val);

#define __imsic_id_set_enable(__id)		\
	__imsic_eix_update((__id), 1, false, true)
#define __imsic_id_clear_enable(__id)	\
	__imsic_eix_update((__id), 1, false, false)

void imsic_local_sync(void);
void imsic_local_delivery(bool enable);

void imsic_vector_mask(struct imsic_vector *vec);
void imsic_vector_unmask(struct imsic_vector *vec);
void imsic_vector_move(struct imsic_vector *old_vec,
			struct imsic_vector *new_vec);

struct imsic_vector *imsic_vector_from_local_id(unsigned int cpu,
						unsigned int local_id);

struct imsic_vector *imsic_vector_alloc(unsigned int hwirq,
					const struct cpumask *mask);
void imsic_vector_free(struct imsic_vector *vector);

void imsic_vector_debug_show(struct seq_file *m,
			     struct imsic_vector *vec, int ind);

void imsic_vector_debug_show_summary(struct seq_file *m, int ind);

int imsic_hwirq_alloc(void);
void imsic_hwirq_free(unsigned int hwirq);

void imsic_state_online(void);
void imsic_state_offline(void);
int imsic_setup_state(struct fwnode_handle *fwnode);

#endif

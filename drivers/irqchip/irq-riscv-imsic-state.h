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

struct imsic_priv {
	/* Device details */
	struct fwnode_handle *fwnode;

	/* Global configuration common for all HARTs */
	struct imsic_global_config global;

	/* Global state of interrupt identities */
	raw_spinlock_t ids_lock;
	unsigned long *ids_used_bimap;
	unsigned long *ids_enabled_bimap;
	unsigned int *ids_target_cpu;

	/* IPI interrupt identity and synchronization */
	u32 ipi_id;
	int ipi_virq;
	struct irq_desc *ipi_lsync_desc;

	/* IRQ domains (created by platform driver) */
	struct irq_domain *base_domain;
	struct irq_domain *pci_domain;
	struct irq_domain *plat_domain;
};

extern struct imsic_priv *imsic;

void __imsic_eix_update(unsigned long base_id,
			unsigned long num_id, bool pend, bool val);

#define __imsic_id_enable(__id)		\
	__imsic_eix_update((__id), 1, false, true)
#define __imsic_id_disable(__id)	\
	__imsic_eix_update((__id), 1, false, false)

void imsic_id_set_target(unsigned int id, unsigned int target_cpu);
unsigned int imsic_id_get_target(unsigned int id);

void imsic_ids_local_sync(void);
void imsic_ids_local_delivery(bool enable);

#ifdef CONFIG_SMP
void imsic_ids_remote_sync(void);
#else
static inline void imsic_ids_remote_sync(void)
{
}
#endif

int imsic_ids_alloc(unsigned int order);
void imsic_ids_free(unsigned int base_id, unsigned int order);

int imsic_setup_state(struct fwnode_handle *fwnode);

#endif

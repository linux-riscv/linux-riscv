// SPDX-License-Identifier: GPL-2.0-only
/*
 * RISC-V IOMMU debug interface.
 *
 * Copyright © 2023 Rivos Inc.
 *
 * Author: Tomasz Jeznach <tjeznach@rivosinc.com>
 */

#include <linux/debugfs.h>
#include <linux/pci.h>
#include <linux/iommu.h>

#include "iommu.h"

static struct dentry *riscv_iommu_debugfs;
static DEFINE_MUTEX(riscv_iommu_debugfs_lock);

struct riscv_iommu_regs_info {
	unsigned int offset;
	unsigned int length;
	const char *name;
};

#define RISCV_IOMMU_REG_ENTRY(_reg_, _bits_) \
	{ RISCV_IOMMU_REG_##_reg_, _bits_, __stringify(_reg_) }

#define RISCV_IOMMU_REG_ENTRY_N(_reg_, _n_, _bits_) \
	{ RISCV_IOMMU_REG_##_reg_(_n_), _bits_, __stringify(_reg_) #_n_ }

static const struct riscv_iommu_regs_info riscv_iommu_regs[] = {
	RISCV_IOMMU_REG_ENTRY(CAP, 64),
	RISCV_IOMMU_REG_ENTRY(FCTL, 64),
	RISCV_IOMMU_REG_ENTRY(CQH, 32),
	RISCV_IOMMU_REG_ENTRY(CQT, 32),
	RISCV_IOMMU_REG_ENTRY(CQCSR, 32),
	RISCV_IOMMU_REG_ENTRY(FQH, 32),
	RISCV_IOMMU_REG_ENTRY(FQT, 32),
	RISCV_IOMMU_REG_ENTRY(FQCSR, 32),
	RISCV_IOMMU_REG_ENTRY(PQH, 32),
	RISCV_IOMMU_REG_ENTRY(PQT, 32),
	RISCV_IOMMU_REG_ENTRY(PQCSR, 32),
	RISCV_IOMMU_REG_ENTRY(IPSR, 32),
	RISCV_IOMMU_REG_ENTRY(IVEC, 32),
	RISCV_IOMMU_REG_ENTRY(TR_REQ_IOVA, 64),
	RISCV_IOMMU_REG_ENTRY(TR_REQ_CTL, 64),
	RISCV_IOMMU_REG_ENTRY(TR_RESPONSE, 64),
	RISCV_IOMMU_REG_ENTRY(IOCOUNTOVF, 32),
	RISCV_IOMMU_REG_ENTRY(IOCOUNTINH, 32),
	RISCV_IOMMU_REG_ENTRY(IOHPMCYCLES, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMEVT, 0, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMCTR, 0, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMEVT, 1, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMCTR, 1, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMEVT, 2, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMCTR, 2, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMEVT, 3, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMCTR, 3, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMEVT, 4, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMCTR, 4, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMEVT, 5, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMCTR, 5, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMEVT, 6, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMCTR, 6, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMEVT, 7, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMCTR, 7, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMEVT, 8, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMCTR, 8, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMEVT, 9, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMCTR, 9, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMEVT, 10, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMCTR, 10, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMEVT, 11, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMCTR, 11, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMEVT, 12, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMCTR, 12, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMEVT, 13, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMCTR, 13, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMEVT, 14, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMCTR, 14, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMEVT, 15, 64),
	RISCV_IOMMU_REG_ENTRY_N(IOHPMCTR, 15, 64),
};

static int riscv_iommu_regs_show(struct seq_file *m, void *unused)
{
	struct riscv_iommu_device *iommu = (struct riscv_iommu_device *)m->private;
	u64 value;
	int i;

	seq_puts(m, "Name\t\t\tOffset\t\tValue\n");
	for (i = 0 ; i < ARRAY_SIZE(riscv_iommu_regs); i++) {
		if (riscv_iommu_regs[i].length == 64)
			value = riscv_iommu_readq(iommu, riscv_iommu_regs[i].offset);
		else
			value = riscv_iommu_readl(iommu, riscv_iommu_regs[i].offset);

		seq_printf(m, "%-16s\t0x%02x\t\t0x%016llx\n",
			   riscv_iommu_regs[i].name, riscv_iommu_regs[i].offset,
			   value);
	}
	seq_putc(m, '\n');

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(riscv_iommu_regs);

static int riscv_iommu_endpoints_show(struct seq_file *m, void *unused)
{
	struct riscv_iommu_device *iommu = (struct riscv_iommu_device *)m->private;
	struct riscv_iommu_endpoint *ep;
	struct riscv_iommu_dc *dc;
	struct rb_node *n;
	int i;
	char name[32];

	mutex_lock(&iommu->eps_mutex);
	for (n = rb_first(&iommu->eps); n; n = rb_next(n)) {
		ep = rb_entry(n, struct riscv_iommu_endpoint, node);
		dc = ep->dc;

		/* report endpoint info */
		if (dev_is_pci(ep->dev))
			snprintf(name, sizeof(name) - 1, "%04x:%02x:%02x.%u",
				 ep->domid,
				 PCI_BUS_NUM(ep->devid),
				 PCI_SLOT(ep->devid),
				 PCI_FUNC(ep->devid));
		else
			snprintf(name, sizeof(name) - 1, "%04x#%04x",
				 ep->domid,
				 ep->devid);

		if (!dc) {
			seq_printf(m, "%s\tDISABLED\n", name);
			continue;
		}

		seq_printf(m, "%s\ttc: %016llx\tg-atp: %016llx\n",
			   name, ep->dc->tc, ep->dc->iohgatp);

		mutex_lock(&ep->lock);
		seq_printf(m, "\t\tta: %016llx\ts-atp: %016llx\n", dc->ta, dc->fsc);
		for (i = 0; ep->pc && i < 256; i++) {
			if (!(ep->pc[i].ta & RISCV_IOMMU_PC_TA_V))
				continue;
			seq_printf(m, "\t# %i\tta: %016llx\ts-atp: %016llx\n",
				   i, ep->pc[i].ta, ep->pc[i].fsc);
		}
		mutex_unlock(&ep->lock);
	}
	mutex_unlock(&iommu->eps_mutex);
	seq_putc(m, '\n');

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(riscv_iommu_endpoints);

#define	MAX_NAME_LEN	64

void riscv_iommu_debugfs_setup(struct riscv_iommu_device *iommu)
{
	char name[MAX_NAME_LEN + 1];

	mutex_lock(&riscv_iommu_debugfs_lock);
	if (!riscv_iommu_debugfs)
		riscv_iommu_debugfs = debugfs_create_dir("riscv", iommu_debugfs_dir);
	mutex_unlock(&riscv_iommu_debugfs_lock);

	snprintf(name, MAX_NAME_LEN, "iommu@%lx", (unsigned long)iommu->reg_phys);
	iommu->debugfs = debugfs_create_dir(name, riscv_iommu_debugfs);

	debugfs_create_file("regs", 0444, iommu->debugfs, iommu,
			    &riscv_iommu_regs_fops);

	debugfs_create_file("endpoints", 0444, iommu->debugfs, iommu,
			    &riscv_iommu_endpoints_fops);
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * IOMMU API for RISC-V IOMMU implementations.
 *
 * Copyright © 2022-2023 Rivos Inc.
 * Copyright © 2023 FORTH-ICS/CARV
 *
 * Authors
 *	Tomasz Jeznach <tjeznach@rivosinc.com>
 *	Nick Kossifidis <mick@ics.forth.gr>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/bitfield.h>
#include <linux/compiler.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/dma-map-ops.h>
#include <linux/init.h>
#include <linux/iommu.h>
#include <linux/irqdomain.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci-ats.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/uaccess.h>
#include <asm/csr.h>
#include <asm/page.h>

#include "../dma-iommu.h"
#include "iommu.h"

MODULE_DESCRIPTION("Driver for RISC-V IOMMU");
MODULE_AUTHOR("Tomasz Jeznach <tjeznach@rivosinc.com>");
MODULE_AUTHOR("Nick Kossifidis <mick@ics.forth.gr>");
MODULE_ALIAS("riscv-iommu");
MODULE_LICENSE("GPL v2");

/* Global IOMMU params. */
static int ddt_mode = RISCV_IOMMU_DDTP_MODE_3LVL;
module_param(ddt_mode, int, 0644);
MODULE_PARM_DESC(ddt_mode, "Device Directory Table mode.");

/* IOMMU PSCID allocation namespace. */
#define RISCV_IOMMU_MAX_PSCID	BIT(20)
static DEFINE_IDA(riscv_iommu_pscids);

/* 1 second */
#define RISCV_IOMMU_TIMEOUT	riscv_timebase

/* Default queue lengths */
#define RISCV_IOMMU_DEF_CQ_COUNT	1024
#define RISCV_IOMMU_DEF_FQ_COUNT	 512
#define RISCV_IOMMU_DEF_PQ_COUNT	1024

/* RISC-V IOMMU PPN <> PHYS address conversions, PHYS <=> PPN[53:10] */
#define phys_to_ppn(va)  (((va) >> 2) & (((1ULL << 44) - 1) << 10))
#define ppn_to_phys(pn)	 (((pn) << 2) & (((1ULL << 44) - 1) << 12))

#define iommu_domain_to_riscv(iommu_domain) \
	container_of(iommu_domain, struct riscv_iommu_domain, domain)

#define iommu_device_to_riscv(iommu_device) \
	container_of(iommu_device, struct riscv_iommu, iommu)

static const struct iommu_domain_ops riscv_iommu_domain_ops;
static const struct iommu_ops riscv_iommu_ops;

/*
 * Common queue management routines
 */

/* Note: offsets are the same for all queues */
#define Q_HEAD(q) ((q)->qbr + (RISCV_IOMMU_REG_CQH - RISCV_IOMMU_REG_CQB))
#define Q_TAIL(q) ((q)->qbr + (RISCV_IOMMU_REG_CQT - RISCV_IOMMU_REG_CQB))

static unsigned int riscv_iommu_queue_consume(struct riscv_iommu_device *iommu,
					      struct riscv_iommu_queue *q,
					      unsigned int *ready)
{
	cycles_t end_cycles = RISCV_IOMMU_TIMEOUT + get_cycles();
	u32 tail = riscv_iommu_readl(iommu, Q_TAIL(q));
	*ready = q->lui;

	/* retry read if tail value is not reasonable */
	while (WARN_ON_ONCE(q->cnt <= tail) && get_cycles() < end_cycles)
		tail = riscv_iommu_readl(iommu, Q_TAIL(q));

	if (q->lui <= tail)
		return tail - q->lui;
	return q->cnt - q->lui;
}

static void riscv_iommu_queue_release(struct riscv_iommu_device *iommu,
				      struct riscv_iommu_queue *q, unsigned int count)
{
	q->lui = (q->lui + count) & (q->cnt - 1);
	riscv_iommu_writel(iommu, Q_HEAD(q), q->lui);
}

static u32 riscv_iommu_queue_ctrl(struct riscv_iommu_device *iommu,
				  struct riscv_iommu_queue *q, u32 val)
{
	cycles_t end_cycles = RISCV_IOMMU_TIMEOUT + get_cycles();

	riscv_iommu_writel(iommu, q->qcr, val);
	do {
		val = riscv_iommu_readl(iommu, q->qcr);
		if (!(val & RISCV_IOMMU_QUEUE_BUSY))
			break;
		cpu_relax();
	} while (get_cycles() < end_cycles);

	return val;
}

static void riscv_iommu_queue_free(struct riscv_iommu_device *iommu,
				   struct riscv_iommu_queue *q)
{
	riscv_iommu_queue_ctrl(iommu, q, 0);
	if (q->irq)
		free_irq(q->irq, q);

	/* Note: devres_release_all() will release queue resources */
}

static irqreturn_t riscv_iommu_cmdq_irq_check(int irq, void *data);
static irqreturn_t riscv_iommu_cmdq_process(int irq, void *data);
static irqreturn_t riscv_iommu_fltq_irq_check(int irq, void *data);
static irqreturn_t riscv_iommu_fltq_process(int irq, void *data);
static irqreturn_t riscv_iommu_priq_irq_check(int irq, void *data);
static irqreturn_t riscv_iommu_priq_process(int irq, void *data);

static int riscv_iommu_queue_init(struct riscv_iommu_device *iommu,
				  int queue_id)
{
	struct device *dev = iommu->dev;
	struct riscv_iommu_queue *q = NULL;
	size_t queue_size;
	size_t item_size;
	irq_handler_t irq_check;
	irq_handler_t irq_process;
	const char *name;
	unsigned int order;
	unsigned int item_count;
	int irq;
	u64 qbr_val = 0;
	u64 qbr_readback = 0;
	u64 qbr_paddr = 0;
	u64 ivec;

	/* Read out actual cause to vector mapping */
	ivec = riscv_iommu_readq(iommu, RISCV_IOMMU_REG_IVEC);

	switch (queue_id) {
	case RISCV_IOMMU_FAULT_QUEUE:
		name = "fltq";
		q = &iommu->fltq;
		q->qbr = RISCV_IOMMU_REG_FQB;
		q->qcr = RISCV_IOMMU_REG_FQCSR;
		item_size = sizeof(struct riscv_iommu_fq_record);
		item_count = q->cnt ?: RISCV_IOMMU_DEF_FQ_COUNT;
		irq_check = riscv_iommu_fltq_irq_check;
		irq_process = riscv_iommu_fltq_process;
		irq = iommu->irqs[FIELD_GET(RISCV_IOMMU_IVEC_FIV, ivec) %
				  RISCV_IOMMU_INTR_COUNT];
		break;
	case RISCV_IOMMU_COMMAND_QUEUE:
		name = "cmdq";
		q = &iommu->cmdq;
		q->qbr = RISCV_IOMMU_REG_CQB;
		q->qcr = RISCV_IOMMU_REG_CQCSR;
		item_size = sizeof(struct riscv_iommu_command);
		item_count = q->cnt ?: RISCV_IOMMU_DEF_CQ_COUNT;
		irq_check = riscv_iommu_cmdq_irq_check;
		irq_process = riscv_iommu_cmdq_process;
		irq = iommu->irqs[FIELD_GET(RISCV_IOMMU_IVEC_CIV, ivec) %
				  RISCV_IOMMU_INTR_COUNT];
		break;
	case RISCV_IOMMU_PAGE_REQUEST_QUEUE:
		name = "priq";
		q = &iommu->priq;
		q->qbr = RISCV_IOMMU_REG_PQB;
		q->qcr = RISCV_IOMMU_REG_PQCSR;
		item_size = sizeof(struct riscv_iommu_pq_record);
		item_count = q->cnt ?: RISCV_IOMMU_DEF_PQ_COUNT;
		irq_check = riscv_iommu_priq_irq_check;
		irq_process = riscv_iommu_priq_process;
		irq = iommu->irqs[FIELD_GET(RISCV_IOMMU_IVEC_PIV, ivec) %
				  RISCV_IOMMU_INTR_COUNT];
		break;
	default:
		dev_err(dev, "invalid queue index %i\n", queue_id);
		return -EINVAL;
	}

	/* Polling not implemented */
	if (!irq)
		return -ENODEV;

	/* Allocate queue in memory and set the base register */
	order = ilog2(item_count);
	do {
		queue_size = item_size << order;
		q->base = dmam_alloc_coherent(dev, queue_size, &q->base_dma, GFP_KERNEL);
		if (q->base || queue_size < PAGE_SIZE)
			break;

		order--;
	} while (1);

	if (!q->base) {
		dev_err(dev, "failed to allocate %s queue (cnt: %u)\n",
			name, item_count);
		return -ENOMEM;
	}

	qbr_val = phys_to_ppn(q->base_dma) |
	    FIELD_PREP(RISCV_IOMMU_QUEUE_LOGSZ_FIELD, order - 1);

	riscv_iommu_writeq(iommu, q->qbr, qbr_val);

	/*
	 * Queue base registers are WARL, so it's possible that whatever we wrote
	 * there was illegal/not supported by the hw in which case we need to make
	 * sure we set a supported PPN and/or queue size.
	 */
	qbr_readback = riscv_iommu_readq(iommu, q->qbr);
	if (qbr_readback == qbr_val) {
		q->cnt = 1UL << order;
		goto irq;
	}

	dmam_free_coherent(dev, queue_size, q->base, q->base_dma);

	/* Get supported queue size */
	order = FIELD_GET(RISCV_IOMMU_QUEUE_LOGSZ_FIELD, qbr_readback) + 1;
	item_count = 1UL << order;
	queue_size = item_size << order;

	/*
	 * In case we also failed to set PPN, it means the field is hardcoded and the
	 * queue resides in I/O memory instead, so get its physical address and
	 * ioremap it.
	 */
	qbr_paddr = ppn_to_phys(qbr_readback);
	if (qbr_paddr != q->base_dma) {
		dev_dbg(dev,
			"hardcoded ppn in %s base register, using io memory for the queue\n",
			name);
		dev_dbg(dev, "queue length for %s set to %u\n", name, item_count);
		q->in_iomem = true;
		q->base = devm_ioremap(dev, qbr_paddr, queue_size);
		if (!q->base) {
			dev_err(dev, "failed to map %s queue (cnt: %u)\n", name, item_count);
			return -ENOMEM;
		}
		q->cnt = item_count;
		q->base_dma = qbr_paddr;
	} else {
		/*
		 * We only failed to set the queue size, re-try to allocate memory with
		 * the queue size supported by the hw.
		 */
		dev_dbg(dev, "hardcoded queue size in %s base register\n", name);
		dev_dbg(dev, "retrying with queue length: %u\n", item_count);
		q->base = dmam_alloc_coherent(dev, queue_size, &q->base_dma, GFP_KERNEL);
		if (!q->base) {
			dev_err(dev, "failed to allocate %s queue (cnt: %u)\n",
				name, item_count);
			return -ENOMEM;
		}
		q->cnt = item_count;
	}

	qbr_val = phys_to_ppn(q->base_dma) |
		  FIELD_PREP(RISCV_IOMMU_QUEUE_LOGSZ_FIELD, order - 1);
	riscv_iommu_writeq(iommu, q->qbr, qbr_val);

	/* Final check to make sure hw accepted our write */
	qbr_readback = riscv_iommu_readq(iommu, q->qbr);
	if (qbr_readback != qbr_val) {
		dev_err(dev, "failed to set base register for %s\n", name);
		riscv_iommu_queue_free(iommu, q);
		return -ENODEV;
	}

 irq:
	if (request_threaded_irq(irq, irq_check, irq_process, IRQF_ONESHOT | IRQF_SHARED,
				 dev_name(dev), q)) {
		dev_err(dev, "fail to request irq %d for %s\n", irq, name);
		riscv_iommu_queue_free(iommu, q);
		return -ENODEV;
	}

	q->irq = irq;

	/* Note: All RIO_xQ_EN/IE fields are in the same offsets */
	if (riscv_iommu_queue_ctrl(iommu, q,
				   RISCV_IOMMU_QUEUE_ENABLE |
				   RISCV_IOMMU_QUEUE_INTR_ENABLE) &
				   RISCV_IOMMU_QUEUE_BUSY) {
		dev_err(dev, "%s init timeout\n", name);
		riscv_iommu_queue_free(iommu, q);
		return -EBUSY;
	}

	return 0;
}

/*
 * I/O MMU Command queue chapter 3.1
 */

static inline void riscv_iommu_cmd_inval_vma(struct riscv_iommu_command *cmd)
{
	cmd->dword0 = FIELD_PREP(RISCV_IOMMU_CMD_OPCODE,
				 RISCV_IOMMU_CMD_IOTINVAL_OPCODE) |
		      FIELD_PREP(RISCV_IOMMU_CMD_FUNC,
				 RISCV_IOMMU_CMD_IOTINVAL_FUNC_VMA);
	cmd->dword1 = 0;
}

static inline void riscv_iommu_cmd_inval_set_addr(struct riscv_iommu_command *cmd,
						  u64 addr)
{
	cmd->dword0 |= RISCV_IOMMU_CMD_IOTINVAL_AV;
	cmd->dword1 = FIELD_PREP(RISCV_IOMMU_CMD_IOTINVAL_ADDR, phys_to_pfn(addr));
}

static inline void riscv_iommu_cmd_inval_set_pscid(struct riscv_iommu_command *cmd,
						   unsigned int pscid)
{
	cmd->dword0 |= FIELD_PREP(RISCV_IOMMU_CMD_IOTINVAL_PSCID, pscid) |
		       RISCV_IOMMU_CMD_IOTINVAL_PSCV;
}

static inline void riscv_iommu_cmd_inval_set_gscid(struct riscv_iommu_command *cmd,
						   unsigned int gscid)
{
	cmd->dword0 |= FIELD_PREP(RISCV_IOMMU_CMD_IOTINVAL_GSCID, gscid) |
		       RISCV_IOMMU_CMD_IOTINVAL_GV;
}

static inline void riscv_iommu_cmd_iofence(struct riscv_iommu_command *cmd)
{
	cmd->dword0 = FIELD_PREP(RISCV_IOMMU_CMD_OPCODE,
				 RISCV_IOMMU_CMD_IOFENCE_OPCODE) |
		      FIELD_PREP(RISCV_IOMMU_CMD_FUNC,
				 RISCV_IOMMU_CMD_IOFENCE_FUNC_C);
	cmd->dword1 = 0;
}

static inline void riscv_iommu_cmd_iofence_set_av(struct riscv_iommu_command *cmd,
						  u64 addr, u32 data)
{
	cmd->dword0 = FIELD_PREP(RISCV_IOMMU_CMD_OPCODE,
				 RISCV_IOMMU_CMD_IOFENCE_OPCODE) |
		      FIELD_PREP(RISCV_IOMMU_CMD_FUNC,
				 RISCV_IOMMU_CMD_IOFENCE_FUNC_C) |
		      FIELD_PREP(RISCV_IOMMU_CMD_IOFENCE_DATA, data) |
		      RISCV_IOMMU_CMD_IOFENCE_AV;
	cmd->dword1 = addr >> 2;
}

static inline void riscv_iommu_cmd_iodir_inval_ddt(struct riscv_iommu_command *cmd)
{
	cmd->dword0 = FIELD_PREP(RISCV_IOMMU_CMD_OPCODE,
				 RISCV_IOMMU_CMD_IODIR_OPCODE) |
		      FIELD_PREP(RISCV_IOMMU_CMD_FUNC,
				 RISCV_IOMMU_CMD_IODIR_FUNC_INVAL_DDT);
	cmd->dword1 = 0;
}

static inline void riscv_iommu_cmd_iodir_inval_pdt(struct riscv_iommu_command *cmd)
{
	cmd->dword0 = FIELD_PREP(RISCV_IOMMU_CMD_OPCODE,
				 RISCV_IOMMU_CMD_IODIR_OPCODE) |
		      FIELD_PREP(RISCV_IOMMU_CMD_FUNC,
				 RISCV_IOMMU_CMD_IODIR_FUNC_INVAL_PDT);
	cmd->dword1 = 0;
}

static inline void riscv_iommu_cmd_iodir_set_did(struct riscv_iommu_command *cmd,
						 unsigned int devid)
{
	cmd->dword0 |= FIELD_PREP(RISCV_IOMMU_CMD_IODIR_DID, devid) |
		       RISCV_IOMMU_CMD_IODIR_DV;
}

/* TODO: Convert into lock-less MPSC implementation. */
static bool riscv_iommu_post_sync(struct riscv_iommu_device *iommu,
				  struct riscv_iommu_command *cmd, bool sync)
{
	u32 head, tail, next, last;
	unsigned long flags;

	spin_lock_irqsave(&iommu->cq_lock, flags);
	head = riscv_iommu_readl(iommu, RISCV_IOMMU_REG_CQH) & (iommu->cmdq.cnt - 1);
	tail = riscv_iommu_readl(iommu, RISCV_IOMMU_REG_CQT) & (iommu->cmdq.cnt - 1);
	last = iommu->cmdq.lui;
	if (tail != last) {
		spin_unlock_irqrestore(&iommu->cq_lock, flags);
		/*
		 * FIXME: This is a workaround for dropped MMIO writes/reads on QEMU platform.
		 *        While debugging of the problem is still ongoing, this provides
		 *        a simple impolementation of try-again policy.
		 *        Will be changed to lock-less algorithm in the feature.
		 */
		dev_dbg(iommu->dev, "IOMMU CQT: %x != %x (1st)\n", last, tail);
		spin_lock_irqsave(&iommu->cq_lock, flags);
		tail =
		    riscv_iommu_readl(iommu, RISCV_IOMMU_REG_CQT) & (iommu->cmdq.cnt - 1);
		last = iommu->cmdq.lui;
		if (tail != last) {
			spin_unlock_irqrestore(&iommu->cq_lock, flags);
			dev_dbg(iommu->dev, "IOMMU CQT: %x != %x (2nd)\n", last, tail);
			spin_lock_irqsave(&iommu->cq_lock, flags);
		}
	}

	next = (last + 1) & (iommu->cmdq.cnt - 1);
	if (next != head) {
		struct riscv_iommu_command *ptr = iommu->cmdq.base;

		ptr[last] = *cmd;
		/* Enforce in-memory command record ordering before device doorbell write */
		wmb();
		riscv_iommu_writel(iommu, RISCV_IOMMU_REG_CQT, next);
		iommu->cmdq.lui = next;
	}

	spin_unlock_irqrestore(&iommu->cq_lock, flags);

	if (sync && head != next) {
		cycles_t start_time = get_cycles();

		while (1) {
			last = riscv_iommu_readl(iommu, RISCV_IOMMU_REG_CQH) &
			    (iommu->cmdq.cnt - 1);
			if (head < next && last >= next)
				break;
			if (head > next && last < head && last >= next)
				break;
			if (RISCV_IOMMU_TIMEOUT < (get_cycles() - start_time)) {
				dev_err(iommu->dev, "IOFENCE TIMEOUT\n");
				return false;
			}
			cpu_relax();
		}
	}

	return next != head;
}

static bool riscv_iommu_post(struct riscv_iommu_device *iommu,
			     struct riscv_iommu_command *cmd)
{
	return riscv_iommu_post_sync(iommu, cmd, false);
}

static bool riscv_iommu_iodir_inv_devid(struct riscv_iommu_device *iommu, unsigned int devid)
{
	struct riscv_iommu_command cmd;

	riscv_iommu_cmd_iodir_inval_ddt(&cmd);
	riscv_iommu_cmd_iodir_set_did(&cmd, devid);
	return riscv_iommu_post(iommu, &cmd);
}

static bool riscv_iommu_iofence_sync(struct riscv_iommu_device *iommu)
{
	struct riscv_iommu_command cmd;

	riscv_iommu_cmd_iofence(&cmd);
	return riscv_iommu_post_sync(iommu, &cmd, true);
}

/* Command queue primary interrupt handler */
static irqreturn_t riscv_iommu_cmdq_irq_check(int irq, void *data)
{
	struct riscv_iommu_queue *q = (struct riscv_iommu_queue *)data;
	struct riscv_iommu_device *iommu =
	    container_of(q, struct riscv_iommu_device, cmdq);
	u32 ipsr = riscv_iommu_readl(iommu, RISCV_IOMMU_REG_IPSR);

	if (ipsr & RISCV_IOMMU_IPSR_CIP)
		return IRQ_WAKE_THREAD;
	return IRQ_NONE;
}

/* Command queue interrupt hanlder thread function */
static irqreturn_t riscv_iommu_cmdq_process(int irq, void *data)
{
	struct riscv_iommu_queue *q = (struct riscv_iommu_queue *)data;
	struct riscv_iommu_device *iommu;
	unsigned int ctrl;

	iommu = container_of(q, struct riscv_iommu_device, cmdq);

	/* Error reporting, clear error reports if any. */
	ctrl = riscv_iommu_readl(iommu, RISCV_IOMMU_REG_CQCSR);
	if (ctrl & (RISCV_IOMMU_CQCSR_CQMF |
		    RISCV_IOMMU_CQCSR_CMD_TO | RISCV_IOMMU_CQCSR_CMD_ILL)) {
		riscv_iommu_queue_ctrl(iommu, &iommu->cmdq, ctrl);
		dev_warn_ratelimited(iommu->dev,
				     "Command queue error: fault: %d tout: %d err: %d\n",
				     !!(ctrl & RISCV_IOMMU_CQCSR_CQMF),
				     !!(ctrl & RISCV_IOMMU_CQCSR_CMD_TO),
				     !!(ctrl & RISCV_IOMMU_CQCSR_CMD_ILL));
	}

	/* Clear fault interrupt pending. */
	riscv_iommu_writel(iommu, RISCV_IOMMU_REG_IPSR, RISCV_IOMMU_IPSR_CIP);

	return IRQ_HANDLED;
}

/*
 * Fault/event queue, chapter 3.2
 */

static void riscv_iommu_fault_report(struct riscv_iommu_device *iommu,
				     struct riscv_iommu_fq_record *event)
{
	unsigned int err, devid;

	err = FIELD_GET(RISCV_IOMMU_FQ_HDR_CAUSE, event->hdr);
	devid = FIELD_GET(RISCV_IOMMU_FQ_HDR_DID, event->hdr);

	dev_warn_ratelimited(iommu->dev,
			     "Fault %d devid: %d iotval: %llx iotval2: %llx\n", err,
			     devid, event->iotval, event->iotval2);
}

/* Fault/event queue primary interrupt handler */
static irqreturn_t riscv_iommu_fltq_irq_check(int irq, void *data)
{
	struct riscv_iommu_queue *q = (struct riscv_iommu_queue *)data;
	struct riscv_iommu_device *iommu =
	    container_of(q, struct riscv_iommu_device, fltq);
	u32 ipsr = riscv_iommu_readl(iommu, RISCV_IOMMU_REG_IPSR);

	if (ipsr & RISCV_IOMMU_IPSR_FIP)
		return IRQ_WAKE_THREAD;
	return IRQ_NONE;
}

/* Fault queue interrupt hanlder thread function */
static irqreturn_t riscv_iommu_fltq_process(int irq, void *data)
{
	struct riscv_iommu_queue *q = (struct riscv_iommu_queue *)data;
	struct riscv_iommu_device *iommu;
	struct riscv_iommu_fq_record *events;
	unsigned int cnt, len, idx, ctrl;

	iommu = container_of(q, struct riscv_iommu_device, fltq);
	events = (struct riscv_iommu_fq_record *)q->base;

	/* Error reporting, clear error reports if any. */
	ctrl = riscv_iommu_readl(iommu, RISCV_IOMMU_REG_FQCSR);
	if (ctrl & (RISCV_IOMMU_FQCSR_FQMF | RISCV_IOMMU_FQCSR_FQOF)) {
		riscv_iommu_queue_ctrl(iommu, &iommu->fltq, ctrl);
		dev_warn_ratelimited(iommu->dev,
				     "Fault queue error: fault: %d full: %d\n",
				     !!(ctrl & RISCV_IOMMU_FQCSR_FQMF),
				     !!(ctrl & RISCV_IOMMU_FQCSR_FQOF));
	}

	/* Clear fault interrupt pending. */
	riscv_iommu_writel(iommu, RISCV_IOMMU_REG_IPSR, RISCV_IOMMU_IPSR_FIP);

	/* Report fault events. */
	do {
		cnt = riscv_iommu_queue_consume(iommu, q, &idx);
		if (!cnt)
			break;
		for (len = 0; len < cnt; idx++, len++)
			riscv_iommu_fault_report(iommu, &events[idx]);
		riscv_iommu_queue_release(iommu, q, cnt);
	} while (1);

	return IRQ_HANDLED;
}

/*
 * Page request queue, chapter 3.3
 */

/*
 * Register device for IOMMU tracking.
 */
static void riscv_iommu_add_device(struct riscv_iommu_device *iommu, struct device *dev)
{
	struct riscv_iommu_endpoint *ep, *rb_ep;
	struct rb_node **new_node, *parent_node = NULL;

	mutex_lock(&iommu->eps_mutex);

	ep = dev_iommu_priv_get(dev);

	new_node = &iommu->eps.rb_node;
	while (*new_node) {
		rb_ep = rb_entry(*new_node, struct riscv_iommu_endpoint, node);
		parent_node = *new_node;
		if (rb_ep->devid > ep->devid) {
			new_node = &((*new_node)->rb_left);
		} else if (rb_ep->devid < ep->devid) {
			new_node = &((*new_node)->rb_right);
		} else {
			dev_warn(dev, "device %u already in the tree\n", ep->devid);
			break;
		}
	}

	rb_link_node(&ep->node, parent_node, new_node);
	rb_insert_color(&ep->node, &iommu->eps);

	mutex_unlock(&iommu->eps_mutex);
}

/* Page request interface queue primary interrupt handler */
static irqreturn_t riscv_iommu_priq_irq_check(int irq, void *data)
{
	struct riscv_iommu_queue *q = (struct riscv_iommu_queue *)data;
	struct riscv_iommu_device *iommu =
	    container_of(q, struct riscv_iommu_device, priq);
	u32 ipsr = riscv_iommu_readl(iommu, RISCV_IOMMU_REG_IPSR);

	if (ipsr & RISCV_IOMMU_IPSR_PIP)
		return IRQ_WAKE_THREAD;
	return IRQ_NONE;
}

/* Page request interface queue interrupt hanlder thread function */
static irqreturn_t riscv_iommu_priq_process(int irq, void *data)
{
	struct riscv_iommu_queue *q = (struct riscv_iommu_queue *)data;
	struct riscv_iommu_device *iommu;
	struct riscv_iommu_pq_record *requests;
	unsigned int cnt, idx, ctrl;

	iommu = container_of(q, struct riscv_iommu_device, priq);
	requests = (struct riscv_iommu_pq_record *)q->base;

	/* Error reporting, clear error reports if any. */
	ctrl = riscv_iommu_readl(iommu, RISCV_IOMMU_REG_PQCSR);
	if (ctrl & (RISCV_IOMMU_PQCSR_PQMF | RISCV_IOMMU_PQCSR_PQOF)) {
		riscv_iommu_queue_ctrl(iommu, &iommu->priq, ctrl);
		dev_warn_ratelimited(iommu->dev,
				     "Page request queue error: fault: %d full: %d\n",
				     !!(ctrl & RISCV_IOMMU_PQCSR_PQMF),
				     !!(ctrl & RISCV_IOMMU_PQCSR_PQOF));
	}

	/* Clear page request interrupt pending. */
	riscv_iommu_writel(iommu, RISCV_IOMMU_REG_IPSR, RISCV_IOMMU_IPSR_PIP);

	/* Process page requests. */
	do {
		cnt = riscv_iommu_queue_consume(iommu, q, &idx);
		if (!cnt)
			break;
		dev_warn(iommu->dev, "unexpected %u page requests\n", cnt);
		riscv_iommu_queue_release(iommu, q, cnt);
	} while (1);

	return IRQ_HANDLED;
}

/*
 * Endpoint management
 */

static int riscv_iommu_of_xlate(struct device *dev, struct of_phandle_args *args)
{
	return iommu_fwspec_add_ids(dev, args->args, 1);
}

static bool riscv_iommu_capable(struct device *dev, enum iommu_cap cap)
{
	switch (cap) {
	case IOMMU_CAP_CACHE_COHERENCY:
	case IOMMU_CAP_PRE_BOOT_PROTECTION:
		return true;

	default:
		break;
	}

	return false;
}

/* TODO: implement proper device context management, e.g. teardown flow */

/* Lookup or initialize device directory info structure. */
static struct riscv_iommu_dc *riscv_iommu_get_dc(struct riscv_iommu_device *iommu,
						 unsigned int devid)
{
	const bool base_format = !(iommu->cap & RISCV_IOMMU_CAP_MSI_FLAT);
	unsigned int depth = iommu->ddt_mode - RISCV_IOMMU_DDTP_MODE_1LVL;
	unsigned long ddt;
	u8 ddi_bits[3] = { 0 };
	u64 *ddtp = NULL;

	if (iommu->ddt_mode == RISCV_IOMMU_DDTP_MODE_OFF ||
	    iommu->ddt_mode == RISCV_IOMMU_DDTP_MODE_BARE)
		return NULL;

	/* Make sure the mode is valid */
	if (iommu->ddt_mode > RISCV_IOMMU_DDTP_MODE_MAX)
		return NULL;

	/*
	 * Device id partitioning for base format:
	 * DDI[0]: bits 0 - 6   (1st level) (7 bits)
	 * DDI[1]: bits 7 - 15  (2nd level) (9 bits)
	 * DDI[2]: bits 16 - 23 (3rd level) (8 bits)
	 *
	 * For extended format:
	 * DDI[0]: bits 0 - 5   (1st level) (6 bits)
	 * DDI[1]: bits 6 - 14  (2nd level) (9 bits)
	 * DDI[2]: bits 15 - 23 (3rd level) (9 bits)
	 */
	if (base_format) {
		ddi_bits[0] = 7;
		ddi_bits[1] = 7 + 9;
		ddi_bits[2] = 7 + 9 + 8;
	} else {
		ddi_bits[0] = 6;
		ddi_bits[1] = 6 + 9;
		ddi_bits[2] = 6 + 9 + 9;
	}

	/* Make sure device id is within range */
	if (devid >= (1 << ddi_bits[depth]))
		return NULL;

	/* Get to the level of the non-leaf node that holds the device context */
	for (ddtp = (u64 *)iommu->ddtp; depth-- > 0;) {
		const int split = ddi_bits[depth];
		/*
		 * Each non-leaf node is 64bits wide and on each level
		 * nodes are indexed by DDI[depth].
		 */
		ddtp += (devid >> split) & 0x1FF;

 retry:
		/*
		 * Check if this node has been populated and if not
		 * allocate a new level and populate it.
		 */
		ddt = READ_ONCE(*(unsigned long *)ddtp);
		if (ddt & RISCV_IOMMU_DDTE_VALID) {
			ddtp = __va(ppn_to_phys(ddt));
		} else {
			unsigned long old, new;
			unsigned long ptr = get_zeroed_page(GFP_KERNEL);

			if (!ptr)
				return NULL;

			new = phys_to_ppn(__pa(ptr)) | RISCV_IOMMU_DDTE_VALID;
			old = cmpxchg_relaxed((unsigned long *)ddtp, ddt, new);

			if (old != ddt) {
				free_page(ptr);
				goto retry;
			}

			ddtp = (u64 *)ptr;
		}
	}

	/*
	 * Grab the node that matches DDI[depth], note that when using base
	 * format the device context is 4 * 64bits, and the extended format
	 * is 8 * 64bits, hence the (3 - base_format) below.
	 */
	ddtp += (devid & ((64 << base_format) - 1)) << (3 - base_format);
	return (struct riscv_iommu_dc *)ddtp;
}

static struct iommu_device *riscv_iommu_probe_device(struct device *dev)
{
	struct riscv_iommu_device *iommu;
	struct riscv_iommu_endpoint *ep;
	struct iommu_fwspec *fwspec;

	fwspec = dev_iommu_fwspec_get(dev);
	if (!fwspec || fwspec->ops != &riscv_iommu_ops ||
	    !fwspec->iommu_fwnode || !fwspec->iommu_fwnode->dev)
		return ERR_PTR(-ENODEV);

	iommu = dev_get_drvdata(fwspec->iommu_fwnode->dev);
	if (!iommu)
		return ERR_PTR(-ENODEV);

	if (dev_iommu_priv_get(dev))
		return &iommu->iommu;

	ep = kzalloc(sizeof(*ep), GFP_KERNEL);
	if (!ep)
		return ERR_PTR(-ENOMEM);

	mutex_init(&ep->lock);
	INIT_LIST_HEAD(&ep->domain);

	if (dev_is_pci(dev)) {
		ep->devid = pci_dev_id(to_pci_dev(dev));
		ep->domid = pci_domain_nr(to_pci_dev(dev)->bus);
	} else {
		/* TODO: Make this generic, for now hardcode domain id to 0 */
		ep->devid = fwspec->ids[0];
		ep->domid = 0;
	}

	ep->iommu = iommu;
	ep->dev = dev;

	/* Initial DC pointer can be NULL if IOMMU is configured in OFF or BARE mode */
	ep->dc = riscv_iommu_get_dc(iommu, ep->devid);

	dev_dbg(iommu->dev, "adding device %s with domid:devid %i:%i\n",
		dev_name(dev), ep->domid, ep->devid);

	dev_iommu_priv_set(dev, ep);
	riscv_iommu_add_device(iommu, dev);

	return &iommu->iommu;
}

static void riscv_iommu_probe_finalize(struct device *dev)
{
	set_dma_ops(dev, NULL);
	iommu_setup_dma_ops(dev, 0, U64_MAX);
}

static void riscv_iommu_release_device(struct device *dev)
{
	struct riscv_iommu_endpoint *ep = dev_iommu_priv_get(dev);
	struct riscv_iommu_device *iommu = ep->iommu;

	dev_dbg(iommu->dev, "release device %s with domid:devid %i:%i\n",
		dev_name(dev), ep->domid, ep->devid);

	mutex_lock(&ep->lock);
	list_del(&ep->domain);
	mutex_unlock(&ep->lock);

	if (ep->dc) {
		ep->dc->tc = 0ULL;
		/* Enforce device invalidation write ordering before updating FSC */
		wmb();
		ep->dc->fsc = 0ULL;
		ep->dc->iohgatp = 0ULL;
		riscv_iommu_iodir_inv_devid(iommu, ep->devid);
	}

	/* Remove endpoint from IOMMU tracking structures */
	mutex_lock(&iommu->eps_mutex);
	rb_erase(&ep->node, &iommu->eps);
	mutex_unlock(&iommu->eps_mutex);

	set_dma_ops(dev, NULL);
	dev_iommu_priv_set(dev, NULL);

	kfree(ep);
}

static struct iommu_group *riscv_iommu_device_group(struct device *dev)
{
	if (dev_is_pci(dev))
		return pci_device_group(dev);
	return generic_device_group(dev);
}

static void riscv_iommu_get_resv_regions(struct device *dev, struct list_head *head)
{
	iommu_dma_get_resv_regions(dev, head);
}

/*
 * Domain management
 */

static struct iommu_domain *riscv_iommu_domain_alloc(unsigned int type)
{
	struct riscv_iommu_domain *domain;

	if (type != IOMMU_DOMAIN_DMA &&
	    type != IOMMU_DOMAIN_DMA_FQ &&
	    type != IOMMU_DOMAIN_UNMANAGED &&
	    type != IOMMU_DOMAIN_IDENTITY &&
	    type != IOMMU_DOMAIN_BLOCKED)
		return NULL;

	domain = kzalloc(sizeof(*domain), GFP_KERNEL);
	if (!domain)
		return NULL;

	mutex_init(&domain->lock);
	INIT_LIST_HEAD(&domain->endpoints);

	domain->domain.ops = &riscv_iommu_domain_ops;
	domain->mode = RISCV_IOMMU_DC_FSC_MODE_BARE;
	domain->pscid = ida_alloc_range(&riscv_iommu_pscids, 1,
					RISCV_IOMMU_MAX_PSCID, GFP_KERNEL);

	return &domain->domain;
}

static void riscv_iommu_domain_free(struct iommu_domain *iommu_domain)
{
	struct riscv_iommu_domain *domain = iommu_domain_to_riscv(iommu_domain);

	if (!list_empty(&domain->endpoints))
		pr_warn("IOMMU domain is not empty!\n");

	if (domain->pgtbl.cookie)
		free_io_pgtable_ops(&domain->pgtbl.ops);

	if (domain->pgd_root)
		free_pages((unsigned long)domain->pgd_root, 0);

	if ((int)domain->pscid > 0)
		ida_free(&riscv_iommu_pscids, domain->pscid);

	kfree(domain);
}

static int riscv_iommu_domain_finalize(struct riscv_iommu_domain *domain,
				       struct riscv_iommu_device *iommu)
{
	struct iommu_domain_geometry *geometry;

	/* Domain assigned to another iommu */
	if (domain->iommu && domain->iommu != iommu)
		return -EINVAL;
	/* Domain already initialized */
	else if (domain->iommu)
		return 0;

	/*
	 * TODO: Before using VA_BITS and satp_mode here, verify they
	 * are supported by the iommu, through the capabilities register.
	 */

	geometry = &domain->domain.geometry;

	/*
	 * Note: RISC-V Privilege spec mandates that virtual addresses
	 * need to be sign-extended, so if (VA_BITS - 1) is set, all
	 * bits >= VA_BITS need to also be set or else we'll get a
	 * page fault. However the code that creates the mappings
	 * above us (e.g. iommu_dma_alloc_iova()) won't do that for us
	 * for now, so we'll end up with invalid virtual addresses
	 * to map. As a workaround until we get this sorted out
	 * limit the available virtual addresses to VA_BITS - 1.
	 */
	geometry->aperture_start = 0;
	geometry->aperture_end = DMA_BIT_MASK(VA_BITS - 1);
	geometry->force_aperture = true;

	domain->iommu = iommu;

	if (domain->domain.type == IOMMU_DOMAIN_IDENTITY)
		return 0;

#ifndef CONFIG_64BIT
	domain->is_32bit = true;
	domain->mode = RISCV_IOMMU_DC_FSC_IOSATP_MODE_SV32;
#else
	/* Follow system address translation mode. */
	domain->mode = satp_mode >> 60;
#endif
	domain->pgd_root = (pgd_t *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);

	if (!domain->pgd_root)
		return -ENOMEM;

	if (!alloc_io_pgtable_ops(RISCV_IOMMU, &domain->pgtbl.cfg, domain))
		return -ENOMEM;

	return 0;
}

static u64 riscv_iommu_domain_atp(struct riscv_iommu_domain *domain)
{
	u64 atp = FIELD_PREP(RISCV_IOMMU_DC_FSC_MODE, domain->mode);

	if (domain->mode != RISCV_IOMMU_DC_FSC_MODE_BARE)
		atp |= FIELD_PREP(RISCV_IOMMU_DC_FSC_PPN, virt_to_pfn(domain->pgd_root));
	return atp;
}

static int riscv_iommu_attach_dev(struct iommu_domain *iommu_domain, struct device *dev)
{
	struct riscv_iommu_domain *domain = iommu_domain_to_riscv(iommu_domain);
	struct riscv_iommu_endpoint *ep = dev_iommu_priv_get(dev);
	struct riscv_iommu_dc *dc = ep->dc;
	int ret;
	u64 val;

	/* PSCID not valid */
	if ((int)domain->pscid < 0)
		return -ENOMEM;

	mutex_lock(&domain->lock);
	mutex_lock(&ep->lock);

	if (!list_empty(&ep->domain)) {
		dev_warn(dev, "endpoint already attached to a domain. dropping\n");
		list_del_init(&ep->domain);
	}

	/* allocate root pages, initialize io-pgtable ops, etc. */
	ret = riscv_iommu_domain_finalize(domain, ep->iommu);
	if (ret < 0) {
		dev_err(dev, "can not finalize domain: %d\n", ret);
		mutex_unlock(&ep->lock);
		mutex_unlock(&domain->lock);
		return ret;
	}

	if (ep->iommu->ddt_mode == RISCV_IOMMU_DDTP_MODE_BARE &&
	    domain->domain.type == IOMMU_DOMAIN_IDENTITY) {
		dev_dbg(dev, "domain type %d attached w/ PSCID %u\n",
			domain->domain.type, domain->pscid);
		return 0;
	}

	if (!dc)
		return -ENODEV;

	/*
	 * S-Stage translation table. G-Stage remains unmodified (BARE).
	 */
	val = FIELD_PREP(RISCV_IOMMU_DC_TA_PSCID, domain->pscid);

	dc->ta = cpu_to_le64(val);
	dc->fsc = cpu_to_le64(riscv_iommu_domain_atp(domain));

	/* Enforce in-memory device context write ordering before marking it valid */
	wmb();

	/* Mark device context as valid, synchronise device context cache. */
	val = RISCV_IOMMU_DC_TC_V;

	if (ep->iommu->cap & RISCV_IOMMU_CAP_AMO) {
		val |= RISCV_IOMMU_DC_TC_GADE |
		       RISCV_IOMMU_DC_TC_SADE;
	}

	if (domain->is_32bit)
		val |= RISCV_IOMMU_DC_TC_SXL;

	dc->tc = cpu_to_le64(val);
	/* Enforce in-memory device context write ordering before sending IODIR.INV */
	wmb();

	list_add_tail(&ep->domain, &domain->endpoints);
	mutex_unlock(&ep->lock);
	mutex_unlock(&domain->lock);

	dev_dbg(dev, "domain type %d attached w/ PSCID %u\n",
		domain->domain.type, domain->pscid);

	riscv_iommu_iodir_inv_devid(ep->iommu, ep->devid);

	return 0;
}

static void riscv_iommu_flush_iotlb_range(struct iommu_domain *iommu_domain,
					  unsigned long *start, unsigned long *end,
					  size_t *pgsize)
{
	struct riscv_iommu_domain *domain = iommu_domain_to_riscv(iommu_domain);
	struct riscv_iommu_command cmd;
	unsigned long iova;

	if (domain->mode == RISCV_IOMMU_DC_FSC_MODE_BARE)
		return;

	/* Domain not attached to an IOMMU! */
	BUG_ON(!domain->iommu);

	riscv_iommu_cmd_inval_vma(&cmd);
	riscv_iommu_cmd_inval_set_pscid(&cmd, domain->pscid);

	if (start && end && pgsize) {
		/* Cover only the range that is needed */
		for (iova = *start; iova <= *end; iova += *pgsize) {
			riscv_iommu_cmd_inval_set_addr(&cmd, iova);
			riscv_iommu_post(domain->iommu, &cmd);
		}
	} else {
		riscv_iommu_post(domain->iommu, &cmd);
	}
	riscv_iommu_iofence_sync(domain->iommu);
}

static void riscv_iommu_flush_iotlb_all(struct iommu_domain *iommu_domain)
{
	riscv_iommu_flush_iotlb_range(iommu_domain, NULL, NULL, NULL);
}

static void riscv_iommu_iotlb_sync(struct iommu_domain *iommu_domain,
				   struct iommu_iotlb_gather *gather)
{
	riscv_iommu_flush_iotlb_range(iommu_domain, &gather->start, &gather->end,
				      &gather->pgsize);
}

static int riscv_iommu_map_pages(struct iommu_domain *iommu_domain,
				 unsigned long iova, phys_addr_t phys,
				 size_t pgsize, size_t pgcount, int prot,
				 gfp_t gfp, size_t *mapped)
{
	struct riscv_iommu_domain *domain = iommu_domain_to_riscv(iommu_domain);

	if (!domain->pgtbl.ops.map_pages)
		return -ENODEV;

	return domain->pgtbl.ops.map_pages(&domain->pgtbl.ops, iova, phys,
					   pgsize, pgcount, prot, gfp, mapped);
}

static size_t riscv_iommu_unmap_pages(struct iommu_domain *iommu_domain,
				      unsigned long iova, size_t pgsize,
				      size_t pgcount, struct iommu_iotlb_gather *gather)
{
	struct riscv_iommu_domain *domain = iommu_domain_to_riscv(iommu_domain);

	if (!domain->pgtbl.ops.unmap_pages)
		return 0;

	return domain->pgtbl.ops.unmap_pages(&domain->pgtbl.ops, iova, pgsize,
					     pgcount, gather);
}

static phys_addr_t riscv_iommu_iova_to_phys(struct iommu_domain *iommu_domain,
					    dma_addr_t iova)
{
	struct riscv_iommu_domain *domain = iommu_domain_to_riscv(iommu_domain);

	if (!domain->pgtbl.ops.iova_to_phys)
		return 0;

	return domain->pgtbl.ops.iova_to_phys(&domain->pgtbl.ops, iova);
}

/*
 * Translation mode setup
 */

static u64 riscv_iommu_get_ddtp(struct riscv_iommu_device *iommu)
{
	u64 ddtp;
	cycles_t end_cycles = RISCV_IOMMU_TIMEOUT + get_cycles();

	/* Wait for DDTP.BUSY to be cleared and return latest value */
	do {
		ddtp = riscv_iommu_readq(iommu, RISCV_IOMMU_REG_DDTP);
		if (!(ddtp & RISCV_IOMMU_DDTP_BUSY))
			break;
		cpu_relax();
	} while (get_cycles() < end_cycles);

	return ddtp;
}

static void riscv_iommu_ddt_cleanup(struct riscv_iommu_device *iommu)
{
	/* TODO: teardown whole device directory tree. */
	if (iommu->ddtp) {
		if (iommu->ddtp_in_iomem)
			iounmap((void *)iommu->ddtp);
		else
			free_page(iommu->ddtp);
		iommu->ddtp = 0;
	}
}

static int riscv_iommu_enable(struct riscv_iommu_device *iommu, unsigned int requested_mode)
{
	struct device *dev = iommu->dev;
	u64 ddtp = 0;
	u64 ddtp_paddr = 0;
	unsigned int mode = requested_mode;
	unsigned int mode_readback = 0;

	ddtp = riscv_iommu_get_ddtp(iommu);
	if (ddtp & RISCV_IOMMU_DDTP_BUSY)
		return -EBUSY;

	/* Disallow state transtion from xLVL to xLVL. */
	switch (FIELD_GET(RISCV_IOMMU_DDTP_MODE, ddtp)) {
	case RISCV_IOMMU_DDTP_MODE_BARE:
	case RISCV_IOMMU_DDTP_MODE_OFF:
		break;
	default:
		if (mode != RISCV_IOMMU_DDTP_MODE_BARE &&
		    mode != RISCV_IOMMU_DDTP_MODE_OFF)
			return -EINVAL;
		break;
	}

 retry:
	switch (mode) {
	case RISCV_IOMMU_DDTP_MODE_BARE:
	case RISCV_IOMMU_DDTP_MODE_OFF:
		riscv_iommu_ddt_cleanup(iommu);
		ddtp = FIELD_PREP(RISCV_IOMMU_DDTP_MODE, mode);
		break;
	case RISCV_IOMMU_DDTP_MODE_1LVL:
	case RISCV_IOMMU_DDTP_MODE_2LVL:
	case RISCV_IOMMU_DDTP_MODE_3LVL:
		if (!iommu->ddtp) {
			/*
			 * We haven't initialized ddtp yet, since it's WARL make
			 * sure that we don't have a hardwired PPN field there
			 * that points to i/o memory instead.
			 */
			riscv_iommu_writeq(iommu, RISCV_IOMMU_REG_DDTP, 0);
			ddtp = riscv_iommu_get_ddtp(iommu);
			ddtp_paddr = ppn_to_phys(ddtp);
			if (ddtp_paddr) {
				iommu->ddtp = (unsigned long)ioremap(ddtp_paddr, PAGE_SIZE);
				iommu->ddtp_in_iomem = true;
			} else {
				iommu->ddtp = get_zeroed_page(GFP_KERNEL);
			}
		}
		if (!iommu->ddtp)
			return -ENOMEM;

		ddtp = FIELD_PREP(RISCV_IOMMU_DDTP_MODE, mode) |
		       phys_to_ppn(__pa(iommu->ddtp));

		break;
	default:
		return -EINVAL;
	}

	riscv_iommu_writeq(iommu, RISCV_IOMMU_REG_DDTP, ddtp);
	ddtp = riscv_iommu_get_ddtp(iommu);
	if (ddtp & RISCV_IOMMU_DDTP_BUSY) {
		dev_warn(dev, "timeout when setting ddtp (ddt mode: %u)\n", mode);
		return -EBUSY;
	}

	mode_readback = FIELD_GET(RISCV_IOMMU_DDTP_MODE, ddtp);
	dev_dbg(dev, "mode_readback: %u, mode: %u\n", mode_readback, mode);
	if (mode_readback != mode) {
		/*
		 * Mode field is WARL, an I/O MMU may support a subset of
		 * directory table levels in which case if we tried to set
		 * an unsupported number of levels we'll readback either
		 * a valid xLVL or off/bare. If we got off/bare, try again
		 * with a smaller xLVL.
		 */
		if (mode_readback < RISCV_IOMMU_DDTP_MODE_1LVL &&
		    mode > RISCV_IOMMU_DDTP_MODE_1LVL) {
			mode--;
			goto retry;
		}

		/*
		 * We tried all supported xLVL modes and still got off/bare instead,
		 * an I/O MMU must support at least one supported xLVL mode so something
		 * went very wrong.
		 */
		if (mode_readback < RISCV_IOMMU_DDTP_MODE_1LVL &&
		    mode == RISCV_IOMMU_DDTP_MODE_1LVL)
			goto fail;

		/*
		 * We tried setting off or bare and got something else back, something
		 * went very wrong since off/bare is always legal.
		 */
		if (mode < RISCV_IOMMU_DDTP_MODE_1LVL)
			goto fail;

		/*
		 * We tried setting an xLVL mode but got another xLVL mode that
		 * we don't support (e.g. a custom one).
		 */
		if (mode_readback > RISCV_IOMMU_DDTP_MODE_MAX)
			goto fail;

		/* We tried setting an xLVL mode but got another supported xLVL mode */
		mode = mode_readback;
	}

	if (mode != requested_mode)
		dev_warn(dev, "unsupported DDT mode requested (%u), using %u instead\n",
			 requested_mode, mode);

	iommu->ddt_mode = mode;
	dev_dbg(dev, "ddt_mode: %u\n", iommu->ddt_mode);
	return 0;

 fail:
	dev_err(dev, "failed to set DDT mode, tried: %u and got %u\n", mode,
		mode_readback);
	riscv_iommu_ddt_cleanup(iommu);
	return -EINVAL;
}

/*
 * Common I/O MMU driver probe/teardown
 */

static const struct iommu_domain_ops riscv_iommu_domain_ops = {
	.free = riscv_iommu_domain_free,
	.attach_dev = riscv_iommu_attach_dev,
	.map_pages = riscv_iommu_map_pages,
	.unmap_pages = riscv_iommu_unmap_pages,
	.iova_to_phys = riscv_iommu_iova_to_phys,
	.iotlb_sync = riscv_iommu_iotlb_sync,
	.flush_iotlb_all = riscv_iommu_flush_iotlb_all,
};

static const struct iommu_ops riscv_iommu_ops = {
	.owner = THIS_MODULE,
	.pgsize_bitmap = SZ_4K | SZ_2M | SZ_512M,
	.capable = riscv_iommu_capable,
	.domain_alloc = riscv_iommu_domain_alloc,
	.probe_device = riscv_iommu_probe_device,
	.probe_finalize = riscv_iommu_probe_finalize,
	.release_device = riscv_iommu_release_device,
	.device_group = riscv_iommu_device_group,
	.get_resv_regions = riscv_iommu_get_resv_regions,
	.of_xlate = riscv_iommu_of_xlate,
	.default_domain_ops = &riscv_iommu_domain_ops,
};

void riscv_iommu_remove(struct riscv_iommu_device *iommu)
{
#ifdef CONFIG_RISCV_IOMMU_DEBUGFS
	debugfs_remove(iommu->debugfs);
#endif
	iommu_device_sysfs_remove(&iommu->iommu);
	iommu_device_unregister(&iommu->iommu);
	riscv_iommu_enable(iommu, RISCV_IOMMU_DDTP_MODE_OFF);
	riscv_iommu_queue_free(iommu, &iommu->cmdq);
	riscv_iommu_queue_free(iommu, &iommu->fltq);
	riscv_iommu_queue_free(iommu, &iommu->priq);
}

int riscv_iommu_init(struct riscv_iommu_device *iommu)
{
	struct device *dev = iommu->dev;
	u32 fctl = 0;
	u64 ivec = 0;
	int ret;

	iommu->eps = RB_ROOT;

	fctl = riscv_iommu_readl(iommu, RISCV_IOMMU_REG_FCTL);

#ifdef CONFIG_CPU_BIG_ENDIAN
	if (!(cap & RISCV_IOMMU_CAP_END)) {
		dev_err(dev, "IOMMU doesn't support Big Endian\n");
		return -EIO;
	} else if (!(fctl & RISCV_IOMMU_FCTL_BE)) {
		fctl |= FIELD_PREP(RISCV_IOMMU_FCTL_BE, 1);
		riscv_iommu_writel(iommu, RISCV_IOMMU_REG_FCTL, fctl);
	}
#endif

	/* Clear any pending interrupt flag. */
	riscv_iommu_writel(iommu, RISCV_IOMMU_REG_IPSR,
			   RISCV_IOMMU_IPSR_CIP |
			   RISCV_IOMMU_IPSR_FIP |
			   RISCV_IOMMU_IPSR_PMIP | RISCV_IOMMU_IPSR_PIP);

	riscv_iommu_writel(iommu, RISCV_IOMMU_REG_FCTL, fctl);

	/* Set 1:1 mapping for interrupt vectors if available */
	if (iommu->irqs_count >= 4) {
		ivec = FIELD_PREP(RISCV_IOMMU_IVEC_CIV,  0) |
		       FIELD_PREP(RISCV_IOMMU_IVEC_FIV,  1) |
		       FIELD_PREP(RISCV_IOMMU_IVEC_PMIV, 2) |
		       FIELD_PREP(RISCV_IOMMU_IVEC_PIV,  3);
	}
	riscv_iommu_writeq(iommu, RISCV_IOMMU_REG_IVEC, ivec);

	spin_lock_init(&iommu->cq_lock);
	mutex_init(&iommu->eps_mutex);
	ret = riscv_iommu_queue_init(iommu, RISCV_IOMMU_COMMAND_QUEUE);
	if (ret)
		goto fail;
	ret = riscv_iommu_queue_init(iommu, RISCV_IOMMU_FAULT_QUEUE);
	if (ret)
		goto fail;
	if (!(iommu->cap & RISCV_IOMMU_CAP_ATS))
		goto no_ats;
	ret = riscv_iommu_queue_init(iommu, RISCV_IOMMU_PAGE_REQUEST_QUEUE);
	if (ret)
		goto fail;

 no_ats:
	ret = riscv_iommu_enable(iommu, ddt_mode);
	if (ret) {
		dev_err(dev, "cannot enable iommu device (%d)\n", ret);
		goto fail;
	}

	ret = iommu_device_sysfs_add(&iommu->iommu, NULL, NULL, "riscv-iommu@%lx",
				     (unsigned long)iommu->reg_phys);
	if (ret) {
		dev_err(dev, "cannot register sysfs interface (%d)\n", ret);
		goto fail;
	}

	ret = iommu_device_register(&iommu->iommu, &riscv_iommu_ops, dev);
	if (ret) {
		dev_err(dev, "cannot register iommu interface (%d)\n", ret);
		iommu_device_sysfs_remove(&iommu->iommu);
		goto fail;
	}

#ifdef CONFIG_RISCV_IOMMU_DEBUGFS
	riscv_iommu_debugfs_setup(iommu);
#endif
	return 0;
 fail:
	riscv_iommu_enable(iommu, RISCV_IOMMU_DDTP_MODE_OFF);
	riscv_iommu_queue_free(iommu, &iommu->priq);
	riscv_iommu_queue_free(iommu, &iommu->fltq);
	riscv_iommu_queue_free(iommu, &iommu->cmdq);
	return ret;
}

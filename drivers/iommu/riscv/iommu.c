// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2022 Rivos Inc.
 * Author: Tomasz Jeznach <tjeznach@rivosinc.com>
 */

/* Rivos Inc. implementation for RISC-V I/O Memory Management Unit */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define DRV_NAME       "riscv-iommu"
#define DRV_VERSION    "0.0.6"

#include <linux/bitfield.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/compiler.h>
#include <linux/pci.h>
#include <linux/pci-ats.h>
#include <linux/init.h>
#include <linux/completion.h>
#include <linux/uaccess.h>
#include <linux/iommu.h>
#include <linux/platform_device.h>
#include <linux/dma-map-ops.h>
#include <asm/page.h>

#include "../dma-iommu.h"
#include "../iommu-sva.h"
#include "iommu.h"

#include <asm/csr.h>
#include <asm/delay.h>

/* Rivos Inc. assigned PCI Vendor and Device IDs */
#ifndef PCI_VENDOR_ID_RIVOS
#define PCI_VENDOR_ID_RIVOS             0x1efd
#endif

#ifndef PCI_DEVICE_ID_RIVOS_IOMMU
#define PCI_DEVICE_ID_RIVOS_IOMMU       0xedf1
#endif

/* TODO: Enable MSI remapping */
#define RISCV_IMSIC_BASE	0x28000000

/* 1 second */
#define RISCV_IOMMU_TIMEOUT		riscv_timebase

/* Number of elements in command, fault, page request queues */
#define CQ_COUNT		(4 << 10)
#define FQ_COUNT		(8 << 10)
#define PQ_COUNT		(8 << 10)

#define RIO_MIN_REVISION        0x0002
#define RIO_REG_MIN_SIZE	0x0300

#ifndef VA_BITS
#define VA_BITS CONFIG_VA_BITS
#endif

#ifndef CONFIG_64BIT
/* RV32I */
#ifndef SATP_MODE
#define SATP_MODE                 0x1000000000000000ULL
#endif
#else
/* RV64I */
#ifndef SATP_MODE
#define SATP_MODE                 satp_mode
#endif
#endif

/* RISC-V IOMMU PPN <> PHYS address conversions, PPN[53:10] */
#define phys_to_ppn(va)  (((va) >> 2) & (((1ULL << 44) - 1) << 10))
#define ppn_to_phys(pn)	 (((pn) << 2) & (((1ULL << 44) - 1) << 12))

/* Global IOMMU params. */
static int ddt_mode = RIO_DDTP_MODE_3LVL;
module_param(ddt_mode, int, 0644);
MODULE_PARM_DESC(ddt_mode, "Device Directory Table mode.");

#define to_riscv_iommu_domain(iommu_domain) \
    container_of(iommu_domain, struct riscv_iommu_domain, domain)

#define device_to_iommu(dev) \
    container_of(dev->iommu->iommu_dev, struct riscv_iommu_device, iommu)

#define dev_to_riscv_iommu(dev) \
    container_of(dev_get_drvdata(dev), struct riscv_iommu_device, iommu)

static void __cmd_iodir_all(struct riscv_iommu_command *cmd)
{
	cmd->request = FIELD_PREP(RIO_CMD_OP, RIO_CMD_IODIR_DDT);
	cmd->address = 0;
}

static void __cmd_iodir_devid(struct riscv_iommu_command *cmd, unsigned devid)
{
	cmd->request = FIELD_PREP(RIO_CMD_OP, RIO_CMD_IODIR_DDT) |
	    FIELD_PREP(RIO_IODIR_DID, devid) | RIO_IODIR_DV;
	cmd->address = 0;
}

static void __cmd_iodir_pasid(struct riscv_iommu_command *cmd, unsigned devid,
			      unsigned pasid)
{
	cmd->request = FIELD_PREP(RIO_CMD_OP, RIO_CMD_IODIR_PDT) |
	    FIELD_PREP(RIO_IODIR_DID, devid) | RIO_IODIR_DV |
	    FIELD_PREP(RIO_IODIR_PID, pasid);
	cmd->address = 0;
}

static void __cmd_inval_vma(struct riscv_iommu_command *cmd)
{
	cmd->request = FIELD_PREP(RIO_CMD_OP, RIO_CMD_IOTINVAL_VMA);
	cmd->address = 0;
}

static void __cmd_inval_set_addr(struct riscv_iommu_command *cmd, u64 addr)
{
	cmd->request |= RIO_IOTINVAL_AV;
	cmd->address = addr;
}

static void __cmd_inval_set_pscid(struct riscv_iommu_command *cmd,
				  unsigned pscid)
{
	cmd->request |= FIELD_PREP(RIO_IOTINVAL_PSCID, pscid) |
	    RIO_IOTINVAL_PSCV;
}

static void __cmd_inval_set_gscid(struct riscv_iommu_command *cmd,
				  unsigned gscid)
{
	cmd->request |= FIELD_PREP(RIO_IOTINVAL_GSCID, gscid) | RIO_IOTINVAL_GV;
}

static void __cmd_iofence(struct riscv_iommu_command *cmd)
{
	cmd->request = FIELD_PREP(RIO_CMD_OP, RIO_CMD_IOFENCE_C);
	cmd->address = 0;
}

static void __cmd_iofence_set_av(struct riscv_iommu_command *cmd, u64 addr,
				 u32 data)
{
	cmd->request = FIELD_PREP(RIO_CMD_OP, RIO_CMD_IOFENCE_C) |
	    FIELD_PREP(RIO_IOFENCE_DATA, data) | RIO_IOFENCE_AV;
	cmd->address = addr;
}

/* Lookup or initialize device directory info structure. */
static struct riscv_iommu_dc *riscv_iommu_get_dc(struct riscv_iommu_device
						 *iommu, unsigned device_id)
{
	const bool dc32 = iommu->dc_format32;
	unsigned depth = iommu->ddt_mode - RIO_DDTP_MODE_1LVL;
	u64 *ddt;

	if (!iommu->ddtp)
		return NULL;

	/* Check supported device id range. */
	if (device_id >= (1 << (depth * 9 + 6 + (dc32 && depth != 2))))
		return NULL;

	for (ddt = (u64 *) iommu->ddtp; depth-- > 0;) {
		const int split = depth * 9 + 6 + dc32;
		ddt += (device_id >> split) & 0x1FF;

		if (*ddt & RIO_DDTE_VALID) {
			ddt = __va(ppn_to_phys(*ddt));
		} else {
			/* Allocate next device directory level. */
			unsigned long ddtp = get_zeroed_page(GFP_KERNEL);
			if (!ddtp)
				return NULL;
			*ddt = phys_to_ppn(__pa(ddtp)) | RIO_DDTE_VALID;
			ddt = (u64 *) ddtp;
		}
	}

	ddt += (device_id & ((64 << dc32) - 1)) << (3 - dc32);
	return (struct riscv_iommu_dc *)ddt;
}

/* TODO: Convert into lock-less MPSC implementation. */
static bool riscv_iommu_post(struct riscv_iommu_device *iommu,
			     struct riscv_iommu_command *cmd)
{
	u32 head, tail, next, last;
	unsigned long flags;

	spin_lock_irqsave(&iommu->cq_lock, flags);
	head = riscv_iommu_readl(iommu, RIO_REG_CQH) & (iommu->cmdq.cnt - 1);
	tail = riscv_iommu_readl(iommu, RIO_REG_CQT) & (iommu->cmdq.cnt - 1);
	last = iommu->cmdq.lui;
	if (tail != last) {
		spin_unlock_irqrestore(&iommu->cq_lock, flags);
		/* TRY AGAIN */
		dev_err(iommu->dev, "IOMMU CQT: %x != %x (1st)\n", last, tail);
		spin_lock_irqsave(&iommu->cq_lock, flags);
		tail =
		    riscv_iommu_readl(iommu,
				      RIO_REG_CQT) & (iommu->cmdq.cnt - 1);
		last = iommu->cmdq.lui;
		if (tail != last) {
			spin_unlock_irqrestore(&iommu->cq_lock, flags);
			dev_err(iommu->dev, "IOMMU CQT: %x != %x (2nd)\n", last,
				tail);
			spin_lock_irqsave(&iommu->cq_lock, flags);
		}
	}

	next = (iommu->cmdq.lui + 1) & (iommu->cmdq.cnt - 1);
	if (next != head) {
		struct riscv_iommu_command *ptr = iommu->cmdq.base;
		memcpy(&ptr[iommu->cmdq.lui], cmd, sizeof(*cmd));
		wmb();
		riscv_iommu_writel(iommu, RIO_REG_CQT, next);
		iommu->cmdq.lui = next;
	}

	spin_unlock_irqrestore(&iommu->cq_lock, flags);

	return next != head;
}

static bool riscv_iommu_iodir_inv_all(struct riscv_iommu_device *iommu)
{
	struct riscv_iommu_command cmd;
	__cmd_iodir_all(&cmd);
	return riscv_iommu_post(iommu, &cmd);
}

static bool riscv_iommu_iodir_inv_devid(struct riscv_iommu_device *iommu,
					unsigned devid)
{
	struct riscv_iommu_command cmd;
	__cmd_iodir_devid(&cmd, devid);
	return riscv_iommu_post(iommu, &cmd);
}

static bool riscv_iommu_iodir_inv_pasid(struct riscv_iommu_device *iommu,
					unsigned devid, unsigned pasid)
{
	struct riscv_iommu_command cmd;
	__cmd_iodir_pasid(&cmd, devid, pasid);
	return riscv_iommu_post(iommu, &cmd);
}

static bool riscv_iommu_iofence_sync(struct riscv_iommu_device *iommu)
{
	volatile u64 *sync = (u64 *) iommu->sync;
	struct riscv_iommu_command cmd;
	cycles_t start_time;

	/* TODO: define per cpu location of watermark notifier */
	sync += get_cpu();
	put_cpu();

	*sync = 0ULL;

	/* TODO: move to watermark notifier */
	__cmd_iofence(&cmd);
	__cmd_iofence_set_av(&cmd, __pa(sync), 1);

	if (!riscv_iommu_post(iommu, &cmd))
		return false;

	start_time = get_cycles();
	while (*sync == 0) {
		if (RISCV_IOMMU_TIMEOUT < (get_cycles() - start_time)) {
			dev_err(iommu->dev, "IOFENCE TIMEOUT\n");
			return false;
		}
		cpu_relax();
	}

	return true;
}

static void riscv_iommu_detach_dev(struct iommu_domain *dom, struct device *dev)
{
	struct riscv_iommu_domain *domain = to_riscv_iommu_domain(dom);
	struct riscv_iommu_endpoint *ep = dev_iommu_priv_get(dev);

	if (domain->g_stage) {
		list_del(&ep->g_list);
	} else {
		list_del(&ep->s_list);
	}

	if (ep->dc) {
		u64 atp = virt_to_pfn(ep->iommu->zero) | SATP_MODE;
		if (domain->g_stage) {
			ep->dc->gatp = cpu_to_le64(atp);
		} else {
			ep->dc->fsc = cpu_to_le64(atp);
		}
		wmb();
		riscv_iommu_iodir_inv_devid(ep->iommu, ep->device_id);
	}
}

static int riscv_iommu_attach_dev(struct iommu_domain *dom, struct device *dev)
{
	struct riscv_iommu_domain *domain = to_riscv_iommu_domain(dom);
	struct riscv_iommu_endpoint *ep = NULL;
	struct iommu_domain_geometry *geometry;
	struct iommu_resv_region *entry;
	u64 val;
	int i;

	/* Allocate device context for the end-point */
	ep = dev_iommu_priv_get(dev);

	mutex_lock(&domain->lock);

	if (list_empty(domain->g_stage ? &ep->g_list : &ep->s_list))
		list_add_tail(domain->g_stage ? &ep->g_list : &ep->s_list,
			      &domain->endpoints);

	if (!ep->dc) {
		ep->dc = riscv_iommu_get_dc(ep->iommu, ep->device_id);
		if (!ep->dc) {
			mutex_unlock(&domain->lock);
			return -ENOMEM;
		}
	}

	/* Initialize S-Stage translation: pass-through, disabled, active */
	if (dom->type == IOMMU_DOMAIN_IDENTITY) {
		val = 0ULL;
		goto skip_pgtable;
	}

	if (dom->type == IOMMU_DOMAIN_SVA) {
		WARN_ON(!ep->sva_enabled);
		val = virt_to_pfn(ep->iommu->zero) | SATP_MODE;
		goto skip_pgtable;
	}

	if (dom->type == IOMMU_DOMAIN_BLOCKED) {
		val = virt_to_pfn(ep->iommu->zero) | SATP_MODE;
		goto skip_pgtable;
	}

	domain->pgd_root =
	    (pgd_t *) __get_free_pages(GFP_KERNEL | __GFP_ZERO,
				       domain->g_stage ? 2 : 0);
	if (!domain->pgd_root) {
		mutex_unlock(&domain->lock);
		return -ENOMEM;
	}

	geometry = &dom->geometry;
	geometry->aperture_start = 0;
	geometry->aperture_end = DMA_BIT_MASK(VA_BITS);
	geometry->force_aperture = true;

	val = virt_to_pfn(domain->pgd_root) | SATP_MODE;

 skip_pgtable:

	if (domain->g_stage) {
		ep->dc->gatp = cpu_to_le64(val);
		/* FIXME: re-enable S-Stage translation and MSI remapping */
		ep->dc->fsc = 0ULL;
		ep->dc->msiptp = 0ULL;
		goto skip_msiptp;
	}

	/* Set S-Stage translation */
	ep->dc->fsc = cpu_to_le64(val);

	/* Initialize MSI remapping */
	if (ep->iommu->dc_format32)
		goto skip_msiptp;

	/* FIXME: implement remapping device */
	val = get_zeroed_page(GFP_KERNEL);
	if (!val) {
		mutex_unlock(&domain->lock);
		return -ENOMEM;
	}

	domain->msi_root = (struct riscv_iommu_msipte *)val;

	for (i = 0; i < 256; i++) {
		domain->msi_root[i].msipte =
		    pte_val(pfn_pte
			    (phys_to_pfn(RISCV_IMSIC_BASE) + i,
			     __pgprot(_PAGE_WRITE | _PAGE_PRESENT)));
	}

	entry = iommu_alloc_resv_region(RISCV_IMSIC_BASE, PAGE_SIZE * 256, 0,
					IOMMU_RESV_SW_MSI, GFP_KERNEL);
	if (entry) {
		list_add_tail(&entry->list, &ep->regions);
	}

	val = virt_to_pfn(domain->msi_root) |
	    FIELD_PREP(RIO_DCMSI_MODE, RIO_DCMSI_MODE_FLAT);
	ep->dc->msiptp = cpu_to_le64(val);

	/* Single page of MSIPTP, 256 IMSIC files */
	ep->dc->msi_addr_mask = cpu_to_le64(255);
	ep->dc->msi_addr_pattern = cpu_to_le64(RISCV_IMSIC_BASE >> 12);

 skip_msiptp:

	/* FIXME: verify spec if TA.V is required. */
	val = FIELD_PREP(RIO_PCTA_PSCID, ep->pscid) | RIO_PCTA_V;
	ep->dc->ta = cpu_to_le64(val);

	/* Mark device context as valid */
	wmb();
	ep->dc->tc = cpu_to_le64(RIO_DCTC_EN_ATS | RIO_DCTC_VALID);

	mutex_unlock(&domain->lock);
	riscv_iommu_iodir_inv_devid(ep->iommu, ep->device_id);

	return 0;
}

struct riscv_iommu_sva {
	struct iommu_sva sva;
	struct mm_struct *mm;
	struct list_head list;
	refcount_t refs;
};

static void ___riscv_iommu_sva_remove_dev_pasid(struct iommu_domain *domain,
						struct device *dev,
						ioasid_t pasid)
{
	struct mm_struct *mm = domain->mm;
	struct riscv_iommu_sva *sva = NULL, *i;
	struct riscv_iommu_endpoint *ep = dev_iommu_priv_get(dev);
	struct riscv_iommu_command cmd;

	list_for_each_entry(i, &ep->bindings, list) {
		if (i->mm == mm) {
			sva = i;
			break;
		}
	}

	if (!WARN_ON(!sva) && refcount_dec_and_test(&sva->refs)) {
		list_del(&sva->list);

		ep->pc[pasid].ta = 0;
		wmb();

		/* 1. invalidate PDT entry */
		__cmd_iodir_pasid(&cmd, ep->device_id, pasid);
		riscv_iommu_post(ep->iommu, &cmd);

		/* 2. invalidate all matching IOATC entries */
		__cmd_inval_vma(&cmd);
		__cmd_inval_set_gscid(&cmd, 0);
		__cmd_inval_set_pscid(&cmd, pasid);
		riscv_iommu_post(ep->iommu, &cmd);

		/* 3. Wait IOATC flush to happen */
		riscv_iommu_iofence_sync(ep->iommu);
		kfree(sva);
	}
}

static int __riscv_iommu_set_dev_pasid(struct iommu_domain *domain,
				       struct device *dev, ioasid_t pasid)
{
	struct mm_struct *mm = domain->mm;
	struct riscv_iommu_endpoint *ep = dev_iommu_priv_get(dev);
	struct riscv_iommu_dc *dc = ep->dc;
	struct riscv_iommu_pc *pc = ep->pc;
	struct riscv_iommu_sva *sva;

	if (!ep || !ep->sva_enabled)
		return -ENODEV;

	list_for_each_entry(sva, &ep->bindings, list) {
		if (sva->mm == mm) {
			refcount_inc(&sva->refs);
			return 0;
		}
	}

	sva = kzalloc(sizeof(*sva), GFP_KERNEL);
	if (!sva)
		return -ENOMEM;

	sva->mm = mm;
	sva->sva.dev = dev;
	refcount_set(&sva->refs, 1);
	list_add(&sva->list, &ep->bindings);

	if (!pc)
		pc = (struct riscv_iommu_pc *)get_zeroed_page(GFP_KERNEL);
	if (!pc)
		return -ENOMEM;

	/* Use PASID for PSCID tag */
	pc[pasid].ta = cpu_to_le64(FIELD_PREP(RIO_PCTA_PSCID, pasid) |
				   RIO_PCTA_V);
	pc[pasid].fsc = cpu_to_le64(virt_to_pfn(mm->pgd) | SATP_MODE);

	/* update DC with sva->mm */
	if (!(ep->dc->tc & RIO_DCTC_PDTV)) {
		/* migrate to PD, domain mappings moved to PASID:0 */
		pc[0].ta = dc->ta;
		pc[0].fsc = dc->fsc;

		dc->fsc = cpu_to_le64(virt_to_pfn(pc) |
				      FIELD_PREP(RIO_ATP_MODE,
						 RIO_PDTP_MODE_PD8));
		dc->tc =
		    cpu_to_le64(RIO_DCTC_PDTV | RIO_DCTC_EN_ATS |
				RIO_DCTC_VALID);
		ep->pc = pc;
		wmb();

		/* TODO: transition to PD steps */
		riscv_iommu_iodir_inv_devid(ep->iommu, ep->device_id);
	} else {
		wmb();
		riscv_iommu_iodir_inv_pasid(ep->iommu, ep->device_id, pasid);
	}

	riscv_iommu_iofence_sync(ep->iommu);

	return 0;
}

static int riscv_iommu_set_dev_pasid(struct iommu_domain *domain,
				     struct device *dev, ioasid_t pasid)
{
	int ret;
//      struct mm_struct *mm = domain->mm;

//      mutex_lock(&sva_lock);
	ret = __riscv_iommu_set_dev_pasid(domain, dev, pasid);
//      mutex_unlock(&sva_lock);

	return ret;
}

static void riscv_iommu_sva_domain_free(struct iommu_domain *domain)
{
	kfree(domain);
}

static const struct iommu_domain_ops riscv_iommu_sva_domain_ops = {
	.free = riscv_iommu_sva_domain_free,
	.set_dev_pasid = riscv_iommu_set_dev_pasid,
};

struct iommu_domain *riscv_iommu_sva_domain_alloc(void)
{
	struct iommu_domain *domain;

	domain = kzalloc(sizeof(*domain), GFP_KERNEL);
	if (!domain)
		return NULL;

	domain->ops = &riscv_iommu_sva_domain_ops;

	return domain;
}

static struct iommu_domain *riscv_iommu_domain_alloc(unsigned type)
{
	struct riscv_iommu_domain *domain;

	if (type == IOMMU_DOMAIN_SVA)
		return riscv_iommu_sva_domain_alloc();

	if (type != IOMMU_DOMAIN_DMA &&
	    type != IOMMU_DOMAIN_DMA_FQ &&
	    type != IOMMU_DOMAIN_UNMANAGED &&
	    type != IOMMU_DOMAIN_IDENTITY && type != IOMMU_DOMAIN_BLOCKED)
		return NULL;

	domain = kzalloc(sizeof(*domain), GFP_KERNEL);
	if (!domain)
		return NULL;

	mutex_init(&domain->lock);
	INIT_LIST_HEAD(&domain->endpoints);

	return &domain->domain;
}

static void riscv_iommu_domain_free(struct iommu_domain *iommu_domain)
{
	struct riscv_iommu_domain *domain = to_riscv_iommu_domain(iommu_domain);

	if (domain->pgd_root)
		free_pages((unsigned long)domain->pgd_root,
			   domain->g_stage ? 2 : 0);

	kfree(domain);
}

static pte_t *riscv_iommu_pgd_walk(struct riscv_iommu_domain *domain,
				   unsigned long iova,
				   unsigned long (*pd_alloc)(gfp_t), gfp_t gfp)
{
	/* TODO: merge dev/iopgtable */
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	unsigned long pfn;

	pgd = pgd_offset_pgd(domain->pgd_root, iova);
	if (pgd_none(*pgd)) {
		pfn = pd_alloc ? virt_to_pfn(pd_alloc(gfp)) : 0;
		if (!pfn)
			return NULL;
		set_pgd(pgd, pfn_pgd(pfn, __pgprot(_PAGE_TABLE)));
	}

	p4d = p4d_offset(pgd, iova);
	if (p4d_none(*p4d)) {
		pfn = pd_alloc ? virt_to_pfn(pd_alloc(gfp)) : 0;
		if (!pfn)
			return NULL;
		set_p4d(p4d, __p4d((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
	}

	pud = pud_offset(p4d, iova);
	if (pud_none(*pud)) {
		pfn = pd_alloc ? virt_to_pfn(pd_alloc(gfp)) : 0;
		if (!pfn)
			return NULL;
		set_pud(pud, __pud((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
	}

	pmd = pmd_offset(pud, iova);
	if (pmd_none(*pmd)) {
		pfn = pd_alloc ? virt_to_pfn(pd_alloc(gfp)) : 0;
		if (!pfn)
			return NULL;
		set_pmd(pmd, __pmd((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
	}

	return pte_offset_kernel(pmd, iova);
}

static int riscv_iommu_map_pages(struct iommu_domain *dom,
				 unsigned long iova, phys_addr_t phys,
				 size_t pgsize, size_t pgcount, int prot,
				 gfp_t gfp, size_t *mapped)
{
	struct riscv_iommu_domain *domain = to_riscv_iommu_domain(dom);
	size_t size = 0;
	pte_t *pte;
	pte_t pte_val;

	if (domain->domain.type == IOMMU_DOMAIN_BLOCKED)
		return -ENODEV;

	if (domain->domain.type == IOMMU_DOMAIN_IDENTITY) {
		// TODO: should we be here ?
		*mapped = pgsize * pgcount;
		return 0;
	}

	if (pgsize != PAGE_SIZE) {
		return -EIO;
	}

	while (pgcount--) {
		pte = riscv_iommu_pgd_walk(domain, iova, get_zeroed_page, gfp);
		if (!pte) {
			*mapped = size;
			return -ENOMEM;
		}

		pte_val = pfn_pte(phys_to_pfn(phys),
				  (prot & IOMMU_WRITE) ? PAGE_WRITE :
				  PAGE_READ);

		set_pte(pte, pte_val);

		size += PAGE_SIZE;
		iova += PAGE_SIZE;
		phys += PAGE_SIZE;
	}

	*mapped = size;
	return 0;
}

static size_t riscv_iommu_unmap_pages(struct iommu_domain *dom,
				      unsigned long iova, size_t pgsize,
				      size_t pgcount,
				      struct iommu_iotlb_gather *gather)
{
	struct riscv_iommu_domain *domain = to_riscv_iommu_domain(dom);
	size_t size = 0;
	pte_t *pte;

	if (domain->domain.type == IOMMU_DOMAIN_IDENTITY)
		return pgsize * pgcount;

	if (pgsize != PAGE_SIZE) {
		return -EIO;
	}

	while (pgcount--) {
		pte = riscv_iommu_pgd_walk(domain, iova, NULL, 0);
		if (!pte)
			return size;

		set_pte(pte, __pte(0));

		size += PAGE_SIZE;
		iova += PAGE_SIZE;
	}

	return size;
}

static phys_addr_t riscv_iommu_iova_to_phys(struct iommu_domain *dom,
					    dma_addr_t iova)
{
	struct riscv_iommu_domain *domain = to_riscv_iommu_domain(dom);
	pte_t *pte;

	if (domain->domain.type == IOMMU_DOMAIN_IDENTITY)
		return (phys_addr_t) iova;

	pte = riscv_iommu_pgd_walk(domain, iova, NULL, 0);
	if (!pte || !pte_present(*pte))
		return 0;

	return (pfn_to_phys(pte_pfn(*pte)) | (iova & PAGE_MASK));
}

static void riscv_iommu_flush_iotlb_all(struct iommu_domain *dom)
{
	struct riscv_iommu_domain *domain = to_riscv_iommu_domain(dom);
	struct riscv_iommu_command cmd;
	struct riscv_iommu_endpoint *ep;

	__cmd_inval_vma(&cmd);

	/* TODO: Optimize for one (domain) to many (endpoints) case. */
	if (domain->g_stage) {
		list_for_each_entry(ep, &domain->endpoints, g_list) {
			__cmd_inval_set_gscid(&cmd, 0);
			__cmd_inval_set_pscid(&cmd, ep->pscid);
			riscv_iommu_post(ep->iommu, &cmd);
			riscv_iommu_iofence_sync(ep->iommu);
		}
	} else {
		list_for_each_entry(ep, &domain->endpoints, s_list) {
			__cmd_inval_set_gscid(&cmd, 0);
			__cmd_inval_set_pscid(&cmd, ep->pscid);
			riscv_iommu_post(ep->iommu, &cmd);
			riscv_iommu_iofence_sync(ep->iommu);
		}
	}
}

static void riscv_iommu_iotlb_sync(struct iommu_domain *dom,
				   struct iommu_iotlb_gather *gather)
{
	riscv_iommu_flush_iotlb_all(dom);
}

static void riscv_iommu_iotlb_sync_map(struct iommu_domain *dom,
				       unsigned long iova, size_t size)
{
	riscv_iommu_flush_iotlb_all(dom);
}

static int riscv_iommu_enable_nesting(struct iommu_domain *dom)
{
	struct riscv_iommu_domain *domain = to_riscv_iommu_domain(dom);

	if (domain->domain.type != IOMMU_DOMAIN_UNMANAGED)
		return -EINVAL;

	if (!list_empty(&domain->endpoints))
		return -EBUSY;

	domain->g_stage = true;
	return 0;
}

static void riscv_iommu_get_resv_regions(struct device *dev,
					 struct list_head *head)
{
	struct iommu_resv_region *entry, *new_entry;
	struct riscv_iommu_endpoint *ep = dev_iommu_priv_get(dev);

	list_for_each_entry(entry, &ep->regions, list) {
		new_entry = kmemdup(entry, sizeof(*entry), GFP_KERNEL);
		if (new_entry)
			list_add_tail(&new_entry->list, head);
	}

	iommu_dma_get_resv_regions(dev, head);
}

static const struct iommu_ops riscv_iommu_ops;

static ioasid_t iommu_sva_alloc_pscid(void)
{
	/* TODO: Provide anonymous pasid value */
	struct mm_struct mm = {
		.pasid = INVALID_IOASID,
	};

	if (iommu_sva_alloc_pasid(&mm, 1, (1 << 20) - 1))
		return INVALID_IOASID;

	return mm.pasid;
}

/* FIXME: maybe ep should be simpler ? */
static struct iommu_device *riscv_iommu_probe_device(struct device *dev)
{
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
	struct pci_dev *pdev = dev_is_pci(dev) ? to_pci_dev(dev) : NULL;
	struct riscv_iommu_endpoint *ep;
	struct riscv_iommu_device *iommu;
	int ret, feat, num;

	if (!fwspec || fwspec->ops != &riscv_iommu_ops)
		return ERR_PTR(-ENODEV);

	if (!fwspec->iommu_fwnode || !fwspec->iommu_fwnode->dev)
		return ERR_PTR(-EBUSY);

	iommu = dev_get_drvdata(fwspec->iommu_fwnode->dev);
	if (!iommu)
		return ERR_PTR(-ENODEV);

	ep = kzalloc(sizeof(*ep), GFP_KERNEL);
	if (!ep)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&ep->regions);
	INIT_LIST_HEAD(&ep->bindings);
	INIT_LIST_HEAD(&ep->s_list);
	INIT_LIST_HEAD(&ep->g_list);

	ep->dev = dev;
	ep->iommu = iommu;
	ep->pscid = iommu_sva_alloc_pscid();

	if (!pasid_valid(ep->pscid))
		return ERR_PTR(-ENOMEM);

	dev_iommu_priv_set(dev, ep);

	/* FIXME: how to get device id from non-pci devices? */
	if (!dev_is_pci(dev))
		return &iommu->iommu;

	ep->device_id = pci_dev_id(pdev);

	/* Try to enable PASID */
	do {
		feat = pci_pasid_features(pdev);
		if (feat < 0)
			break;
		num = pci_max_pasids(pdev);
		if (num <= 0)
			break;
		ret = pci_enable_pasid(pdev, feat);
		if (ret)
			break;

		ep->pasid_feat = feat;
		ep->pasid_bits = ilog2(num);

		dev_info(dev, "PASID support enabled, %d bits\n",
			 ep->pasid_bits);
	} while (0);

	return &iommu->iommu;
}

static void riscv_iommu_release_device(struct device *dev)
{
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
	struct riscv_iommu_endpoint *ep = dev_iommu_priv_get(dev);

	if (!fwspec || fwspec->ops != &riscv_iommu_ops || !ep)
		return;

	if (dev_is_pci(ep->dev)) {
		struct pci_dev *pdev = to_pci_dev(ep->dev);

		if (pdev->pasid_enabled)
			pci_disable_pasid(pdev);

		ep->pasid_bits = 0;
	}

	if (pasid_valid(ep->pscid))
		ioasid_free(ep->pscid);

	dev_iommu_priv_set(dev, NULL);
	kfree(ep);
	set_dma_ops(dev, NULL);
}

static void riscv_iommu_probe_finalize(struct device *dev)
{
	set_dma_ops(dev, NULL);
	iommu_setup_dma_ops(dev, 0, U64_MAX);
}

static struct iommu_group *riscv_iommu_device_group(struct device *dev)
{
	if (dev_is_pci(dev))
		return pci_device_group(dev);
	return generic_device_group(dev);
}

static int
riscv_iommu_of_xlate(struct device *dev, struct of_phandle_args *args)
{
	return iommu_fwspec_add_ids(dev, args->args, 1);
}

static bool riscv_iommu_capable(struct device *dev, enum iommu_cap cap)
{
	switch (cap) {
	case IOMMU_CAP_CACHE_COHERENCY:
	case IOMMU_CAP_INTR_REMAP:
	case IOMMU_CAP_PRE_BOOT_PROTECTION:
		return true;

	default:
		break;
	}

	return false;
}

static int riscv_iommu_enable_iopf(struct device *dev)
{
	/* TODO: merge dev/iopf */
	return -EINVAL;
}

static int riscv_iommu_disable_iopf(struct device *dev)
{
	/* TODO: merge dev/iopf */
	return -EINVAL;
}

static int riscv_iommu_enable_sva(struct device *dev)
{
	struct riscv_iommu_endpoint *ep = dev_iommu_priv_get(dev);
	ep->sva_enabled = !!ep->pasid_bits;
	return ep->sva_enabled ? 0 : -ENODEV;
}

static int riscv_iommu_disable_sva(struct device *dev)
{
	/* TODO: merge dev/iopf */
	struct riscv_iommu_endpoint *ep = dev_iommu_priv_get(dev);
	ep->sva_enabled = false;
	return 0;
}

static int riscv_iommu_dev_enable_feat(struct device *dev,
				       enum iommu_dev_features feat)
{
	switch (feat) {
	case IOMMU_DEV_FEAT_IOPF:
		return riscv_iommu_enable_iopf(dev);

	case IOMMU_DEV_FEAT_SVA:
		return riscv_iommu_enable_sva(dev);

	default:
		return -ENODEV;
	}
}

static int riscv_iommu_dev_disable_feat(struct device *dev,
					enum iommu_dev_features feat)
{
	switch (feat) {
	case IOMMU_DEV_FEAT_IOPF:
		return riscv_iommu_disable_iopf(dev);

	case IOMMU_DEV_FEAT_SVA:
		return riscv_iommu_disable_sva(dev);

	default:
		return -ENODEV;
	}
}

static int riscv_iommu_page_response(struct device *dev,
				     struct iommu_fault_event *evt,
				     struct iommu_page_response *msg)
{
	/* TODO: merge dev/iopf */
	return -ENODEV;
}

static void riscv_iommu_remove_dev_pasid(struct device *dev, ioasid_t pasid)
{
	struct iommu_domain *domain;

	domain = iommu_get_domain_for_dev_pasid(dev, pasid, IOMMU_DOMAIN_SVA);
	if (WARN_ON(IS_ERR(domain)) || !domain)
		return;

	// TODO: remove SVA bind.
	___riscv_iommu_sva_remove_dev_pasid(domain, dev, pasid);
}

static const struct iommu_domain_ops riscv_iommu_domain_ops = {
	.free = riscv_iommu_domain_free,
	.attach_dev = riscv_iommu_attach_dev,
	.detach_dev = riscv_iommu_detach_dev,
	.map_pages = riscv_iommu_map_pages,
	.unmap_pages = riscv_iommu_unmap_pages,
	.iova_to_phys = riscv_iommu_iova_to_phys,
	.iotlb_sync = riscv_iommu_iotlb_sync,
	.iotlb_sync_map = riscv_iommu_iotlb_sync_map,
	.flush_iotlb_all = riscv_iommu_flush_iotlb_all,
	.enable_nesting = riscv_iommu_enable_nesting,
};

static const struct iommu_ops riscv_iommu_ops = {
	.owner = THIS_MODULE,
	.pgsize_bitmap = SZ_4K,
	.capable = riscv_iommu_capable,
	.domain_alloc = riscv_iommu_domain_alloc,
	.probe_device = riscv_iommu_probe_device,
	.probe_finalize = riscv_iommu_probe_finalize,
	.release_device = riscv_iommu_release_device,
	.remove_dev_pasid = riscv_iommu_remove_dev_pasid,
	.device_group = riscv_iommu_device_group,
	.get_resv_regions = riscv_iommu_get_resv_regions,
	.of_xlate = riscv_iommu_of_xlate,
	.dev_enable_feat = riscv_iommu_dev_enable_feat,
	.dev_disable_feat = riscv_iommu_dev_disable_feat,
	.page_response = riscv_iommu_page_response,
	.default_domain_ops = &riscv_iommu_domain_ops,
	// N/A
	//      bool (*is_attach_deferred)(struct device *dev);
	//      int (*def_domain_type)(struct device *dev);
};

#define Q_HEAD(q) ((q)->qbr + (RIO_REG_CQH - RIO_REG_CQB))
#define Q_TAIL(q) ((q)->qbr + (RIO_REG_CQT - RIO_REG_CQB))

static unsigned riscv_iommu_queue_consume(struct riscv_iommu_device *iommu,
					  struct riscv_iommu_queue *q,
					  unsigned *ready)
{
	u32 tail = riscv_iommu_readl(iommu, Q_TAIL(q));
	*ready = q->lui;

	BUG_ON(q->cnt <= tail);
	if (q->lui <= tail)
		return tail - q->lui;
	return q->cnt - q->lui;
}

static void riscv_iommu_queue_release(struct riscv_iommu_device *iommu,
				      struct riscv_iommu_queue *q,
				      unsigned count)
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
		if (!(val & RIO_CQ_BUSY))
			break;
		cpu_relax();
	} while (get_cycles() < end_cycles);

	return val;
}

static int riscv_iommu_queue_init(struct riscv_iommu_device *iommu,
				  struct riscv_iommu_queue *q, unsigned count,
				  size_t item_size, unsigned qbr, unsigned qcr,
				  irq_handler_t irq_fn, const char *name)
{
	unsigned order = ilog2(count);

	do {
		size_t size = item_size * (1ULL << order);
		q->base = dmam_alloc_coherent(iommu->dev, size, &q->base_dma,
					      GFP_KERNEL);
		if (q->base || size < PAGE_SIZE)
			break;

		order--;
	} while (1);

	if (!q->base) {
		dev_err(iommu->dev, "failed to allocate %s queue (count: %u)\n",
			name, count);
		return -ENOMEM;
	}

	q->len = item_size;
	q->cnt = 1ULL << order;
	q->qbr = qbr;		/* queue base register */
	q->qcr = qcr;		/* queue control and status register */

	/* TODO: CPU affinity for queue handlers */
	if (request_threaded_irq
	    (q->irq, NULL, irq_fn, IRQF_ONESHOT, dev_name(iommu->dev), q)) {
		dev_err(iommu->dev, "failt to request irq %d for %s\n", q->irq,
			name);
		return -ENOMEM;
	}

	riscv_iommu_writeq(iommu, qbr, (order - 1) | phys_to_ppn(q->base_dma));
	riscv_iommu_queue_ctrl(iommu, q, RIO_CQ_EN | RIO_CQ_IE);

	/* TODO: check queue status */

	return 0;
}

static void riscv_iommu_queue_free(struct riscv_iommu_device *iommu,
				   struct riscv_iommu_queue *q)
{
	size_t size = q->len * q->cnt;

	riscv_iommu_queue_ctrl(iommu, q, 0);

	if (q->base)
		dmam_free_coherent(iommu->dev, size, q->base, q->base_dma);
	if (q->irq)
		free_irq(q->irq, q);
}

static irqreturn_t riscv_iommu_cmdq_handler(int irq, void *data)
{
	struct riscv_iommu_device *iommu =
	    container_of(data, struct riscv_iommu_device, cmdq);
	/* TODO: merge dev/inval */
	riscv_iommu_writel(iommu, RIO_REG_IPSR, RIO_IPSR_CQIP);
	return IRQ_HANDLED;
}

static void riscv_iommu_fault_report(struct riscv_iommu_device *iommu,
				     struct riscv_iommu_event *event)
{
	if (printk_ratelimit()) {
		unsigned bdf, err;
		bdf = FIELD_GET(RIO_EVENT_DID, event->reason);
		err = FIELD_GET(RIO_EVENT_CAUSE, event->reason);

		dev_warn(iommu->dev, "RIO Event: "
			 "cause: %d bdf: %04x:%02x.%x iova: %llx gpa: %llx\n",
			 err, PCI_BUS_NUM(bdf), PCI_SLOT(bdf), PCI_FUNC(bdf),
			 event->iova, event->phys);
	}
}

static irqreturn_t riscv_iommu_fault_handler(int irq, void *data)
{
	struct riscv_iommu_queue *q = (struct riscv_iommu_queue *)data;
	struct riscv_iommu_device *iommu;
	struct riscv_iommu_event *events;
	unsigned cnt, len, idx, ctrl;

	iommu = container_of(q, struct riscv_iommu_device, fltq);
	events = (struct riscv_iommu_event *)q->base;

	/* Clear fault interrupt pending. */
	riscv_iommu_writel(iommu, RIO_REG_IPSR, RIO_IPSR_FQIP);

	/* Error reporting, clear error reports if any. */
	ctrl = riscv_iommu_readl(iommu, RIO_REG_FQCSR);
	if (ctrl & (RIO_FQ_FULL | RIO_FQ_FAULT)) {
		riscv_iommu_queue_ctrl(iommu, &iommu->fltq, ctrl);
		dev_warn(iommu->dev, "RIO Event: fault: %d full: %d\n",
			 !!(ctrl & RIO_FQ_FAULT), !!(ctrl & RIO_FQ_FULL));
	}

	/* Report fault events. */
	do {
		cnt = riscv_iommu_queue_consume(iommu, q, &idx);
		if (!cnt)
			break;
		for (len = 0; len < cnt; idx++, len++)
			riscv_iommu_fault_report(iommu, &events[idx]);
		riscv_iommu_queue_release(iommu, q, cnt);
		cpu_relax();
	} while (1);

	return IRQ_HANDLED;
}

static void riscv_iommu_page_request(struct riscv_iommu_device *iommu,
				     struct riscv_iommu_page_request *req)
{
	/* TODO: merge IOPF */
}

static irqreturn_t riscv_iommu_page_request_handler(int irq, void *data)
{
	struct riscv_iommu_queue *q = (struct riscv_iommu_queue *)data;
	struct riscv_iommu_device *iommu;
	struct riscv_iommu_page_request *requests;
	unsigned cnt, len, idx, ctrl;

	iommu = container_of(q, struct riscv_iommu_device, priq);
	requests = (struct riscv_iommu_page_request *)q->base;

	/* Clear page request interrupt pending. */
	riscv_iommu_writel(iommu, RIO_REG_IPSR, RIO_IPSR_PQIP);

	/* Error reporting, clear error reports if any. */
	ctrl = riscv_iommu_readl(iommu, RIO_REG_PQCSR);
	if (ctrl & (RIO_PQ_FULL | RIO_PQ_FAULT)) {
		riscv_iommu_queue_ctrl(iommu, &iommu->priq, ctrl);
		dev_warn(iommu->dev,
			 "RIO Page Request Queue: fault: %d full: %d\n",
			 !!(ctrl & RIO_PQ_FAULT), !!(ctrl & RIO_PQ_FULL));
	}

	/* Process page requests. */
	do {
		cnt = riscv_iommu_queue_consume(iommu, q, &idx);
		if (!cnt)
			break;
		for (len = 0; len < cnt; idx++, len++)
			riscv_iommu_page_request(iommu, &requests[idx]);
		riscv_iommu_queue_release(iommu, q, cnt);
		cpu_relax();
	} while (1);

	return IRQ_HANDLED;
}

static int riscv_iommu_wait_ddtp_ready(struct riscv_iommu_device *iommu)
{
	cycles_t start_time;

	while (riscv_iommu_readq(iommu, RIO_REG_DDTP) & RIO_DDTP_BUSY) {
		if (RISCV_IOMMU_TIMEOUT < (get_cycles() - start_time)) {
			dev_err(iommu->dev, "Can not disable IOMMU");
			return -EBUSY;
		}
		cpu_relax();
	}

	return 0;
}

static void riscv_iommu_disable_dd(struct riscv_iommu_device *iommu)
{
	/* Ignore EBUSY and try to clear DDTP anyway. */
	riscv_iommu_wait_ddtp_ready(iommu);
	riscv_iommu_writeq(iommu, RIO_REG_DDTP, 0ULL);
}

static int riscv_iommu_enable_dd(struct riscv_iommu_device *iommu)
{
	u64 ddtp;

	iommu->dc_format32 = !(iommu->cap & RIO_CAP_MSI_FLAT);

	/* IOMMU must be either disabled or in pass-through mode. */
	ddtp = riscv_iommu_readq(iommu, RIO_REG_DDTP);
	switch (FIELD_GET(RIO_DDTP_MODE, ddtp)) {
	case RIO_DDTP_MODE_BARE:
	case RIO_DDTP_MODE_OFF:
		break;
	default:
		return -EINVAL;
	}

	if (iommu_default_passthrough() && ddt_mode == RIO_DDTP_MODE_BARE) {
		/* Disable IOMMU translation, enable pass-through mode. */
		iommu->ddt_mode = RIO_DDTP_MODE_BARE;
		ddtp = FIELD_PREP(RIO_DDTP_MODE, RIO_DDTP_MODE_BARE);
	} else {
		switch (ddt_mode) {
		case RIO_DDTP_MODE_1LVL:
		case RIO_DDTP_MODE_2LVL:
		case RIO_DDTP_MODE_3LVL:
			iommu->ddt_mode = ddt_mode;
			break;
		default:
			return -EINVAL;
		}
		ddtp = (u64) iommu->ddt_mode | phys_to_ppn(__pa(iommu->ddtp));
	}

	if (riscv_iommu_wait_ddtp_ready(iommu))
		return -EBUSY;

	riscv_iommu_writeq(iommu, RIO_REG_DDTP, ddtp);

	return 0;
}

#define sysfs_dev_to_iommu(dev) \
	container_of(dev_get_drvdata(dev), struct riscv_iommu_device, iommu)

static ssize_t address_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct riscv_iommu_device *iommu = sysfs_dev_to_iommu(dev);
	return sprintf(buf, "%llx\n", iommu->reg_phys);
}

static DEVICE_ATTR_RO(address);

#define ATTR_RD_REG32(name, offset)					\
	ssize_t reg_ ## name ## _show(struct device *dev,		\
			struct device_attribute *attr, char *buf)	\
{									\
	struct riscv_iommu_device *iommu = sysfs_dev_to_iommu(dev);	\
	return sprintf(buf, "0x%x\n",					\
			riscv_iommu_readl(iommu, offset));		\
}

#define ATTR_RD_REG64(name, offset)					\
	ssize_t reg_ ## name ## _show(struct device *dev,		\
			struct device_attribute *attr, char *buf)	\
{									\
	struct riscv_iommu_device *iommu = sysfs_dev_to_iommu(dev);	\
	return sprintf(buf, "0x%llx\n",					\
			riscv_iommu_readq(iommu, offset));		\
}

#define ATTR_WR_REG32(name, offset)					\
	ssize_t reg_ ## name ## _store(struct device *dev,		\
			struct device_attribute *attr,			\
			const char *buf, size_t len)			\
{									\
	struct riscv_iommu_device *iommu = sysfs_dev_to_iommu(dev);	\
	unsigned long val;						\
	int ret;							\
	ret = kstrtoul(buf, 0, &val);					\
	if (ret)							\
		return ret;						\
	riscv_iommu_writel(iommu, offset, val);				\
	return len;							\
}

#define ATTR_WR_REG64(name, offset)					\
	ssize_t reg_ ## name ## _store(struct device *dev,		\
			struct device_attribute *attr,			\
			const char *buf, size_t len)			\
{									\
	struct riscv_iommu_device *iommu = sysfs_dev_to_iommu(dev);	\
	unsigned long long val;						\
	int ret;							\
	ret = kstrtoull(buf, 0, &val);					\
	if (ret)							\
		return ret;						\
	riscv_iommu_writeq(iommu, offset, val);				\
	return len;							\
}

#define ATTR_RO_REG32(name, offset)					\
static ATTR_RD_REG32(name, offset)					\
static DEVICE_ATTR_RO(reg_ ## name)

#define ATTR_RW_REG32(name, offset)					\
static ATTR_RD_REG32(name, offset)					\
static ATTR_WR_REG32(name, offset)					\
static DEVICE_ATTR_RW(reg_ ## name)

#define ATTR_RO_REG64(name, offset)					\
static ATTR_RD_REG64(name, offset)					\
static DEVICE_ATTR_RO(reg_ ## name)

#define ATTR_RW_REG64(name, offset)					\
static ATTR_RD_REG64(name, offset)					\
static ATTR_WR_REG64(name, offset)					\
static DEVICE_ATTR_RW(reg_ ## name)

ATTR_RO_REG64(cap, RIO_REG_CAP);
ATTR_RO_REG64(fctl, RIO_REG_FCTL);
ATTR_RO_REG32(cqh, RIO_REG_CQH);
ATTR_RO_REG32(cqt, RIO_REG_CQT);
ATTR_RO_REG32(cqcsr, RIO_REG_CQCSR);
ATTR_RO_REG32(fqh, RIO_REG_FQH);
ATTR_RO_REG32(fqt, RIO_REG_FQT);
ATTR_RO_REG32(fqcsr, RIO_REG_FQCSR);
ATTR_RO_REG32(pqh, RIO_REG_PQH);
ATTR_RO_REG32(pqt, RIO_REG_PQT);
ATTR_RO_REG32(pqcsr, RIO_REG_PQCSR);
ATTR_RO_REG32(ipsr, RIO_REG_IPSR);
ATTR_RO_REG32(ivec, RIO_REG_IVEC);
ATTR_RW_REG32(iocntovf, RIO_REG_IOCNTOVF);
ATTR_RW_REG32(iocntinh, RIO_REG_IOCNTINH);
ATTR_RW_REG64(iohpmcycles, RIO_REG_IOHPMCYCLES);
ATTR_RW_REG64(iohpmevt_1, RIO_REG_IOHPMEVT_BASE + 0x00);
ATTR_RW_REG64(iohpmevt_2, RIO_REG_IOHPMEVT_BASE + 0x08);
ATTR_RW_REG64(iohpmevt_3, RIO_REG_IOHPMEVT_BASE + 0x10);
ATTR_RW_REG64(iohpmevt_4, RIO_REG_IOHPMEVT_BASE + 0x18);
ATTR_RW_REG64(iohpmevt_5, RIO_REG_IOHPMEVT_BASE + 0x20);
ATTR_RW_REG64(iohpmevt_6, RIO_REG_IOHPMEVT_BASE + 0x28);
ATTR_RW_REG64(iohpmevt_7, RIO_REG_IOHPMEVT_BASE + 0x30);
ATTR_RW_REG64(iohpmctr_1, RIO_REG_IOHPMCTR_BASE + 0x00);
ATTR_RW_REG64(iohpmctr_2, RIO_REG_IOHPMCTR_BASE + 0x08);
ATTR_RW_REG64(iohpmctr_3, RIO_REG_IOHPMCTR_BASE + 0x10);
ATTR_RW_REG64(iohpmctr_4, RIO_REG_IOHPMCTR_BASE + 0x18);
ATTR_RW_REG64(iohpmctr_5, RIO_REG_IOHPMCTR_BASE + 0x20);
ATTR_RW_REG64(iohpmctr_6, RIO_REG_IOHPMCTR_BASE + 0x28);
ATTR_RW_REG64(iohpmctr_7, RIO_REG_IOHPMCTR_BASE + 0x30);

static struct attribute *riscv_iommu_attrs[] = {
	&dev_attr_address.attr,
	&dev_attr_reg_cap.attr,
	&dev_attr_reg_fctl.attr,
	&dev_attr_reg_cqh.attr,
	&dev_attr_reg_cqt.attr,
	&dev_attr_reg_cqcsr.attr,
	&dev_attr_reg_fqh.attr,
	&dev_attr_reg_fqt.attr,
	&dev_attr_reg_fqcsr.attr,
	&dev_attr_reg_pqh.attr,
	&dev_attr_reg_pqt.attr,
	&dev_attr_reg_pqcsr.attr,
	&dev_attr_reg_ipsr.attr,
	&dev_attr_reg_ivec.attr,
	&dev_attr_reg_iocntovf.attr,
	&dev_attr_reg_iocntinh.attr,
	&dev_attr_reg_iohpmcycles.attr,
	&dev_attr_reg_iohpmctr_1.attr,
	&dev_attr_reg_iohpmevt_1.attr,
	&dev_attr_reg_iohpmctr_2.attr,
	&dev_attr_reg_iohpmevt_2.attr,
	&dev_attr_reg_iohpmctr_3.attr,
	&dev_attr_reg_iohpmevt_3.attr,
	&dev_attr_reg_iohpmctr_4.attr,
	&dev_attr_reg_iohpmevt_4.attr,
	&dev_attr_reg_iohpmctr_5.attr,
	&dev_attr_reg_iohpmevt_5.attr,
	&dev_attr_reg_iohpmctr_6.attr,
	&dev_attr_reg_iohpmevt_6.attr,
	&dev_attr_reg_iohpmctr_7.attr,
	&dev_attr_reg_iohpmevt_7.attr,
	NULL,
};

static struct attribute_group riscv_iommu_group = {
	.name = "riscv-iommu",
	.attrs = riscv_iommu_attrs,
};

const struct attribute_group *riscv_iommu_groups[] = {
	&riscv_iommu_group,
	NULL,
};

/* Common IOMMU driver teardown code */
static void riscv_iommu_remove(struct riscv_iommu_device *iommu)
{
	riscv_iommu_disable_dd(iommu);
	riscv_iommu_queue_free(iommu, &iommu->priq);
	riscv_iommu_queue_free(iommu, &iommu->fltq);
	riscv_iommu_queue_free(iommu, &iommu->cmdq);
	iommu_device_unregister(&iommu->iommu);
	iommu_device_sysfs_remove(&iommu->iommu);
	free_pages(iommu->sync, 0);
	free_pages(iommu->zero, 0);
	free_pages(iommu->ddtp, 0);
	devm_kfree(iommu->dev, iommu);
}

/* Common IOMMU driver setup code */
static int riscv_iommu_probe(struct device *dev,
			     phys_addr_t reg_phys, size_t reg_size)
{
	int ret;
	struct riscv_iommu_device *iommu;

	iommu = devm_kzalloc(dev, sizeof(*iommu), GFP_KERNEL);
	if (!iommu)
		return -ENOMEM;

	iommu->ddtp = get_zeroed_page(GFP_KERNEL);
	if (!iommu->ddtp) {
		devm_kfree(dev, iommu);
		return -ENOMEM;
	}

	iommu->zero = get_zeroed_page(GFP_KERNEL);
	if (!iommu->zero) {
		free_pages(iommu->ddtp, 0);
		devm_kfree(dev, iommu);
		return -ENOMEM;
	}

	iommu->sync = get_zeroed_page(GFP_KERNEL);
	if (!iommu->sync) {
		free_pages(iommu->zero, 0);
		free_pages(iommu->ddtp, 0);
		devm_kfree(dev, iommu);
		return -ENOMEM;
	}

	spin_lock_init(&iommu->cq_lock);
	iommu->reg = ioremap(reg_phys, reg_size);

	if (!iommu->reg) {
		dev_err(dev, "unable to map hardware register set\n");
		devm_kfree(dev, iommu);
		return -ENODEV;
	}

	iommu->reg_phys = reg_phys;
	iommu->reg_size = reg_size;
	iommu->dev = dev;
	iommu->cap = riscv_iommu_readq(iommu, RIO_REG_CAP);

	if (dev_is_pci(dev)) {
		struct pci_dev *pdev = to_pci_dev(dev);
		riscv_iommu_writel(iommu, RIO_REG_IVEC, 0x3210);
		iommu->cmdq.irq = pci_irq_vector(pdev, RIO_INT_CQ);
		iommu->fltq.irq = pci_irq_vector(pdev, RIO_INT_FQ);
		iommu->priq.irq = pci_irq_vector(pdev, RIO_INT_PQ);
	} else {
		dev_err(dev, "wire signalled interrupt not supported\n");
		goto fail;
	}

	ret = riscv_iommu_queue_init(iommu, &iommu->cmdq, CQ_COUNT,
				     sizeof(struct riscv_iommu_command),
				     RIO_REG_CQB, RIO_REG_CQCSR,
				     riscv_iommu_cmdq_handler, "cmdq");
	if (ret)
		goto fail;

	ret = riscv_iommu_queue_init(iommu, &iommu->fltq, FQ_COUNT,
				     sizeof(struct riscv_iommu_event),
				     RIO_REG_FQB, RIO_REG_FQCSR,
				     riscv_iommu_fault_handler, "fltq");
	if (ret)
		goto fail;

	ret = riscv_iommu_queue_init(iommu, &iommu->priq, PQ_COUNT,
				     sizeof(struct riscv_iommu_page_request),
				     RIO_REG_PQB, RIO_REG_PQCSR,
				     riscv_iommu_page_request_handler, "priq");
	if (ret)
		goto fail;

	ret = riscv_iommu_enable_dd(iommu);
	if (ret < 0) {
		dev_err(dev, "cannot enable iommu device (%d)\n", ret);
		goto fail;
	}
	// FIXME: use IOMMU capabilities to enable PASID
	iommu->iommu.max_pasids = 1u << 20;

	ret = iommu_device_sysfs_add(&iommu->iommu, NULL, riscv_iommu_groups,
				     "riscv-iommu@%llx", iommu->reg_phys);
	if (ret < 0) {
		dev_err(dev, "cannot register sysfs interface (%d)\n", ret);
		goto fail;
	}

	ret = iommu_device_register(&iommu->iommu, &riscv_iommu_ops, dev);
	if (ret < 0) {
		dev_err(dev, "cannot register iommu interface (%d)\n", ret);
		goto fail_sysfs;
	}

	dev_set_drvdata(dev, iommu);

	return 0;

 fail_sysfs:
	iommu_device_sysfs_remove(&iommu->iommu);
 fail:
	riscv_iommu_disable_dd(iommu);
	riscv_iommu_queue_free(iommu, &iommu->priq);
	riscv_iommu_queue_free(iommu, &iommu->fltq);
	riscv_iommu_queue_free(iommu, &iommu->cmdq);
	iounmap(iommu->reg);
	free_pages(iommu->sync, 0);
	free_pages(iommu->zero, 0);
	free_pages(iommu->ddtp, 0);
	devm_kfree(dev, iommu);
	return ret;
}

/* RISCV IOMMU as a PCIe device */

static int riscv_iommu_pci_iomap_probe(struct pci_dev *pdev)
{
	phys_addr_t reg_phys;
	size_t reg_size;
	int ret;

	ret = pci_request_mem_regions(pdev, DRV_NAME);
	if (ret < 0)
		return ret;

	if (!(pci_resource_flags(pdev, 0) & IORESOURCE_MEM))
		return -ENODEV;

	reg_size = pci_resource_len(pdev, 0);
	if (reg_size < RIO_REG_MIN_SIZE)
		return -ENODEV;

	reg_phys = pci_resource_start(pdev, 0);
	if (!reg_phys)
		return -ENODEV;

	ret = pci_alloc_irq_vectors(pdev, 1, RIO_INT_COUNT,
				    PCI_IRQ_MSI | PCI_IRQ_MSIX);
	if (ret < 0)
		return ret;

	return riscv_iommu_probe(&pdev->dev, reg_phys, reg_size);
}

static int riscv_iommu_pci_probe(struct pci_dev *pdev,
				 const struct pci_device_id *ent)
{
	int ret;

	ret = pci_enable_device_mem(pdev);
	if (ret < 0)
		return ret;

	pci_set_master(pdev);

	ret = riscv_iommu_pci_iomap_probe(pdev);
	if (ret < 0) {
		pci_free_irq_vectors(pdev);
		pci_clear_master(pdev);
		pci_release_regions(pdev);
		pci_disable_device(pdev);
		return ret;
	}

	return 0;
}

static void riscv_iommu_pci_remove(struct pci_dev *pdev)
{
	riscv_iommu_remove(dev_get_drvdata(&pdev->dev));
	pci_free_irq_vectors(pdev);
	pci_clear_master(pdev);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
}

static int __maybe_unused riscv_iommu_suspend(struct device *device)
{
	/* TODO: impl power management interfaces */
	return 0;
}

static int __maybe_unused riscv_iommu_resume(struct device *device)
{
	/* TODO: impl power management interfaces */
	return 0;
}

static SIMPLE_DEV_PM_OPS(riscv_iommu_pm_ops, riscv_iommu_suspend,
			 riscv_iommu_resume);

static const struct pci_device_id riscv_iommu_pci_tbl[] = {
	{PCI_VENDOR_ID_RIVOS, PCI_DEVICE_ID_RIVOS_IOMMU,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0,}
};

MODULE_DEVICE_TABLE(pci, riscv_iommu_pci_tbl);

static const struct of_device_id riscv_iommu_of_match[] = {
	{.compatible = "rivos,pci-iommu",},
	{},
};

MODULE_DEVICE_TABLE(of, riscv_iommu_of_match);

static struct pci_driver riscv_iommu_pci_driver = {
	.name = DRV_NAME,
	.id_table = riscv_iommu_pci_tbl,
	.probe = riscv_iommu_pci_probe,
	.remove = riscv_iommu_pci_remove,
	.driver.pm = &riscv_iommu_pm_ops,
	.driver.of_match_table = riscv_iommu_of_match,
};

static int __init riscv_iommu_init_module(void)
{
	return pci_register_driver(&riscv_iommu_pci_driver);
}

static void __exit riscv_iommu_cleanup_module(void)
{
	pci_unregister_driver(&riscv_iommu_pci_driver);
}

module_init(riscv_iommu_init_module);
module_exit(riscv_iommu_cleanup_module);

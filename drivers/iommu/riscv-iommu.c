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
#include <linux/riscv-iommu.h>
#include <linux/dma-map-ops.h>
#include <asm/page.h>


#include "dma-iommu.h"
#include "iommu-sva-lib.h"

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
#define CQ_ORDER		2
#define FQ_ORDER		2
#define PQ_ORDER		2

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
    container_of(dev->iommu->iommu_dev, struct riscv_iommu, iommu)

#define dev_to_riscv_iommu(dev) \
    container_of(dev_get_drvdata(dev), struct riscv_iommu, iommu)

/* IOMMU register accessors */
static inline u64 __reg_get64(struct riscv_iommu *iommu, unsigned r)
{
	return readq(iommu->reg + r);
}

static inline void __reg_set64(struct riscv_iommu *iommu, unsigned r, u64 v)
{
	writeq(v, iommu->reg + r);
}

static inline u32 __reg_get32(struct riscv_iommu *iommu, unsigned r)
{
	return readl(iommu->reg + r);
}

static inline void __reg_set32(struct riscv_iommu *iommu, unsigned r, u32 v)
{
	writel(v, iommu->reg + r);
}

static void __cmd_iodir_all(struct riscv_iommu_command *cmd)
{
	cmd->request = FIELD_PREP(RIO_CMD_MASK_FUN_OP, RIO_CMD_IODIR);
	cmd->address = 0;
}

static void __cmd_iodir_devid(struct riscv_iommu_command *cmd, unsigned devid)
{
	cmd->request = FIELD_PREP(RIO_CMD_MASK_FUN_OP, RIO_CMD_IODIR) |
	    FIELD_PREP(RIO_IODIR_MASK_DID, devid) | RIO_IODIR_DID_VALID;
	cmd->address = 0;
}

static void __cmd_iodir_pasid(struct riscv_iommu_command *cmd, unsigned devid,
			      unsigned pasid)
{
	cmd->request = FIELD_PREP(RIO_CMD_MASK_FUN_OP, RIO_CMD_IODIR) |
	    FIELD_PREP(RIO_IODIR_MASK_DID, devid) | RIO_IODIR_DID_VALID |
	    FIELD_PREP(RIO_IODIR_MASK_PID, pasid) | RIO_IODIR_PID_VALID;
	cmd->address = 0;
}

static void __cmd_inval_vma(struct riscv_iommu_command *cmd)
{
	cmd->request = FIELD_PREP(RIO_CMD_MASK_FUN_OP, RIO_CMD_IOTINVAL_VMA);
	cmd->address = 0;
}

static void __cmd_inval_set_addr(struct riscv_iommu_command *cmd, u64 addr)
{
	cmd->request |= RIO_IOTINVAL_ADDR_VALID;
	cmd->address = addr;
}

static void __cmd_inval_set_pscid(struct riscv_iommu_command *cmd,
				  unsigned pscid)
{
	cmd->request |= FIELD_PREP(RIO_IOTINVAL_MASK_PSCID, pscid) |
	    RIO_IOTINVAL_PSCID_VALID;
}

static void __cmd_inval_set_gscid(struct riscv_iommu_command *cmd,
				  unsigned gscid)
{
	cmd->request |= FIELD_PREP(RIO_IOTINVAL_MASK_GSCID, gscid) |
	    RIO_IOTINVAL_GSCID_VALID;
}

static void __cmd_iofence(struct riscv_iommu_command *cmd)
{
	cmd->request = FIELD_PREP(RIO_CMD_MASK_FUN_OP, RIO_CMD_IOFENCE_C);
	cmd->address = 0;
}

static void __cmd_iofence_set_av(struct riscv_iommu_command *cmd, u64 addr,
				 u32 data)
{
	cmd->request = FIELD_PREP(RIO_CMD_MASK_FUN_OP, RIO_CMD_IOFENCE_C) |
	    FIELD_PREP(RIO_IOFENCE_MASK_DATA, data) | RIO_IOFENCE_AV;
	cmd->address = addr;
}

/* Lookup or initialize device directory info structure. */
static struct riscv_iommu_dc *riscv_iommu_get_dc(struct riscv_iommu *iommu,
						 unsigned device_id)
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

/* Caller shall verify there is enough space in the command queue. */
static bool riscv_iommu_post(struct riscv_iommu *iommu,
			     struct riscv_iommu_command *cmd)
{
	u32 head, tail, next;
	unsigned long flags;

	/* TODO: rework to lock-less enqueue */
	spin_lock_irqsave(&iommu->cq_lock, flags);
	head = __reg_get32(iommu, RIO_REG_CQH) & iommu->cq_mask;
	tail = __reg_get32(iommu, RIO_REG_CQT) & iommu->cq_mask;
	next = (tail + 1) & iommu->cq_mask;
	if (next != head) {
		memcpy(iommu->cq + tail, cmd, sizeof(*cmd));
		__reg_set32(iommu, RIO_REG_CQT, next);
	}
	spin_unlock_irqrestore(&iommu->cq_lock, flags);

	return next != head;
}

static bool riscv_iommu_iodir_inv_all(struct riscv_iommu *iommu)
{
	struct riscv_iommu_command cmd;
	__cmd_iodir_all(&cmd);
	return riscv_iommu_post(iommu, &cmd);
}

static bool riscv_iommu_iodir_inv_devid(struct riscv_iommu *iommu,
					unsigned devid)
{
	struct riscv_iommu_command cmd;
	__cmd_iodir_devid(&cmd, devid);
	return riscv_iommu_post(iommu, &cmd);
}

static bool riscv_iommu_iodir_inv_pasid(struct riscv_iommu *iommu,
					unsigned devid, unsigned pasid)
{
	struct riscv_iommu_command cmd;
	__cmd_iodir_pasid(&cmd, devid, pasid);
	return riscv_iommu_post(iommu, &cmd);
}

static bool riscv_iommu_iofence_sync(struct riscv_iommu *iommu)
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

	if (dom->type == IOMMU_DOMAIN_BLOCKED || ep->sva_enabled) {
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
					IOMMU_RESV_SW_MSI);
	if (entry) {
		list_add_tail(&entry->list, &ep->regions);
	}

	val = virt_to_pfn(domain->msi_root) |
			FIELD_PREP(RIO_DCMSI_MASK_MODE, RIO_DCMSI_MODE_FLAT);
	ep->dc->msiptp = cpu_to_le64(val);

	/* Single page of MSIPTP, 256 IMSIC files */
	ep->dc->msi_addr_mask = cpu_to_le64(255);
	ep->dc->msi_addr_pattern = cpu_to_le64(RISCV_IMSIC_BASE >> 12);

 skip_msiptp:

	/* FIXME: verify spec if TA.V is required. */
	val = FIELD_PREP(RIO_PCTA_MASK_PSCID, ep->pscid) | RIO_PCTA_V;
	ep->dc->ta = cpu_to_le64(val);

	/* Mark device context as valid */
	wmb();
	ep->dc->tc = cpu_to_le64(RIO_DCTC_EN_ATS | RIO_DCTC_VALID);

	mutex_unlock(&domain->lock);
	riscv_iommu_iodir_inv_devid(ep->iommu, ep->device_id);

	return 0;
}

static struct iommu_domain *riscv_iommu_domain_alloc(unsigned type)
{
	struct riscv_iommu_domain *domain;

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
	struct riscv_iommu *iommu;
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

struct riscv_iommu_sva {
	struct iommu_sva sva;
	struct mm_struct *mm;
	struct list_head list;
	refcount_t refs;
};

static struct iommu_sva *riscv_iommu_sva_bind(struct device *dev,
					      struct mm_struct *mm,
					      void *drvdata)
{
	struct riscv_iommu_endpoint *ep = dev_iommu_priv_get(dev);
	struct riscv_iommu_dc *dc = ep->dc;
	struct riscv_iommu_pc *pc = ep->pc;
	struct riscv_iommu_sva *sva;
	ioasid_t max_pasid, pscid;
	int ret;

	if (!ep || !ep->sva_enabled)
		return ERR_PTR(-ENODEV);

	list_for_each_entry(sva, &ep->bindings, list) {
		if (sva->mm == mm) {
			refcount_inc(&sva->refs);
			return &sva->sva;
		}
	}

	sva = kzalloc(sizeof(*sva), GFP_KERNEL);
	if (!sva)
		return ERR_PTR(-ENOMEM);

	max_pasid = (1U << ep->pasid_bits) - 1;
	/* FIXME: remove limits due PD8 */
	max_pasid = min(max_pasid, 255u);

	ret = iommu_sva_alloc_pasid(mm, 1, max_pasid);
	if (ret < 0) {
		kfree(sva);
		return ERR_PTR(ret);
	}

	sva->mm = mm;
	sva->sva.dev = dev;
	refcount_set(&sva->refs, 1);
	list_add(&sva->list, &ep->bindings);

	if (!pc)
		pc = (struct riscv_iommu_pc *)get_zeroed_page(GFP_KERNEL);
	if (!pc)
		return ERR_PTR(-ENOMEM);

	/* Use PASID for PSCID tag */
	pscid = mm->pasid;
	/* bind mm page table to device PDT */
	pc[pscid].ta = cpu_to_le64(FIELD_PREP(RIO_PCTA_MASK_PSCID, pscid) |
				   RIO_PCTA_V);
	pc[pscid].fsc = cpu_to_le64(virt_to_pfn(mm->pgd) | SATP_MODE);

	/* update DC with sva->mm */
	if (!(ep->dc->tc & RIO_DCTC_PDTV)) {
		/* migrate to PD, domain mappings moved to PASID:0 */
		pc[0].ta = dc->ta;
		pc[0].fsc = dc->fsc;

		dc->fsc = cpu_to_le64(virt_to_pfn(pc) |
				      FIELD_PREP(RIO_ATP_MASK_MODE,
						 RIO_PDTP_MODE_PD8));
		dc->tc = cpu_to_le64(RIO_DCTC_PDTV | RIO_DCTC_EN_ATS | RIO_DCTC_VALID);
		ep->pc = pc;
		wmb();

		/* TODO: transition to PD steps */
		riscv_iommu_iodir_inv_devid(ep->iommu, ep->device_id);
	} else {
		wmb();
		riscv_iommu_iodir_inv_pasid(ep->iommu, ep->device_id,
					    mm->pasid);
	}

	riscv_iommu_iofence_sync(ep->iommu);

	return &sva->sva;
}

static void riscv_iommu_sva_unbind(struct iommu_sva *handle)
{
	/* TODO: merge dev/iopf */
	struct riscv_iommu_sva *sva = (struct riscv_iommu_sva *)handle;
	struct riscv_iommu_endpoint *ep = dev_iommu_priv_get(sva->sva.dev);
	struct riscv_iommu_command cmd;

	if (refcount_dec_and_test(&sva->refs)) {
		list_del(&sva->list);

		ep->pc[sva->mm->pasid].ta = 0;
		wmb();

		/* 1. invalidate PDT entry */
		__cmd_iodir_pasid(&cmd, ep->device_id, sva->mm->pasid);
		riscv_iommu_post(ep->iommu, &cmd);

		/* 2. invalidate all matching IOATC entries */
		__cmd_inval_vma(&cmd);
		__cmd_inval_set_gscid(&cmd, 0);
		__cmd_inval_set_pscid(&cmd, sva->mm->pasid);
		riscv_iommu_post(ep->iommu, &cmd);

		/* 3. Wait IOATC flush to happen */
		riscv_iommu_iofence_sync(ep->iommu);
		kfree(sva);
	}
}

static u32 riscv_iommu_get_pasid(struct iommu_sva *handle)
{
	struct riscv_iommu_sva *sva = (struct riscv_iommu_sva *)handle;
	return sva->mm->pasid;
}

int riscv_iommu_page_response(struct device *dev,
			      struct iommu_fault_event *evt,
			      struct iommu_page_response *msg)
{
	/* TODO: merge dev/iopf */
	return -ENODEV;
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
	.device_group = riscv_iommu_device_group,
	.get_resv_regions = riscv_iommu_get_resv_regions,
	.of_xlate = riscv_iommu_of_xlate,
	.dev_enable_feat = riscv_iommu_dev_enable_feat,
	.dev_disable_feat = riscv_iommu_dev_disable_feat,
	.sva_bind = riscv_iommu_sva_bind,
	.sva_unbind = riscv_iommu_sva_unbind,
	.sva_get_pasid = riscv_iommu_get_pasid,
	.page_response = riscv_iommu_page_response,
	.default_domain_ops = &riscv_iommu_domain_ops,
};

static void riscv_iommu_report_event(struct riscv_iommu *iommu, int idx)
{
	struct riscv_iommu_event *event = iommu->fq + idx;
	unsigned bdf, err;

	if (printk_ratelimit()) {
		bdf = FIELD_GET(RIO_EVENT_MASK_DID, event->reason);
		err = FIELD_GET(RIO_EVENT_MASK_CAUSE, event->reason);

		dev_warn(iommu->dev, "RIO Event: "
			 "cause: %d bdf: %04x:%02x.%x iova: %llx gpa: %llx\n",
			 err, PCI_BUS_NUM(bdf), PCI_SLOT(bdf), PCI_FUNC(bdf),
			 event->iova, event->phys);
	}
}

static void riscv_iommu_poll_events(struct riscv_iommu *iommu)
{
	u32 head, tail, ctrl;

	head = __reg_get32(iommu, RIO_REG_FQH) & iommu->fq_mask;
	tail = __reg_get32(iommu, RIO_REG_FQT) & iommu->fq_mask;
	while (head != tail) {
		riscv_iommu_report_event(iommu, head);
		head = (head + 1) & iommu->fq_mask;
	}
	__reg_set32(iommu, RIO_REG_FQH, head);

	/* Error reporting, clear error reports if any. */
	ctrl = __reg_get32(iommu, RIO_REG_FQCSR);
	if (ctrl & (RIO_FQ_FULL | RIO_FQ_FAULT)) {
		__reg_set32(iommu, RIO_REG_FQCSR, ctrl);
		dev_warn(iommu->dev, "RIO Event: fault: %d full: %d\n",
			 !!(ctrl & RIO_FQ_FAULT), !!(ctrl & RIO_FQ_FULL));
	}
}

static irqreturn_t riscv_iommu_cq_thread(int irq, void *data)
{
	struct riscv_iommu *iommu = (struct riscv_iommu *)data;
	/* TODO: merge dev/inval */
	__reg_set32(iommu, RIO_REG_IPSR, RIO_IPSR_CQIP);
	return IRQ_HANDLED;
}

static irqreturn_t riscv_iommu_fq_thread(int irq, void *data)
{
	struct riscv_iommu *iommu = (struct riscv_iommu *)data;
	riscv_iommu_poll_events(iommu);
	__reg_set32(iommu, RIO_REG_IPSR, RIO_IPSR_FQIP);
	return IRQ_HANDLED;
}

static irqreturn_t riscv_iommu_pq_thread(int irq, void *data)
{
	struct riscv_iommu *iommu = (struct riscv_iommu *)data;
	/* TODO: merge dev/iopf */
	__reg_set32(iommu, RIO_REG_IPSR, RIO_IPSR_PQIP);
	return IRQ_HANDLED;
}

static int riscv_iommu_enable_cq(struct riscv_iommu *iommu)
{
	const size_t logsz = PAGE_SHIFT + CQ_ORDER -
	    ilog2(sizeof(struct riscv_iommu_command));
	unsigned long ptr;
	int ret;

	ptr = __get_free_pages(GFP_KERNEL | __GFP_ZERO, CQ_ORDER);
	if (!ptr)
		return -ENOMEM;

	if (iommu->cq_irq < 0)
		return -EINVAL;

	ret = devm_request_threaded_irq(iommu->dev,
					iommu->cq_irq, NULL,
					riscv_iommu_cq_thread, IRQF_ONESHOT,
					NULL, iommu);
	if (ret) {
		free_pages(ptr, CQ_ORDER);
		return ret;
	}

	iommu->cq_mask = (1ULL << logsz) - 1;
	iommu->cq = (struct riscv_iommu_command *)ptr;

	__reg_set64(iommu, RIO_REG_CQB, (logsz - 1) | phys_to_ppn(__pa(ptr)));
	__reg_set32(iommu, RIO_REG_CQCSR, RIO_CQ_EN | RIO_CQ_IE);

	return 0;
}

static void riscv_iommu_disable_cq(struct riscv_iommu *iommu)
{
	if (iommu->cq_irq >= 0) {
		devm_free_irq(iommu->dev, iommu->cq_irq, iommu);
	}
	__reg_set32(iommu, RIO_REG_CQCSR, 0);
	__reg_set64(iommu, RIO_REG_CQB, 0ULL);
	/* TODO: merge dev/inval */
	free_pages((unsigned long)iommu->cq, CQ_ORDER);
	iommu->cq_mask = 0;
	iommu->cq = 0;
}

static int riscv_iommu_enable_fq(struct riscv_iommu *iommu)
{
	const size_t logsz = PAGE_SHIFT + FQ_ORDER -
	    ilog2(sizeof(struct riscv_iommu_event));
	unsigned long ptr;
	int ret;

	if (iommu->fq_irq < 0)
		return -EINVAL;

	ptr = __get_free_pages(GFP_KERNEL | __GFP_ZERO, FQ_ORDER);
	if (!ptr)
		return -ENOMEM;

	ret = devm_request_threaded_irq(iommu->dev,
					iommu->fq_irq, NULL,
					riscv_iommu_fq_thread, IRQF_ONESHOT,
					NULL, iommu);
	if (ret) {
		free_pages(ptr, FQ_ORDER);
		return ret;
	}

	iommu->fq_mask = (1ULL << logsz) - 1;
	iommu->fq = (struct riscv_iommu_event *)ptr;

	__reg_set64(iommu, RIO_REG_FQB, (logsz - 1) | phys_to_ppn(__pa(ptr)));
	__reg_set32(iommu, RIO_REG_FQCSR, RIO_FQ_EN | RIO_FQ_IE);

	return 0;
}

static void riscv_iommu_disable_fq(struct riscv_iommu *iommu)
{
	if (iommu->fq_irq >= 0) {
		devm_free_irq(iommu->dev, iommu->fq_irq, iommu);
	}
	__reg_set32(iommu, RIO_REG_FQCSR, 0);
	__reg_set64(iommu, RIO_REG_FQB, 0ULL);

	free_pages((unsigned long)iommu->fq, FQ_ORDER);

	iommu->fq_mask = 0;
	iommu->fq = 0;
}

static int riscv_iommu_enable_pq(struct riscv_iommu *iommu)
{
	const size_t logsz = PAGE_SHIFT + PQ_ORDER -
	    ilog2(sizeof(struct riscv_iommu_page_request));
	unsigned long ptr;
	struct iopf_queue *iopf;
	int ret;

	if (iommu->pq_irq < 0)
		return -EINVAL;

	ptr = __get_free_pages(GFP_KERNEL | __GFP_ZERO, PQ_ORDER);
	if (!ptr)
		return -ENOMEM;

	iopf = iopf_queue_alloc(dev_name(iommu->dev));
	if (!iopf) {
		free_pages(ptr, PQ_ORDER);
		return -ENOMEM;
	}

	ret = devm_request_threaded_irq(iommu->dev,
					iommu->pq_irq, NULL,
					riscv_iommu_pq_thread, IRQF_ONESHOT,
					NULL, iommu);
	if (ret) {
		iopf_queue_free(iopf);
		free_pages(ptr, PQ_ORDER);
		return ret;
	}

	iommu->pq_work = iopf;
	iommu->pq_mask = (1ULL << logsz) - 1;
	iommu->pq = (struct riscv_iommu_page_request *)ptr;

	__reg_set64(iommu, RIO_REG_PQB, (logsz - 1) | phys_to_ppn(__pa(ptr)));
	__reg_set32(iommu, RIO_REG_PQCSR, RIO_PQ_EN | RIO_PQ_IE);

	return 0;
}

static void riscv_iommu_disable_pq(struct riscv_iommu *iommu)
{
	__reg_set32(iommu, RIO_REG_FQCSR, 0);
	__reg_set64(iommu, RIO_REG_FQB, 0ULL);

	if (iommu->fq_irq >= 0) {
		devm_free_irq(iommu->dev, iommu->fq_irq, iommu);
	}

	if (iommu->pq_work) {
		iopf_queue_free(iommu->pq_work);
		iommu->pq_work = NULL;
	}

	free_pages((unsigned long)iommu->fq, PQ_ORDER);

	iommu->fq_mask = 0;
	iommu->fq = 0;
}

static int riscv_iommu_wait_ddtp_ready(struct riscv_iommu *iommu)
{
	cycles_t start_time;

	while (__reg_get64(iommu, RIO_REG_DDTP) & RIO_DDTP_BUSY) {
		if (RISCV_IOMMU_TIMEOUT < (get_cycles() - start_time)) {
			dev_err(iommu->dev, "Can not disable IOMMU");
			return -EBUSY;
		}
		cpu_relax();
	}

	return 0;
}

static void riscv_iommu_disable_dd(struct riscv_iommu *iommu)
{
	/* Ignore EBUSY and try to clear DDTP anyway. */
	riscv_iommu_wait_ddtp_ready(iommu);
	__reg_set64(iommu, RIO_REG_DDTP, 0ULL);
}

static int riscv_iommu_enable_dd(struct riscv_iommu *iommu)
{
	u64 ddtp;

	iommu->dc_format32 = !(iommu->cap & RIO_CAP_MSI_FLAT);

	/* IOMMU must be either disabled or in pass-through mode. */
	ddtp = __reg_get64(iommu, RIO_REG_DDTP);
	switch (FIELD_GET(RIO_DDTP_MASK_MODE, ddtp)) {
	case RIO_DDTP_MODE_BARE:
	case RIO_DDTP_MODE_OFF:
		break;
	default:
		return -EINVAL;
	}

	if (iommu_default_passthrough() && ddt_mode == RIO_DDTP_MODE_BARE) {
		/* Disable IOMMU translation, enable pass-through mode. */
		iommu->ddt_mode = RIO_DDTP_MODE_BARE;
		ddtp = FIELD_PREP(RIO_DDTP_MASK_MODE, RIO_DDTP_MODE_BARE);
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
		ddtp = (u64)iommu->ddt_mode | phys_to_ppn(__pa(iommu->ddtp));
	}

	if (riscv_iommu_wait_ddtp_ready(iommu))
		return -EBUSY;

	__reg_set64(iommu, RIO_REG_DDTP, ddtp);

	return 0;
}

static ssize_t address_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct riscv_iommu *iommu = dev_to_riscv_iommu(dev);
	return sprintf(buf, "%llx\n", iommu->reg_phys);
}

static DEVICE_ATTR_RO(address);

static ssize_t cap_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct riscv_iommu *iommu = dev_to_riscv_iommu(dev);
	return sprintf(buf, "%llx\n", iommu->cap);
}

static DEVICE_ATTR_RO(cap);

static struct attribute *riscv_iommu_attrs[] = {
	&dev_attr_address.attr,
	&dev_attr_cap.attr,
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
static void riscv_iommu_remove(struct riscv_iommu *iommu)
{
	riscv_iommu_disable_dd(iommu);
	riscv_iommu_disable_pq(iommu);
	riscv_iommu_disable_cq(iommu);
	riscv_iommu_disable_fq(iommu);
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
	struct riscv_iommu *iommu;

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
	iommu->cap = __reg_get64(iommu, RIO_REG_CAP);

	if (dev_is_pci(dev)) {
		struct pci_dev *pdev = to_pci_dev(dev);
		iommu->cq_irq = pci_irq_vector(pdev, RIO_INT_CQ);
		iommu->fq_irq = pci_irq_vector(pdev, RIO_INT_FQ);
		iommu->pq_irq = pci_irq_vector(pdev, RIO_INT_PQ);
	} else {
		/* TODO: enable wired interrupt mapping or MSI if supported */
		iommu->cq_irq = -1;
		iommu->fq_irq = -1;
		iommu->pq_irq = -1;
	}

	ret = riscv_iommu_enable_fq(iommu);
	if (ret < 0) {
		dev_err(dev, "cannot enable fault queue (%d)\n", ret);
		goto err_fq;
	}

	ret = riscv_iommu_enable_cq(iommu);
	if (ret < 0) {
		dev_err(dev, "cannot enable command queue (%d)\n", ret);
		goto err_cq;
	}

	ret = riscv_iommu_enable_pq(iommu);
	if (ret < 0) {
		dev_err(dev, "cannot enable page request queue (%d)\n", ret);
		goto err_pq;
	}

	ret = riscv_iommu_enable_dd(iommu);
	if (ret < 0) {
		dev_err(dev, "cannot enable iommu device (%d)\n", ret);
		goto err_dd;
	}

	ret = iommu_device_sysfs_add(&iommu->iommu, NULL, riscv_iommu_groups,
				     "riscv-iommu@%llx", iommu->reg_phys);
	if (ret < 0) {
		dev_err(dev, "cannot register sysfs interface (%d)\n", ret);
		goto err_sysfs;
	}

	ret = iommu_device_register(&iommu->iommu, &riscv_iommu_ops, dev);
	if (ret < 0) {
		dev_err(dev, "cannot register iommu interface (%d)\n", ret);
		goto err_ops;
	}

	dev_set_drvdata(dev, iommu);

	return 0;

 err_ops:
	iommu_device_sysfs_remove(&iommu->iommu);
 err_sysfs:
	riscv_iommu_disable_dd(iommu);
 err_dd:
	riscv_iommu_disable_pq(iommu);
 err_pq:
	riscv_iommu_disable_cq(iommu);
 err_cq:
	riscv_iommu_disable_fq(iommu);
 err_fq:
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

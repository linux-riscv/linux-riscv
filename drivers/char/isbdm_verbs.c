// SPDX-License-Identifier: GPL-2.0

/* Authors: Evan Green <evan@rivosinc.com> */
/* Copyright (c) 2023 Rivos Inc. */

// #include <linux/errno.h>
#include <linux/pci.h>
#include <linux/types.h>
// #include <linux/uaccess.h>
#include <linux/vmalloc.h>
// #include <linux/xarray.h>
// #include <net/addrconf.h>

// #include <rdma/iw_cm.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_verbs.h>
// #include <rdma/ib_user_verbs.h>
#include <rdma/uverbs_ioctl.h>

#include "isbdmex.h"
#include "isbdm_verbs.h"
#include "isbdm_mem.h"

static int ib_qp_state_to_siw_qp_state[IB_QPS_ERR + 1] = {
	[IB_QPS_RESET] = ISBDM_QP_STATE_IDLE,
	[IB_QPS_INIT] = ISBDM_QP_STATE_IDLE,
	[IB_QPS_RTR] = ISBDM_QP_STATE_RTR,
	[IB_QPS_RTS] = ISBDM_QP_STATE_RTS,
	[IB_QPS_SQD] = ISBDM_QP_STATE_CLOSING,
	[IB_QPS_SQE] = ISBDM_QP_STATE_TERMINATE,
	[IB_QPS_ERR] = ISBDM_QP_STATE_ERROR
};

static char ib_qp_state_to_string[IB_QPS_ERR + 1][sizeof("RESET")] = {
	[IB_QPS_RESET] = "RESET",
	[IB_QPS_INIT] = "INIT",
	[IB_QPS_RTR] = "RTR",
	[IB_QPS_RTS] = "RTS",
	[IB_QPS_SQD] = "SQD",
	[IB_QPS_SQE] = "SQE",
	[IB_QPS_ERR] = "ERR"
};

void isbdm_mmap_free(struct rdma_user_mmap_entry *rdma_entry)
{
	struct isbdm_user_mmap_entry *entry = to_isbdm_mmap_entry(rdma_entry);

	kfree(entry);
}

int isbdm_mmap(struct ib_ucontext *ctx, struct vm_area_struct *vma)
{
	struct isbdm_ucontext *uctx = to_isbdm_ctx(ctx);
	size_t size = vma->vm_end - vma->vm_start;
	struct rdma_user_mmap_entry *rdma_entry;
	struct isbdm_user_mmap_entry *entry;
	int rv = -EINVAL;

	if (vma->vm_start & (PAGE_SIZE - 1)) {
		pr_warn("siw: mmap not page aligned\n");
		return -EINVAL;
	}

	rdma_entry = rdma_user_mmap_entry_get(&uctx->base_ucontext, vma);
	if (!rdma_entry) {
		isbdm_dbg(&uctx->sdev->base_dev,
			  "mmap lookup failed: %lu, %#zx\n",
			  vma->vm_pgoff, size);

		return -EINVAL;
	}

	entry = to_isbdm_mmap_entry(rdma_entry);
	rv = remap_vmalloc_range(vma, entry->address, 0);
	if (rv) {
		pr_warn("remap_vmalloc_range failed: %lu, %zu\n", vma->vm_pgoff,
			size);

		goto out;
	}

out:
	rdma_user_mmap_entry_put(rdma_entry);
	return rv;
}

int isbdm_alloc_ucontext(struct ib_ucontext *base_ctx, struct ib_udata *udata)
{
	struct isbdm_device *sdev = to_isbdm_dev(base_ctx->device);
	struct isbdm_ucontext *ctx = to_isbdm_ctx(base_ctx);
	struct isbdm_uresp_alloc_ctx uresp = {};
	int rv;

	if (atomic_inc_return(&sdev->num_ctx) > ISBDM_MAX_CONTEXT) {
		rv = -ENOMEM;
		goto err_out;
	}

	ctx->sdev = sdev;
	uresp.dev_id = sdev->vendor_part_id;
	if (udata->outlen < sizeof(uresp)) {
		rv = -EINVAL;
		goto err_out;
	}

	rv = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
	if (rv)
		goto err_out;

	isbdm_dbg(base_ctx->device, "success. now %d context(s)\n",
		  atomic_read(&sdev->num_ctx));

	return 0;

err_out:
	atomic_dec(&sdev->num_ctx);
	isbdm_dbg(base_ctx->device, "failure %d. now %d context(s)\n", rv,
		  atomic_read(&sdev->num_ctx));

	return rv;
}

void isbdm_dealloc_ucontext(struct ib_ucontext *base_ctx)
{
	struct isbdm_ucontext *uctx = to_isbdm_ctx(base_ctx);

	atomic_dec(&uctx->sdev->num_ctx);
}

int isbdm_query_device(struct ib_device *base_dev, struct ib_device_attr *attr,
		       struct ib_udata *udata)
{
	struct isbdm_device *sdev = to_isbdm_dev(base_dev);

	if (udata->inlen || udata->outlen)
		return -EINVAL;

	memset(attr, 0, sizeof(*attr));
	attr->device_cap_flags = IB_DEVICE_MEM_MGT_EXTENSIONS;
	attr->kernel_cap_flags = IBK_ALLOW_USER_UNREG;
	attr->max_cq = sdev->attrs.max_cq;
	attr->max_cqe = sdev->attrs.max_cqe;
	attr->max_fast_reg_page_list_len = ISBDM_MAX_SGE_PBL;
	attr->max_mr = sdev->attrs.max_mr;
	attr->max_mw = sdev->attrs.max_mw;
	attr->max_mr_size = ~0ull;
	attr->max_pd = sdev->attrs.max_pd;
	attr->max_qp = sdev->attrs.max_qp;
	attr->max_qp_init_rd_atom = sdev->attrs.max_ird;
	attr->max_qp_rd_atom = sdev->attrs.max_ord;
	attr->max_qp_wr = sdev->attrs.max_qp_wr;
	attr->max_recv_sge = sdev->attrs.max_sge;
	attr->max_res_rd_atom = sdev->attrs.max_qp * sdev->attrs.max_ird;
	attr->max_send_sge = sdev->attrs.max_sge;
	attr->max_sge_rd = sdev->attrs.max_sge_rd;
	attr->max_srq = sdev->attrs.max_srq;
	attr->max_srq_sge = sdev->attrs.max_srq_sge;
	attr->max_srq_wr = sdev->attrs.max_srq_wr;
	attr->page_size_cap = PAGE_SIZE;
	attr->vendor_id = ISBDM_VENDOR_ID;
	attr->vendor_part_id = sdev->vendor_part_id;
	attr->max_pkeys = 1;
	/* ISBDM supports global atomic CompareExchange and Fetch'n'Add. */
	attr->atomic_cap = IB_ATOMIC_GLOB;
	/* ISBDM does not support partially masked atomics. */
	attr->masked_atomic_cap = IB_ATOMIC_NONE;

	/* TODO: How is sysimage_guid different than node_guid? */
	base_dev->node_guid = cpu_to_be64(isbdm_gid(sdev->ii));
	return 0;
}

int isbdm_query_port(struct ib_device *base_dev, u32 port,
		     struct ib_port_attr *attr)
{
	struct isbdm_device *sdev = to_isbdm_dev(base_dev);

	memset(attr, 0, sizeof(*attr));

	/* TODO: How are speed and width used, and how do we set them? */
	// rv = ib_get_eth_speed(base_dev, port, &attr->active_speed,
	// 		 &attr->active_width);
	attr->active_speed = IB_SPEED_FDR;
	attr->active_width = IB_WIDTH_1X;
	attr->gid_tbl_len = 1;
	attr->pkey_tbl_len = 1;
	attr->max_msg_sz = -1;
	/* TODO: How does MTU get set and used? */
	attr->max_mtu = ib_mtu_int_to_enum(PAGE_SIZE);
	attr->active_mtu = ib_mtu_int_to_enum(PAGE_SIZE);
	attr->phys_state = sdev->state == IB_PORT_ACTIVE ?
		IB_PORT_PHYS_STATE_LINK_UP : IB_PORT_PHYS_STATE_DISABLED;

	attr->port_cap_flags = sdev->port_cap_flags; // TODO: | IB_PORT_DEVICE_MGMT_SUP;
	attr->state = sdev->state;
	attr->lid = sdev->lid;
	attr->lmc = sdev->lmc;
	attr->sm_lid = sdev->sm_lid;
	attr->sm_sl = sdev->sm_sl;
	/*
	 * All zero
	 *
	 * attr->bad_pkey_cntr = 0;
	 * attr->qkey_viol_cntr = 0;
	 * attr->max_vl_num = 0;
	 * attr->subnet_timeout = 0;
	 * attr->init_type_repy = 0;
	 */
	return 0;
}

int isbdm_get_port_immutable(struct ib_device *base_dev, u32 port,
			     struct ib_port_immutable *port_immutable)
{
	struct ib_port_attr attr;
	int rv = isbdm_query_port(base_dev, port, &attr);

	if (rv)
		return rv;

	port_immutable->gid_tbl_len = attr.gid_tbl_len;
	port_immutable->pkey_tbl_len = attr.pkey_tbl_len;
	port_immutable->core_cap_flags = RDMA_CORE_PORT_IBA_IB;
	port_immutable->max_mad_size = IB_MGMT_MAD_SIZE;
	return 0;
}

int isbdm_query_gid(struct ib_device *base_dev, u32 port, int idx,
		  union ib_gid *gid)
{
	struct isbdm_device *sdev = to_isbdm_dev(base_dev);

	memset(gid, 0, sizeof(*gid));
	gid->global.interface_id = cpu_to_be64(isbdm_gid(sdev->ii));
	return 0;
}

int isbdm_modify_port(struct ib_device *ibdev, u32 port_num,
		      int port_modify_mask, struct ib_port_modify *props)
{
	struct isbdm_device *sdev = to_isbdm_dev(ibdev);

	WARN_ON(port_modify_mask & IB_PORT_OPA_MASK_CHG);

	sdev->port_cap_flags |= props->set_port_cap_mask;
	sdev->port_cap_flags &= ~props->clr_port_cap_mask;
	return 0;
}

int isbdm_query_pkey(struct ib_device *ibdev, u32 port, u16 index, u16 *pkey)
{
	if (index > 0)
		return -EINVAL;

	*pkey = 0xffff;
	return 0;
}

int isbdm_alloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	struct isbdm_pd *ipd = to_isbdm_pd(pd);
	struct isbdm_device *sdev = to_isbdm_dev(pd->device);

	if (atomic_inc_return(&sdev->num_pd) > ISBDM_MAX_PD) {
		atomic_dec(&sdev->num_pd);
		return -ENOMEM;
	}

	/* Make sure this process gets a PASID. */
	if (current->mm) {
		ipd->sva = iommu_sva_bind_device(&sdev->ii->pdev->dev,
						 current->mm);

		if (IS_ERR(ipd->sva)) {
			int rv = PTR_ERR(ipd->sva);

			ipd->sva = NULL;
			dev_err(&sdev->ii->pdev->dev,
				"pasid allocation failed: %d\n",
				rv);

			return rv;
		}

		ipd->mm = current->mm;
		ipd->pasid = ipd->mm->pasid;

		WARN_ON_ONCE(ipd->pasid == IOMMU_PASID_INVALID);
	}

	isbdm_dbg_pd(pd, "now %d PDs\n", atomic_read(&sdev->num_pd));
	return 0;
}

int isbdm_dealloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	struct isbdm_pd *ipd = to_isbdm_pd(pd);
	struct isbdm_device *sdev = to_isbdm_dev(pd->device);

	isbdm_dbg_pd(pd, "free PD\n");
	atomic_dec(&sdev->num_pd);
	if (ipd->sva)
		iommu_sva_unbind_device(ipd->sva);

	return 0;
}

int isbdm_create_ah(struct ib_ah *ibah, struct rdma_ah_init_attr *init_attr,
		    struct ib_udata *udata)
{
	struct isbdm_ah *ah = to_isbdm_ah(ibah);

	rdma_copy_ah_attr(&ah->attr, init_attr->ah_attr);
	return 0;
}

int isbdm_destroy_ah(struct ib_ah *ibah, u32 flags)
{
	struct isbdm_ah *ah = to_isbdm_ah(ibah);

	rdma_destroy_ah_attr(&ah->attr);
	return 0;
}

int isbdm_query_ah(struct ib_ah *ibah, struct rdma_ah_attr *ah_attr)
{
	struct isbdm_ah *ah = to_isbdm_ah(ibah);

	*ah_attr = ah->attr;
	return 0;
}

void isbdm_qp_get_ref(struct ib_qp *base_qp)
{
	isbdm_qp_get(to_isbdm_qp(base_qp));
}

void isbdm_qp_put_ref(struct ib_qp *base_qp)
{
	isbdm_qp_put(to_isbdm_qp(base_qp));
}

static struct rdma_user_mmap_entry *
isbdm_mmap_entry_insert(struct isbdm_ucontext *uctx,
			void *address, size_t length,
			u64 *offset)
{
	struct isbdm_user_mmap_entry *entry;
	int rv;

	*offset = ISBDM_INVAL_UOBJ_KEY;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	entry->address = address;
	rv = rdma_user_mmap_entry_insert(&uctx->base_ucontext,
					 &entry->rdma_entry,
					 length);
	if (rv) {
		kfree(entry);
		return NULL;
	}

	*offset = rdma_user_mmap_get_offset(&entry->rdma_entry);
	return &entry->rdma_entry;
}

static void isbdm_send_worker(struct work_struct *work)
{
	struct isbdm_qp *qp = container_of(work, struct isbdm_qp, send_work);
	int rc;

	down_read(&qp->state_lock);
	rc = isbdm_process_send_qp(qp);
	up_read(&qp->state_lock);
	if (rc)
		isbdm_dbg_qp(qp, "processing send queue failed: %d\n", rc);
}

/*
 * isbdm_create_qp()
 *
 * Create Queue Pair of requested size on given device.
 *
 * @qp:		Queue pait
 * @attrs:	Initial QP attributes.
 * @udata:	used to provide QP ID, SQ and RQ size back to user.
 */

int isbdm_create_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *attrs,
		    struct ib_udata *udata)
{
	struct ib_pd *pd = ibqp->pd;
	struct isbdm_qp *qp = to_isbdm_qp(ibqp);
	struct ib_device *base_dev = pd->device;
	struct isbdm_device *sdev = to_isbdm_dev(base_dev);
	struct isbdm_ucontext *uctx =
		rdma_udata_to_drv_context(udata, struct isbdm_ucontext,
					  base_ucontext);
	unsigned long flags;
	int num_sqe, num_rqe, rv = 0;
	size_t length;

	isbdm_dbg(base_dev, "create new QP\n");
	if (attrs->create_flags)
		return -EOPNOTSUPP;

	if (atomic_inc_return(&sdev->num_qp) > ISBDM_MAX_QP) {
		isbdm_dbg(base_dev, "too many QPs\n");
		rv = -ENOMEM;
		goto err_atomic;
	}

	if ((attrs->cap.max_send_wr > ISBDM_MAX_QP_WR) ||
	    (attrs->cap.max_recv_wr > ISBDM_MAX_QP_WR) ||
	    (attrs->cap.max_send_sge > ISBDM_MAX_SGE) ||
	    (attrs->cap.max_recv_sge > ISBDM_MAX_SGE)) {
		isbdm_dbg(base_dev, "QP size error\n");
		rv = -EINVAL;
		goto err_atomic;
	}

	if (attrs->cap.max_inline_data > ISBDM_MAX_INLINE) {
		isbdm_dbg(base_dev, "max inline send: %d > %d\n",
			  attrs->cap.max_inline_data, (int)ISBDM_MAX_INLINE);
		rv = -EINVAL;
		goto err_atomic;
	}

	/*
	 * NOTE: Allow for zero element SQ and RQ WQEs but not for a QP unable
	 * to hold any WQE (SQ + RQ)
	 */
	if ((attrs->cap.max_send_wr + attrs->cap.max_recv_wr) == 0) {
		isbdm_dbg(base_dev, "QP must have send or receive queue\n");
		rv = -EINVAL;
		goto err_atomic;
	}

	if (!attrs->send_cq || (!attrs->recv_cq && !attrs->srq)) {
		isbdm_dbg(base_dev, "send CQ or receive CQ invalid\n");
		rv = -EINVAL;
		goto err_atomic;
	}

	init_rwsem(&qp->state_lock);
	spin_lock_init(&qp->sq_lock);
	spin_lock_init(&qp->rq_lock);
	spin_lock_init(&qp->orq_lock);
	INIT_WORK(&qp->send_work, isbdm_send_worker);
	rv = isbdm_qp_add(sdev, qp);
	if (rv)
		goto err_atomic;

	num_sqe = attrs->cap.max_send_wr;
	num_rqe = attrs->cap.max_recv_wr;

	/*
	 * All queue indices are derived from modulo operations on a free
	 * running 'get' (consumer) and 'put' (producer) unsigned counter.
	 * Having queue sizes at power of two avoids handling counter wrap
	 * around.
	 */
	if (num_sqe) {
		num_sqe = roundup_pow_of_two(num_sqe);

	} else {
		/* Zero sized SQ is not supported */
		rv = -EINVAL;
		goto err_out_xa;
	}

	if (num_rqe)
		num_rqe = roundup_pow_of_two(num_rqe);

	if (udata)
		qp->sendq = vmalloc_user(num_sqe * sizeof(struct isbdm_sqe));
	else
		qp->sendq = vzalloc(num_sqe * sizeof(struct isbdm_sqe));

	if (qp->sendq == NULL) {
		rv = -ENOMEM;
		goto err_out_xa;
	}

	if (attrs->sq_sig_type != IB_SIGNAL_REQ_WR) {
		if (attrs->sq_sig_type == IB_SIGNAL_ALL_WR)
			qp->attrs.flags |= ISBDM_SIGNAL_ALL_WR;
		else {
			rv = -EINVAL;
			goto err_out_xa;
		}
	}
	qp->pd = pd;
	qp->scq = to_isbdm_cq(attrs->send_cq);
	qp->rcq = to_isbdm_cq(attrs->recv_cq);
	if (attrs->srq) {
		/*
		 * SRQ support.
		 * Verbs 6.3.7: ignore RQ size, if SRQ present
		 * Verbs 6.3.5: do not check PD of SRQ against PD of QP
		 */
		qp->srq = to_isbdm_srq(attrs->srq);
		qp->attrs.rq_size = 0;
		isbdm_dbg(base_dev, "QP [%u]: SRQ attached\n",
			  qp->base_qp.qp_num);

	} else if (num_rqe) {
		size_t recvq_size = num_rqe * sizeof(struct isbdm_rqe);

		if (udata)
			qp->recvq = vmalloc_user(recvq_size);
		else
			qp->recvq = vzalloc(recvq_size);

		if (qp->recvq == NULL) {
			rv = -ENOMEM;
			goto err_out_xa;
		}

		qp->attrs.rq_size = num_rqe;
	}

	qp->attrs.sq_size = num_sqe;
	qp->attrs.sq_max_sges = attrs->cap.max_send_sge;
	qp->attrs.rq_max_sges = attrs->cap.max_recv_sge;

	/* Make those two tunables fixed for now. */
	// qp->tx_ctx.gso_seg_limit = 1;
	// qp->tx_ctx.zcopy_tx = zcopy_tx;

	qp->attrs.state = ISBDM_QP_STATE_IDLE;
	if (udata) {
		struct isbdm_uresp_create_qp uresp = {};

		uresp.num_sqe = num_sqe;
		uresp.num_rqe = num_rqe;
		uresp.qp_id = qp_id(qp);
		if (qp->sendq) {
			length = num_sqe * sizeof(struct isbdm_sqe);
			qp->sq_entry =
				isbdm_mmap_entry_insert(uctx, qp->sendq,
							length, &uresp.sq_key);

			if (!qp->sq_entry) {
				rv = -ENOMEM;
				goto err_out_xa;
			}
		}

		if (qp->recvq) {
			length = num_rqe * sizeof(struct isbdm_rqe);
			qp->rq_entry =
				isbdm_mmap_entry_insert(uctx, qp->recvq,
							length, &uresp.rq_key);

			if (!qp->rq_entry) {
				uresp.sq_key = ISBDM_INVAL_UOBJ_KEY;
				rv = -ENOMEM;
				goto err_out_xa;
			}
		}

		if (udata->outlen < sizeof(uresp)) {
			rv = -EINVAL;
			goto err_out_xa;
		}

		rv = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if (rv)
			goto err_out_xa;
	}

	// qp->tx_cpu = siw_get_tx_cpu(sdev);
	// if (qp->tx_cpu < 0) {
	// 	rv = -EINVAL;
	// 	goto err_out_xa;
	// }
	INIT_LIST_HEAD(&qp->devq);
	spin_lock_irqsave(&sdev->lock, flags);
	list_add_tail(&qp->devq, &sdev->qp_list);
	spin_unlock_irqrestore(&sdev->lock, flags);
	init_completion(&qp->qp_free);
	return 0;

err_out_xa:
	xa_erase(&sdev->qp_xa, qp_id(qp));
	if (uctx) {
		rdma_user_mmap_entry_remove(qp->sq_entry);
		rdma_user_mmap_entry_remove(qp->rq_entry);
	}

	vfree(qp->sendq);
	vfree(qp->recvq);

err_atomic:
	atomic_dec(&sdev->num_qp);
	return rv;
}

/*
 * Minimum isbdm_query_qp() verb interface.
 *
 * @qp_attr_mask is not used, all available information is provided
 */
int isbdm_query_qp(struct ib_qp *base_qp, struct ib_qp_attr *qp_attr,
		   int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr)
{
	struct isbdm_qp *qp;

	if (base_qp && qp_attr && qp_init_attr) {
		qp = to_isbdm_qp(base_qp);

	} else {
		return -EINVAL;
	}

	qp_attr->cap.max_inline_data = ISBDM_MAX_INLINE;
	qp_attr->cap.max_send_wr = qp->attrs.sq_size;
	qp_attr->cap.max_send_sge = qp->attrs.sq_max_sges;
	qp_attr->cap.max_recv_wr = qp->attrs.rq_size;
	qp_attr->cap.max_recv_sge = qp->attrs.rq_max_sges;
	/* TODO: How does MTU get set and used? */
	qp_attr->path_mtu = ib_mtu_int_to_enum(PAGE_SIZE);
	qp_attr->max_rd_atomic = qp->attrs.irq_size;
	qp_attr->max_dest_rd_atomic = qp->attrs.orq_size;
	qp_attr->ah_attr = qp->remote_ah_attr;
	qp_attr->qp_access_flags = IB_ACCESS_LOCAL_WRITE |
				   IB_ACCESS_REMOTE_WRITE |
				   IB_ACCESS_REMOTE_READ;

	qp_init_attr->qp_type = base_qp->qp_type;
	qp_init_attr->send_cq = base_qp->send_cq;
	qp_init_attr->recv_cq = base_qp->recv_cq;
	qp_init_attr->srq = base_qp->srq;
	qp_init_attr->cap = qp_attr->cap;
	return 0;
}

int isbdm_verbs_modify_qp(struct ib_qp *base_qp, struct ib_qp_attr *attr,
			  int attr_mask, struct ib_udata *udata)
{
	struct isbdm_qp_attrs new_attrs;
	enum isbdm_qp_attr_mask isbdm_attr_mask = 0;
	struct isbdm_qp *qp = to_isbdm_qp(base_qp);
	int rv = 0;

	if (!attr_mask)
		return 0;

	if (attr_mask & ~IB_QP_ATTR_STANDARD_BITS)
		return -EOPNOTSUPP;

	memset(&new_attrs, 0, sizeof(new_attrs));
	if (attr_mask & IB_QP_ACCESS_FLAGS) {
		isbdm_attr_mask = ISBDM_QP_ATTR_ACCESS_FLAGS;
		if (attr->qp_access_flags & IB_ACCESS_REMOTE_READ)
			new_attrs.flags |= ISBDM_RDMA_READ_ENABLED;
		if (attr->qp_access_flags & IB_ACCESS_REMOTE_WRITE)
			new_attrs.flags |= ISBDM_RDMA_WRITE_ENABLED;
		if (attr->qp_access_flags & IB_ACCESS_MW_BIND)
			new_attrs.flags |= ISBDM_RDMA_BIND_ENABLED;
	}

	if (attr_mask & IB_QP_STATE) {
		isbdm_dbg_qp(qp, "desired IB QP state: %s\n",
			     ib_qp_state_to_string[attr->qp_state]);

		new_attrs.state = ib_qp_state_to_siw_qp_state[attr->qp_state];

		if (new_attrs.state > ISBDM_QP_STATE_RTS)
			qp->tx_ctx.tx_halted = true;

		isbdm_attr_mask |= ISBDM_QP_ATTR_STATE;
	}

	if (attr_mask & IB_QP_DEST_QPN) {
		isbdm_attr_mask |= ISBDM_QP_ATTR_DEST_QP_NUM;
		new_attrs.dest_qp_num = attr->dest_qp_num;
	}

	if (attr_mask & IB_QP_AV) {
		isbdm_attr_mask |= ISBDM_QP_ATTR_AV;
		new_attrs.ah_attr = attr->ah_attr;
	}

	if (!isbdm_attr_mask)
		goto out;

	down_write(&qp->state_lock);
	rv = isbdm_qp_modify(qp, &new_attrs, isbdm_attr_mask);
	up_write(&qp->state_lock);

out:
	return rv;
}

int isbdm_destroy_qp(struct ib_qp *base_qp, struct ib_udata *udata)
{
	struct isbdm_qp *qp = to_isbdm_qp(base_qp);
	struct isbdm_ucontext *uctx =
		rdma_udata_to_drv_context(udata, struct isbdm_ucontext,
					  base_ucontext);
	struct isbdm_qp_attrs qp_attrs;

	isbdm_dbg_qp(qp, "state %d\n", qp->attrs.state);

	/*
	 * Mark QP as in process of destruction to prevent from
	 * any async callbacks to RDMA core
	 */
	qp->attrs.flags |= ISBDM_QP_IN_DESTROY;
	/* TODO: is this needed? */
	// qp->rx_stream.rx_suspend = 1;

	if (uctx) {
		rdma_user_mmap_entry_remove(qp->sq_entry);
		rdma_user_mmap_entry_remove(qp->rq_entry);
	}

	down_write(&qp->state_lock);
	qp_attrs.state = ISBDM_QP_STATE_ERROR;
	isbdm_qp_modify(qp, &qp_attrs, ISBDM_QP_ATTR_STATE);

	/* TODO: Needed? */
	// if (qp->cep) {
	// 	siw_cep_put(qp->cep);
	// 	qp->cep = NULL;
	// }
	up_write(&qp->state_lock);

	/* TODO: Not needed, right? */
	// kfree(qp->tx_ctx.mpa_crc_hd);
	// kfree(qp->rx_stream.mpa_crc_hd);

	qp->scq = qp->rcq = NULL;
	isbdm_qp_put(qp);
	wait_for_completion(&qp->qp_free);
	return 0;
}

/*
 * isbdm_copy_inline_sgl()
 *
 * Prepare Scatter Gather List of inlined data for sending. For userland callers
 * function checks if given buffer addresses and lens are within process context
 * bounds. Data from all provided Scatter Gather Entries (sges) are copied
 * together into the Work Queue Entry, referenced by a single sge.
 */
static int isbdm_copy_inline_sgl(const struct ib_send_wr *core_wr,
				 struct isbdm_sqe *sqe)
{
	struct ib_sge *core_sge = core_wr->sg_list;
	void *kbuf = &sqe->sge[1];
	int num_sge = core_wr->num_sge;
	int bytes = 0;

	sqe->sge[0].laddr = (uintptr_t)kbuf;
	sqe->sge[0].lkey = 0;
	while (num_sge--) {
		if (!core_sge->length) {
			core_sge++;
			continue;
		}

		bytes += core_sge->length;
		if (bytes > ISBDM_MAX_INLINE) {
			bytes = -EINVAL;
			break;
		}

		memcpy(kbuf, (void *)(uintptr_t)core_sge->addr,
		       core_sge->length);

		kbuf += core_sge->length;
		core_sge++;
	}

	sqe->sge[0].length = max(bytes, 0);
	sqe->num_sge = bytes > 0 ? 1 : 0;
	return bytes;
}

/* Complete Send Queue Work Requests without processing */
static int isbdm_sq_flush_wr(struct isbdm_qp *qp, const struct ib_send_wr *wr,
			     const struct ib_send_wr **bad_wr)
{
	int rv = 0;

	while (wr) {
		struct isbdm_sqe sqe = {};

		switch (wr->opcode) {
		case IB_WR_RDMA_WRITE:
			sqe.opcode = ISBDM_OP_WRITE;
			break;
		case IB_WR_RDMA_READ:
			sqe.opcode = ISBDM_OP_READ;
			break;
		case IB_WR_RDMA_READ_WITH_INV:
			sqe.opcode = ISBDM_OP_READ_LOCAL_INV;
			break;
		case IB_WR_SEND:
			sqe.opcode = ISBDM_OP_SEND;
			break;
		case IB_WR_SEND_WITH_IMM:
			sqe.opcode = ISBDM_OP_SEND_WITH_IMM;
			break;
		case IB_WR_SEND_WITH_INV:
			sqe.opcode = ISBDM_OP_SEND_REMOTE_INV;
			break;
		case IB_WR_LOCAL_INV:
			sqe.opcode = ISBDM_OP_INVAL_STAG;
			break;
		case IB_WR_REG_MR:
			sqe.opcode = ISBDM_OP_REG_MR;
			break;
		default:
			rv = -EINVAL;
			break;
		}

		if (!rv) {
			sqe.id = wr->wr_id;
			rv = isbdm_sqe_complete(qp, &sqe, 0,
						ISBDM_WC_WR_FLUSH_ERR);
		}

		if (rv) {
			if (bad_wr)
				*bad_wr = wr;

			break;
		}

		wr = wr->next;
	}

	return rv;
}

/* Complete Receive Queue Work Requests without processing */
static int isbdm_rq_flush_wr(struct isbdm_qp *qp, const struct ib_recv_wr *wr,
			     const struct ib_recv_wr **bad_wr)
{
	struct isbdm_rqe rqe = {};
	int rv = 0;

	while (wr) {
		rqe.id = wr->wr_id;
		rv = isbdm_rqe_complete(qp, &rqe, 0, 0, 0, 0, 0,
					ISBDM_WC_WR_FLUSH_ERR);

		if (rv) {
			if (bad_wr)
				*bad_wr = wr;

			break;
		}

		wr = wr->next;
	}

	return rv;
}

/*
 * Fill out an atomic-flavored isbdm_sqe from a stock work request. Assumes
 * the opcode itself has already been set.
 */
static int isbdm_setup_atomic_sqe(struct isbdm_qp *qp,
				  const struct ib_send_wr *wr,
				  struct isbdm_sqe *sqe)
{
	const struct ib_atomic_wr *a_wr = atomic_wr(wr);

	if (wr->num_sge != 1) {
		isbdm_dbg_qp(qp, "Wanted 1 atomic op SGE, got %u\n",
			     wr->num_sge);

		return -EINVAL;
	}

	sqe->rkey = a_wr->rkey;
	sqe->raddr = a_wr->remote_addr;
	sqe->atomic.compare_add = a_wr->compare_add;
	sqe->atomic.exchange = a_wr->swap;
	memcpy(&sqe->atomic.sge,
		wr->sg_list,
		sizeof(sqe->atomic.sge));

	return 0;
}

/*
 * isbdm_post_send()
 *
 * Post a list of Send (flavored) Work Request's to a Send Queue.
 *
 * @base_qp:	Base Queue Pair contained in isbdm QP
 * @wr:		Null terminated list of user work requests
 * @bad_wr:	Points to failing work request in case of synchronous failure.
 */
int isbdm_post_send(struct ib_qp *base_qp, const struct ib_send_wr *wr,
		    const struct ib_send_wr **bad_wr)
{
	struct isbdm_qp *qp = to_isbdm_qp(base_qp);
	int enqueue_count = 0;
	unsigned long flags;
	int rv = 0;

	if (wr && !rdma_is_kernel_res(&qp->base_qp.res)) {
		isbdm_dbg_qp(qp, "wr must be empty for user mapped sq\n");
		*bad_wr = wr;
		return -EINVAL;
	}

	/*
	 * Try to acquire QP state lock. Must be non-blocking
	 * to accommodate kernel clients needs.
	 */
	if (!down_read_trylock(&qp->state_lock)) {
		if (qp->attrs.state == ISBDM_QP_STATE_ERROR) {

			/*
			 * ERROR state is final, so we can be sure
			 * this state will not change as long as the QP
			 * exists.
			 *
			 * This handles an ib_drain_sq() call with
			 * a concurrent request to set the QP state
			 * to ERROR.
			 */
			rv = isbdm_sq_flush_wr(qp, wr, bad_wr);

		} else {
			isbdm_dbg_qp(qp, "QP locked, state %d\n",
				   qp->attrs.state);

			*bad_wr = wr;
			rv = -ENOTCONN;
		}
		return rv;
	}

	if (unlikely(qp->attrs.state != ISBDM_QP_STATE_RTS)) {
		if (qp->attrs.state == ISBDM_QP_STATE_ERROR) {

			/*
			 * Immediately flush this WR to CQ, if QP
			 * is in ERROR state. SQ is guaranteed to
			 * be empty, so WR complets in-order.
			 *
			 * Typically triggered by ib_drain_sq().
			 */
			rv = isbdm_sq_flush_wr(qp, wr, bad_wr);

		} else {
			isbdm_dbg_qp(qp, "QP out of state %d\n",
				     qp->attrs.state);

			*bad_wr = wr;
			rv = -ENOTCONN;
		}

		up_read(&qp->state_lock);
		return rv;
	}

	spin_lock_irqsave(&qp->sq_lock, flags);
	while (wr) {
		u32 idx = qp->sq_put % qp->attrs.sq_size;
		struct isbdm_sqe *sqe = &qp->sendq[idx];

		if (sqe->flags) {
			isbdm_dbg_qp(qp, "sq full\n");
			rv = -ENOMEM;
			break;
		}

		if (wr->num_sge > qp->attrs.sq_max_sges) {
			isbdm_dbg_qp(qp, "too many sge's: %d\n", wr->num_sge);
			rv = -EINVAL;
			break;
		}

		sqe->id = wr->wr_id;
		if ((wr->send_flags & IB_SEND_SIGNALED) ||
		    (qp->attrs.flags & ISBDM_SIGNAL_ALL_WR))
			sqe->flags |= ISBDM_WQE_SIGNALLED;

		if (wr->send_flags & IB_SEND_FENCE)
			sqe->flags |= ISBDM_WQE_READ_FENCE;

		switch (wr->opcode) {
		case IB_WR_SEND:
		case IB_WR_SEND_WITH_INV:
		case IB_WR_SEND_WITH_IMM:
			if (wr->send_flags & IB_SEND_SOLICITED)
				sqe->flags |= ISBDM_WQE_SOLICITED;

			if (!(wr->send_flags & IB_SEND_INLINE)) {
				isbdm_copy_sgl(wr->sg_list, sqe->sge,
					       wr->num_sge);

				sqe->num_sge = wr->num_sge;

			} else {
				rv = isbdm_copy_inline_sgl(wr, sqe);
				if (rv <= 0) {
					rv = -EINVAL;
					break;
				}

				sqe->flags |= ISBDM_WQE_INLINE;
				sqe->num_sge = 1;
			}

			if (wr->opcode == IB_WR_SEND) {
				sqe->opcode = ISBDM_OP_SEND;

			} else if (wr->opcode == IB_WR_SEND_WITH_INV) {
				sqe->opcode = ISBDM_OP_SEND_REMOTE_INV;
				sqe->invalidate_rkey = wr->ex.invalidate_rkey;
				sqe->flags |= ISBDM_WQE_REM_INVAL;

			} else {
				sqe->opcode = ISBDM_OP_SEND_WITH_IMM;
				sqe->imm_data = wr->ex.imm_data;
				sqe->flags |= ISBDM_WQE_HAS_IMMEDIATE;
			}

			if (qp->base_qp.qp_type == IB_QPT_UD ||
			    qp->base_qp.qp_type == IB_QPT_GSI) {
				struct isbdm_ah *ah =
					to_isbdm_ah(ud_wr(wr)->ah);

				/*
				 * rkey and remote_qpn need to be de-unioned if
				 * this is allowed.
				 */
				WARN_ON_ONCE(sqe->opcode ==
					     ISBDM_OP_SEND_REMOTE_INV);

				sqe->ud.remote_qpn = ud_wr(wr)->remote_qpn;
				sqe->ud.dlid = ah->attr.ib.dlid;
			}

			break;

		case IB_WR_RDMA_READ_WITH_INV:
		case IB_WR_RDMA_READ:
			if (unlikely(wr->num_sge != 1)) {
				rv = -EINVAL;
				break;
			}

			isbdm_copy_sgl(wr->sg_list, &sqe->sge[0], 1);

			/* NOTE: zero length RREAD is allowed! */
			sqe->raddr = rdma_wr(wr)->remote_addr;
			sqe->rkey = rdma_wr(wr)->rkey;
			sqe->num_sge = 1;
			if (wr->opcode == IB_WR_RDMA_READ) {
				sqe->opcode = ISBDM_OP_READ;

			} else {
				sqe->opcode = ISBDM_OP_READ_LOCAL_INV;
				sqe->invalidate_rkey = wr->ex.invalidate_rkey;
			}

			break;

		case IB_WR_RDMA_WRITE:
			if (!(wr->send_flags & IB_SEND_INLINE)) {
				isbdm_copy_sgl(wr->sg_list, &sqe->sge[0],
					       wr->num_sge);

				sqe->num_sge = wr->num_sge;

			} else {
				rv = isbdm_copy_inline_sgl(wr, sqe);
				if (unlikely(rv < 0)) {
					rv = -EINVAL;
					break;
				}

				sqe->flags |= ISBDM_WQE_INLINE;
				sqe->num_sge = 1;
			}

			sqe->raddr = rdma_wr(wr)->remote_addr;
			sqe->rkey = rdma_wr(wr)->rkey;
			sqe->opcode = ISBDM_OP_WRITE;
			break;

		case IB_WR_REG_MR:
			sqe->base_mr = (uintptr_t)reg_wr(wr)->mr;
			sqe->rkey = reg_wr(wr)->key;
			/* TODO: Why was IWARP_ACCESS_MASK a thing? */
			//sqe->access = reg_wr(wr)->access & IWARP_ACCESS_MASK;
			sqe->access = reg_wr(wr)->access;
			sqe->opcode = ISBDM_OP_REG_MR;
			break;

		case IB_WR_LOCAL_INV:
			sqe->rkey = wr->ex.invalidate_rkey;
			sqe->opcode = ISBDM_OP_INVAL_STAG;
			break;

		case IB_WR_ATOMIC_CMP_AND_SWP:
			sqe->opcode = ISBDM_OP_COMP_AND_SWAP;
			rv = isbdm_setup_atomic_sqe(qp, wr, sqe);
			break;

		case IB_WR_ATOMIC_FETCH_AND_ADD:
			sqe->opcode = ISBDM_OP_FETCH_AND_ADD;
			rv = isbdm_setup_atomic_sqe(qp, wr, sqe);
			break;

		default:
			isbdm_dbg_qp(qp, "ib wr type %d unsupported\n",
				     wr->opcode);

			rv = -EINVAL;
			break;
		}

		isbdm_dbg_qp(qp, "opcode %d, flags 0x%x, wr_id 0x%pK\n",
			     sqe->opcode, sqe->flags,
			     (void *)(uintptr_t)sqe->id);

		if (unlikely(rv < 0))
			break;

		/* make SQE only valid after completely written */
		smp_wmb();
		sqe->flags |= ISBDM_WQE_VALID;
		qp->sq_put++;
		wr = wr->next;
		enqueue_count++;
	}

	/*
	 * If nobody is processing the send queue, this routine needs to start
	 * it, either by processing directly (for usermode callers) or kicking
	 * off a worker thread (kernel callers that may be in an IRQ context).
	 * The sq_lock synchronizes both other senders trying to get here, and
	 * the worker itself trying to finish.
	 */
	if (qp->tx_ctx.send_pending) {
		spin_unlock_irqrestore(&qp->sq_lock, flags);
		goto skip_direct_sending;
	}

	qp->tx_ctx.send_pending = true;
	spin_unlock_irqrestore(&qp->sq_lock, flags);
	if (rv < 0)
		goto skip_direct_sending;

	/*
	 * If this is a kernel caller (as evidenced by sending down a wr
	 * pointer), then they may have a spinlock held and cannot do the
	 * mutex_lock() needed to send now. Queue a work item to get off of this
	 * context and send in peace.
	 */
	if (enqueue_count)
		schedule_work(&qp->send_work);
	else
		rv = isbdm_process_send_qp(qp);

skip_direct_sending:
	up_read(&qp->state_lock);
	if (rv >= 0)
		return 0;

	/* Immediate error */
	isbdm_dbg_qp(qp, "error %d\n", rv);
	*bad_wr = wr;
	return rv;
}

/*
 * isbdm_post_receive()
 *
 * Post a list of Receive (flavored) Work Requests to a Recieve Queue.
 *
 * @base_qp:	Base Queue Pair contained in ISBDM QP
 * @wr:		Null terminated list of user Work Requests.
 * @bad_wr:	Points to failing work request in case of synchronous failure.
 */
int isbdm_post_receive(struct ib_qp *base_qp, const struct ib_recv_wr *wr,
		       const struct ib_recv_wr **bad_wr)
{
	struct isbdm_qp *qp = to_isbdm_qp(base_qp);
	unsigned long flags;
	int rv = 0;

	isbdm_dbg_qp(qp, "Post recv\n");
	if (qp->srq || qp->attrs.rq_size == 0) {
		*bad_wr = wr;
		return -EINVAL;
	}

	if (!rdma_is_kernel_res(&qp->base_qp.res)) {
		isbdm_dbg_qp(qp, "no kernel post_recv for user mapped rq\n");
		*bad_wr = wr;
		return -EINVAL;
	}

	/*
	 * Try to acquire QP state lock. Must be non-blocking to accommodate
	 * kernel clients needs.
	 */
	if (!down_read_trylock(&qp->state_lock)) {
		if (qp->attrs.state == ISBDM_QP_STATE_ERROR) {

			/*
			 * ERROR state is final, so we can be sure this state
			 * will not change as long as the QP exists.
			 *
			 * This handles an ib_drain_rq() call with a concurrent
			 * request to set the QP state to ERROR.
			 */
			rv = isbdm_rq_flush_wr(qp, wr, bad_wr);

		} else {
			isbdm_dbg_qp(qp, "QP locked, state %d\n",
				   qp->attrs.state);

			*bad_wr = wr;
			rv = -ENOTCONN;
		}

		return rv;
	}

	if (qp->attrs.state > ISBDM_QP_STATE_RTS) {
		if (qp->attrs.state == ISBDM_QP_STATE_ERROR) {

			/*
			 * Immediately flush this WR to CQ, if QP is in ERROR
			 * state. RQ is guaranteed to be empty, so WR completes
			 * in order.
			 *
			 * Typically triggered by ib_drain_rq().
			 */
			rv = isbdm_rq_flush_wr(qp, wr, bad_wr);

		} else {
			isbdm_dbg_qp(qp, "QP out of state %d\n",
				     qp->attrs.state);

			*bad_wr = wr;
			rv = -ENOTCONN;
		}

		up_read(&qp->state_lock);
		return rv;
	}

	/*
	 * Serialize potentially multiple producers. Not needed for single
	 * threaded consumer side.
	 */
	spin_lock_irqsave(&qp->rq_lock, flags);
	while (wr) {
		u32 idx = qp->rq_put % qp->attrs.rq_size;
		struct isbdm_rqe *rqe = &qp->recvq[idx];

		if (rqe->flags) {
			isbdm_dbg_qp(qp, "RQ full\n");
			rv = -ENOMEM;
			break;
		}

		if (wr->num_sge > qp->attrs.rq_max_sges) {
			isbdm_dbg_qp(qp, "too many sge's: %d\n", wr->num_sge);
			rv = -EINVAL;
			break;
		}

		rqe->id = wr->wr_id;
		rqe->num_sge = wr->num_sge;
		isbdm_copy_sgl(wr->sg_list, rqe->sge, wr->num_sge);

		/* make sure RQE is completely written before valid */
		smp_wmb();
		rqe->flags = ISBDM_WQE_VALID;
		qp->rq_put++;
		wr = wr->next;
	}

	spin_unlock_irqrestore(&qp->rq_lock, flags);
	up_read(&qp->state_lock);
	if (rv < 0) {
		isbdm_dbg_qp(qp, "error %d\n", rv);
		*bad_wr = wr;
	}

	return rv > 0 ? 0 : rv;
}

int isbdm_destroy_cq(struct ib_cq *base_cq, struct ib_udata *udata)
{
	struct isbdm_cq *cq = to_isbdm_cq(base_cq);
	struct isbdm_device *sdev = to_isbdm_dev(base_cq->device);
	struct isbdm_ucontext *ctx =
		rdma_udata_to_drv_context(udata, struct isbdm_ucontext,
					  base_ucontext);

	isbdm_dbg_cq(cq, "free CQ resources\n");
	isbdm_cq_flush(cq);
	if (ctx)
		rdma_user_mmap_entry_remove(cq->cq_entry);

	atomic_dec(&sdev->num_cq);
	vfree(cq->queue);
	return 0;
}

/*
 * isbdm_create_cq()
 *
 * Populate Completion Queue of requested size
 *
 * @base_cq: CQ as allocated by RDMA midlayer
 * @attr: Initial CQ attributes
 * @udata: relates to user context
 */

int isbdm_create_cq(struct ib_cq *base_cq, const struct ib_cq_init_attr *attr,
		    struct ib_udata *udata)
{
	struct isbdm_device *sdev = to_isbdm_dev(base_cq->device);
	struct isbdm_cq *cq = to_isbdm_cq(base_cq);
	int rv, size = attr->cqe;

	if (attr->flags)
		return -EOPNOTSUPP;

	if (atomic_inc_return(&sdev->num_cq) > ISBDM_MAX_CQ) {
		isbdm_dbg(base_cq->device, "too many CQs\n");
		rv = -ENOMEM;
		goto err_out;
	}

	if (size < 1 || size > sdev->attrs.max_cqe) {
		isbdm_dbg(base_cq->device, "CQ size error: %d\n", size);
		rv = -EINVAL;
		goto err_out;
	}

	size = roundup_pow_of_two(size);
	cq->base_cq.cqe = size;
	cq->num_cqe = size;
	if (udata) {
		cq->queue = vmalloc_user(size * sizeof(struct isbdm_cqe) +
					 sizeof(struct isbdm_cq_ctrl));
	} else {
		cq->queue = vzalloc(size * sizeof(struct isbdm_cqe) +
				    sizeof(struct isbdm_cq_ctrl));
	}

	if (cq->queue == NULL) {
		rv = -ENOMEM;
		goto err_out;
	}

	get_random_bytes(&cq->id, 4);
	isbdm_dbg(base_cq->device, "new CQ [%u]\n", cq->id);
	spin_lock_init(&cq->lock);
	cq->notify = (struct isbdm_cq_ctrl *)&cq->queue[size];
	if (udata) {
		struct isbdm_uresp_create_cq uresp = {};
		struct isbdm_ucontext *ctx =
			rdma_udata_to_drv_context(udata, struct isbdm_ucontext,
						  base_ucontext);
		size_t length = size * sizeof(struct isbdm_cqe) +
			sizeof(struct isbdm_cq_ctrl);

		cq->cq_entry =
			isbdm_mmap_entry_insert(ctx, cq->queue,
						length, &uresp.cq_key);

		if (!cq->cq_entry) {
			rv = -ENOMEM;
			goto err_out;
		}

		uresp.cq_id = cq->id;
		uresp.num_cqe = size;
		if (udata->outlen < sizeof(uresp)) {
			rv = -EINVAL;
			goto err_out;
		}

		rv = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if (rv)
			goto err_out;
	}

	return 0;

err_out:
	isbdm_dbg(base_cq->device, "CQ creation failed: %d", rv);
	if (cq->queue) {
		struct isbdm_ucontext *ctx =
			rdma_udata_to_drv_context(udata, struct isbdm_ucontext,
						  base_ucontext);
		if (ctx)
			rdma_user_mmap_entry_remove(cq->cq_entry);

		vfree(cq->queue);
	}

	atomic_dec(&sdev->num_cq);
	return rv;
}

/*
 * isbdm_poll_cq()
 *
 * Reap Completion Queue  entries if available and copy work completion status
 * into array of Work Completions provided by caller. Returns number of reaped
 * Completion Queue Entries.
 *
 * @base_cq:    Base CQ contained in ISBDM CQ.
 * @num_cqe:    Maximum number of CQE's to reap.
 * @wc:         Array of work completions to be filled by siw.
 */
int isbdm_poll_cq(struct ib_cq *base_cq, int num_cqe, struct ib_wc *wc)
{
	struct isbdm_cq *cq = to_isbdm_cq(base_cq);
	int i;

	for (i = 0; i < num_cqe; i++) {
		if (!isbdm_reap_cqe(cq, wc))
			break;
		wc++;
	}

	return i;
}

/*
 * isbdm_req_notify_cq()
 *
 * Request notification when new Completion Queue Entries are added to the given
 * Completion Queue.
 *
 * Possible flags:
 * - ISBDM_NOTIFY_SOLICITED lets ISBDM trigger a notification
 *   event if a Work Queue Entry with notification flag set enters the CQ.
 * - ISBDM_NOTIFY_NEXT_COMP lets ISBDM trigger a notification
 *   event if a Work Queue Entry enters the CQ.
 * - IB_CQ_REPORT_MISSED_EVENTS: return value will provide the
 *   number of not reaped Completion Queue Entries regardless of its
 *   notification type and current or new CQ notification settings.
 *
 * @base_cq:	Base CQ contained in ISBDM CQ.
 * @flags:	Requested notification flags.
 */
int isbdm_req_notify_cq(struct ib_cq *base_cq, enum ib_cq_notify_flags flags)
{
	struct isbdm_cq *cq = to_isbdm_cq(base_cq);

	isbdm_dbg_cq(cq, "flags: 0x%02x\n", flags);
	if ((flags & IB_CQ_SOLICITED_MASK) == IB_CQ_SOLICITED) {

		/*
		 * Enable CQ event for next solicited completion.
		 * and make it visible to all associated producers.
		 */
		smp_store_mb(cq->notify->flags, ISBDM_NOTIFY_SOLICITED);

	} else {

		/*
		 * Enable CQ event for any signalled completion.
		 * and make it visible to all associated producers.
		 */
		smp_store_mb(cq->notify->flags, ISBDM_NOTIFY_ALL);
	}

	if (flags & IB_CQ_REPORT_MISSED_EVENTS)
		return cq->cq_put - cq->cq_get;

	return 0;
}

/*
 * isbdm_dereg_mr()
 *
 * Release Memory Region.
 *
 * @base_mr: Base MR contained in siw MR.
 * @udata: points to user context, unused.
 */
int isbdm_dereg_mr(struct ib_mr *base_mr, struct ib_udata *udata)
{
	struct isbdm_mr *mr = to_isbdm_mr(base_mr);
	struct isbdm_device *sdev = to_isbdm_dev(base_mr->device);

	isbdm_dbg_mem(mr->mem, "deregister MR\n");
	atomic_dec(&sdev->num_mr);
	isbdm_mr_drop_mem(mr);
	kfree_rcu(mr, rcu);
	return 0;
}

/*
 * isbdm_reg_user_mr()
 *
 * Register Memory Region.
 *
 * @pd:		Protection Domain
 * @start:	starting address of MR (virtual address)
 * @len:	len of MR
 * @rnic_va:	not used by siw
 * @rights:	MR access rights
 * @udata:	user buffer to communicate STag and Key.
 */
struct ib_mr *isbdm_reg_user_mr(struct ib_pd *pd, u64 start, u64 len,
			        u64 rnic_va, int rights,
				struct ib_udata *udata)
{
	struct isbdm_mr *mr = NULL;
	struct isbdm_umem *umem = NULL;
	struct isbdm_ureq_reg_mr ureq;
	struct isbdm_device *sdev = to_isbdm_dev(pd->device);
	unsigned long mem_limit = rlimit(RLIMIT_MEMLOCK);
	int rv;

	isbdm_dbg_pd(pd, "start: 0x%pK, va: 0x%pK, len: %llu\n",
		     (void *)(uintptr_t)start, (void *)(uintptr_t)rnic_va,
		     (unsigned long long)len);

	if (atomic_inc_return(&sdev->num_mr) > ISBDM_MAX_MR) {
		isbdm_dbg_pd(pd, "too many MRs\n");
		rv = -ENOMEM;
		goto err_out;
	}

	if (!len) {
		rv = -EINVAL;
		goto err_out;
	}

	if (mem_limit != RLIM_INFINITY) {
		unsigned long num_pages =
			(PAGE_ALIGN(len + (start & ~PAGE_MASK))) >> PAGE_SHIFT;

		mem_limit >>= PAGE_SHIFT;
		if (num_pages > mem_limit - current->mm->locked_vm) {
			isbdm_dbg_pd(pd, "pages req %lu, max %lu, lock %lu\n",
				     num_pages, mem_limit,
				     current->mm->locked_vm);

			rv = -ENOMEM;
			goto err_out;
		}
	}

	umem = isbdm_umem_get(start, len, ib_access_writable(rights));
	if (IS_ERR(umem)) {
		rv = PTR_ERR(umem);
		isbdm_dbg_pd(pd, "getting user memory failed: %d\n", rv);
		umem = NULL;
		goto err_out;
	}

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		rv = -ENOMEM;
		goto err_out;
	}

	rv = isbdm_mr_add_mem(mr, pd, umem, start, len, rights);
	if (rv)
		goto err_out;

	if (udata) {
		struct isbdm_uresp_reg_mr uresp = {};
		struct isbdm_mem *mem = mr->mem;

		if (udata->inlen < sizeof(ureq)) {
			rv = -EINVAL;
			goto err_out;
		}

		rv = ib_copy_from_udata(&ureq, udata, sizeof(ureq));
		if (rv)
			goto err_out;

		mr->base_mr.lkey |= ureq.stag_key;
		mr->base_mr.rkey |= ureq.stag_key;
		mem->stag |= ureq.stag_key;
		/* Update the security key to include the user's key. */
		isbdm_set_rmb_key(sdev->ii,
				  isbdm_stag_to_rmbi(mem->stag),
				  mem->stag);

		uresp.stag = mem->stag;
		if (udata->outlen < sizeof(uresp)) {
			rv = -EINVAL;
			goto err_out;
		}

		rv = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if (rv)
			goto err_out;
	}

	mr->mem->stag_valid = 1;
	return &mr->base_mr;

err_out:
	atomic_dec(&sdev->num_mr);
	if (mr) {
		if (mr->mem)
			isbdm_mr_drop_mem(mr);

		kfree_rcu(mr, rcu);

	} else {
		if (umem)
			isbdm_umem_release(umem, false);
	}

	return ERR_PTR(rv);
}

struct ib_mr *isbdm_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
			     u32 max_sge)
{
	struct isbdm_device *sdev = to_isbdm_dev(pd->device);
	struct isbdm_mr *mr = NULL;
	struct isbdm_pbl *pbl = NULL;
	int rv;

	if (atomic_inc_return(&sdev->num_mr) > ISBDM_MAX_MR) {
		isbdm_dbg_pd(pd, "too many MRs\n");
		rv = -ENOMEM;
		goto err_out;
	}

	if (mr_type != IB_MR_TYPE_MEM_REG) {
		isbdm_dbg_pd(pd, "mr type %d unsupported\n", mr_type);
		rv = -EOPNOTSUPP;
		goto err_out;
	}

	if (max_sge > ISBDM_MAX_SGE_PBL) {
		isbdm_dbg_pd(pd, "too many SGEs: %d\n", max_sge);
		rv = -ENOMEM;
		goto err_out;
	}

	pbl = isbdm_pbl_alloc(max_sge);
	if (IS_ERR(pbl)) {
		rv = PTR_ERR(pbl);
		isbdm_dbg_pd(pd, "pbl allocation failed: %d\n", rv);
		pbl = NULL;
		goto err_out;
	}

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		rv = -ENOMEM;
		goto err_out;
	}

	rv = isbdm_mr_add_mem(mr, pd, pbl, 0, max_sge * PAGE_SIZE, 0);
	if (rv)
		goto err_out;

	mr->mem->is_pbl = 1;
	isbdm_dbg_pd(pd, "[MEM %u]: success\n", mr->mem->stag);
	return &mr->base_mr;

err_out:
	atomic_dec(&sdev->num_mr);
	if (!mr) {
		kfree(pbl);

	} else {
		if (mr->mem)
			isbdm_mr_drop_mem(mr);

		kfree_rcu(mr, rcu);
	}

	isbdm_dbg_pd(pd, "failed: %d\n", rv);
	return ERR_PTR(rv);
}

/* Just used to count number of pages being mapped */
static int isbdm_set_pbl_page(struct ib_mr *base_mr, u64 buf_addr)
{
	return 0;
}

int isbdm_map_mr_sg(struct ib_mr *base_mr, struct scatterlist *sl, int num_sle,
		    unsigned int *sg_off)
{
	struct scatterlist *slp;
	struct isbdm_mr *mr = to_isbdm_mr(base_mr);
	struct isbdm_mem *mem = mr->mem;
	struct isbdm_pbl *pbl = mem->pbl;
	struct isbdm_pble *pble;
	unsigned long pbl_size;
	int i, rv;

	if (!pbl) {
		isbdm_dbg_mem(mem, "no PBL allocated\n");
		return -EINVAL;
	}

	pble = pbl->pbe;
	if (pbl->max_buf < num_sle) {
		isbdm_dbg_mem(mem, "too many SGEs: %d > %d\n",
			      mem->pbl->max_buf, num_sle);

		return -ENOMEM;
	}

	for_each_sg(sl, slp, num_sle, i) {
		if (sg_dma_len(slp) == 0) {
			isbdm_dbg_mem(mem, "empty SGE\n");
			return -EINVAL;
		}

		if (i == 0) {
			pble->addr = sg_dma_address(slp);
			pble->size = sg_dma_len(slp);
			pble->pbl_off = 0;
			pbl_size = pble->size;
			pbl->num_buf = 1;

		} else {
			/* Merge PBL entries if adjacent */
			if (pble->addr + pble->size == sg_dma_address(slp)) {
				pble->size += sg_dma_len(slp);

			} else {
				pble++;
				pbl->num_buf++;
				pble->addr = sg_dma_address(slp);
				pble->size = sg_dma_len(slp);
				pble->pbl_off = pbl_size;
			}

			pbl_size += sg_dma_len(slp);
		}

		isbdm_dbg_mem(mem,
			      "sge[%d], size %u, addr 0x%p, total %lu\n",
			      i, pble->size, (void *)(uintptr_t)pble->addr,
			      pbl_size);
	}

	rv = ib_sg_to_pages(base_mr, sl, num_sle, sg_off, isbdm_set_pbl_page);
	if (rv > 0) {
		mem->len = base_mr->length;
		mem->va = base_mr->iova;
		isbdm_dbg_mem(mem,
			      "%llu bytes, start 0x%pK, %u SLE to %u entries\n",
			      mem->len, (void *)(uintptr_t)mem->va, num_sle,
			      pbl->num_buf);
	}

	return rv;
}

/*
 * isbdm_get_dma_mr()
 *
 * Create a (empty) DMA memory region, where no umem is attached.
 */
struct ib_mr *isbdm_get_dma_mr(struct ib_pd *pd, int rights)
{
	struct isbdm_device *sdev = to_isbdm_dev(pd->device);
	struct isbdm_mr *mr = NULL;
	int rv;

	if (atomic_inc_return(&sdev->num_mr) > ISBDM_MAX_MR) {
		isbdm_dbg_pd(pd, "too many MRs\n");
		rv = -ENOMEM;
		goto err_out;
	}

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		rv = -ENOMEM;
		goto err_out;
	}

	rv = isbdm_mr_add_mem(mr, pd, NULL, 0, ULONG_MAX, rights);
	if (rv)
		goto err_out;

	mr->mem->stag_valid = 1;
	isbdm_dbg_pd(pd, "[MEM %u]: success\n", mr->mem->stag);
	return &mr->base_mr;

err_out:
	if (rv)
		kfree(mr);

	atomic_dec(&sdev->num_mr);
	return ERR_PTR(rv);
}

/*
 * isbdm_create_srq()
 *
 * Create Shared Receive Queue of attributes @init_attrs
 * within protection domain given by @pd.
 *
 * @base_srq:	Base SRQ contained in siw SRQ.
 * @init_attrs:	SRQ init attributes.
 * @udata:	points to user context
 */
int isbdm_create_srq(struct ib_srq *base_srq,
		     struct ib_srq_init_attr *init_attrs,
		     struct ib_udata *udata)
{
	struct isbdm_srq *srq = to_isbdm_srq(base_srq);
	struct ib_srq_attr *attrs = &init_attrs->attr;
	struct isbdm_device *sdev = to_isbdm_dev(base_srq->device);
	struct isbdm_ucontext *ctx =
		rdma_udata_to_drv_context(udata, struct isbdm_ucontext,
					  base_ucontext);
	int rv;

	if (init_attrs->srq_type != IB_SRQT_BASIC)
		return -EOPNOTSUPP;

	if (atomic_inc_return(&sdev->num_srq) > ISBDM_MAX_SRQ) {
		isbdm_dbg_pd(base_srq->pd, "too many SRQs\n");
		rv = -ENOMEM;
		goto err_out;
	}

	if (attrs->max_wr == 0 || attrs->max_wr > ISBDM_MAX_SRQ_WR ||
	    attrs->max_sge > ISBDM_MAX_SGE ||
	    attrs->srq_limit > attrs->max_wr) {

		rv = -EINVAL;
		goto err_out;
	}

	srq->max_sge = attrs->max_sge;
	srq->num_rqe = roundup_pow_of_two(attrs->max_wr);
	srq->limit = attrs->srq_limit;
	if (srq->limit)
		srq->armed = true;

	srq->is_kernel_res = !udata;
	if (udata)
		srq->recvq =
			vmalloc_user(srq->num_rqe * sizeof(struct isbdm_rqe));
	else
		srq->recvq = vzalloc(srq->num_rqe * sizeof(struct isbdm_rqe));

	if (srq->recvq == NULL) {
		rv = -ENOMEM;
		goto err_out;
	}

	if (udata) {
		struct isbdm_uresp_create_srq uresp = {};
		size_t length = srq->num_rqe * sizeof(struct isbdm_rqe);

		srq->srq_entry =
			isbdm_mmap_entry_insert(ctx, srq->recvq,
						length, &uresp.srq_key);

		if (!srq->srq_entry) {
			rv = -ENOMEM;
			goto err_out;
		}

		uresp.num_rqe = srq->num_rqe;
		if (udata->outlen < sizeof(uresp)) {
			rv = -EINVAL;
			goto err_out;
		}

		rv = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if (rv)
			goto err_out;
	}

	spin_lock_init(&srq->lock);
	isbdm_dbg_pd(base_srq->pd, "[SRQ]: success\n");
	return 0;

err_out:
	if (srq->recvq) {
		if (ctx)
			rdma_user_mmap_entry_remove(srq->srq_entry);

		vfree(srq->recvq);
	}

	atomic_dec(&sdev->num_srq);
	return rv;
}

/*
 * isbdm_modify_srq()
 *
 * Modify SRQ. The caller may resize SRQ and/or set/reset notification
 * limit and (re)arm IB_EVENT_SRQ_LIMIT_REACHED notification.
 *
 * NOTE: it is unclear if RDMA core allows for changing the MAX_SGE
 * parameter. siw_modify_srq() does not check the attrs->max_sge param.
 */
int isbdm_modify_srq(struct ib_srq *base_srq, struct ib_srq_attr *attrs,
		     enum ib_srq_attr_mask attr_mask, struct ib_udata *udata)
{
	struct isbdm_srq *srq = to_isbdm_srq(base_srq);
	unsigned long flags;
	int rv = 0;

	spin_lock_irqsave(&srq->lock, flags);
	if (attr_mask & IB_SRQ_MAX_WR) {
		/* resize request not yet supported */
		rv = -EOPNOTSUPP;
		goto out;
	}

	if (attr_mask & IB_SRQ_LIMIT) {
		if (attrs->srq_limit) {
			if (unlikely(attrs->srq_limit > srq->num_rqe)) {
				rv = -EINVAL;
				goto out;
			}

			srq->armed = true;

		} else {
			srq->armed = false;
		}

		srq->limit = attrs->srq_limit;
	}

out:
	spin_unlock_irqrestore(&srq->lock, flags);
	return rv;
}

/*
 * isbdm_query_srq()
 *
 * Query SRQ attributes.
 */
int isbdm_query_srq(struct ib_srq *base_srq, struct ib_srq_attr *attrs)
{
	struct isbdm_srq *srq = to_isbdm_srq(base_srq);
	unsigned long flags;

	spin_lock_irqsave(&srq->lock, flags);
	attrs->max_wr = srq->num_rqe;
	attrs->max_sge = srq->max_sge;
	attrs->srq_limit = srq->limit;
	spin_unlock_irqrestore(&srq->lock, flags);
	return 0;
}

/*
 * isbdm_destroy_srq()
 *
 * Destroy SRQ.
 * It is assumed that the SRQ is not referenced by any
 * QP anymore - the code trusts the RDMA core environment to keep track
 * of QP references.
 */
int isbdm_destroy_srq(struct ib_srq *base_srq, struct ib_udata *udata)
{
	struct isbdm_srq *srq = to_isbdm_srq(base_srq);
	struct isbdm_device *sdev = to_isbdm_dev(base_srq->device);
	struct isbdm_ucontext *ctx =
		rdma_udata_to_drv_context(udata, struct isbdm_ucontext,
					  base_ucontext);

	if (ctx)
		rdma_user_mmap_entry_remove(srq->srq_entry);

	vfree(srq->recvq);
	atomic_dec(&sdev->num_srq);
	return 0;
}

/*
 * isbdm_post_srq_recv()
 *
 * Post a list of receive queue elements to SRQ.
 * NOTE: The function does not check or lock a certain SRQ state
 *       during the post operation. The code simply trusts the
 *       RDMA core environment.
 *
 * @base_srq:	Base SRQ contained in siw SRQ
 * @wr:		List of R-WR's
 * @bad_wr:	Updated to failing WR if posting fails.
 */
int isbdm_post_srq_recv(struct ib_srq *base_srq, const struct ib_recv_wr *wr,
			const struct ib_recv_wr **bad_wr)
{
	struct isbdm_srq *srq = to_isbdm_srq(base_srq);
	unsigned long flags;
	int rv = 0;

	if (unlikely(!srq->is_kernel_res)) {
		isbdm_dbg_pd(base_srq->pd,
			     "[SRQ]: no kernel post_recv for mapped srq\n");

		rv = -EINVAL;
		goto out;
	}

	/*
	 * Serialize potentially multiple producers.
	 * Also needed to serialize potentially multiple
	 * consumers.
	 */
	spin_lock_irqsave(&srq->lock, flags);
	while (wr) {
		u32 idx = srq->rq_put % srq->num_rqe;
		struct isbdm_rqe *rqe = &srq->recvq[idx];

		if (rqe->flags) {
			isbdm_dbg_pd(base_srq->pd, "SRQ full\n");
			rv = -ENOMEM;
			break;
		}

		if (unlikely(wr->num_sge > srq->max_sge)) {
			isbdm_dbg_pd(base_srq->pd,
				     "[SRQ]: too many SGEs: %d\n", wr->num_sge);

			rv = -EINVAL;
			break;
		}

		rqe->id = wr->wr_id;
		rqe->num_sge = wr->num_sge;
		isbdm_copy_sgl(wr->sg_list, rqe->sge, wr->num_sge);

		/* Make sure S-RQE is completely written before valid */
		smp_wmb();
		rqe->flags = ISBDM_WQE_VALID;
		srq->rq_put++;
		wr = wr->next;
	}

	spin_unlock_irqrestore(&srq->lock, flags);

out:
	if (unlikely(rv < 0)) {
		isbdm_dbg_pd(base_srq->pd, "[SRQ]: error %d\n", rv);
		*bad_wr = wr;
	}

	return rv;
}

void isbdm_qp_event(struct isbdm_qp *qp, enum ib_event_type etype)
{
	struct ib_event event;
	struct ib_qp *base_qp = &qp->base_qp;

	/*
	 * Do not report asynchronous errors on QP which gets
	 * destroyed via verbs interface (siw_destroy_qp())
	 */
	if (qp->attrs.flags & ISBDM_QP_IN_DESTROY)
		return;

	event.event = etype;
	event.device = base_qp->device;
	event.element.qp = base_qp;
	if (base_qp->event_handler) {
		isbdm_dbg_qp(qp, "reporting event %d\n", etype);
		base_qp->event_handler(&event, base_qp->qp_context);
	}
}

void isbdm_cq_event(struct isbdm_cq *cq, enum ib_event_type etype)
{
	struct ib_event event;
	struct ib_cq *base_cq = &cq->base_cq;

	event.event = etype;
	event.device = base_cq->device;
	event.element.cq = base_cq;
	if (base_cq->event_handler) {
		isbdm_dbg_cq(cq, "reporting CQ event %d\n", etype);
		base_cq->event_handler(&event, base_cq->cq_context);
	}
}

void isbdm_srq_event(struct isbdm_srq *srq, enum ib_event_type etype)
{
	struct ib_event event;
	struct ib_srq *base_srq = &srq->base_srq;

	event.event = etype;
	event.device = base_srq->device;
	event.element.srq = base_srq;
	if (base_srq->event_handler) {
		isbdm_dbg_pd(srq->base_srq.pd,
			     "reporting SRQ event %d\n", etype);
		base_srq->event_handler(&event, base_srq->srq_context);
	}
}

// void siw_port_event(struct siw_device *sdev, u32 port, enum ib_event_type etype)
// {
// 	struct ib_event event;

// 	event.event = etype;
// 	event.device = &sdev->base_dev;
// 	event.element.port_num = port;

// 	siw_dbg(&sdev->base_dev, "reporting port event %d\n", etype);

// 	ib_dispatch_event(&event);
// }

// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause

/* Authors: Evan Green <evan@rivosinc.com> */
/* Copyright (c) 2023 Rivos Inc. */

#include <linux/init.h>
#include <linux/list.h>
#include <linux/pci.h>

#include <rdma/rdma_netlink.h>

#include "isbdmex.h"
#include "isbdm_verbs.h"


static void isbdm_device_cleanup(struct ib_device *base_dev)
{
	struct isbdm_device *sdev = to_isbdm_dev(base_dev);

	xa_destroy(&sdev->qp_xa);
	xa_destroy(&sdev->mem_xa);
}

static struct ib_qp *isbdm_get_base_qp(struct ib_device *base_dev, int id)
{
	struct isbdm_qp *qp = isbdm_qp_id2obj(to_isbdm_dev(base_dev), id);

	if (qp) {
		/* isbdm_qp_id2obj() increments object reference count */
		isbdm_qp_put(qp);
		return &qp->base_qp;
	}

	return NULL;
}

/* Called when the port goes up or down. */
void isbdm_port_status_change(struct isbdm *ii)
{
	struct ib_event ib_event;

	if (!ii->ib_device)
		return;

	memset(&ib_event, 0, sizeof(ib_event));

	ib_event.device = &ii->ib_device->base_dev;
	ib_event.element.port_num = 1;
	if (ii->link_status == ISBDM_LINK_DOWN) {
		ib_event.event = IB_EVENT_PORT_ERR;
		ii->ib_device->state = IB_PORT_DOWN;

	} else {
		ib_event.event = IB_EVENT_PORT_ACTIVE;
		ii->ib_device->state = IB_PORT_ACTIVE;
	}

	ib_dispatch_event(&ib_event);
}

static const struct ib_device_ops isbdm_device_ops = {
	.owner = THIS_MODULE,
	.uverbs_abi_ver = ISBDM_ABI_VERSION,
	.driver_id = RDMA_DRIVER_ISBDM,

	.alloc_mr = isbdm_alloc_mr,
	.alloc_pd = isbdm_alloc_pd,
	.alloc_ucontext = isbdm_alloc_ucontext,
	.create_ah = isbdm_create_ah,
	.create_cq = isbdm_create_cq,
	.create_qp = isbdm_create_qp,
	.create_user_ah = isbdm_create_ah,
	.create_srq = isbdm_create_srq,
	.dealloc_driver = isbdm_device_cleanup,
	.dealloc_pd = isbdm_dealloc_pd,
	.dealloc_ucontext = isbdm_dealloc_ucontext,
	.dereg_mr = isbdm_dereg_mr,
	.destroy_ah = isbdm_destroy_ah,
	.destroy_cq = isbdm_destroy_cq,
	.destroy_qp = isbdm_destroy_qp,
	.destroy_srq = isbdm_destroy_srq,
	.get_dma_mr = isbdm_get_dma_mr,
	.get_port_immutable = isbdm_get_port_immutable,
	.iw_add_ref = isbdm_qp_get_ref,
	.iw_get_qp = isbdm_get_base_qp,
	.iw_rem_ref = isbdm_qp_put_ref,
	.map_mr_sg = isbdm_map_mr_sg,
	.mmap = isbdm_mmap,
	.mmap_free = isbdm_mmap_free,
	.modify_port = isbdm_modify_port,
	.modify_qp = isbdm_verbs_modify_qp,
	.modify_srq = isbdm_modify_srq,
	.poll_cq = isbdm_poll_cq,
	.post_recv = isbdm_post_receive,
	.post_send = isbdm_post_send,
	.process_mad = isbdm_process_mad,
	.post_srq_recv = isbdm_post_srq_recv,
	.query_ah = isbdm_query_ah,
	.query_device = isbdm_query_device,
	.query_gid = isbdm_query_gid,
	.query_pkey = isbdm_query_pkey,
	.query_port = isbdm_query_port,
	.query_qp = isbdm_query_qp,
	.query_srq = isbdm_query_srq,
	.req_notify_cq = isbdm_req_notify_cq,
	.reg_user_mr = isbdm_reg_user_mr,

	INIT_RDMA_OBJ_SIZE(ib_ah, isbdm_ah, base_ah),
	INIT_RDMA_OBJ_SIZE(ib_cq, isbdm_cq, base_cq),
	INIT_RDMA_OBJ_SIZE(ib_pd, isbdm_pd, base_pd),
	INIT_RDMA_OBJ_SIZE(ib_qp, isbdm_qp, base_qp),
	INIT_RDMA_OBJ_SIZE(ib_srq, isbdm_srq, base_srq),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, isbdm_ucontext, base_ucontext),
};

static int isbdm_device_register(struct isbdm_device *sdev, const char *name)
{
	struct ib_device *base_dev = &sdev->base_dev;
	int rv;

	sdev->vendor_part_id = sdev->ii->instance;
	rv = ib_register_device(base_dev, sdev->ii->misc.name, NULL);
	if (rv) {
		pr_warn("isbdm: device registration error %d\n", rv);
		return rv;
	}

	return 0;
}

struct isbdm_device *isbdm_device_create(struct isbdm *ii)
{
	struct isbdm_device *sdev = NULL;
	struct ib_device *base_dev;
	int rv;

	sdev = ib_alloc_device(isbdm_device, base_dev);
	if (!sdev)
		return NULL;

	base_dev = &sdev->base_dev;

	base_dev->node_guid = cpu_to_be64(isbdm_gid(ii));
	dev_info(&ii->pdev->dev, "Node GUID is %llx\n", isbdm_gid(ii));
	base_dev->uverbs_cmd_mask |= BIT_ULL(IB_USER_VERBS_CMD_POST_SEND);
	/* ISBDM is closer to a CA than it is a NIC, so... */
	base_dev->node_type = RDMA_NODE_IB_CA;
	memcpy(base_dev->node_desc, ISBDM_NODE_DESC_COMMON,
	       sizeof(ISBDM_NODE_DESC_COMMON));

	base_dev->phys_port_cnt = 1;
	base_dev->num_comp_vectors = 1;
	base_dev->dev.parent = &ii->pdev->dev;
	xa_init_flags(&sdev->qp_xa, XA_FLAGS_ALLOC);
	xa_init_flags(&sdev->mem_xa, XA_FLAGS_ALLOC1);
	ib_set_device_ops(base_dev, &isbdm_device_ops);
	sdev->attrs.max_qp = ISBDM_MAX_QP;
	sdev->attrs.max_qp_wr = ISBDM_MAX_QP_WR;
	sdev->attrs.max_ord = ISBDM_MAX_ORD_QP;
	sdev->attrs.max_ird = ISBDM_MAX_IRD_QP;
	sdev->attrs.max_sge = ISBDM_MAX_SGE;
	sdev->attrs.max_sge_rd = ISBDM_MAX_SGE_RD;
	sdev->attrs.max_cq = ISBDM_MAX_CQ;
	sdev->attrs.max_cqe = ISBDM_MAX_CQE;
	sdev->attrs.max_mr = ISBDM_MAX_MR;
	sdev->attrs.max_pd = ISBDM_MAX_PD;
	sdev->attrs.max_mw = ISBDM_MAX_MW;
	sdev->attrs.max_srq = ISBDM_MAX_SRQ;
	sdev->attrs.max_srq_wr = ISBDM_MAX_SRQ_WR;
	sdev->attrs.max_srq_sge = ISBDM_MAX_SGE;
	sdev->lid = isbdm_gid(ii);
	INIT_LIST_HEAD(&sdev->cep_list);
	INIT_LIST_HEAD(&sdev->qp_list);
	atomic_set(&sdev->num_ctx, 0);
	atomic_set(&sdev->num_srq, 0);
	atomic_set(&sdev->num_qp, 0);
	atomic_set(&sdev->num_cq, 0);
	atomic_set(&sdev->num_mr, 0);
	atomic_set(&sdev->num_pd, 0);
	spin_lock_init(&sdev->lock);
	if (ii->link_status == ISBDM_LINK_DOWN)
		sdev->state = IB_PORT_DOWN;
	else
		sdev->state = IB_PORT_ACTIVE;

	sdev->ii = ii;
	rv = isbdm_device_register(sdev, ii->misc.name);
	if (rv)
		goto error;

	return sdev;

error:
	ib_dealloc_device(base_dev);
	return NULL;
}

static void __exit isbdm_exit_module(void)
{
	ib_unregister_driver(RDMA_DRIVER_ISBDM);
	pr_info("ISBDM detached\n");
}

module_exit(isbdm_exit_module);

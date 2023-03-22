/* SPDX-License-Identifier: GPL-2.0 */

/* Authors: Evan Green <evan@rivosinc.com> */
/* Copyright (c) 2023 Rivos Inc. */

#ifndef _ISBDM_VERBS_H
#define _ISBDM_VERBS_H

// #include <linux/errno.h>

// #include <rdma/iw_cm.h>
// #include <rdma/ib_verbs.h>
// #include <rdma/ib_user_verbs.h>

#include "isbdm-ib.h"
// #include "siw_cm.h"

/*
 * isbdm_copy_sgl()
 *
 * Copy SGL from RDMA core representation to local
 * representation.
 */
static inline void isbdm_copy_sgl(struct ib_sge *sge, struct isbdm_sge *siw_sge,
				  int num_sge)
{
	while (num_sge--) {
		siw_sge->laddr = sge->addr;
		siw_sge->length = sge->length;
		siw_sge->lkey = sge->lkey;

		siw_sge++;
		sge++;
	}
}

int isbdm_alloc_ucontext(struct ib_ucontext *base_ctx, struct ib_udata *udata);
void isbdm_dealloc_ucontext(struct ib_ucontext *base_ctx);
int isbdm_get_port_immutable(struct ib_device *base_dev, u32 port,
			     struct ib_port_immutable *port_immutable);
int isbdm_query_device(struct ib_device *base_dev, struct ib_device_attr *attr,
		       struct ib_udata *udata);
int isbdm_create_cq(struct ib_cq *base_cq, const struct ib_cq_init_attr *attr,
		    struct ib_udata *udata);
int isbdm_query_port(struct ib_device *base_dev, u32 port,
		     struct ib_port_attr *attr);
int isbdm_query_gid(struct ib_device *base_dev, u32 port, int idx,
		    union ib_gid *gid);
int isbdm_modify_port(struct ib_device *ibdev, u32 port_num,
		      int port_modify_mask, struct ib_port_modify *props);
int isbdm_query_pkey(struct ib_device *ibdev, u32 port, u16 index, u16 *pkey);
int isbdm_alloc_pd(struct ib_pd *base_pd, struct ib_udata *udata);
int isbdm_dealloc_pd(struct ib_pd *base_pd, struct ib_udata *udata);
int isbdm_create_ah(struct ib_ah *ibah, struct rdma_ah_init_attr *init_attr,
		    struct ib_udata *udata);
int isbdm_destroy_ah(struct ib_ah *ibah, u32 flags);
int isbdm_query_ah(struct ib_ah *ibah, struct rdma_ah_attr *ah_attr);
int isbdm_create_qp(struct ib_qp *qp, struct ib_qp_init_attr *attr,
		    struct ib_udata *udata);
int isbdm_query_qp(struct ib_qp *base_qp, struct ib_qp_attr *qp_attr,
		   int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr);
int isbdm_verbs_modify_qp(struct ib_qp *base_qp, struct ib_qp_attr *attr,
			  int attr_mask, struct ib_udata *udata);
int isbdm_destroy_qp(struct ib_qp *base_qp, struct ib_udata *udata);
int isbdm_post_send(struct ib_qp *base_qp, const struct ib_send_wr *wr,
		    const struct ib_send_wr **bad_wr);
int isbdm_post_receive(struct ib_qp *base_qp, const struct ib_recv_wr *wr,
		       const struct ib_recv_wr **bad_wr);
int isbdm_destroy_cq(struct ib_cq *base_cq, struct ib_udata *udata);
int isbdm_poll_cq(struct ib_cq *base_cq, int num_entries, struct ib_wc *wc);
int isbdm_req_notify_cq(struct ib_cq *base_cq, enum ib_cq_notify_flags flags);
struct ib_mr *isbdm_reg_user_mr(struct ib_pd *base_pd, u64 start, u64 len,
			        u64 rnic_va, int rights,
				struct ib_udata *udata);
struct ib_mr *isbdm_alloc_mr(struct ib_pd *base_pd, enum ib_mr_type mr_type,
			     u32 max_sge);
struct ib_mr *isbdm_get_dma_mr(struct ib_pd *base_pd, int rights);
int isbdm_map_mr_sg(struct ib_mr *base_mr, struct scatterlist *sl, int num_sle,
		    unsigned int *sg_off);
int isbdm_dereg_mr(struct ib_mr *base_mr, struct ib_udata *udata);
int isbdm_create_srq(struct ib_srq *base_srq,
		     struct ib_srq_init_attr *init_attrs,
		     struct ib_udata *udata);
int isbdm_modify_srq(struct ib_srq *base_srq, struct ib_srq_attr *attrs,
		     enum ib_srq_attr_mask attr_mask, struct ib_udata *udata);
int isbdm_query_srq(struct ib_srq *base_srq, struct ib_srq_attr *attr);
int isbdm_destroy_srq(struct ib_srq *base_srq, struct ib_udata *udata);
int isbdm_post_srq_recv(struct ib_srq *base_srq, const struct ib_recv_wr *wr,
		        const struct ib_recv_wr **bad_wr);
int isbdm_mmap(struct ib_ucontext *ctx, struct vm_area_struct *vma);
void isbdm_mmap_free(struct rdma_user_mmap_entry *rdma_entry);
void isbdm_qp_event(struct isbdm_qp *qp, enum ib_event_type type);
void isbdm_cq_event(struct isbdm_cq *cq, enum ib_event_type type);
void isbdm_srq_event(struct isbdm_srq *srq, enum ib_event_type type);
// void siw_port_event(struct siw_device *dev, u32 port, enum ib_event_type type);
int isbdm_process_mad(struct ib_device *ibdev, int mad_flags, u32 port,
		      const struct ib_wc *in_wc, const struct ib_grh *in_grh,
		      const struct ib_mad *in, struct ib_mad *out,
		      size_t *out_mad_size, u16 *out_mad_pkey_index);

#endif

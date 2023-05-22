// SPDX-License-Identifier: GPL-2.0

/* Authors: Evan Green <evan@rivosinc.com> */
/* Copyright (c) 2023 Rivos Inc. */

#include <linux/errno.h>
#include <linux/types.h>

#include <rdma/ib_verbs.h>

#include "isbdm-ib.h"

static int map_wc_opcode[ISBDM_NUM_OPCODES] = {
	[ISBDM_OP_WRITE] = IB_WC_RDMA_WRITE,
	[ISBDM_OP_SEND] = IB_WC_SEND,
	[ISBDM_OP_SEND_WITH_IMM] = IB_WC_SEND,
	[ISBDM_OP_READ] = IB_WC_RDMA_READ,
	[ISBDM_OP_READ_LOCAL_INV] = IB_WC_RDMA_READ,
	[ISBDM_OP_COMP_AND_SWAP] = IB_WC_COMP_SWAP,
	[ISBDM_OP_FETCH_AND_ADD] = IB_WC_FETCH_ADD,
	[ISBDM_OP_INVAL_STAG] = IB_WC_LOCAL_INV,
	[ISBDM_OP_REG_MR] = IB_WC_REG_MR,
	[ISBDM_OP_RECEIVE] = IB_WC_RECV,
};

enum ib_wc_status map_cqe_status[ISBDM_NUM_WC_STATUS] = {
	[ISBDM_WC_SUCCESS] = IB_WC_SUCCESS,
	[ISBDM_WC_LOC_LEN_ERR] = IB_WC_LOC_LEN_ERR,
	[ISBDM_WC_LOC_PROT_ERR] = IB_WC_LOC_PROT_ERR,
	[ISBDM_WC_LOC_QP_OP_ERR] = IB_WC_LOC_QP_OP_ERR,
	[ISBDM_WC_WR_FLUSH_ERR] = IB_WC_WR_FLUSH_ERR,
	[ISBDM_WC_BAD_RESP_ERR] = IB_WC_BAD_RESP_ERR,
	[ISBDM_WC_LOC_ACCESS_ERR] = IB_WC_LOC_ACCESS_ERR,
	[ISBDM_WC_REM_ACCESS_ERR] = IB_WC_REM_ACCESS_ERR,
	[ISBDM_WC_REM_INV_REQ_ERR] = IB_WC_REM_INV_REQ_ERR,
	[ISBDM_WC_GENERAL_ERR] = IB_WC_GENERAL_ERR,
};

/*
 * Reap one Completion Queue Entry from the Completion Queue. Only used by
 * kernel clients during CQ normal operation. Might be called during CQ flush
 * for user mapped Completion Queue Entry array as well.
 */
int isbdm_reap_cqe(struct isbdm_cq *cq, struct ib_wc *wc)
{
	struct isbdm_cqe *cqe;
	unsigned long flags;

	spin_lock_irqsave(&cq->lock, flags);
	cqe = &cq->queue[cq->cq_get % cq->num_cqe];
	if (READ_ONCE(cqe->flags) & ISBDM_WQE_VALID) {
		memset(wc, 0, sizeof(*wc));
		wc->wr_id = cqe->id;
		wc->byte_len = cqe->bytes;
		wc->slid = cqe->src_lid;
		wc->src_qp = cqe->src_qp;

		/*
		 * During CQ flush, also user land CQE's may get reaped here,
		 * which do not hold a QP reference and do not qualify for
		 * memory extension verbs.
		 */
		if (likely(rdma_is_kernel_res(&cq->base_cq.res))) {
			if (cqe->flags & ISBDM_WQE_REM_INVAL) {
				wc->ex.invalidate_rkey = cqe->inval_stag;
				wc->wc_flags = IB_WC_WITH_INVALIDATE;
			}

			wc->qp = cqe->base_qp;
			wc->opcode = map_wc_opcode[cqe->opcode];
			wc->status = map_cqe_status[cqe->status];
			isbdm_dbg_cq(cq,
				     "idx %u, type %d, flags %2x, slid %x, "
				     "sqp %x, id 0x%pK\n",
				     cq->cq_get % cq->num_cqe, cqe->opcode,
				     cqe->flags, cqe->src_lid, cqe->src_qp,
				     (void *)(uintptr_t)cqe->id);
		} else {
			u8 opcode = cqe->opcode;
			u16 status = cqe->status;

			if (opcode >= ISBDM_NUM_OPCODES) {
				opcode = 0;
				status = ISBDM_WC_GENERAL_ERR;

			} else if (status >= ISBDM_NUM_WC_STATUS) {
				status = ISBDM_WC_GENERAL_ERR;
			}

			wc->opcode = map_wc_opcode[opcode];
			wc->status = map_cqe_status[status];

		}

		WRITE_ONCE(cqe->flags, 0);
		cq->cq_get++;
		spin_unlock_irqrestore(&cq->lock, flags);
		return 1;
	}

	spin_unlock_irqrestore(&cq->lock, flags);
	return 0;
}

/*
 * isbdm_cq_flush()
 *
 * Flush all Completion Queue elements.
 */
void isbdm_cq_flush(struct isbdm_cq *cq)
{
	struct ib_wc wc;

	while (isbdm_reap_cqe(cq, &wc))
		;
}

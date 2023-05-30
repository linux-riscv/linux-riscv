/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) */

/* Authors: Evan Green <evan@rivosinc.com> */
/* Copyright (c) 2023 Rivos Inc. */

#ifndef _ISBDM_ABI_H
#define _ISBDM_ABI_H

#include <linux/types.h>

#define ISBDM_NODE_DESC_COMMON "Rivos ISBDM"
#define ISBDM_ABI_VERSION 1
#define ISBDM_MAX_SGE 6
#define ISBDM_UOBJ_MAX_KEY 0x08FFFF
#define ISBDM_INVAL_UOBJ_KEY (ISBDM_UOBJ_MAX_KEY + 1)

struct isbdm_uresp_create_cq {
	__u32 cq_id;
	__u32 num_cqe;
	__aligned_u64 cq_key;
};

struct isbdm_uresp_create_qp {
	__u32 qp_id;
	__u32 num_sqe;
	__u32 num_rqe;
	__u32 pad;
	__aligned_u64 sq_key;
	__aligned_u64 rq_key;
};

struct isbdm_ureq_reg_mr {
	__u8 stag_key;
	__u8 reserved[3];
	__u32 pad;
};

struct isbdm_uresp_reg_mr {
	__u32 stag;
	__u32 pad;
};

struct isbdm_uresp_create_srq {
	__u32 num_rqe;
	__u32 pad;
	__aligned_u64 srq_key;
};

struct isbdm_uresp_alloc_ctx {
	__u32 dev_id;
	__u32 pad;
};

enum isbdm_opcode {
	ISBDM_OP_WRITE,
	ISBDM_OP_READ,
	ISBDM_OP_READ_LOCAL_INV,
	ISBDM_OP_SEND,
	ISBDM_OP_SEND_WITH_IMM,
	ISBDM_OP_SEND_REMOTE_INV,
	ISBDM_OP_FETCH_AND_ADD,
	ISBDM_OP_COMP_AND_SWAP,

	ISBDM_OP_RECEIVE,
	/*
	 * below opcodes valid for
	 * in-kernel clients only
	 */
	ISBDM_OP_INVAL_STAG,
	ISBDM_OP_REG_MR,
	ISBDM_NUM_OPCODES
};

/* Keep it same as ibv_sge to allow for memcpy */
struct isbdm_sge {
	__aligned_u64 laddr;
	__u32 length;
	__u32 lkey;
};

/*
 * Inline data are kept within the work request itself occupying
 * the space of sge[1] .. sge[n]. Therefore, inline data cannot be
 * supported if ISBDM_MAX_SGE is below 2 elements.
 */
#define ISBDM_MAX_INLINE (sizeof(struct isbdm_sge) * (ISBDM_MAX_SGE - 1))

#if ISBDM_MAX_SGE < 2
#error "ISBDM_MAX_SGE must be at least 2"
#endif

enum isbdm_wqe_flags {
	ISBDM_WQE_VALID = (1 << 0),
	ISBDM_WQE_INLINE = (1 << 1),
	ISBDM_WQE_SIGNALLED = (1 << 2),
	ISBDM_WQE_SOLICITED = (1 << 3),
	ISBDM_WQE_READ_FENCE = (1 << 4),
	ISBDM_WQE_REM_INVAL = (1 << 5),
	ISBDM_WQE_HAS_IMMEDIATE = (1 << 6),
	ISBDM_WQE_COMPLETED = (1 << 7)
};

/* Send Queue Element */
struct isbdm_sqe {
	__aligned_u64 id;
	__u16 flags;
	__u8 num_sge;
	/* Contains enum isbdm_opcode values */
	__u8 opcode;
	__u32 rkey;
	union {
		__u32 imm_data;
		__u32 invalidate_rkey;
	};
	union {
		__aligned_u64 raddr;
		__aligned_u64 base_mr;
		struct {
			__u32 remote_qpn;
			__u16 dlid;
		} ud;
	};
	union {
		struct isbdm_sge sge[ISBDM_MAX_SGE];
		__aligned_u64 access;
		struct {
			struct isbdm_sge sge;
			__aligned_u64 compare_add;
			__aligned_u64 exchange;
		} atomic;
	};
};

/* Receive Queue Element */
struct isbdm_rqe {
	__aligned_u64 id;
	__u16 flags;
	__u8 num_sge;
	/*
	 * only used by kernel driver,
	 * ignored if set by user
	 */
	__u8 opcode;
	__u32 unused;
	struct isbdm_sge sge[ISBDM_MAX_SGE];
};

enum isbdm_notify_flags {
	ISBDM_NOTIFY_NOT = (0),
	ISBDM_NOTIFY_SOLICITED = (1 << 0),
	ISBDM_NOTIFY_NEXT_COMPLETION = (1 << 1),
	ISBDM_NOTIFY_MISSED_EVENTS = (1 << 2),
	ISBDM_NOTIFY_ALL = ISBDM_NOTIFY_SOLICITED |
			   ISBDM_NOTIFY_NEXT_COMPLETION |
			   ISBDM_NOTIFY_MISSED_EVENTS
};

enum isbdm_wc_status {
	ISBDM_WC_SUCCESS,
	ISBDM_WC_LOC_PROT_ERR,
	ISBDM_WC_LOC_QP_OP_ERR,
	ISBDM_WC_WR_FLUSH_ERR,
	ISBDM_WC_LOC_ACCESS_ERR,
	ISBDM_WC_REM_ACCESS_ERR,
	ISBDM_WC_REM_INV_REQ_ERR,
	ISBDM_WC_GENERAL_ERR,
	ISBDM_NUM_WC_STATUS
};

struct isbdm_cqe {
	__aligned_u64 id;
	__u8 flags;
	__u8 opcode;
	__u16 status;
	__u32 bytes;
	union {
		__u32 imm_data;
		__u32 inval_stag;
	};
	/* QP number or QP pointer */
	union {
		struct ib_qp *base_qp;
		__aligned_u64 qp_id;
	};
	/* Source Queue Pair number */
	__u32 src_qp;
	/* Source local ID */
	__u16 src_lid;
};

/*
 * Shared structure between user and kernel
 * to control CQ arming.
 */
struct isbdm_cq_ctrl {
	__u32 flags;
	__u32 pad;
};

#endif

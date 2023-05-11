/* SPDX-License-Identifier: GPL-2.0 */

/* Authors: Evan Green <evan@rivosinc.com> */
/* Copyright (c) 2023, Rivos Inc. */

#ifndef _ISBDM_IB_H
#define _ISBDM_IB_H

#include <rdma/ib_verbs.h>
#include <linux/iommu.h>
#include <linux/workqueue.h>
// #include <rdma/restrack.h>
// #include <linux/socket.h>
// #include <linux/skbuff.h>
// #include <crypto/hash.h>
// #include <linux/crc32.h>
// #include <linux/crc32c.h>

#include <rdma/isbdm-abi.h>
// #include "iwarp.h"

#define ISBDM_VENDOR_ID 0x6f766952 /* ascii 'Rivo' */
// #define SIW_VENDORT_PART_ID 0
#define ISBDM_MAX_QP (1024 * 100)
#define ISBDM_MAX_QP_WR (1024 * 32)
#define ISBDM_MAX_ORD_QP 128
#define ISBDM_MAX_IRD_QP 128
/* ISBDM only supports a single address+size per memory region. */
#define ISBDM_MAX_SGE_PBL 1
#define ISBDM_MAX_SGE_RD 1 /* TODO: increase this?*/
#define ISBDM_MAX_CQ (1024 * 100)
#define ISBDM_MAX_CQE (ISBDM_MAX_QP_WR * 100)

/*
 * Define the maximum number of memory regions based on ISBDM_RDMA_RMBI_MASK,
 * the maximum remote memory buffer index. Clamp this to the max STag index.
 */
#define ISBDM_MAX_MR 0x00ffffff
#define ISBDM_MAX_PD ISBDM_MAX_QP
#define ISBDM_MAX_MW 0 /* to be set if MW's are supported */
#define ISBDM_MAX_SRQ ISBDM_MAX_QP
#define ISBDM_MAX_SRQ_WR (ISBDM_MAX_QP_WR * 10)
#define ISBDM_MAX_CONTEXT ISBDM_MAX_PD

// /* Min number of bytes for using zero copy transmit */
// #define SENDPAGE_THRESH PAGE_SIZE

// /* Maximum number of frames which can be send in one SQ processing */
// #define SQ_USER_MAXBURST 100

// /* Maximum number of consecutive IRQ elements which get served
//  * if SQ has pending work. Prevents starving local SQ processing
//  * by serving peer Read Requests.
//  */
// #define SIW_IRQ_MAXBURST_SQ_ACTIVE 4

struct isbdm_dev_cap {
	int max_qp;
	int max_qp_wr;
	int max_ord; /* max. outbound read queue depth */
	int max_ird; /* max. inbound read queue depth */
	int max_sge;
	int max_sge_rd;
	int max_cq;
	int max_cqe;
	int max_mr;
	int max_pd;
	int max_mw;
	int max_srq;
	int max_srq_wr;
	int max_srq_sge;
};

struct isbdm_pd {
	struct ib_pd base_pd;
	/* Context handle returned from calling iommu_sva_bind_device(). */
	struct iommu_sva *sva;
	/* PASID of the owning task. */
	uint64_t pasid;
	/* MM of the owning task, used for loopback RDMAs. */
	struct mm_struct *mm;
};

struct isbdm;
struct isbdm_device {
	struct ib_device base_dev;
	struct isbdm *ii;
// 	struct net_device *netdev;
	struct isbdm_dev_cap attrs;

	u32 vendor_part_id;
// 	int numa_node;

// 	/* physical port state (only one port per device) */
	enum ib_port_state state;

	spinlock_t lock;

	struct xarray qp_xa;
	struct xarray mem_xa;

	struct list_head cep_list;
	struct list_head qp_list;

	/* active objects statistics to enforce limits */
	atomic_t num_qp;
	atomic_t num_cq;
	atomic_t num_pd;
	atomic_t num_mr;
	atomic_t num_srq;
	atomic_t num_ctx;

// 	struct work_struct netdev_down;
	u16 lid;
	/* Lid mask control. */
	u8 lmc;
	/* Subnet Manager local ID */
	u16 sm_lid;
	u8 sm_sl;
	/* Port capability flags, not used by hardware. */
	u32 port_cap_flags;
};

struct isbdm_ucontext {
	struct ib_ucontext base_ucontext;
	struct isbdm_device *sdev;
};

// /*
//  * The RDMA core does not define LOCAL_READ access, which is always
//  * enabled implicitly.
//  */
// #define IWARP_ACCESS_MASK					\
// 	(IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE	|	\
// 	 IB_ACCESS_REMOTE_READ)

/*
 * siw presentation of user memory registered as source
 * or target of RDMA operations.
 */

struct isbdm_page_chunk {
	struct page **plist;
};

struct isbdm_umem {
	struct isbdm_page_chunk *page_chunk;
	int num_pages;
	bool writable;
	u64 fp_addr; /* First page base address */
	struct mm_struct *owning_mm;
};

struct isbdm_pble {
	dma_addr_t addr; /* Address of assigned buffer */
	unsigned int size; /* Size of this entry */
	unsigned long pbl_off; /* Total offset from start of PBL */
};

struct isbdm_pbl {
	unsigned int num_buf;
	unsigned int max_buf;
	struct isbdm_pble pbe[];
};

struct isbdm_ah {
	struct ib_ah base_ah;
	struct rdma_ah_attr attr;
};

/*
 * Generic memory representation for registered ISBDM memory.
 * Memory lookup always via higher 24 bit of STag (STag index).
 */
struct isbdm_mem {
	struct isbdm_device *sdev;
	struct kref ref;
	u64 va; /* VA of memory */
	u64 len; /* length of the memory buffer in bytes */
	u32 stag; /* IB memory access steering tag */
	u8 stag_valid; /* 1 if valid, 0 if invalid */
	u8 is_pbl; /* PBL or user space mem */
	u8 is_mw; /* Memory Region or Memory Window */
	enum ib_access_flags perms; /* local/remote READ & WRITE */
	union {
		struct isbdm_umem *umem;
		struct isbdm_pbl *pbl;
		void *mem_obj;
	};
	struct ib_pd *pd;
};

struct isbdm_mr {
	struct ib_mr base_mr;
	struct isbdm_mem *mem;
	struct rcu_head rcu;
};

/*
 * Error codes for local or remote
 * access to registered memory
 */
enum isbdm_access_status {
	E_ACCESS_OK,
	E_STAG_INVALID,
	E_BASE_BOUNDS,
	E_ACCESS_PERM,
	E_PD_MISMATCH
};

enum isbdm_wr_state {
	ISBDM_WR_IDLE,
	ISBDM_WR_QUEUED, /* processing has not started yet */
	ISBDM_WR_INPROGRESS /* initiated processing of the WR */
};

/* The WQE currently being processed (RX or TX) */
struct isbdm_wqe {
	/* Copy of applications SQE or RQE */
	union {
		struct isbdm_sqe sqe;
		struct isbdm_rqe rqe;
	};
	struct isbdm_mem *mem[ISBDM_MAX_SGE]; /* per sge's resolved mem */
	enum isbdm_wr_state wr_status;
	enum isbdm_wc_status wc_status;
	u32 bytes; /* total bytes to process */
	u32 processed; /* bytes processed */
};

struct isbdm_cq {
	struct ib_cq base_cq;
	spinlock_t lock;
	struct isbdm_cq_ctrl *notify;
	struct isbdm_cqe *queue;
	u32 cq_put;
	u32 cq_get;
	u32 num_cqe;
	struct rdma_user_mmap_entry *cq_entry; /* mmap info for CQE array */
	u32 id; /* For debugging only */
};

enum isbdm_qp_state {
	ISBDM_QP_STATE_IDLE,
	ISBDM_QP_STATE_RTR,
	ISBDM_QP_STATE_RTS,
	ISBDM_QP_STATE_CLOSING,
	ISBDM_QP_STATE_TERMINATE,
	ISBDM_QP_STATE_ERROR,
	ISBDM_QP_STATE_COUNT
};

enum isbdm_qp_flags {
	ISBDM_RDMA_BIND_ENABLED = (1 << 0),
	ISBDM_RDMA_WRITE_ENABLED = (1 << 1),
	ISBDM_RDMA_READ_ENABLED = (1 << 2),
	ISBDM_SIGNAL_ALL_WR = (1 << 3),
	ISBDM_MPA_CRC = (1 << 4),
	ISBDM_QP_IN_DESTROY = (1 << 5)
};

enum isbdm_qp_attr_mask {
	ISBDM_QP_ATTR_STATE = (1 << 0),
	ISBDM_QP_ATTR_ACCESS_FLAGS = (1 << 1),
	ISBDM_QP_ATTR_LLP_HANDLE = (1 << 2),
	ISBDM_QP_ATTR_ORD = (1 << 3),
	ISBDM_QP_ATTR_IRD = (1 << 4),
	ISBDM_QP_ATTR_SQ_SIZE = (1 << 5),
	ISBDM_QP_ATTR_RQ_SIZE = (1 << 6),
	ISBDM_QP_ATTR_MPA = (1 << 7),
	ISBDM_QP_ATTR_DEST_QP_NUM = (1 << 8),
	ISBDM_QP_ATTR_AV = (1 << 9),
};

struct isbdm_srq {
	struct ib_srq base_srq;
	spinlock_t lock;
	u32 max_sge;
	u32 limit; /* low watermark for async event */
	struct isbdm_rqe *recvq;
	u32 rq_put;
	u32 rq_get;
	u32 num_rqe; /* max # of wqe's allowed */
	struct rdma_user_mmap_entry *srq_entry; /* mmap info for SRQ array */
	bool armed:1; /* inform user if limit hit */
	bool is_kernel_res:1; /* true if kernel client */
};

struct isbdm_qp_attrs {
	enum isbdm_qp_state state;
	u32 sq_size;
	u32 rq_size;
	u32 orq_size;
	u32 irq_size;
	u32 sq_max_sges;
	u32 rq_max_sges;
	u32 dest_qp_num;
	enum isbdm_qp_flags flags;
	struct rdma_ah_attr ah_attr;

	//struct socket *sk;
};

// enum siw_tx_ctx {
// 	SIW_SEND_HDR, /* start or continue sending HDR */
// 	SIW_SEND_DATA, /* start or continue sending DDP payload */
// 	SIW_SEND_TRAILER, /* start or continue sending TRAILER */
// 	SIW_SEND_SHORT_FPDU/* send whole FPDU hdr|data|trailer at once */
// };

// enum siw_rx_state {
// 	SIW_GET_HDR, /* await new hdr or within hdr */
// 	SIW_GET_DATA_START, /* start of inbound DDP payload */
// 	SIW_GET_DATA_MORE, /* continuation of (misaligned) DDP payload */
// 	SIW_GET_TRAILER/* await new trailer or within trailer */
// };

// struct siw_rx_stream {
// 	struct sk_buff *skb;
// 	int skb_new; /* pending unread bytes in skb */
// 	int skb_offset; /* offset in skb */
// 	int skb_copied; /* processed bytes in skb */

// 	union iwarp_hdr hdr;
// 	struct mpa_trailer trailer;

// 	enum siw_rx_state state;

// 	/*
// 	 * For each FPDU, main RX loop runs through 3 stages:
// 	 * Receiving protocol headers, placing DDP payload and receiving
// 	 * trailer information (CRC + possibly padding).
// 	 * Next two variables keep state on receive status of the
// 	 * current FPDU part (hdr, data, trailer).
// 	 */
// 	int fpdu_part_rcvd; /* bytes in pkt part copied */
// 	int fpdu_part_rem; /* bytes in pkt part not seen */

// 	/*
// 	 * Next expected DDP MSN for each QN +
// 	 * expected steering tag +
// 	 * expected DDP tagget offset (all HBO)
// 	 */
// 	u32 ddp_msn[RDMAP_UNTAGGED_QN_COUNT];
// 	u32 ddp_stag;
// 	u64 ddp_to;
// 	u32 inval_stag; /* Stag to be invalidated */

// 	struct shash_desc *mpa_crc_hd;
// 	u8 rx_suspend : 1;
// 	u8 pad : 2; /* # of pad bytes expected */
// 	u8 rdmap_op : 4; /* opcode of current frame */
// };

/* Context associated with an active RX association. */
struct isbdm_rx {
	/*
	 * Local destination memory of inbound RDMA operation.
	 * Valid, according to wqe->wr_status
	 */
	struct isbdm_wqe wqe_active;

// 	unsigned int pbl_idx; /* Index into current PBL */
// 	unsigned int sge_idx; /* current sge in rx */
// 	unsigned int sge_off; /* already rcvd in curr. sge */

// 	char first_ddp_seg; /* this is the first DDP seg */
// 	char more_ddp_segs; /* more DDP segs expected */
// 	u8 prev_rdmap_op : 4; /* opcode of prev frame */
};

// /*
//  * Shorthands for short packets w/o payload
//  * to be transmitted more efficient.
//  */
// struct siw_send_pkt {
// 	struct iwarp_send send;
// 	__be32 crc;
// };

// struct siw_write_pkt {
// 	struct iwarp_rdma_write write;
// 	__be32 crc;
// };

// struct siw_rreq_pkt {
// 	struct iwarp_rdma_rreq rreq;
// 	__be32 crc;
// };

// struct siw_rresp_pkt {
// 	struct iwarp_rdma_rresp rresp;
// 	__be32 crc;
// };

/* Context associated with the active outgoing transmission. */
struct isbdm_tx {
// 	union {
// 		union iwarp_hdr hdr;

// 		/* Generic part of FPDU header */
// 		struct iwarp_ctrl ctrl;
// 		struct iwarp_ctrl_untagged c_untagged;
// 		struct iwarp_ctrl_tagged c_tagged;

// 		/* FPDU headers */
// 		struct iwarp_rdma_write rwrite;
// 		struct iwarp_rdma_rreq rreq;
// 		struct iwarp_rdma_rresp rresp;
// 		struct iwarp_terminate terminate;
// 		struct iwarp_send send;
// 		struct iwarp_send_inv send_inv;

// 		/* complete short FPDUs */
// 		struct siw_send_pkt send_pkt;
// 		struct siw_write_pkt write_pkt;
// 		struct siw_rreq_pkt rreq_pkt;
// 		struct siw_rresp_pkt rresp_pkt;
// 	} pkt;

// 	struct mpa_trailer trailer;
// 	/* DDP MSN for untagged messages */
// 	u32 ddp_msn[RDMAP_UNTAGGED_QN_COUNT];

// 	enum siw_tx_ctx state;
// 	u16 ctrl_len; /* ddp+rdmap hdr */
// 	u16 ctrl_sent;
// 	int burst;
// 	int bytes_unsent; /* ddp payload bytes */

// 	struct shash_desc *mpa_crc_hd;

// 	u8 do_crc : 1; /* do crc for segment */
// 	u8 use_sendpage : 1; /* send w/o copy */
// 	u8 tx_suspend : 1; /* stop sending DDP segs. */
// 	u8 pad : 2; /* # pad in current fpdu */
// 	u8 orq_fence : 1; /* ORQ full or Send fenced */
// 	u8 in_syscall : 1; /* TX out of user context */
// 	u8 zcopy_tx : 1; /* Use TCP_SENDPAGE if possible */
// 	u8 gso_seg_limit; /* Maximum segments for GSO, 0 = unbound */

// 	u16 fpdu_len; /* len of FPDU to tx */
// 	unsigned int tcp_seglen; /* remaining tcp seg space */

	struct isbdm_wqe wqe_active;

// 	int pbl_idx; /* Index into current PBL */
// 	int sge_idx; /* current sge in tx */
// 	u32 sge_off; /* already sent in curr. sge */
};

struct isbdm_qp {
	struct ib_qp base_qp;
	struct isbdm_device *sdev;
	struct kref ref;
	struct completion qp_free;
	struct list_head devq;
// 	int tx_cpu;
	struct isbdm_qp_attrs attrs;

// 	struct siw_cep *cep;
	struct rw_semaphore state_lock;

 	struct ib_pd *pd;
	struct isbdm_cq *scq;
	struct isbdm_cq *rcq;
	struct isbdm_srq *srq;

	struct isbdm_tx tx_ctx; /* Transmit context */
	spinlock_t sq_lock;
	struct isbdm_sqe *sendq; /* send queue element array */
	uint32_t sq_get; /* consumer index into sq array */
	uint32_t sq_put; /* kernel prod. index into sq array */
// 	struct llist_node tx_list;

	struct isbdm_sqe *orq; /* outbound read queue element array */
	spinlock_t orq_lock;
	uint32_t orq_get; /* consumer index into orq array */
	uint32_t orq_put; /* shared producer index for ORQ */

// 	struct siw_rx_stream rx_stream;
// 	struct siw_rx_fpdu *rx_fpdu;
	struct isbdm_rx rx_tagged;
	struct isbdm_rx rx_untagged;
	spinlock_t rq_lock;
	struct isbdm_rqe *recvq; /* recv queue element array */
	uint32_t rq_get; /* consumer index into rq array */
	uint32_t rq_put; /* kernel prod. index into rq array */

	struct isbdm_sqe *irq; /* inbound read queue element array */
	uint32_t irq_get; /* consumer index into irq array */
	uint32_t irq_put; /* producer index into irq array */
// 	int irq_burst;

// 	struct { /* information to be carried in TERMINATE pkt, if valid */
// 		u8 valid;
// 		u8 in_tx;
// 		u8 layer : 4, etype : 4;
// 		u8 ecode;
// 	} term_info;
	struct rdma_user_mmap_entry *sq_entry; /* mmap info for SQE array */
	struct rdma_user_mmap_entry *rq_entry; /* mmap info for RQE array */
// 	struct rcu_head rcu;

	struct rdma_ah_attr remote_ah_attr; /* Remote address handle info. */
	struct work_struct send_work;
};

// /* helper macros */
// #define rx_qp(rx) container_of(rx, struct siw_qp, rx_stream)
// #define tx_qp(tx) container_of(tx, struct siw_qp, tx_ctx)
#define tx_wqe(qp) (&(qp)->tx_ctx.wqe_active)
#define rx_wqe(rctx) (&(rctx)->wqe_active)
// #define rx_mem(rctx) ((rctx)->wqe_active.mem[0])
#define tx_type(wqe) ((wqe)->sqe.opcode)
#define rx_type(wqe) ((wqe)->rqe.opcode)
#define tx_flags(wqe) ((wqe)->sqe.flags)

// struct iwarp_msg_info {
// 	int hdr_len;
// 	struct iwarp_ctrl ctrl;
// 	int (*rx_data)(struct siw_qp *qp);
// };

struct isbdm_user_mmap_entry {
	struct rdma_user_mmap_entry rdma_entry;
	void *address;
};

// /* Global siw parameters. Currently set in siw_main.c */
// extern const bool zcopy_tx;
// extern const bool try_gso;
// extern const bool loopback_enabled;
// extern const bool mpa_crc_required;
// extern const bool mpa_crc_strict;
// extern const bool siw_tcp_nagle;
// extern u_char mpa_version;
// extern const bool peer_to_peer;
// extern struct task_struct *siw_tx_thread[];

// extern struct crypto_shash *siw_crypto_shash;
// extern struct iwarp_msg_info iwarp_pktinfo[RDMAP_TERMINATE + 1];

// /* QP general functions */
int isbdm_qp_modify(struct isbdm_qp *qp, struct isbdm_qp_attrs *attr,
		    enum isbdm_qp_attr_mask mask);
// int siw_qp_mpa_rts(struct siw_qp *qp, enum mpa_v2_ctrl ctrl);
// void siw_qp_llp_close(struct siw_qp *qp);
// void siw_qp_cm_drop(struct siw_qp *qp, int schedule);
// void siw_send_terminate(struct siw_qp *qp);

void isbdm_qp_get_ref(struct ib_qp *qp);
void isbdm_qp_put_ref(struct ib_qp *qp);
int isbdm_qp_add(struct isbdm_device *sdev, struct isbdm_qp *qp);
void isbdm_free_qp(struct kref *ref);

// void siw_init_terminate(struct siw_qp *qp, enum term_elayer layer,
// 			u8 etype, u8 ecode, int in_tx);
// enum ddp_ecode siw_tagged_error(enum siw_access_state state);
// enum rdmap_ecode siw_rdmap_error(enum siw_access_state state);

// void siw_read_to_orq(struct siw_sqe *rreq, struct siw_sqe *sqe);
int isbdm_sqe_complete(struct isbdm_qp *qp, struct isbdm_sqe *sqe, u32 bytes,
		       enum isbdm_wc_status status);
int isbdm_rqe_complete(struct isbdm_qp *qp, struct isbdm_rqe *rqe, u32 bytes,
		       u32 inval_stag, u16 src_lid, u32 src_qp,
		       enum isbdm_wc_status status);
// void siw_qp_llp_data_ready(struct sock *sk);
// void siw_qp_llp_write_space(struct sock *sk);

// /* QP TX path functions */
// int siw_run_sq(void *arg);
// int siw_qp_sq_process(struct siw_qp *qp);
// int siw_sq_start(struct siw_qp *qp);
// int siw_activate_tx(struct siw_qp *qp);
// void siw_stop_tx_thread(int nr_cpu);
// int siw_get_tx_cpu(struct siw_device *sdev);
// void siw_put_tx_cpu(int cpu);

// /* QP RX path functions */
// int siw_proc_send(struct siw_qp *qp);
// int siw_proc_rreq(struct siw_qp *qp);
// int siw_proc_rresp(struct siw_qp *qp);
// int siw_proc_write(struct siw_qp *qp);
// int siw_proc_terminate(struct siw_qp *qp);

// int siw_tcp_rx_data(read_descriptor_t *rd_desc, struct sk_buff *skb,
// 		    unsigned int off, size_t len);

// static inline void set_rx_fpdu_context(struct siw_qp *qp, u8 opcode)
// {
// 	if (opcode == RDMAP_RDMA_WRITE || opcode == RDMAP_RDMA_READ_RESP)
// 		qp->rx_fpdu = &qp->rx_tagged;
// 	else
// 		qp->rx_fpdu = &qp->rx_untagged;

// 	qp->rx_stream.rdmap_op = opcode;
// }

static inline struct isbdm_ah *to_isbdm_ah(struct ib_ah *base_ah)
{
	return container_of(base_ah, struct isbdm_ah, base_ah);
}

static inline struct isbdm_ucontext *to_isbdm_ctx(struct ib_ucontext *base_ctx)
{
	return container_of(base_ctx, struct isbdm_ucontext, base_ucontext);
}

static inline struct isbdm_pd *to_isbdm_pd(struct ib_pd *base_pd)
{
	return container_of(base_pd, struct isbdm_pd, base_pd);
}

static inline struct isbdm_qp *to_isbdm_qp(struct ib_qp *base_qp)
{
	return container_of(base_qp, struct isbdm_qp, base_qp);
}

static inline struct isbdm_cq *to_isbdm_cq(struct ib_cq *base_cq)
{
	return container_of(base_cq, struct isbdm_cq, base_cq);
}

static inline struct isbdm_srq *to_isbdm_srq(struct ib_srq *base_srq)
{
	return container_of(base_srq, struct isbdm_srq, base_srq);
}

static inline struct isbdm_device *to_isbdm_dev(struct ib_device *base_dev)
{
	return container_of(base_dev, struct isbdm_device, base_dev);
}

static inline struct isbdm_mr *to_isbdm_mr(struct ib_mr *base_mr)
{
	return container_of(base_mr, struct isbdm_mr, base_mr);
}

static inline struct isbdm_user_mmap_entry *
to_isbdm_mmap_entry(struct rdma_user_mmap_entry *rdma_mmap)
{
	return container_of(rdma_mmap, struct isbdm_user_mmap_entry,
			    rdma_entry);
}

static inline struct isbdm_qp *isbdm_qp_id2obj(struct isbdm_device *sdev, int id)
{
	struct isbdm_qp *qp;

	rcu_read_lock();
	qp = xa_load(&sdev->qp_xa, id);
	if (likely(qp && kref_get_unless_zero(&qp->ref))) {
		rcu_read_unlock();
		return qp;
	}
	rcu_read_unlock();
	return NULL;
}

static inline u32 qp_id(struct isbdm_qp *qp)
{
	return qp->base_qp.qp_num;
}

static inline void isbdm_qp_get(struct isbdm_qp *qp)
{
	kref_get(&qp->ref);
}

static inline void isbdm_qp_put(struct isbdm_qp *qp)
{
	kref_put(&qp->ref, isbdm_free_qp);
}

// static inline int siw_sq_empty(struct siw_qp *qp)
// {
// 	struct siw_sqe *sqe = &qp->sendq[qp->sq_get % qp->attrs.sq_size];

// 	return READ_ONCE(sqe->flags) == 0;
// }

static inline struct isbdm_sqe *sq_get_next(struct isbdm_qp *qp)
{
	struct isbdm_sqe *sqe = &qp->sendq[qp->sq_get % qp->attrs.sq_size];

	if (READ_ONCE(sqe->flags) & ISBDM_WQE_VALID)
		return sqe;

	return NULL;
}

// static inline struct siw_sqe *orq_get_current(struct siw_qp *qp)
// {
// 	return &qp->orq[qp->orq_get % qp->attrs.orq_size];
// }

// static inline struct siw_sqe *orq_get_free(struct siw_qp *qp)
// {
// 	struct siw_sqe *orq_e = &qp->orq[qp->orq_put % qp->attrs.orq_size];

// 	if (READ_ONCE(orq_e->flags) == 0)
// 		return orq_e;

// 	return NULL;
// }

// static inline int siw_orq_empty(struct siw_qp *qp)
// {
// 	return qp->orq[qp->orq_get % qp->attrs.orq_size].flags == 0 ? 1 : 0;
// }

// static inline struct siw_sqe *irq_alloc_free(struct siw_qp *qp)
// {
// 	struct siw_sqe *irq_e = &qp->irq[qp->irq_put % qp->attrs.irq_size];

// 	if (READ_ONCE(irq_e->flags) == 0) {
// 		qp->irq_put++;
// 		return irq_e;
// 	}
// 	return NULL;
// }

// static inline __wsum siw_csum_update(const void *buff, int len, __wsum sum)
// {
// 	return (__force __wsum)crc32c((__force __u32)sum, buff, len);
// }

// static inline __wsum siw_csum_combine(__wsum csum, __wsum csum2, int offset,
// 				      int len)
// {
// 	return (__force __wsum)__crc32c_le_combine((__force __u32)csum,
// 						   (__force __u32)csum2, len);
// }

// static inline void siw_crc_skb(struct siw_rx_stream *srx, unsigned int len)
// {
// 	const struct skb_checksum_ops siw_cs_ops = {
// 		.update = siw_csum_update,
// 		.combine = siw_csum_combine,
// 	};
// 	__wsum crc = *(u32 *)shash_desc_ctx(srx->mpa_crc_hd);

// 	crc = __skb_checksum(srx->skb, srx->skb_offset, len, crc,
// 			     &siw_cs_ops);
// 	*(u32 *)shash_desc_ctx(srx->mpa_crc_hd) = crc;
// }

/* Convert from an STag index to a Remote Memory Buffer index. Avoid STag 0. */
#define isbdm_stag_to_rmbi(value) ((value >> 8) - 1)
#define isbdm_rmbi_to_stag(value) ((value + 1) << 8)

/* TODO: Flip these back to ibdev_dbg(). */
#define isbdm_dbg(ibdev, fmt, ...)                                             \
	ibdev_dbg(ibdev, "%s: " fmt, __func__, ##__VA_ARGS__)

#define isbdm_dbg_qp(qp, fmt, ...)                                             \
	ibdev_dbg(&qp->sdev->base_dev, "QP[%u] %s: " fmt, qp_id(qp), __func__, \
		  ##__VA_ARGS__)

#define isbdm_dbg_cq(cq, fmt, ...)                                             \
	ibdev_dbg(cq->base_cq.device, "CQ[%u] %s: " fmt, cq->id, __func__,     \
		  ##__VA_ARGS__)

#define isbdm_dbg_pd(pd, fmt, ...)                                             \
	ibdev_dbg(pd->device, "PD[%u] %s: " fmt, pd->res.id, __func__,         \
		  ##__VA_ARGS__)

#define isbdm_dbg_mem(mem, fmt, ...)                                           \
	ibdev_dbg(&mem->sdev->base_dev,                                        \
		  "MEM[0x%08x] %s: " fmt, mem->stag, __func__, ##__VA_ARGS__)

void isbdm_cq_flush(struct isbdm_cq *cq);
void isbdm_sq_flush(struct isbdm_qp *qp);
void isbdm_rq_flush(struct isbdm_qp *qp);
int isbdm_reap_cqe(struct isbdm_cq *cq, struct ib_wc *wc);

int isbdm_create_local_mb(struct isbdm_mr *mr);
int isbdm_process_send_qp(struct isbdm_qp *qp);

void isbdm_port_status_change(struct isbdm *ii);
struct isbdm_device *isbdm_device_create(struct isbdm *ii);

#endif

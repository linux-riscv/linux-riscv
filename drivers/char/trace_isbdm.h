/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2023, Rivos, Inc.
 */

#if !defined(__TRACE_ISBDM_H) || defined(TRACE_HEADER_MULTI_READ)
#define __TRACE_ISBDM_H

#include <linux/tracepoint.h>
#include <linux/trace_seq.h>

#include "isbdmex.h"

#undef TRACE_SYSTEM
#define TRACE_SYSTEM isbdm

#define ISBDM_DEV_ENTRY(ii) __string(dev, dev_name(&(ii)->pdev->dev))
#define ISBDM_DEV_ASSIGN(ii) __assign_str(dev, dev_name(&(ii)->pdev->dev))

/* Template for printing a TX or RX descriptor. */
DECLARE_EVENT_CLASS(
	isbdm_desc_template,
	TP_PROTO(struct isbdm *ii, u32 idx, dma_addr_t iova, u32 length, u32 flags),
	TP_ARGS(ii, idx, iova, length, flags),
	TP_STRUCT__entry(ISBDM_DEV_ENTRY(ii)
			 __field(int, idx)
			 __field(dma_addr_t, iova)
			 __field(u32, length)
			 __field(u32, flags)
			 ),
	TP_fast_assign(ISBDM_DEV_ASSIGN(ii);
		       __entry->idx = idx;
		       __entry->iova = iova;
		       __entry->length = length;
		       __entry->flags = flags;
		       ),
	TP_printk("[%s] %x %llx %x %x", __get_str(dev), __entry->idx,
		  (unsigned long long)__entry->iova, __entry->length,
		  __entry->flags)
);

/* Event fired when a new TX descriptor is written to the hardware ring. */
DEFINE_EVENT(
	isbdm_desc_template, isbdm_tx_enqueue,
	TP_PROTO(struct isbdm *ii, u32 idx, dma_addr_t iova, u32 length, u32 flags),
	TP_ARGS(ii, idx, iova, length, flags));

/* Event fired when an RX descriptor is read off of the hardware ring. */
DEFINE_EVENT(
	isbdm_desc_template, isbdm_rx_dequeue,
	TP_PROTO(struct isbdm *ii, u32 idx, dma_addr_t iova, u32 length, u32 flags),
	TP_ARGS(ii, idx, iova, length, flags));

/* Event fired when the RX ring is refilled with fresh buffers. */
TRACE_EVENT(isbdm_rx_refill,
	    TP_PROTO(struct isbdm *ii, u32 count, u32 tail),
	    TP_ARGS(ii, count, tail),
	    TP_STRUCT__entry(ISBDM_DEV_ENTRY(ii)
			     __field(u32, count)
			     __field(u32, tail)
			     ),
	    TP_fast_assign(ISBDM_DEV_ASSIGN(ii);
			   __entry->count = count;
			   __entry->tail = tail;
			   ),
	    TP_printk("[%s] %d %x", __get_str(dev),
		      __entry->count, __entry->tail)
);

/* Event fired when an RDMA command is written to the hardware ring. */
TRACE_EVENT(isbdm_cmd_enqueue,
	    TP_PROTO(struct isbdm *ii, u32 idx, struct isbdm_rdma_command *cmd),
	    TP_ARGS(ii, idx, cmd),
	    TP_STRUCT__entry(ISBDM_DEV_ENTRY(ii)
			     __field(u32, idx)
			     __field(u8, cmd)
			     __field(u64, size)
			     __field(dma_addr_t, iova)
			     __field(u32, pasid)
			     __field(u32, flags)
			     __field(u64, rmbi)
			     __field(u64, riova)
			     ),
	    TP_fast_assign(ISBDM_DEV_ASSIGN(ii);
			   __entry->idx = idx;
			   __entry->cmd =
				(le64_to_cpu(cmd->rmbi_command) >>
				 ISBDM_RDMA_COMMAND_SHIFT) &
				 ISBDM_RDMA_COMMAND_MASK;
			   __entry->size = le64_to_cpu(cmd->size_pasid_flags) &
					   ISBDM_RDMA_SIZE_MASK;
			   __entry->iova = le64_to_cpu(cmd->iova);
			   __entry->pasid =
				(le64_to_cpu(cmd->size_pasid_flags) >>
				 ISBDM_RDMA_PASID_SHIFT) &
				 ISBDM_RDMA_PASID_MASK;
			   __entry->flags = __isbdm_cmd_flags(cmd);
			   __entry->rmbi = le64_to_cpu(cmd->rmbi_command) &
					   ISBDM_RDMA_RMBI_MASK;
			   __entry->riova = le64_to_cpu(cmd->riova);
			   ),
	    TP_printk("[%s] %x %x %llx %llx %x %x %llx %llx", __get_str(dev),
		      __entry->idx, __entry->cmd, __entry->size,
		      (unsigned long long)__entry->iova, __entry->pasid,
		      __entry->flags, (unsigned long long)__entry->rmbi,
		      (unsigned long long)__entry->riova)
);

/* Template for when a TX or CMD tail is updated. */
DECLARE_EVENT_CLASS(
	isbdm_tail_template,
	TP_PROTO(struct isbdm *ii, u32 tail),
	TP_ARGS(ii, tail),
	TP_STRUCT__entry(ISBDM_DEV_ENTRY(ii)
			 __field(u32, tail)
			 ),
	TP_fast_assign(ISBDM_DEV_ASSIGN(ii);
		       __entry->tail = tail;
		       ),
	TP_printk("[%s] %x", __get_str(dev), __entry->tail)
);

/*
 * Event fired when the TX tail pointer is adjusted, making new entries visible
 * to hardware.
 */
DEFINE_EVENT(isbdm_tail_template, isbdm_tx_tail,
	     TP_PROTO(struct isbdm *ii, u32 tail),
	     TP_ARGS(ii, tail));

/*
 * Event fired when the command tail pointer is written, making new entries
 * visible to hardware.
 */
DEFINE_EVENT(isbdm_tail_template, isbdm_cmd_tail,
	     TP_PROTO(struct isbdm *ii, u32 tail),
	     TP_ARGS(ii, tail));

/* Event fired when a Remote Memory Buffer is allocated. */
TRACE_EVENT(isbdm_rmb_alloc,
	    TP_PROTO(struct isbdm *ii, u32 idx,
		     struct isbdm_remote_buffer *rmb),
	    TP_ARGS(ii, idx, rmb),
	    TP_STRUCT__entry(ISBDM_DEV_ENTRY(ii)
			     __field(u64, iova)
			     __field(u32, pasid)
			     __field(u64, size)
			     __field(u32, flags)
			     ),
	    TP_fast_assign(ISBDM_DEV_ASSIGN(ii);
			   __entry->iova = le64_to_cpu(rmb->iova);
			   __entry->pasid = le64_to_cpu(rmb->pasid_flags) &
					    ISBDM_REMOTE_BUF_PASID_MASK;
			   __entry->size = le64_to_cpu(rmb->size) &
					   ISBDM_REMOTE_BUF_SIZE_MASK;
			   __entry->flags = __isbdm_rmb_flags(rmb);
			   ),
	    TP_printk("[%s] %llx %x %llx %x", __get_str(dev),
		      (unsigned long long)__entry->iova, __entry->pasid,
		      (unsigned long long)__entry->size, __entry->flags)
);

/* Event fired when an RMB entry is released. */
TRACE_EVENT(isbdm_rmb_free,
	    TP_PROTO(struct isbdm *ii, u32 idx),
	    TP_ARGS(ii, idx),
	    TP_STRUCT__entry(ISBDM_DEV_ENTRY(ii)
			     __field(u32, idx)
			     ),
	    TP_fast_assign(ISBDM_DEV_ASSIGN(ii);
			   __entry->idx = idx;
			   ),
	    TP_printk("[%s] %x", __get_str(dev),
		      __entry->idx)
);

/* Event fired when connection status changes. */
TRACE_EVENT(isbdm_link_status,
	    TP_PROTO(struct isbdm *ii, u8 state),
	    TP_ARGS(ii, state),
	    TP_STRUCT__entry(ISBDM_DEV_ENTRY(ii)
			     __field(u8, state)
			     ),
	    TP_fast_assign(ISBDM_DEV_ASSIGN(ii);
			   __entry->state = state;
			   ),
	    TP_printk("[%s] %x", __get_str(dev),
		      __entry->state)
);

#ifndef __TRACE_ISBDM_HELPER_FUNCTIONS
#define __TRACE_ISBDM_HELPER_FUNCTIONS

/*
 * Combine the flags from size_pasid_flags and rmbi_command into a single 32-bit
 * value, for efficient storage.
 */
static inline u32 __isbdm_cmd_flags(struct isbdm_rdma_command *cmd)
{
	u32 flags0;
	u32 flags1;

	/*
	 * The layout should look like: pv pp nv li at the high end, and ro nch
	 * rdma_gap at the low end.
	 */

	flags0 =  (le64_to_cpu(cmd->size_pasid_flags) &
		   (ISBDM_RDMA_PV | ISBDM_RDMA_PP | ISBDM_RDMA_NV |
		    ISBDM_RDMA_LI)) >> 32;

	flags1 = (le64_to_cpu(cmd->rmbi_command) &
		  ((ISBDM_RDMA_GAP_MASK << ISBDM_RDMA_GAP_SHIFT) |
		   ISBDM_RDMA_NCH | ISBDM_RDMA_RO)) >> ISBDM_RDMA_GAP_SHIFT;

	return flags0 | flags1;
}

/*
 * Combine the flags from pasid_flags and size into a single 32-bit value, for
 * efficient storage.
 */
static inline u32 __isbdm_rmb_flags(struct isbdm_remote_buffer *rmb)
{
	u32 flags0;
	u32 flags1;
	u64 pasid_flags;

	/*
	 * Keep pv and pp at the top, shift rdma_gap and nch down, and then add
	 * W on its own.
	 */
	pasid_flags = le64_to_cpu(rmb->pasid_flags);
	flags0 = pasid_flags & (ISBDM_REMOTE_BUF_PP | ISBDM_REMOTE_BUF_PV);
	if (pasid_flags & ISBDM_REMOTE_BUF_W)
		flags0 |= BIT(29);

	flags1 = (le64_to_cpu(rmb->size) &
		 ((ISBDM_REMOTE_BUF_RDMA_GAP_MASK <<
		   ISBDM_REMOTE_BUF_RDMA_GAP_SHIFT) | ISBDM_REMOTE_BUF_NCH)) >>
		 ISBDM_REMOTE_BUF_RDMA_GAP_SHIFT;

	return flags0 | flags1;
}

#endif

#endif /* __TRACE_ISBDM_H */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH ../../drivers/char
#define TRACE_INCLUDE_FILE trace_isbdm
#include <trace/define_trace.h>

// SPDX-License-Identifier: GPL-2.0

/* Authors: Evan Green <evan@rivosinc.com> */
/* Copyright (c) 2023 Rivos Inc. */

#include <linux/types.h>
#include <linux/pci.h>

#include "isbdmex.h"
#include "isbdm_verbs.h"
#include "isbdm_mem.h"

/* Create a new entry in the hardware's RMB array. */
int isbdm_create_local_mb(struct isbdm_mr *mr)
{
	struct isbdm_device *sdev = to_isbdm_dev(mr->mem->pd->device);
	struct isbdm_remote_buffer rmb;
	u64 pasid_flags = 0;
	int rv;

	memset(&rmb, 0, sizeof(rmb));
	rmb.iova = cpu_to_le64(mr->mem->va);

	/*
	 * If there's no remote access, allocate a slot to get the index but set
	 * the size to zero.
	 */
	if ((mr->mem->perms &
	    (IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE |
	     IB_ACCESS_REMOTE_ATOMIC)) == 0) {

		rmb.size = cpu_to_le64(0);

	} else {
		rmb.size = cpu_to_le64(mr->mem->len);
	}

	rmb.sw_avail = cpu_to_le64((unsigned long)mr);
	/* This is a usermode address if mem_obj is non-NULL. */
	if (mr->mem->mem_obj != NULL) {
		struct task_struct *task = get_current();
		uint64_t pasid = task->mm->pasid;

		if (pasid == IOMMU_PASID_INVALID) {
			dev_err(&sdev->ii->pdev->dev,
				"Current process doesn't have PASID\n");

			return -EAGAIN;
		}

		if (pasid > ISBDM_REMOTE_BUF_PASID_MASK) {
			dev_err(&sdev->ii->pdev->dev, "PASID out of range\n");
			return -ERANGE;
		}

		pasid_flags = ISBDM_REMOTE_BUF_PV | pasid;

	/* This is a kernel VA otherwise. */
	} else if (rmb.size) {
		/* TODO: Handle kernel VAs. */
		dev_err(&sdev->ii->pdev->dev,
			"Kernel VAs not yet implemented\n");

		return -EINVAL;
	}

	if (mr->mem->perms &
	    (IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_ATOMIC)) {

		pasid_flags |= ISBDM_REMOTE_BUF_W;
	}

	rmb.pasid_flags = cpu_to_le64(pasid_flags);
	rv = isbdm_alloc_rmb(sdev->ii, &rmb);
	if (rv < 0)
		return rv;

	/*
	 * The RMB index needs to fit in the 24-bit STag index, otherwise it
	 * won't transmit correctly throughout the IB subsystem.
	 */
	if (rv >= 0x00ffffff) {
		dev_err(&sdev->ii->pdev->dev, "RMB index %x too high\n", rv);
		isbdm_free_rmb(sdev->ii, rv);
		return -ENOSPC;
	}

	mr->mem->stag = isbdm_rmbi_to_stag(rv);

	/*
	 * Default the security key to be the STag. Usermode adds their own 8
	 * bits to the key later.
	 */
	isbdm_set_rmb_key(sdev->ii, rv, mr->mem->stag);
	return 0;
}

// Fill out a WQE for the next item to send. Returns -ENOENT if there are no
// more entries.
static int isbdm_activate_tx_from_sq(struct isbdm_qp *qp, struct isbdm_wqe *wqe)
{
	struct isbdm_sqe *sqe;
	int rv = 1;

	if (unlikely(qp->tx_ctx.tx_halted)) {
		isbdm_dbg_qp(qp, "QP halted\n");
		return -ENOTCONN;
	}

	sqe = sq_get_next(qp);
	if (!sqe)
		return -ENOENT;

	memset(wqe->mem, 0, sizeof(*wqe->mem) * ISBDM_MAX_SGE);
	wqe->wc_status = ISBDM_WC_SUCCESS;
	wqe->processed = 0;

	/* First copy SQE to kernel private memory */
	memcpy(&wqe->sqe, sqe, sizeof(*sqe));
	if (wqe->sqe.opcode >= ISBDM_NUM_OPCODES) {
		rv = -EINVAL;
		goto out;
	}

	if (wqe->sqe.flags & ISBDM_WQE_INLINE) {
		if (wqe->sqe.opcode != ISBDM_OP_SEND &&
		    wqe->sqe.opcode != ISBDM_OP_WRITE) {
			rv = -EINVAL;
			goto out;
		}

		if (wqe->sqe.sge[0].length > ISBDM_MAX_INLINE) {
			rv = -EINVAL;
			goto out;
		}

		wqe->sqe.sge[0].laddr = (uintptr_t)&wqe->sqe.sge[1];
		wqe->sqe.sge[0].lkey = 0;
		wqe->sqe.num_sge = 1;
	}

	if (wqe->sqe.flags & ISBDM_WQE_READ_FENCE) {
		/* A READ cannot be fenced */
		if (unlikely(wqe->sqe.opcode == ISBDM_OP_READ ||
			     wqe->sqe.opcode == ISBDM_OP_READ_LOCAL_INV)) {

			isbdm_dbg_qp(qp, "cannot fence read\n");
			rv = -EINVAL;
			goto out;
		}

		// spin_lock(&qp->orq_lock);
		// if (qp->attrs.orq_size && !isbdm_orq_empty(qp)) {
		// 	qp->tx_ctx.orq_fence = 1;
		// 	rv = 0;
		// }

		// spin_unlock(&qp->orq_lock);

	} else if (wqe->sqe.opcode == ISBDM_OP_READ ||
		   wqe->sqe.opcode == ISBDM_OP_READ_LOCAL_INV) {
		/* TODO: Figure out what to do about reads. */
		// struct isbdm_sqe *rreq;

		// if (unlikely(!qp->attrs.orq_size)) {
		// 	/* We negotiated not to send READ req's */
		// 	rv = -EINVAL;
		// 	goto out;
		// }

		// wqe->sqe.num_sge = 1;
		// spin_lock(&qp->orq_lock);
		// rreq = orq_get_free(qp);
		// if (rreq) {
		// 	/*
		// 	 * Make an immediate copy in ORQ to be ready
		// 	 * to process loopback READ reply
		// 	 */
		// 	siw_read_to_orq(rreq, &wqe->sqe);
		// 	qp->orq_put++;
		// } else {
		// 	qp->tx_ctx.orq_fence = 1;
		// 	rv = 0;
		// }

		// spin_unlock(&qp->orq_lock);
	}

	/* Clear SQE, can be re-used by application */
	smp_store_mb(sqe->flags, 0);
	qp->sq_get++;

out:
	if (unlikely(rv < 0)) {
		isbdm_dbg_qp(qp, "error %d\n", rv);
	}

	return rv;
}

static struct isbdm_packet_header *
isbdm_fill_packet_header(struct isbdm_buf *buf, u8 type, u8 flags,
			 u16 src_lid, u32 src_qp, u32 dest_qp, u32 imm_or_rkey)
{
	struct isbdm_packet_header *hdr = buf->buf + buf->size;

	if (WARN_ON(buf->size + sizeof(*hdr) > buf->capacity)) {
		return NULL;
	}

	hdr->magic = cpu_to_le16(ISBDM_PACKET_MAGIC);
	hdr->type = type;
	hdr->flags = flags;
	hdr->src_lid = cpu_to_le16(src_lid);
	hdr->src_qp = cpu_to_le32(src_qp);
	hdr->dest_qp = cpu_to_le32(dest_qp);
	hdr->imm_data = cpu_to_le32(imm_or_rkey);
	buf->size += sizeof(*hdr);
	return hdr;
}

/*
 * Turn a direct write() from usermode into a set of buffers, and enqueue it
 * onto the hardware or a software waiting list.
 */
ssize_t isbdmex_raw_send(struct isbdm *ii, const void __user *va, size_t size)
{
	struct isbdm_buf *buf, *tmp;
	LIST_HEAD(local_list);
	int not_done;
	ssize_t rc;
	size_t remaining = size;
	size_t this_size;

	mutex_lock(&ii->tx_ring.lock);
	if (ii->link_status == ISBDM_LINK_DOWN) {
		rc = -ENOTCONN;
		goto out;
	}

	/* The first iteration has a header on it. */
	buf = get_buf(ii, &ii->tx_ring);
	if (!buf) {
		rc = -ENOMEM;
		goto out;
	}

	buf->flags = ISBDM_DESC_FS;
	isbdm_fill_packet_header(buf, ISBDM_PACKET_RAW, 0, 0, 0, 0, 0);

	/* Loop creating packets and queueing them on to our local list. */
	while (remaining != 0) {
		if (!buf) {
			buf = get_buf(ii, &ii->tx_ring);
			if (!buf) {
				rc = -ENOMEM;
				goto out;
			}

			buf->flags = 0;
		}

		this_size = remaining;
		if (this_size > (buf->capacity - buf->size)) {
			this_size = buf->capacity - buf->size;
		}

		WARN_ON_ONCE(buf->size + this_size > ISBDM_DESC_SIZE_MAX);

		not_done = copy_from_user(buf->buf + buf->size, va, this_size);
		if (not_done != 0) {
			rc = -EFAULT;
			goto out;
		}

		va += this_size;
		remaining -= this_size;
		buf->size += this_size;
		if (remaining == 0) {
			buf->flags |= ISBDM_DESC_LS;
		}

		list_add_tail(&buf->node, &local_list);
		buf = NULL;
	}

	/*
	 * Now that all the buffers are set up, enqueue them onto the waitlist,
	 * then stick as many as possible into the hardware.
	 */
	list_splice_tail_init(&local_list, &ii->tx_ring.wait_list);
	isbdm_tx_enqueue(ii);
	rc = size;

out:
	/* On failure, clean up any buffers on the local list. */
	list_for_each_entry_safe(buf, tmp, &local_list, node) {
		put_buf(ii, &ii->tx_ring, buf);
	}

	mutex_unlock(&ii->tx_ring.lock);
	return rc;
}

static bool is_loopback_packet(struct isbdm_qp *qp, struct isbdm_wqe *wqe)
{
	struct isbdm_device *sdev = to_isbdm_dev(qp->pd->device);

	if ((qp->base_qp.qp_type == IB_QPT_RC ||
	     qp->base_qp.qp_type == IB_QPT_UC) &&
	    (rdma_ah_get_dlid(&qp->remote_ah_attr) &
	     ~((1 << sdev->lmc) - 1)) == sdev->lid)
		return true;


	if ((qp->base_qp.qp_type == IB_QPT_UD) &&
	    ((wqe->sqe.ud.dlid & ~((1 << sdev->lmc) - 1)) == sdev->lid))
		return true;

	return false;
}

static void isbdm_process_ib_recv(struct isbdm *ii,
				  struct isbdm_packet_header *hdr,
				  struct list_head *packet_list,
				  bool is_loopback);

static int isbdm_do_send(struct isbdm_qp *qp, struct isbdm_wqe *wqe)
{
	bool is_loopback = is_loopback_packet(qp, wqe);
	struct isbdm_packet_header *hdr;
	u8 hdr_flags = 0;
	u8 hdr_type;
	struct isbdm_buf *buf, *tmp;
	void *dst;
	u32 dest_qp;
	struct isbdm *ii = qp->sdev->ii;
	u32 imm_or_rkey = 0;
	LIST_HEAD(local_list);
	struct isbdm_sge *sge;
	int mem_idx = 0;
	size_t mem_off = 0;
	int rc;

	/*
	 * The SGE indexing and FS flags are wrong if some bytes are already
	 * processed.
	 */
	WARN_ON_ONCE(wqe->processed || !wqe->bytes);

	mutex_lock(&ii->tx_ring.lock);

	/* Fill out a header. */
	buf = get_buf(ii, &ii->tx_ring);
	if (!buf) {
		rc = -ENOMEM;
		goto out;
	}

	buf->flags = ISBDM_DESC_FS;
	list_add_tail(&buf->node, &local_list);
	if ((qp->base_qp.qp_type == IB_QPT_UD) ||
	    (qp->base_qp.qp_type == IB_QPT_GSI)) {

		dest_qp = wqe->sqe.ud.remote_qpn;

	} else {
		dest_qp = qp->attrs.dest_qp_num;
	}

	if (tx_flags(wqe) & ISBDM_WQE_SOLICITED)
		hdr_flags |= ISBDM_PACKET_FLAG_SOLICITED;

	dev_dbg(&ii->pdev->dev,
		"Send %s%slength 0x%x to QP%d->%d\n",
		(hdr_flags & ISBDM_PACKET_FLAG_SOLICITED) ? "solicited " : "",
		is_loopback ? "loopback " : "",
		wqe->bytes,
		qp->base_qp.qp_num,
		dest_qp);

	switch (tx_type(wqe)) {
	case ISBDM_OP_SEND:
		hdr_type = ISBDM_PACKET_IB_SEND;
		break;

	case ISBDM_OP_SEND_REMOTE_INV:
		hdr_type = ISBDM_PACKET_IB_SEND_INVALIDATE;
		imm_or_rkey = cpu_to_le32(wqe->sqe.invalidate_rkey);
		break;

	case ISBDM_OP_SEND_WITH_IMM:
		hdr_type = ISBDM_PACKET_IB_SEND_WITH_IMMEDIATE;
		imm_or_rkey = cpu_to_le32(wqe->sqe.imm_data);
		break;
	}

	hdr = isbdm_fill_packet_header(buf,
				       hdr_type,
				       hdr_flags,
				       qp->sdev->lid,
				       qp->base_qp.qp_num,
				       dest_qp,
				       imm_or_rkey);

	while (wqe->processed < wqe->bytes) {
		size_t size_this_round;

		/* Grab a new buffer if needed. */
		if (!buf || (buf->size >= buf->capacity)) {
			buf = get_buf(ii, &ii->tx_ring);
			if (!buf) {
				rc = -ENOMEM;
				goto out;
			}

			buf->flags = 0;
			list_add_tail(&buf->node, &local_list);
		}

		/*
		 * Do the minimum of filling the buffer up and/or absorbing the
		 * SGE.
		 */
		size_this_round = buf->capacity - buf->size;
		if (mem_idx >= wqe->sqe.num_sge)
			return -EINVAL;

		sge = &wqe->sqe.sge[mem_idx];
		if (size_this_round > (sge->length - mem_off)) {
			size_this_round = sge->length - mem_off;
		}

		dst = buf->buf + buf->size;
		/* Copy that buffer in from somewhere. */
		if (tx_flags(wqe) & ISBDM_WQE_INLINE) {
			memcpy(dst, &wqe->sqe.sge[1], size_this_round);

		} else {
			struct isbdm_mem *mem = wqe->mem[mem_idx];

			if (!mem->mem_obj) {
				const void *src =
					(const void *)(uintptr_t)sge->laddr +
					mem_off;

				/* Kernel client using kva */
				memcpy(dst, src, size_this_round);

			} else {
				const void *src = u64_to_user_ptr(sge->laddr) +
						  mem_off;

				if (copy_from_user(dst, src, size_this_round))
					return -EFAULT;
			}
		}

		buf->size += size_this_round;
		mem_off += size_this_round;
		if (mem_off >= sge->length) {
			mem_off = 0;
			mem_idx++;
		}

		wqe->processed += size_this_round;
	}

	if (buf)
		buf->flags |= ISBDM_DESC_LS;

	if (is_loopback) {
		mutex_unlock(&ii->tx_ring.lock);
		mutex_lock(&ii->rx_ring.lock);
		isbdm_process_ib_recv(ii, hdr, &local_list, true);
		mutex_unlock(&ii->rx_ring.lock);

	} else {

		/*
		 * Now that all the buffers are set up, enqueue them onto the
		 * waitlist, then stick as many as possible into the hardware.
		 */
		list_splice_tail_init(&local_list, &ii->tx_ring.wait_list);
		isbdm_tx_enqueue(ii);
		mutex_unlock(&ii->tx_ring.lock);
	}

	return 0;

out:
	/* On failure, clean up any buffers on the local list. */
	list_for_each_entry_safe(buf, tmp, &local_list, node) {
		put_buf(ii, &ii->tx_ring, buf);
	}

	mutex_unlock(&ii->tx_ring.lock);
	return rc;
}

static int isbdm_qp_sq_proc_local(struct isbdm_qp *qp, struct isbdm_wqe *wqe)
{
	int rv;

	switch (tx_type(wqe)) {
	case ISBDM_OP_REG_MR:
		/* TODO: Handle registering a memory region! */
		// rv = siw_fastreg_mr(qp->pd, &wqe->sqe);
		rv = -ENOSYS;
		break;

	case ISBDM_OP_INVAL_STAG:
		rv = isbdm_invalidate_stag(qp->pd, wqe->sqe.rkey);
		break;

	default:
		rv = -EINVAL;
	}

	return rv;
}

/*
 * isbdm_check_sgl_tx()
 *
 * Check permissions for a list of SGEs (SGL).
 * A successful check will have all memory referenced
 * for transmission resolved and assigned to the WQE.
 *
 * @pd:		Protection Domain SGL should belong to
 * @wqe:	WQE to be checked
 * @perms:	requested access permissions
 *
 */
static int isbdm_check_sgl_tx(struct ib_pd *pd, struct isbdm_wqe *wqe,
			      enum ib_access_flags perms)
{
	struct isbdm_sge *sge = &wqe->sqe.sge[0];
	int i, num_sge = wqe->sqe.num_sge;
	u64 len;

	if (unlikely(num_sge > ISBDM_MAX_SGE))
		return -EINVAL;

	for (i = 0, len = 0; num_sge; num_sge--, i++, sge++) {
		/* rdma verbs: do not check stag for a zero length sge */
		if (sge->length) {
			int rv = isbdm_check_sge(pd, sge, &wqe->mem[i], perms,
						 0, sge->length);

			if (unlikely(rv != E_ACCESS_OK))
				return rv;
		}

		len += sge->length;
	}

	if (len > U32_MAX)
		return -ERANGE;

	wqe->bytes = len;
	return 0;
}

struct isbdm_status_map_entry {
	u32 hw;
	enum isbdm_wc_status status;
};

static struct isbdm_status_map_entry isbdm_status_map[] = {
	{ISBDM_STATUS_MALFORMED_COMMAND, ISBDM_WC_LOC_PROT_ERR},
	{ISBDM_STATUS_RMBA_ACCESS_FAULT, ISBDM_WC_REM_ACCESS_ERR},
	{ISBDM_STATUS_RMBA_DATA_CORRUPTION, ISBDM_WC_REM_INV_REQ_ERR},
	{ISBDM_STATUS_RMB_TRANSLATION_FAULT, ISBDM_WC_REM_ACCESS_ERR},
	{ISBDM_STATUS_RMB_ACCESS_FAULT, ISBDM_WC_REM_ACCESS_ERR},
	{ISBDM_STATUS_RMB_DATA_CORRUPTION, ISBDM_WC_REM_ACCESS_ERR},
	{ISBDM_STATUS_LMB_TRANSLATION_FAULT, ISBDM_WC_LOC_ACCESS_ERR},
	{ISBDM_STATUS_LMB_ACCESS_FAULT, ISBDM_WC_LOC_ACCESS_ERR},
	{ISBDM_STATUS_ABORTED, ISBDM_WC_GENERAL_ERR},
	{ /* Sentinel */ }
};

static enum isbdm_wc_status isbdm_map_hw_status(uint32_t status)
{
	struct isbdm_status_map_entry *entry = &isbdm_status_map[0];

	if (status == ISBDM_STATUS_SUCCESS)
		return ISBDM_WC_SUCCESS;

	while (entry->hw) {
		if (entry->hw == status)
			return entry->status;

		entry++;
	}

	return ISBDM_WC_GENERAL_ERR;
}

static void isbdm_free_command(struct isbdm *ii, struct isbdm_command *command)
{
	if (command->inline_dma_addr != 0) {
		struct isbdm_sge *sge = &command->wqe.sqe.sge[0];
		void *vaddr = (void *)(unsigned long)sge->laddr;

		dma_pool_free(ii->inline_pool, vaddr, command->inline_dma_addr);
		command->inline_dma_addr = 0;
	}
}

/* Called when a completed command descriptor is reaped out of the hw table. */
void isbdm_complete_rdma_cmd(struct isbdm *ii, struct isbdm_command *command,
			     uint32_t status)
{
	enum isbdm_wc_status wc_status = isbdm_map_hw_status(status);
	int cmd_count = command->cmd_count;
	struct isbdm_wqe *wqe = cmd_count ? &command->wqe : command->parent_wqe;
	struct isbdm_qp *qp = command->qp;

	if (status == ISBDM_STATUS_SUCCESS)
		wqe->processed += le64_to_cpu(command->cmd.size_pasid_flags) &
				  ISBDM_RDMA_SIZE_MASK;

	/*
	 * If this is not the last command in the set, just update the parent
	 * and wait for the last one to do the official completion.
	 */
	if (!cmd_count) {
		if ((wc_status != ISBDM_WC_SUCCESS) &&
		    (wqe->wc_status == ISBDM_STATUS_SUCCESS)) {

			wqe->wc_status = wc_status;
		}

		isbdm_free_command(ii, command);
		return;
	}

	/*
	 * This is the last (or only) transfer in the set. Any failure along the
	 * way bubbles up to the end result.
	 */
	if (wqe->wc_status != ISBDM_WC_SUCCESS)
		wc_status = wqe->wc_status;

	isbdm_wqe_put_mem(&command->wqe, command->wqe.sqe.opcode);

	/* Invalidate the STag if this is a read with local invalidate. */
	if ((tx_type(wqe) == ISBDM_OP_READ_LOCAL_INV) &&
	    (wc_status == ISBDM_WC_SUCCESS)) {

		if (rdma_is_kernel_res(&qp->base_qp.res) &&
		    tx_type(wqe) == ISBDM_OP_READ_LOCAL_INV) {

			int rv = isbdm_invalidate_stag(qp->pd,
						       wqe->sqe.sge[0].lkey);

			if (rv) {
				dev_warn(&ii->pdev->dev,
					 "%s: Cannot invalidate STag %x: %d\n",
					 __func__,
					 wqe->sqe.sge[0].lkey,
					 rv);

				wc_status = ISBDM_WC_GENERAL_ERR;
			}
		}
	}

	if ((command->wqe.sqe.flags & ISBDM_WQE_SIGNALLED) ||
	    (wc_status != ISBDM_WC_SUCCESS)) {

		isbdm_sqe_complete(qp,
				   &command->wqe.sqe,
				   wqe->processed,
				   wc_status);
	}

	isbdm_qp_put(qp);
	isbdm_free_command(ii, command);
}

/*
 * Do a copy like the hardware would. If mm is non-null then then addr is a
 * usermode address, otherwise it's a physical address.
 */
static int isbdm_sva_copy(struct isbdm *ii, struct mm_struct *mm, u64 addr,
			  char *mapped_addr, char *kmem, int size,
			  int direction)
{

	int done;

	/* If there's already a kernel mapping, use it directly. */
	if (mapped_addr) {
		if (direction)
			memcpy(kmem, mapped_addr, size);
		else
			memcpy(mapped_addr, kmem, size);

		return size;
	}

	if (mm) {
		if (mm == current->mm) {
			unsigned long not_done;

			if (direction)
				not_done = copy_from_user(
					kmem, (void *)(unsigned long)addr,
					size);

			else
				not_done = copy_to_user(
					(void *)(unsigned long)addr, kmem,
					size);


			done = size - not_done;

		} else {
			int flags = direction ? 0 : FOLL_WRITE;

			done = access_remote_vm(mm, addr, kmem, size, flags);
			if (done < 0) {
				dev_warn(&ii->pdev->dev,
					"Loopback failed to access memory: %d",
					done);
			}
		}

		return done;
	}

	/* TODO: get mappings, copy. */
	dev_warn(&ii->pdev->dev, "TODO: Copy to/from kernel buf: %llx\n", addr);
	return -1;
}

/* Do a CompareExchange or FetchAndAdd locally. */
static u32 isbdm_loopback_amo(struct isbdm *ii,
			      struct isbdm_command *command,
			      int op,
			      u64 size,
			      char *result_buf,
			      struct mm_struct *remote_mm, u64 remote_addr)
{
	struct page *page = NULL;
	int gup_flags = FOLL_WRITE;
	struct vm_area_struct *vma;
	void *maddr;
	void *amo_addr;
	u32 status;
	int ret;

	if ((size != 4) && (size != 8)) {
		dev_warn(&ii->pdev->dev,
			 "Loopback AMO with bad size %llx\n", size);

		return ISBDM_STATUS_MALFORMED_COMMAND;
	}

	/*
	 * The address must be aligned to the size, which also ensures the data
	 * doesn't cross a page boundary.
	 */
	if (remote_addr & (size - 1)) {
		dev_warn(&ii->pdev->dev,
			 "Loopback AMO address misaligned");

		return ISBDM_STATUS_MALFORMED_COMMAND;
	}

	/* Do a deconstructed version of __access_remote_vm() below. */
	if (mmap_read_lock_killable(remote_mm)) {
		dev_warn(&ii->pdev->dev,
			 "Loopback AMO failed to lock remote mm");

		return ISBDM_STATUS_RMB_ACCESS_FAULT;
	}

	ret = get_user_pages_remote(remote_mm, remote_addr, 1,
				    gup_flags, &page, &vma, NULL);

	if (ret <= 0) {
		dev_warn(&ii->pdev->dev,
			 "Loopback AMO failed to get user pages: %d\n", ret);

		status = ISBDM_STATUS_LMB_ACCESS_FAULT;
		goto unlock;
	}

	maddr = kmap(page);
	amo_addr = maddr + (remote_addr & (PAGE_SIZE - 1));
	instrument_copy_from_user_before(amo_addr, (void __user *)remote_addr,
					 size);

	instrument_copy_to_user((void __user *)remote_addr,
				&command->cmd.amo_value1, size);

	if (size == 4) {
		u32 result32;

		if (op == ISBDM_COMMAND_FETCH_ADD) {
			result32 = atomic_fetch_add(command->cmd.amo_value1,
						    (atomic_t *)amo_addr);

		} else {
			WARN_ON_ONCE(op != ISBDM_COMMAND_CAS);

			result32 = atomic_cmpxchg((atomic_t *)amo_addr,
						  (int)command->cmd.amo_value1,
						  (int)command->cmd.amo_value2);
		}

		*(u32 *)result_buf = result32;

	} else {
		u64 result64;

		WARN_ON_ONCE(size != 8);

		if (op == ISBDM_COMMAND_FETCH_ADD) {
			result64 = atomic64_fetch_add(command->cmd.amo_value1,
						      (atomic64_t *)amo_addr);

		} else {
			WARN_ON_ONCE(op != ISBDM_COMMAND_CAS);

			result64 = atomic64_cmpxchg((atomic64_t *)amo_addr,
						    command->cmd.amo_value1,
						    command->cmd.amo_value2);
		}

		*(u64 *)result_buf = result64;
	}

	set_page_dirty_lock(page);
	instrument_copy_from_user_after(amo_addr, (void __user *)remote_addr,
					size, 0);

	flush_icache_user_page(vma, page, (void __user *)remote_addr, size);
	kunmap(page);
	put_page(page);
	status = ISBDM_STATUS_SUCCESS;

unlock:
	mmap_read_unlock(remote_mm);
	return status;
}

/* Do a silly loopback RDMA operation */
static void isbdm_do_loopback_rdma(struct isbdm *ii,
				   struct isbdm_command *command)
{
	u64 size_pasid_flags = le64_to_cpu(command->cmd.size_pasid_flags);
	u64 rmbi_command = le64_to_cpu(command->cmd.rmbi_command);
	u64 op = (rmbi_command >> ISBDM_RDMA_COMMAND_SHIFT) &
		 ISBDM_RDMA_COMMAND_MASK;
	u64 rmb_iova;
	u64 rmb_iova_end;
	u64 rmbi = rmbi_command & ISBDM_RDMA_RMBI_MASK;
	u64 size = size_pasid_flags & ISBDM_RDMA_SIZE_MASK;
	u64 liova = le64_to_cpu(command->cmd.iova);
	void *local_va = NULL;
	struct mm_struct *local_mm = NULL;
	struct mm_struct *remote_mm = NULL;
	u64 riova;
	int this_size;
	bool is_write = (op == ISBDM_COMMAND_WRITE);
	struct isbdm_remote_buffer rmb;
	uint32_t isbdm_status;
	char *page = NULL;

	/* Get the remote memory buffer like the hardware would. */
	if (rmbi >= ISBDMEX_RMB_TABLE_SIZE) {
		isbdm_status = ISBDM_STATUS_RMB_ACCESS_FAULT;
		goto out;
	}

	/*
	 * Acquire the table lock to prevent the RMB and associated mm from
	 * disappearing.
	 */
	mutex_lock(&ii->rmb_table_lock);
	memcpy(&rmb, &ii->rmb_table[rmbi], sizeof(rmb));
	if (rmb.security_key != command->cmd.security_key) {
		mutex_unlock(&ii->rmb_table_lock);
		isbdm_status = ISBDM_STATUS_RMB_ACCESS_FAULT;
		goto out;
	}

	rmb_iova = le64_to_cpu(rmb.iova);
	rmb_iova_end = rmb_iova + le64_to_cpu(rmb.size);
	riova = le64_to_cpu(command->cmd.riova);
	/* Verify the requested remote VA is in bounds. */
	if ((riova < rmb_iova) || ((riova + size) < riova) ||
	    ((riova + size) > rmb_iova_end)) {

		mutex_unlock(&ii->rmb_table_lock);
		isbdm_status = ISBDM_STATUS_RMB_ACCESS_FAULT;
		goto out;
	}

	/* Get the MM associated with the "remote" buffer. */
	if (rmb.pasid_flags & ISBDM_REMOTE_BUF_PV) {
		struct isbdm_mr *remote_mr =
			(void *)(unsigned long)le64_to_cpu(rmb.sw_avail);

		struct isbdm_pd *remote_pd = to_isbdm_pd(remote_mr->base_mr.pd);

		remote_mm = remote_pd->mm;
		if (!remote_mm) {
			mutex_unlock(&ii->rmb_table_lock);
			dev_warn(&ii->pdev->dev, "Failed to find RMB mm\n");
			isbdm_status = ISBDM_STATUS_RMB_TRANSLATION_FAULT;
			goto out;
		}

		mmget(remote_mm);
	}

	mutex_unlock(&ii->rmb_table_lock);

	/*
	 * Get the local MM too, in case the command is not being executed on
	 * the task that submitted it.
	 */
	if (size_pasid_flags & ISBDM_RDMA_PV) {
		struct isbdm_pd *local_pd = to_isbdm_pd(command->qp->base_qp.pd);

		local_mm = local_pd->mm;
		if (!local_mm) {
			dev_warn(&ii->pdev->dev, "Failed to find local mm\n");
			isbdm_status = ISBDM_STATUS_LMB_TRANSLATION_FAULT;
			goto out;
		}

	/* For inline requests, cheat and find the dma_pool VA. */
	} else if (command->inline_dma_addr) {
		struct isbdm_sge *sge = &command->wqe.sqe.sge[0];

		local_va = (void *)(unsigned long)sge->laddr;
	}

	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page) {
		isbdm_status = ISBDM_STATUS_ABORTED;
		goto out;
	}

	/*
	 * Handle atomic operations separately, they require more intricate
	 * surgery to get a direct buffer.
	 */
	if ((op == ISBDM_COMMAND_CAS) || (op == ISBDM_COMMAND_FETCH_ADD)) {
		isbdm_status = isbdm_loopback_amo(ii, command, op, size,
						  page, remote_mm, riova);

		if (isbdm_status != ISBDM_STATUS_SUCCESS) {
			dev_warn(&ii->pdev->dev,
				 "Loopback AMO failed: %x\n", isbdm_status);

			goto out;
		}

		/* Copy back out to the local process. */
		this_size = isbdm_sva_copy(ii, local_mm, liova, local_va, page,
					   size, 0);

		if (this_size != size) {
			dev_warn(&ii->pdev->dev,
				 "Loopback AMO copyback failed\n");

			isbdm_status = ISBDM_STATUS_LMB_ACCESS_FAULT;
		}

		goto out;
	}

	/* Just reads and writes handled here on out. */
	WARN_ON_ONCE((op != ISBDM_COMMAND_READ) && (op != ISBDM_COMMAND_WRITE));

	/* Process a page at a time. */
	while (size) {
		this_size = (size > PAGE_SIZE) ? PAGE_SIZE : size;
		if (is_write) {
			this_size = isbdm_sva_copy(ii, local_mm, liova,
						   local_va, page, this_size,
						   1);

			this_size = isbdm_sva_copy(ii, remote_mm, riova, NULL,
						   page, this_size, 0);

		} else {
			this_size = isbdm_sva_copy(ii, remote_mm, riova, NULL,
						   page, this_size, 1);

			this_size = isbdm_sva_copy(ii, local_mm, liova,
						   local_va, page, this_size,
						   0);
		}

		if (this_size < 0) {
			isbdm_status = ISBDM_STATUS_LMB_ACCESS_FAULT;
			goto out;
		}

		liova += this_size;
		riova += this_size;
		size -= this_size;
	}

	isbdm_status = ISBDM_STATUS_SUCCESS;

out:
	if (remote_mm)
		mmput(remote_mm);

	if (page)
		free_page((unsigned long)page);

	isbdm_complete_rdma_cmd(ii, command, isbdm_status);
	put_cmd(ii, &ii->cmd_ring, command);
}

/*
 * Set up an RDMA command for a single SGE. SGEs must be built in reverse order,
 * so that the parent (last) element is available when the subcommands are
 * created.
 */
static int isbdm_rdma_one_sge(struct isbdm *ii, struct isbdm_qp *qp,
			      struct isbdm_wqe *wqe, struct isbdm_sge *sge,
			      uint64_t *offset, struct list_head *list)
{
	struct isbdm_pd *pd = to_isbdm_pd(qp->pd);
	const char *command_name = "unknown";
	struct isbdm_command *command;
	void *pool_buf = NULL;
	uint64_t value;
	int rc;

	command = get_cmd(ii, &ii->cmd_ring);
	if (!command) {
		rc = -ENOMEM;
		goto err;
	}

	command->qp = qp;

	/*
	 * If the list is empty this must be the first (or only) command
	 * created, AKA the last command in execution order. Make this the
	 * official owner.
	 */
	if (list_empty(list)) {
		memcpy(&command->wqe, wqe, sizeof(command->wqe));
		command->cmd_count = wqe->sqe.num_sge;

		WARN_ON_ONCE(!command->cmd_count);

	} else {
		struct isbdm_command *parent =
			list_last_entry(list, struct isbdm_command, node);

		command->cmd_count = 0;
		command->parent_wqe = &parent->wqe;
	}

	value = sge->length & ISBDM_RDMA_SIZE_MASK;
	value |= ISBDM_RDMA_NV;

	/*
	 * If the data is inline, it's in the SGE array copied here (eg some
	 * random kernel buffer). Grab a DMA-able buffer from a pool dedicated
	 * to this purpose and use that for the actual I/O, without PASID.
	 */
	if (wqe->sqe.flags & ISBDM_WQE_INLINE) {

		WARN_ON_ONCE(sge != &wqe->sqe.sge[0]);

		pool_buf = dma_pool_alloc(ii->inline_pool,
					  GFP_KERNEL,
					  &command->inline_dma_addr);

		if (!pool_buf) {
			rc = -ENOMEM;
			goto err;
		}

		/* We use non-zero to know it's there. */
		WARN_ON_ONCE(!command->inline_dma_addr);

		/*
		 * There's no such thing as an inline read, as we wouldn't know
		 * how to return the data to usermode.
		 */
		WARN_ON_ONCE(tx_type(wqe) != ISBDM_OP_WRITE);

		command->wqe.sqe.sge[0].laddr = (unsigned long)pool_buf;
		memcpy(pool_buf, &wqe->sqe.sge[1], sge->length);
		dma_sync_single_for_device(&ii->pdev->dev,
					   command->inline_dma_addr,
					   sge->length,
					   DMA_TO_DEVICE);

		command->cmd.iova = cpu_to_le64(command->inline_dma_addr);
		value |= ISBDM_RDMA_PP;

	} else {
		command->cmd.iova = cpu_to_le64(sge->laddr);
		value |= ISBDM_RDMA_PV;
		if (pd->pasid > ISBDM_RDMA_PASID_MASK) {
			dev_warn(&ii->pdev->dev, "PASID out of range\n");
			rc = -ERANGE;
			goto err;
		}

		value |= pd->pasid << ISBDM_RDMA_PASID_SHIFT;
	}

	command->cmd.size_pasid_flags = cpu_to_le64(value);
	if ((wqe->sqe.rkey >> 8) == 0) {
		dev_warn(&ii->pdev->dev, "Invalid zeroed rkey\n");
		rc = -EINVAL;
		goto err;
	}

	value = isbdm_stag_to_rmbi(wqe->sqe.rkey) & ISBDM_RDMA_RMBI_MASK;
	switch (tx_type(wqe)) {
	case ISBDM_OP_WRITE:
		value |= ISBDM_COMMAND_WRITE << ISBDM_RDMA_COMMAND_SHIFT;
		command_name = "write";
		break;

	case ISBDM_OP_READ:
		value |= ISBDM_COMMAND_READ << ISBDM_RDMA_COMMAND_SHIFT;
		command_name = "read";
		break;

	case ISBDM_OP_COMP_AND_SWAP:
	case ISBDM_OP_FETCH_AND_ADD:
		if (tx_type(wqe) == ISBDM_OP_COMP_AND_SWAP) {
			value |= ISBDM_COMMAND_CAS << ISBDM_RDMA_COMMAND_SHIFT;
			command_name = "CompareExchange";

		} else {
			value |= ISBDM_COMMAND_FETCH_ADD <<
				 ISBDM_RDMA_COMMAND_SHIFT;

			command_name = "add";
		}

		if ((sge->length != 4) && (sge->length != 8)) {
			dev_warn(&ii->pdev->dev, "Invalid atomic length %d\n",
				 sge->length);

			rc = -EINVAL;
			goto err;
		}

		command->cmd.amo_value1 =
			cpu_to_le64(wqe->sqe.atomic.compare_add);

		command->cmd.amo_value2 = cpu_to_le64(wqe->sqe.atomic.exchange);
		break;

	default:
		dev_warn(&ii->pdev->dev, "Unexpected op %d\n", tx_type(wqe));
		rc = -EINVAL;
		goto err;
	}

	dev_dbg(&ii->pdev->dev,
		"RDMA %s%s, length 0x%x\n",
		command_name,
		is_loopback_packet(qp, wqe) ? " loopback" : "",
		sge->length);

	command->cmd.rmbi_command = cpu_to_le64(value);

	WARN_ON_ONCE(*offset < sge->length);

	*offset -= sge->length;
	command->cmd.riova = cpu_to_le64(wqe->sqe.raddr + *offset);
	command->cmd.notify_iova = 0;
	command->cmd.security_key = cpu_to_le64(wqe->sqe.rkey);
	list_add(&command->node, list);
	return 0;

err:
	if (command) {
		isbdm_free_command(ii, command);
		put_cmd(ii, &ii->cmd_ring, command);
	}

	return rc;
}

/* Submit an RDMA command from userspace */
static int isbdm_do_rdma(struct isbdm_qp *qp, struct isbdm_wqe *wqe)
{
	struct isbdm_device *sdev = to_isbdm_dev(qp->pd->device);
	bool is_loopback = is_loopback_packet(qp, wqe);
	struct isbdm *ii = sdev->ii;
	struct isbdm_command *command;
	struct isbdm_command *tmp;
	LIST_HEAD(command_list);
	struct isbdm_sge *sge = &wqe->sqe.sge[0];
	struct isbdm_pd *pd = to_isbdm_pd(qp->pd);
	uint64_t offset = 0;
	int rc;
	int i;

	/* Just succeed zero sized writes. */
	if (sge->length == 0) {
		isbdm_sqe_complete(qp, &wqe->sqe, 0, ISBDM_WC_SUCCESS);
		return 0;
	}

	/*
	 * TODO: Kernel addresses fill out the structure differently (!PV, no
	 * PASID, physical address, and maybe PP).
	 */
	if (rdma_is_kernel_res(&qp->base_qp.res)) {
		dev_warn(&ii->pdev->dev, "Kernel VAs not yet implemented\n");
		return -EINVAL;
	}

	if (pd->pasid == IOMMU_PASID_INVALID) {
		dev_warn(&ii->pdev->dev, "PD lacks a PASID\n");
		return -EAGAIN;
	}

	/* Compute the total length. */
	for (i = 0; i < wqe->sqe.num_sge; i++)
		offset += sge[i].length;

	/* Grab a reference to give to the command. */
	isbdm_qp_get(qp);
	mutex_lock(&ii->cmd_ring.lock);
	/* Prepare an ISBDM RDMA command for each SGE, in reverse order. */
	for (i = wqe->sqe.num_sge - 1; i >= 0; i--) {
		rc = isbdm_rdma_one_sge(ii, qp, wqe, &sge[i], &offset,
					&command_list);

		if (rc)
			goto out;
	}

	if (is_loopback) {
		list_for_each_entry_safe(command, tmp, &command_list, node) {
			isbdm_do_loopback_rdma(ii, command);
		}

	} else {
		list_splice_tail_init(&command_list, &ii->cmd_ring.wait_list);
		isbdm_cmd_enqueue(ii);
	}

	rc = 0;

out:
	if (rc) {
		isbdm_qp_put(qp);
		list_for_each_entry_safe(command, tmp, &command_list, node) {
			isbdm_free_command(ii, command);
			put_cmd(ii, &ii->cmd_ring, command);
		}
	}

	mutex_unlock(&ii->cmd_ring.lock);
	return rc;
}

/*
 * isbdm_qp_sq_proc_tx()
 *
 * Process one WQE.
 */
static int isbdm_qp_sq_proc_tx(struct isbdm_qp *qp, struct isbdm_wqe *wqe)
{
	int rv = 0;

	if (!(wqe->sqe.flags & ISBDM_WQE_INLINE)) {
		if (tx_type(wqe) != ISBDM_OP_READ &&
		    tx_type(wqe) != ISBDM_OP_READ_LOCAL_INV) {

			/*
			 * Reference memory to be tx'd w/o checking access for
			 * LOCAL_READ permission, since not defined in RDMA
			 * core.
			 */
			rv = isbdm_check_sgl_tx(qp->pd, wqe, 0);
			if (rv < 0) {
				rv = -EINVAL;
				goto tx_error;
			}

		} else {
			wqe->bytes = 0;
		}
	} else {
		wqe->bytes = wqe->sqe.sge[0].length;
		if (!rdma_is_kernel_res(&qp->base_qp.res)) {
			if (wqe->bytes > ISBDM_MAX_INLINE) {
				rv = -EINVAL;
				goto tx_error;
			}

			wqe->sqe.sge[0].laddr =
				(u64)(uintptr_t)&wqe->sqe.sge[1];
		}
	}

	wqe->processed = 0;
	switch (tx_type(wqe)) {
	case ISBDM_OP_SEND:
	case ISBDM_OP_SEND_WITH_IMM:
	case ISBDM_OP_SEND_REMOTE_INV:
		rv = isbdm_do_send(qp, wqe);
		break;

	case ISBDM_OP_WRITE:
	case ISBDM_OP_READ:
	case ISBDM_OP_READ_LOCAL_INV:
	case ISBDM_OP_FETCH_AND_ADD:
	case ISBDM_OP_COMP_AND_SWAP:
		rv = isbdm_do_rdma(qp, wqe);
		break;

	default:
		isbdm_dbg_qp(qp, "Unexpected wqe type %d\n", tx_type(wqe));
		return -EINVAL;
	}

	return 0;

tx_error:
	return rv;
}

/*
 * isbdm_qp_sq_process()
 *
 * Core TX path routine for ISBDM.
 *
 * SQ processing may occur in user context. Processing in user context is
 * limited to non-kernel verbs users.
 *
 * Must be called with the QP state read-locked.
 */
static int isbdm_qp_sq_process(struct isbdm_qp *qp, struct isbdm_wqe *wqe)
{
	enum isbdm_opcode tx_type;
	unsigned long flags;
	int rv = 0;

	//isbdm_dbg_qp(qp, "enter for type %d\n", tx_type(wqe));

next_wqe:
	tx_type = tx_type(wqe);
	if (tx_type <= ISBDM_OP_RECEIVE) {
		rv = isbdm_qp_sq_proc_tx(qp, wqe);

	} else {
		rv = isbdm_qp_sq_proc_local(qp, wqe);
	}

	if (!rv) {
		/* WQE processing done */
		switch (tx_type) {
		case ISBDM_OP_SEND:
		case ISBDM_OP_SEND_WITH_IMM:
		case ISBDM_OP_SEND_REMOTE_INV:
			isbdm_wqe_put_mem(wqe, tx_type);
			fallthrough;

		case ISBDM_OP_INVAL_STAG:
		case ISBDM_OP_REG_MR:
			if (tx_flags(wqe) & ISBDM_WQE_SIGNALLED)
				isbdm_sqe_complete(qp, &wqe->sqe, wqe->bytes,
						   ISBDM_WC_SUCCESS);
			break;

		case ISBDM_OP_WRITE:
		case ISBDM_OP_READ:
		case ISBDM_OP_READ_LOCAL_INV:
		case ISBDM_OP_COMP_AND_SWAP:
		case ISBDM_OP_FETCH_AND_ADD:
			/*
			 * Dereferencing happens in isbdm_complete_rdma_cmd().
			 */
			break;

		default:
			WARN_ONCE(1, "undefined WQE type %d\n", tx_type);
			break;
		}

		/*
		 * Lock to synchronize with new senders wondering if they need
		 * to start TX themselves.
		 */
		spin_lock_irqsave(&qp->sq_lock, flags);
		/* Activate returns -ENOENT if there are no more. */
		rv = isbdm_activate_tx_from_sq(qp, wqe);
		if (rv == -ENOENT) {
			rv = 0;
			qp->tx_ctx.send_pending = 0;
			spin_unlock_irqrestore(&qp->sq_lock, flags);
			goto done;
		}

		spin_unlock_irqrestore(&qp->sq_lock, flags);
		if (rv <= 0)
			goto done;

		goto next_wqe;

	} else {
		/*
		 * WQE processing failed.
		 * Verbs 8.3.2:
		 * o It turns any WQE into a signalled WQE.
		 * o Local catastrophic error must be surfaced
		 * o QP must be moved into Terminate state: done by code
		 *   doing socket state change processing
		 *
		 * o TODO: Termination message must be sent.
		 * o TODO: Implement more precise work completion errors,
		 *         see enum ib_wc_status in ib_verbs.h
		 */
		isbdm_dbg_qp(qp, "wqe type %d processing failed: %d\n",
			     tx_type(wqe), rv);

		switch (tx_type) {
		case ISBDM_OP_SEND:
		case ISBDM_OP_SEND_REMOTE_INV:
		case ISBDM_OP_SEND_WITH_IMM:
		case ISBDM_OP_WRITE:
		case ISBDM_OP_READ:
		case ISBDM_OP_READ_LOCAL_INV:
		case ISBDM_OP_COMP_AND_SWAP:
		case ISBDM_OP_FETCH_AND_ADD:
			isbdm_wqe_put_mem(wqe, tx_type);
			fallthrough;

		case ISBDM_OP_INVAL_STAG:
		case ISBDM_OP_REG_MR:
			isbdm_sqe_complete(qp, &wqe->sqe, wqe->bytes,
					   ISBDM_WC_LOC_QP_OP_ERR);

			isbdm_qp_event(qp, IB_EVENT_QP_FATAL);
			break;

		default:
			WARN(1, "undefined WQE type %d\n", tx_type);
			rv = -EINVAL;
		}

		spin_lock_irqsave(&qp->sq_lock, flags);
		/* Immediately halt further TX processing */
		qp->tx_ctx.tx_halted = true;
		qp->tx_ctx.send_pending = false;
		spin_unlock_irqrestore(&qp->sq_lock, flags);

	}
done:
	return rv;
}

/*
 * Churn through entries added to the send QP. Assumes the synchronization for
 * ensuring only one thread is doing this has already been handled.
 */
int isbdm_process_send_qp(struct isbdm_qp *qp)
{
	struct isbdm_wqe *wqe = &qp->tx_ctx.wqe_active;
	int rc;

	rc = isbdm_activate_tx_from_sq(qp, wqe);
	if (rc <= 0) {
		isbdm_dbg_qp(qp, "Activate TX failed: %d\n", rc);
		return rc;
	}

	rc = isbdm_qp_sq_process(qp, wqe);
	if (rc)
		isbdm_dbg_qp(qp, "SQ processing failed: %d\n", rc);

	return rc;
}

/*
 * Get a new receive queue entry, and fill out the given work queue entry based
 * on it. Returns 0 if the WQE was successfully filled out, or -ENOENT if no
 * RQEs are available.
 */
static int isbdm_rqe_get(struct isbdm_qp *qp, struct isbdm_wqe *wqe)
{
	struct isbdm_rqe *rqe;
	struct isbdm_srq *srq;
	bool srq_event = false;
	unsigned long flags;
	int rv = -ENOENT;

	srq = qp->srq;
	if (srq) {
		spin_lock_irqsave(&srq->lock, flags);
		if (unlikely(!srq->num_rqe))
			goto out;

		rqe = &srq->recvq[srq->rq_get % srq->num_rqe];

	} else {
		if (unlikely(!qp->recvq))
			goto out;

		rqe = &qp->recvq[qp->rq_get % qp->attrs.rq_size];
	}

	if (likely(rqe->flags == ISBDM_WQE_VALID)) {
		int num_sge = rqe->num_sge;

		if (likely(num_sge <= ISBDM_MAX_SGE)) {
			int i = 0;

			wqe->bytes = 0;
			wqe->processed = 0;
			wqe->wc_status = ISBDM_WC_SUCCESS;
			wqe->rqe.id = rqe->id;
			wqe->rqe.opcode = ISBDM_OP_RECEIVE;
			wqe->rqe.num_sge = num_sge;
			while (i < num_sge) {
				wqe->rqe.sge[i].laddr = rqe->sge[i].laddr;
				wqe->rqe.sge[i].lkey = rqe->sge[i].lkey;
				wqe->rqe.sge[i].length = rqe->sge[i].length;
				wqe->bytes += wqe->rqe.sge[i].length;
				wqe->mem[i] = NULL;
				i++;
			}

			/* can be re-used by appl */
			smp_store_mb(rqe->flags, 0);
			rv = 0;

		} else {
			isbdm_dbg_qp(qp, "too many SGEs: %d\n", rqe->num_sge);
			goto out;
		}

		if (!srq) {
			qp->rq_get++;

		} else {
			if (srq->armed) {
				/* Test SRQ limit */
				u32 off = (srq->rq_get + srq->limit) %
					  srq->num_rqe;
				struct isbdm_rqe *rqe2 = &srq->recvq[off];

				if (!(rqe2->flags & ISBDM_WQE_VALID)) {
					srq->armed = false;
					srq_event = true;
				}
			}

			srq->rq_get++;
		}
	}

out:
	if (srq) {
		spin_unlock_irqrestore(&srq->lock, flags);
		if (srq_event)
			isbdm_srq_event(srq, IB_EVENT_SRQ_LIMIT_REACHED);
	}

	return rv;
}

/*
 * isbdm_rx_umem()
 *
 * Receive data of @len into usermode memory target referenced by @dest_addr.
 *
 * @qp:		queue pair
 * @umem:	representation of target usermode memory
 * @dest_addr:	user virtual address
 * @len:	number of bytes to copy
 */
static int isbdm_rx_umem(struct isbdm_qp *qp, struct isbdm_umem *umem,
			 u64 dest_addr, void *src, int len)
{
	int copied = 0;

	while (len) {
		struct page *p;
		int pg_off, bytes;
		void *dest;

		p = isbdm_get_upage(umem, dest_addr);
		if (unlikely(!p)) {
			pr_warn("isbdm: %s: [QP %u]: bogus addr: %pK, %pK\n",
				__func__, qp_id(qp),
				(void *)(uintptr_t)dest_addr,
				(void *)(uintptr_t)umem->fp_addr);

			return -EFAULT;
		}

		pg_off = dest_addr & ~PAGE_MASK;
		bytes = min(len, (int)PAGE_SIZE - pg_off);
		// isbdm_dbg_qp(qp, "page %pK, bytes=%u\n", p, bytes);
		dest = kmap_atomic(p);
		memcpy(dest + pg_off, src, bytes);
		kunmap_atomic(dest);
		copied += bytes;
		len -= bytes;
		dest_addr += bytes;
		src += bytes;
	}

	return copied;
}

static int isbdm_rx_pbl(int *pbl_idx, struct isbdm_mem *mem, u64 addr,
			void *src, int len)
{
	struct isbdm_pbl *pbl = mem->pbl;
	u64 offset = addr - mem->va;
	int copied = 0;

	while (len) {
		int bytes;
		dma_addr_t buf_addr =
			isbdm_pbl_get_buffer(pbl, offset, &bytes, pbl_idx);

		if (!buf_addr)
			break;

		bytes = min(bytes, len);
		memcpy((void *)(uintptr_t)buf_addr, src, bytes);
		copied += bytes;
		offset += bytes;
		src += bytes;
		len -= bytes;
	}

	return copied;
}

/*
 * isbdm_rx_complete()
 *
 * Complete processing of an RX message, or abort processing after encountering
 * an error case.
 */
static int isbdm_rx_complete(struct isbdm_qp *qp,
			     struct isbdm_wqe *wqe,
			     struct isbdm_packet_header *hdr,
			     int error)
{
	enum isbdm_wc_status wc_status = wqe->wc_status;
	struct isbdm *ii = qp->sdev->ii;
	u32 imm_or_stag = 0;
	u32 wc_flags = 0;
	int rv = 0;

	switch (hdr->type) {
	case ISBDM_PACKET_IB_SEND:
	case ISBDM_PACKET_IB_SEND_INVALIDATE:
	case ISBDM_PACKET_IB_SEND_WITH_IMMEDIATE:
		if (hdr->flags & ISBDM_PACKET_FLAG_SOLICITED)
			wqe->rqe.flags |= ISBDM_WQE_SOLICITED;

		if (error != 0 && wc_status == ISBDM_WC_SUCCESS)
			wc_status = ISBDM_WC_GENERAL_ERR;

		if (wc_status == ISBDM_WC_SUCCESS) {
			/* Handle STag invalidation request */
			if (hdr->type == ISBDM_PACKET_IB_SEND_INVALIDATE) {
				imm_or_stag = le32_to_cpu(hdr->invalidate_rkey);
				wc_flags = ISBDM_WQE_REM_INVAL;
				rv = isbdm_invalidate_stag(qp->pd, imm_or_stag);
				if (rv) {
					dev_warn(&ii->pdev->dev,
						 "%s: Invalidate STag %x: %d\n",
						 __func__,
						 imm_or_stag,
						 rv);
				}

			/* Pluck out an immediate if there was one. */
			} else if (hdr->type ==
				   ISBDM_PACKET_IB_SEND_WITH_IMMEDIATE) {

				imm_or_stag = le32_to_cpu(hdr->imm_data);
				wc_flags = ISBDM_WQE_HAS_IMMEDIATE;
			}
		}

		rv = isbdm_rqe_complete(qp, &wqe->rqe, wqe->processed,
					wc_flags, imm_or_stag, hdr->src_lid,
					hdr->src_qp, wc_status);

		isbdm_wqe_put_mem(wqe, ISBDM_OP_RECEIVE);
		break;

	default:
		isbdm_dbg_qp(qp, "Unknown RX op %d\n", hdr->type);
		break;
	}

	return rv;
}

/* Handle an incoming send. */
static void isbdm_process_ib_recv(struct isbdm *ii,
				  struct isbdm_packet_header *hdr,
				  struct list_head *packet_list,
				  bool is_loopback)
{
	struct isbdm_buf *buf;
	struct isbdm_device *sdev = ii->ib_device;
	u32 dest_qp_id = le32_to_cpu(hdr->dest_qp);
	struct isbdm_qp *qp = isbdm_qp_id2obj(sdev, dest_qp_id);
	bool has_grh = (qp->base_qp.qp_type == IB_QPT_UD) ||
		       (qp->base_qp.qp_type == IB_QPT_GSI) ||
		       (qp->base_qp.qp_type == IB_QPT_SMI);
	u32 rcvd_bytes = 0;
	size_t buf_off = sizeof(*hdr);
	int pbl_idx = 0;
	size_t sge_idx = 0;
	size_t sge_off = 0;
	size_t size = 0;
	struct isbdm_wqe *wqe = NULL;
	struct ib_grh grh;
	int rv;

	if (!qp) {
		dev_warn(&ii->pdev->dev,
			 "Dropping RX packet with unknown QP %x\n",
			 dest_qp_id);

		return;
	}

	if ((qp->attrs.state != ISBDM_QP_STATE_RTR) &&
	    (qp->attrs.state != ISBDM_QP_STATE_RTS)) {

		isbdm_dbg_qp(qp,
			     "Dropping RX packet in state %d\n",
			     qp->attrs.state);

		goto out;
	}

	if (has_grh) {
		memset(&grh, 0, sizeof(grh));
		grh.dgid.global.interface_id = cpu_to_be64(isbdm_gid(sdev->ii));
		if (is_loopback)
			grh.sgid = grh.dgid;
		else
			grh.sgid.global.interface_id =
					cpu_to_be64(hdr->src_lid);
	}

	wqe = &qp->rx_ctx.wqe_active;
	rv = isbdm_rqe_get(qp, wqe);
	if (unlikely(rv)) {
		isbdm_dbg_qp(qp, "Dropping RX packet, no RQEs\n");
		wqe = NULL;
		goto out;
	}

	list_for_each_entry(buf, packet_list, node) {
		size += buf->size;
	}

	size -= sizeof(*hdr);
	buf = container_of(packet_list->next, struct isbdm_buf, node);
	while (size) {
		struct ib_pd *pd;
		struct isbdm_mem **mem, *mem_p;
		struct isbdm_sge *sge;
		void *src;
		u32 sge_bytes; /* data bytes avail for SGE */

		if (sge_idx >= wqe->rqe.num_sge) {
			dev_warn(&ii->pdev->dev,
				 "RQE overflow: %zd SGEs: RXed %x/%zx bytes\n",
				 sge_idx,
				 rcvd_bytes,
				 size + rcvd_bytes);

			break;
		}

		sge = &wqe->rqe.sge[sge_idx];
		if (!sge->length) {
			/* just skip empty SGEs */
			sge_idx++;
			sge_off = 0;
			pbl_idx = 0;
			continue;
		}

		sge_bytes = min(size, sge->length - sge_off);

		/* The first few bytes are a header, then comes real data. */
		if (has_grh && (rcvd_bytes < sizeof(grh))) {
			sge_bytes = min(sge_bytes,
					(u32)sizeof(grh) - rcvd_bytes);

			src = (void *)&grh + rcvd_bytes;

		} else {
			sge_bytes = min(sge_bytes, (u32)(buf->size - buf_off));
			src = buf->buf + buf_off;
		}

		mem = &wqe->mem[sge_idx];

		/*
		 * check with QP's PD if no SRQ present, SRQ's PD otherwise
		 */
		pd = qp->srq == NULL ? qp->pd : qp->srq->base_srq.pd;
		pd = qp->pd;
		rv = isbdm_check_sge(pd, sge, mem, IB_ACCESS_LOCAL_WRITE,
				     sge_off, sge_bytes);

		if (unlikely(rv)) {
			isbdm_qp_event(qp, IB_EVENT_QP_ACCESS_ERR);
			goto out;
		}

		mem_p = *mem;
		if (mem_p->mem_obj == NULL) {
			memcpy((void *)(uintptr_t)(sge->laddr + sge_off),
			       src,
			       sge_bytes);

			rv = sge_bytes;

		} else if (!mem_p->is_pbl) {
			rv = isbdm_rx_umem(qp, mem_p->umem,
					   sge->laddr + sge_off,
					   src, sge_bytes);

		} else {
			rv = isbdm_rx_pbl(&pbl_idx, mem_p,
					  sge->laddr + sge_off,
					  src, sge_bytes);

		}

		if (unlikely(rv != sge_bytes)) {
			wqe->processed += rcvd_bytes;
			dev_warn(&ii->pdev->dev, "Failed RX copy\n");
			rv = -EINVAL;
			goto out;
		}

		sge_off += rv;
		if (sge_off == sge->length) {
			sge_idx++;
			sge_off = 0;
			pbl_idx = 0;
		}

		rcvd_bytes += rv;

		/* Finish receiving the header before advancing the buffer. */
		if (has_grh && (rcvd_bytes <= sizeof(grh)))
			continue;

		buf_off += rv;
		if (buf_off == buf->size) {
			buf = container_of(buf->node.next,
					   struct isbdm_buf,
					   node);

			buf_off = 0;
		}

		size -= rv;
	}

	wqe->processed += rcvd_bytes;
	dev_dbg(&ii->pdev->dev,
		"Recv length 0x%x QP%d->%d\n",
		wqe->processed,
		hdr->src_qp,
		hdr->dest_qp);

	rv = 0;

out:
	if (wqe) {

		WARN_ON_ONCE(rv > 0);

		isbdm_rx_complete(qp, wqe, hdr, rv);
	}

	isbdm_qp_put(qp);
	return;
}

/* Process a complete received packet. The RX ring lock is already held. */
void isbdm_process_rx_packet(struct isbdm *ii, struct isbdm_buf *start,
			     struct isbdm_buf *end)
{
	LIST_HEAD(packet_list);
	struct isbdm_buf *buf, *tmp;
	struct list_head *cur, *next;
	struct isbdm_packet_header *hdr;

	if (start == NULL) {
		dev_warn(&ii->pdev->dev, "Got LS without FS\n");
		return;
	}

	/* Move everything between start and end onto the local list. */
	cur = &start->node;
	while (1) {
		next = cur->next;
		list_del(cur);
		list_add_tail(cur, &packet_list);
		if (cur == &end->node)
			break;

		cur = next;
	}

	hdr = start->buf;
	if (le32_to_cpu(start->size) < sizeof(*hdr)) {
		dev_warn(&ii->pdev->dev,
			 "Packet %x too small\n",
			 le32_to_cpu(start->size));

		goto out;
	}

	if (le16_to_cpu(hdr->magic) != ISBDM_PACKET_MAGIC) {
		dev_warn(&ii->pdev->dev, "Bad magic\n");
		goto out;
	}

	switch (hdr->type) {
	case ISBDM_PACKET_RAW:
		/* Just stick a raw packet back on the wait list. */
		list_splice_tail_init(&packet_list, &ii->rx_ring.wait_list);
		break;

	case ISBDM_PACKET_IB_SEND:
	case ISBDM_PACKET_IB_SEND_INVALIDATE:
	case ISBDM_PACKET_IB_SEND_WITH_IMMEDIATE:
		isbdm_process_ib_recv(ii, hdr, &packet_list, false);
		break;

	default:
		dev_warn(&ii->pdev->dev, "Unknown packet type %x\n", hdr->type);
		break;
	}

out:
	list_for_each_entry_safe(buf, tmp, &packet_list, node) {
		put_buf(ii, &ii->rx_ring, buf);
	}

	return;
}

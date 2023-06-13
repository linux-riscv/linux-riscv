// SPDX-License-Identifier: GPL-2.0

/* Authors: Evan Green <evan@rivosinc.com> */
/* Copyright (c) 2023 Rivos Inc. */

// #include <linux/gfp.h>
#include <rdma/ib_verbs.h>
// #include <linux/dma-mapping.h>
// #include <linux/slab.h>
#include <linux/sched/mm.h>
// #include <linux/resource.h>

#include "isbdmex.h"
#include "isbdm_mem.h"

/*
 * isbdm_mem_id2obj()
 *
 * resolves memory from stag given by id. might be called from:
 * o process context before sending out of sgl, or
 * o in softirq when resolving target memory
 */
struct isbdm_mem *isbdm_mem_id2obj(struct isbdm_device *sdev, int stag_index)
{
	struct isbdm_mem *mem;

	rcu_read_lock();
	mem = xa_load(&sdev->mem_xa, stag_index);
	if (likely(mem && kref_get_unless_zero(&mem->ref))) {
		rcu_read_unlock();
		return mem;
	}

	rcu_read_unlock();
	return NULL;
}

static void isbdm_free_plist(struct isbdm_page_chunk *chunk, int num_pages,
			     bool dirty)
{
	unpin_user_pages_dirty_lock(chunk->plist, num_pages, dirty);
}

void isbdm_umem_release(struct isbdm_umem *umem, bool dirty)
{
	struct mm_struct *mm_s = umem->owning_mm;
	int i, num_pages = umem->num_pages;

	for (i = 0; num_pages; i++) {
		int to_free = min_t(int, PAGES_PER_CHUNK, num_pages);

		isbdm_free_plist(&umem->page_chunk[i], to_free,
				 umem->writable && dirty);

		kfree(umem->page_chunk[i].plist);
		num_pages -= to_free;
	}

	atomic64_sub(umem->num_pages, &mm_s->pinned_vm);
	mmdrop(mm_s);
	kfree(umem->page_chunk);
	kfree(umem);
}

int isbdm_mr_add_mem(struct isbdm_mr *mr, struct ib_pd *pd, void *mem_obj,
		     u64 start, u64 len, int rights)
{
	struct isbdm_device *sdev = to_isbdm_dev(pd->device);
	struct isbdm_mem *mem = kzalloc(sizeof(*mem), GFP_KERNEL);
	void *oldval;
	int rv;

	if (!mem)
		return -ENOMEM;

	mem->mem_obj = mem_obj;
	mem->stag_valid = 0;
	mem->sdev = sdev;
	mem->va = start;
	mem->len = len;
	mem->pd = pd;
	/* TODO: Why does this IWARP_ACCESS_MASK exist? */
	//mem->perms = rights & IWARP_ACCESS_MASK;
	mem->perms = rights;
	kref_init(&mem->ref);
	mr->mem = mem;
	rv = isbdm_create_local_mb(mr);
	if (rv)
		goto dealloc;

	oldval = xa_store(&sdev->mem_xa, mem->stag >> 8, mem, GFP_KERNEL);
	if (IS_ERR(oldval)) {
		rv = PTR_ERR(oldval);
		goto release_rmb;
	}

	/* There shouldn't be anything leaking. */
	WARN_ON_ONCE(oldval);

	mr->base_mr.lkey = mem->stag;
	mr->base_mr.rkey = mem->stag;
	return 0;

release_rmb:
	isbdm_free_rmb(sdev->ii, isbdm_stag_to_rmbi(mem->stag));

dealloc:
	mr->mem = NULL;
	kfree(mem);
	return rv;
}

void isbdm_mr_drop_mem(struct isbdm_mr *mr)
{
	struct isbdm_mem *mem = mr->mem;
	struct isbdm_device *sdev = to_isbdm_dev(mem->pd->device);
	struct isbdm_mem *found;

	mem->stag_valid = 0;

	/* make STag invalid visible asap */
	smp_mb();
	isbdm_free_rmb(sdev->ii, isbdm_stag_to_rmbi(mem->stag));
	found = xa_erase(&mem->sdev->mem_xa, mem->stag >> 8);

	WARN_ON(found != mem);

	isbdm_mem_put(mem);
}

void isbdm_free_mem(struct kref *ref)
{
	struct isbdm_mem *mem = container_of(ref, struct isbdm_mem, ref);

	isbdm_dbg_mem(mem, "free mem, pbl: %s\n", mem->is_pbl ? "y" : "n");

	if (!mem->is_mw && mem->mem_obj) {
		if (mem->is_pbl == 0)
			isbdm_umem_release(mem->umem, true);
		else
			kfree(mem->pbl);
	}

	kfree(mem);
}

/*
 * isbdm_check_mem()
 *
 * Check protection domain, STag state, access permissions and
 * address range for memory object.
 *
 * @pd:		Protection Domain memory should belong to
 * @mem:	memory to be checked
 * @addr:	starting addr of mem
 * @perms:	requested access permissions
 * @len:	len of memory interval to be checked
 *
 */
int isbdm_check_mem(struct ib_pd *pd, struct isbdm_mem *mem, u64 addr,
		    enum ib_access_flags perms, int len)
{
	if (!mem->stag_valid) {
		isbdm_dbg_pd(pd, "STag 0x%08x invalid\n", mem->stag);
		return -E_STAG_INVALID;
	}

	if (mem->pd != pd) {
		isbdm_dbg_pd(pd, "STag 0x%08x: PD mismatch\n", mem->stag);
		return -E_PD_MISMATCH;
	}

	/* Check access permissions. */
	if ((mem->perms & perms) < perms) {
		isbdm_dbg_pd(pd, "permissions 0x%08x < 0x%08x\n",
			     mem->perms, perms);

		return -E_ACCESS_PERM;
	}

	/* Check if access falls into valid memory interval. */
	if (addr < mem->va || addr + len > mem->va + mem->len) {
		isbdm_dbg_pd(pd, "MEM interval len %d\n", len);
		isbdm_dbg_pd(pd, "[0x%pK, 0x%pK] out of bounds\n",
			     (void *)(uintptr_t)addr,
			     (void *)(uintptr_t)(addr + len));

		isbdm_dbg_pd(pd, "[0x%pK, 0x%pK] STag=0x%08x\n",
			     (void *)(uintptr_t)mem->va,
			     (void *)(uintptr_t)(mem->va + mem->len),
			     mem->stag);

		return -E_BASE_BOUNDS;
	}

	return E_ACCESS_OK;
}

/*
 * isbdm_check_sge()
 *
 * Check SGE for access rights in given interval
 *
 * @pd:		Protection Domain memory should belong to
 * @sge:	SGE to be checked
 * @mem:	location of memory reference within array
 * @perms:	requested access permissions
 * @off:	starting offset in SGE
 * @len:	len of memory interval to be checked
 *
 * NOTE: Function references SGE's memory object (mem->obj)
 * if not yet done. New reference is kept if check went ok and
 * released if check failed. If mem->obj is already valid, no new
 * lookup is being done and mem is not released if check fails.
 */
int isbdm_check_sge(struct ib_pd *pd, struct isbdm_sge *sge,
		    struct isbdm_mem **mem, enum ib_access_flags perms,
		    u32 off, int len)
{
	struct isbdm_device *sdev = to_isbdm_dev(pd->device);
	struct isbdm_mem *new = NULL;
	int rv = E_ACCESS_OK;

	if (len + off > sge->length) {
		rv = -E_BASE_BOUNDS;
		goto fail;
	}

	if (*mem == NULL) {
		/* The shift by 8 shaves off the key, leaving just the index. */
		new = isbdm_mem_id2obj(sdev, sge->lkey >> 8);
		if (unlikely(!new)) {
			isbdm_dbg_pd(pd, "STag unknown: 0x%08x\n", sge->lkey);
			rv = -E_STAG_INVALID;
			goto fail;
		}

		*mem = new;
	}

	/* Check if user re-registered with different STag key */
	if (unlikely((*mem)->stag != sge->lkey)) {
		isbdm_dbg_mem((*mem), "STag mismatch: 0x%08x\n", sge->lkey);
		rv = -E_STAG_INVALID;
		goto fail;
	}

	rv = isbdm_check_mem(pd, *mem, sge->laddr + off, perms, len);
	if (unlikely(rv))
		goto fail;

	return 0;

fail:
	if (new) {
		*mem = NULL;
		isbdm_mem_put(new);
	}

	return rv;
}

void isbdm_wqe_put_mem(struct isbdm_wqe *wqe, enum isbdm_opcode op)
{
	switch (op) {
	case ISBDM_OP_SEND:
	case ISBDM_OP_WRITE:
	case ISBDM_OP_SEND_WITH_IMM:
	case ISBDM_OP_SEND_REMOTE_INV:
	case ISBDM_OP_READ:
	case ISBDM_OP_READ_LOCAL_INV:
	case ISBDM_OP_COMP_AND_SWAP:
	case ISBDM_OP_FETCH_AND_ADD:
		if (!(wqe->sqe.flags & ISBDM_WQE_INLINE))
			isbdm_unref_mem_sgl(wqe->mem, wqe->sqe.num_sge);

		break;

	case ISBDM_OP_RECEIVE:
		isbdm_unref_mem_sgl(wqe->mem, wqe->rqe.num_sge);
		break;

	default:
		/*
		 * ISBDM_OP_INVAL_STAG and ISBDM_OP_REG_MR
		 * do not hold memory references
		 */
		break;
	}
}

int isbdm_invalidate_stag(struct ib_pd *pd, u32 stag)
{
	struct isbdm_device *sdev = to_isbdm_dev(pd->device);
	struct isbdm_mem *mem = isbdm_mem_id2obj(sdev, stag >> 8);
	int rv = 0;

	if (unlikely(!mem)) {
		isbdm_dbg_pd(pd, "STag 0x%08x unknown\n", stag);
		return -EINVAL;
	}

	if (unlikely(mem->pd != pd)) {
		isbdm_dbg_pd(pd, "PD mismatch for STag 0x%08x\n", stag);
		rv = -EACCES;
		goto out;
	}

	/*
	 * Per RDMA verbs definition, an STag may already be in invalid
	 * state if invalidation is requested. So no state check here.
	 */
	mem->stag_valid = 0;
	isbdm_dbg_pd(pd, "STag 0x%08x now invalid\n", stag);

out:
	isbdm_mem_put(mem);
	return rv;
}

/*
 * Gets physical address backed by PBL element. Address is referenced
 * by linear byte offset into list of variably sized PB elements.
 * Optionally, provides remaining len within current element, and
 * current PBL index for later resume at same element.
 */
dma_addr_t isbdm_pbl_get_buffer(struct isbdm_pbl *pbl, u64 off, int *len,
				int *idx)
{
	int i = idx ? *idx : 0;

	while (i < pbl->num_buf) {
		struct isbdm_pble *pble = &pbl->pbe[i];

		if (pble->pbl_off + pble->size > off) {
			u64 pble_off = off - pble->pbl_off;

			if (len)
				*len = pble->size - pble_off;

			if (idx)
				*idx = i;

			return pble->addr + pble_off;
		}

		i++;
	}

	if (len)
		*len = 0;

	return 0;
}

/*
 * TODO: Is all the pbl stuff necessary given that ISBDM only has one segment
 * per MR?
 */
struct isbdm_pbl *isbdm_pbl_alloc(u32 num_buf)
{
	struct isbdm_pbl *pbl;

	if (num_buf == 0)
		return ERR_PTR(-EINVAL);

	pbl = kzalloc(struct_size(pbl, pbe, num_buf), GFP_KERNEL);
	if (!pbl)
		return ERR_PTR(-ENOMEM);

	pbl->max_buf = num_buf;
	return pbl;
}

struct isbdm_umem *isbdm_umem_get(u64 start, u64 len, bool writable)
{
	struct isbdm_umem *umem;
	struct mm_struct *mm_s;
	u64 first_page_va;
	unsigned long mlock_limit;
	unsigned int foll_flags = FOLL_LONGTERM;
	int num_pages, num_chunks, i, rv = 0;

	/* TODO: Remove all this pinning, when PRI works it's not necessary. */
	if (!can_do_mlock())
		return ERR_PTR(-EPERM);

	if (!len)
		return ERR_PTR(-EINVAL);

	first_page_va = start & PAGE_MASK;
	num_pages = PAGE_ALIGN(start + len - first_page_va) >> PAGE_SHIFT;
	num_chunks = (num_pages >> CHUNK_SHIFT) + 1;
	umem = kzalloc(sizeof(*umem), GFP_KERNEL);
	if (!umem)
		return ERR_PTR(-ENOMEM);

	mm_s = current->mm;
	umem->owning_mm = mm_s;
	umem->writable = writable;
	mmgrab(mm_s);
	if (writable)
		foll_flags |= FOLL_WRITE;

	mmap_read_lock(mm_s);
	mlock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	if (atomic64_add_return(num_pages, &mm_s->pinned_vm) > mlock_limit) {
		rv = -ENOMEM;
		goto out_sem_up;
	}

	umem->fp_addr = first_page_va;
	umem->page_chunk = kcalloc(num_chunks,
				   sizeof(struct isbdm_page_chunk),
				   GFP_KERNEL);

	if (!umem->page_chunk) {
		rv = -ENOMEM;
		goto out_sem_up;
	}

	for (i = 0; num_pages; i++) {
		int nents = min_t(int, num_pages, PAGES_PER_CHUNK);
		struct page **plist =
			kcalloc(nents, sizeof(struct page *), GFP_KERNEL);

		if (!plist) {
			rv = -ENOMEM;
			goto out_sem_up;
		}

		umem->page_chunk[i].plist = plist;
		while (nents) {
			rv = pin_user_pages(first_page_va, nents, foll_flags,
					    plist, NULL);
			if (rv < 0)
				goto out_sem_up;

			umem->num_pages += rv;
			first_page_va += rv * PAGE_SIZE;
			plist += rv;
			nents -= rv;
			num_pages -= rv;
		}
	}

out_sem_up:
	mmap_read_unlock(mm_s);
	if (rv > 0)
		return umem;

	/* Adjust accounting for pages not pinned */
	if (num_pages)
		atomic64_sub(num_pages, &mm_s->pinned_vm);

	isbdm_umem_release(umem, false);
	return ERR_PTR(rv);
}

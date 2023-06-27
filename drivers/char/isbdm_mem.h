/* SPDX-License-Identifier: GPL-2.0 */

/* Authors: Evan Green <evan@rivosinc.com> */
/* Copyright (c) 2023 Rivos Inc. */

#ifndef _ISBDM_MEM_H
#define _ISBDM_MEM_H

struct isbdm_umem *isbdm_umem_get(u64 start, u64 len, bool writable);
void isbdm_umem_release(struct isbdm_umem *umem, bool dirty);
struct isbdm_pbl *isbdm_pbl_alloc(u32 num_buf);
dma_addr_t isbdm_pbl_get_buffer(struct isbdm_pbl *pbl, u64 off, int *len,
				int *idx);
struct isbdm_mem *isbdm_mem_id2obj(struct isbdm_device *sdev, int stag_index);
int isbdm_invalidate_stag(struct ib_pd *pd, u32 stag);
int isbdm_check_mem(struct ib_pd *pd, struct isbdm_mem *mem, u64 addr,
		    enum ib_access_flags perms, int len);
int isbdm_check_sge(struct ib_pd *pd, struct isbdm_sge *sge,
		    struct isbdm_mem **mem, enum ib_access_flags perms,
		    u32 off, int len);
void isbdm_wqe_put_mem(struct isbdm_wqe *wqe, enum isbdm_opcode op);
int isbdm_mr_add_mem(struct isbdm_mr *mr, struct ib_pd *pd, void *mem_obj,
		     u64 start, u64 len, int rights);
void isbdm_mr_drop_mem(struct isbdm_mr *mr);
void isbdm_free_mem(struct kref *ref);

static inline void isbdm_mem_put(struct isbdm_mem *mem)
{
	kref_put(&mem->ref, isbdm_free_mem);
}

static inline void isbdm_unref_mem_sgl(struct isbdm_mem **mem,
				       unsigned int num_sge)
{
	while (num_sge) {
		if (*mem == NULL)
			break;

		isbdm_mem_put(*mem);
		*mem = NULL;
		mem++;
		num_sge--;
	}
}

#define CHUNK_SHIFT 9 /* sets number of pages per chunk */
#define PAGES_PER_CHUNK (_AC(1, UL) << CHUNK_SHIFT)
#define CHUNK_MASK (~(PAGES_PER_CHUNK - 1))
#define PAGE_CHUNK_SIZE (PAGES_PER_CHUNK * sizeof(struct page *))

/*
 * isbdm_get_upage()
 *
 * Get page pointer for address on given umem.
 *
 * @umem: two dimensional list of page pointers
 * @addr: user virtual address
 */
static inline struct page *isbdm_get_upage(struct isbdm_umem *umem, u64 addr)
{
	unsigned int page_idx = (addr - umem->fp_addr) >> PAGE_SHIFT;
	unsigned int chunk_idx = page_idx >> CHUNK_SHIFT;
	unsigned int page_in_chunk = page_idx & ~CHUNK_MASK;

	if (likely(page_idx < umem->num_pages))
		return umem->page_chunk[chunk_idx].plist[page_in_chunk];

	return NULL;
}

#endif

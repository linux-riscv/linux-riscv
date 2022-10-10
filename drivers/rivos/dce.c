
#include <asm-generic/int-ll64.h>
#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/iommu.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/pci_regs.h>
#include <linux/of_device.h>
#include <linux/mm.h>
#include <linux/workqueue.h>

#include "dce.h"

static dev_t dev_num;
static struct dce_driver_priv *dce_priv;

uint64_t dce_reg_read(struct dce_driver_priv *priv, int reg) {
	uint64_t result = ioread64((void __iomem *)(priv->mmio_start + reg));
	// printk(KERN_INFO "Read 0x%llx from address 0x%llx\n", result, priv->mmio_start + reg);
	return result;
}

void dce_reg_write(struct dce_driver_priv *priv, int reg, uint64_t value) {
	// printk(KERN_INFO "Writing 0x%llx to address 0x%llx\n", value, priv->mmio_start + reg);
	iowrite64(value, (void __iomem *)(priv->mmio_start + reg));
}

DescriptorRing * get_desc_ring(struct dce_driver_priv *priv, int wq_num) {
	return &priv->wq[wq_num].descriptor_ring;
}

void clean_up_work(struct work_struct *work) {
	/* FIXME: check which WQ has interrupt pending */

	uint64_t irq_sts = dce_reg_read(dce_priv, DCE_REG_WQIRQSTS);
	// printk(KERN_INFO "Doing important cleaning up work! IRQSTS: 0x%lx\n", irq_sts);

	for(int wq_num = 0; wq_num < NUM_WQ; wq_num++) {
		/* break early if we are done */
		if (!irq_sts) break;
		if (irq_sts & BIT(wq_num)) {
			DescriptorRing * ring = get_desc_ring(dce_priv, wq_num);
			int head = ring->hti->head;
			int curr = ring->clean_up_index;

			while(curr < head) {
				// printk(KERN_INFO "curr :%d, head: %d\n", curr, head);
				/* for every clean up, notify user via eventfd when applicable */
				if (dce_priv->wq[wq_num].efd_ctx_valid) {
					// printk(KERN_INFO "eventfd signalling 0x%lx\n", (uint64_t)dce_priv->wq[wq_num].efd_ctx);
					eventfd_signal(dce_priv->wq[wq_num].efd_ctx, 1);
				}

				int index = (curr % ring->length);
				for(int i = 0; i < NUM_SG_TBLS; i++){
					if (!ring->sg_tables[i][curr].sgl) continue;
					// printk(KERN_INFO "Working on wq %d, index %d", wq_num, i);
					/* unmap the DMA mappings */
					dma_unmap_sg(dce_priv->pci_dev, ring->sg_tables[i][curr].sgl,
						ring->sg_tables[i][curr].orig_nents,
						ring->dma_direction[i][curr]);

					kfree(ring->sg_tables[i][curr].sgl);
					/* unmap the hw_addr */

					kfree(ring->hw_addr[i][curr]);

					/*zero the thing */
					ring->sg_tables[i][curr].sgl = 0;
					ring->sg_tables[i][curr].orig_nents = 0;
					ring->hw_addr[i][curr] = 0;
				}
				curr++;
			}
			ring->clean_up_index = curr;
			irq_sts &= ~BIT(wq_num);
		}
	}

	dce_reg_write(dce_priv, DCE_REG_WQIRQSTS, 0);
}

struct qemu_dce_ctx {
	struct dce_driver_priv *dev;
	struct iommu_sva *sva;
	unsigned int pasid;
};

int dce_ops_open(struct inode *inode, struct file *file)
{
	file->private_data = container_of(inode->i_cdev, struct dce_driver_priv, cdev);
	struct dce_driver_priv *dev = file->private_data;
	struct qemu_dce_ctx * ctx;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->dev = dev;
	ctx->sva = NULL;
	ctx->pasid = 0;

	if (dev->sva_enabled) {
		ctx->sva = iommu_sva_bind_device(dev->pci_dev, current->mm, NULL);
		if (IS_ERR(ctx->sva)) {
			ret = PTR_ERR(ctx->sva);
			dev_err(dev->pci_dev, "SVA allocation failed: %d.\n", ret);
			kfree(ctx);
			return -ENODEV;
		}
		else {
			printk(KERN_INFO "SVA allocation success!\n");
		}
		ctx->pasid = iommu_sva_get_pasid(ctx->sva);
		// printk(KERN_INFO "PASID assigned is %d\n", ctx->pasid);
		if (ctx->pasid == IOMMU_PASID_INVALID) {
			dev_err(dev->pci_dev, "PASID allocation failed.\n");
			iommu_sva_unbind_device(ctx->sva);
			kfree(ctx);
			return -ENODEV;
		}
		else {
			printk(KERN_INFO "PASID allocation success!\n");
		}
	}
	/* keep sva context linked to the file */
	file->private_data = ctx;

	return 0;
}

int dce_ops_release(struct inode *inode, struct file *file)
{
	struct qemu_dce_ctx *ctx = file->private_data;
	struct dce_driver_priv *priv = ctx->dev;
	/* FIXME: do we need lock here? */
	mutex_lock(&priv->lock);
	for(int wq_num = 1; wq_num < NUM_WQ; wq_num++) {
		if (priv->wq[wq_num].owner == file) {
			// printk(KERN_INFO "Unassigning file handle 0x%lx from slot %u\n", file, wq_num);
			priv->wq[wq_num].owner = 0;

			/* Clear the enable bit in dce */
			uint64_t wq_enable = dce_reg_read(priv, DCE_REG_WQENABLE);
			wq_enable &= (~BIT(wq_num));
			dce_reg_write(priv, DCE_REG_WQENABLE, wq_enable);

			/* mark the WQ as disabled in driver */
			priv->wq[wq_num].enable = false;

			/* Clean up the eventfd ctx */
			if (priv->wq[wq_num].efd_ctx_valid)
				eventfd_ctx_put(priv->wq[wq_num].efd_ctx);

			priv->wq[wq_num].efd_ctx_valid = false;
			priv->wq[wq_num].efd_ctx = 0;
			break;
		}
	}
	if (ctx->sva) {
		iommu_sva_unbind_device(ctx->sva);
	}
	kfree(ctx);
	mutex_unlock(&priv->lock);
	// printk(KERN_INFO "Closing file 0x%lx\n", file);
	/* FIXME: Identify and free all allocated memories */
	return 0;
}

ssize_t dce_ops_write(struct file *fp, const char __user *buf, size_t count, loff_t *ppos)
{
	return 0;
}

ssize_t dce_ops_read(struct file *fp, char __user *buf, size_t count, loff_t *ppos)
{
	return 0;
}

/* compute number of descriptors in a WQ using DSCSZ */
static int get_num_desc_for_wq(struct dce_driver_priv *priv, int wq_num) {
	int DSCSZ = priv->WQIT[wq_num].DSCSZ;
	int num_desc = DEFAULT_NUM_DSC_PER_WQ;
	while (DSCSZ--) num_desc *= 2;
	return num_desc;
}

static void dce_push_descriptor(struct dce_driver_priv *priv, DCEDescriptor* descriptor, int wq_num)
{
	DescriptorRing * ring = get_desc_ring(priv, wq_num);
	uint64_t tail_idx = ring->hti->tail;
	uint64_t base = ring->descriptors;
	int num_desc_in_wq = get_num_desc_for_wq(priv, wq_num);
	uint8_t * tail_ptr = base + ((tail_idx % num_desc_in_wq) * sizeof(DCEDescriptor));

	// TODO: handle the case where ring will be full
	// TODO: something here with error handling
	memcpy(tail_ptr, descriptor, sizeof(DCEDescriptor));
	wmb();
	/* increment tail index */
	ring->hti->tail++;
	wmb();
	/* notify DCE */
	uint64_t WQCR_REG = ((wq_num + 1) * PAGE_SIZE) + DCE_REG_WQCR;
	dce_reg_write(priv, WQCR_REG, 1);
	// TODO: release semantics here
}

static uint64_t setup_dma_for_user_buffer(struct dce_driver_priv *drv_priv, int index, bool * result_is_list,
                                          uint8_t __user * user_ptr, size_t size, uint8_t dma_direction, int wq_num) {
	int i, count;
	int first, last, nr_pages;
	struct scatterlist * sg;
	struct scatterlist * sglist;

	DescriptorRing * ring = get_desc_ring(drv_priv, wq_num);

	uint64_t tail_idx = ring->hti->tail;
	first = ((uint64_t)user_ptr & PAGE_MASK) >> PAGE_SHIFT;
	last  = (((uint64_t)user_ptr + size - 1) & PAGE_MASK) >> PAGE_SHIFT;
	nr_pages = last - first + 1;
	struct page * pages[nr_pages];

	int flag = (dma_direction == DMA_FROM_DEVICE) ? FOLL_WRITE : 0;

	// printk(KERN_INFO"User address is 0x%lx\n", user_ptr);
	int ret = get_user_pages_fast(user_ptr, nr_pages, flag, pages);
	// printk(KERN_INFO"get_user_pages_fast return value is %d, nrpages is %d\n", ret, nr_pages);

	/* FIXME needs to be freed */
	ring->dma_direction[index][tail_idx] = dma_direction;
	ring->sg_tables[index][tail_idx].sgl =
		kzalloc(nr_pages * sizeof(struct scatterlist), GFP_KERNEL);
	ring->sg_tables[index][tail_idx].orig_nents = nr_pages;

	sglist = ring->sg_tables[index][tail_idx].sgl;
	for (int i = 0; i < nr_pages; i++) {
		uint64_t _size, _offset = 0;
		if (i == 0) {
			/* first page */
			_size = offset_in_page(user_ptr) + size > PAGE_SIZE ?
								 (PAGE_SIZE - offset_in_page(user_ptr)) :
								 size;
			_offset = offset_in_page(user_ptr);
		} else if (i == nr_pages - 1) {
			/* last page */
			_size = offset_in_page(user_ptr + size);
			if (_size == 0) _size = PAGE_SIZE;
		} else {
			/* middle pages */
			_size = PAGE_SIZE;
		}
		// printk(KERN_INFO"parameters passed to sg_set_page: 0x%lx, 0x%lx, 0x%lx", pages[i], _size, _offset);
		sg_set_page(&sglist[i], pages[i], _size, _offset);
	}
	/* FIXME: dma_unmap_sg when appropriate */
	count = dma_map_sg(drv_priv->pci_dev, sglist, nr_pages, dma_direction);
	// printk(KERN_INFO "Count is %d\n", count);
	if (count > 1)
		*result_is_list = true;

	/* FIXME needs to be freed */
	ring->sg_tables[index][tail_idx].nents = count;
	ring->hw_addr[index][tail_idx] = kzalloc(count * sizeof(DataAddrNode), GFP_KERNEL);

	for_each_sg(sglist, sg, count, i) {
		ring->hw_addr[index][tail_idx][i].ptr = sg_dma_address(sg);
		ring->hw_addr[index][tail_idx][i].size = sg_dma_len(sg);
		// printk(KERN_INFO "Address 0x%lx, Size 0x%lx\n", sg_dma_address(sg), sg_dma_len(sg));
	}

	// printk(KERN_INFO "num_dma_entries: %d, Address is 0x%lx\n", num_dma_entries, sg_dma_address(&sg[0]));
	if (count > 1) {
		return dma_map_single(drv_priv->pci_dev,
					ring->hw_addr[index][tail_idx],
					count, dma_direction);
	}
	else return (uint64_t)(ring->hw_addr[index][tail_idx][0].ptr);
}

void parse_descriptor_based_on_opcode(struct dce_driver_priv *drv_priv,
	struct DCEDescriptor * desc, struct DCEDescriptor * input, int wq_num,
	struct qemu_dce_ctx *ctx)
{
	size_t size, dest_size, iv_size, aad_size;
	bool src_is_list = false;
	bool src2_is_list = false;
	bool dest_is_list = false;

	desc->opcode = input->opcode;
	desc->ctrl = input->ctrl | 1;
	desc->operand0 = input->operand0;
	desc->pasid = 0;

	/* Default handling of operands */
	desc->source = input->source;
	desc->destination = input->destination;
	desc->completion = input->completion;
	desc->operand1 = input->operand1;
	desc->operand2 = input->operand2;
	desc->operand3 = input->operand3;
	desc->operand4 = input->operand4;

	/* no need for DMA setup */
	if (ctx->sva) {
		// Set the pasid and valid bits
		desc->pasid = ctx->pasid;
		desc->ctrl |= PASID_VALID;
		// printk(KERN_INFO "Setting PASID fields");
		return;
	}


	size = desc->operand1;
	dest_size = (desc->opcode == DCE_OPCODE_MEMCMP && !(desc->operand0 & 1)) ?
				8 : size;
	/* Override based on opcode */
	switch (desc->opcode)
	{
		case DCE_OPCODE_MEMCMP:
			/* src2 */
			desc->source = setup_dma_for_user_buffer(drv_priv, SRC,
				&src_is_list, (uint8_t __user *)input->source,
				size, DMA_TO_DEVICE, wq_num);
			desc->operand2 = setup_dma_for_user_buffer(drv_priv, SRC2,
				&src2_is_list, (uint8_t __user *)input->operand2,
				size, DMA_TO_DEVICE, wq_num);
			desc->destination = setup_dma_for_user_buffer(drv_priv, DEST,
				&dest_is_list, (uint8_t __user *)input->destination,
				dest_size, DMA_FROM_DEVICE, wq_num);
			break;
		case DCE_OPCODE_ENCRYPT:
		case DCE_OPCODE_DECRYPT:
		case DCE_OPCODE_MEMCPY:
			desc->source = setup_dma_for_user_buffer(drv_priv, SRC,
				&src_is_list, (uint8_t __user *)input->source,
				size, DMA_TO_DEVICE, wq_num);
			desc->destination = setup_dma_for_user_buffer(drv_priv, DEST,
				&dest_is_list, (uint8_t __user *)input->destination,
				size, DMA_FROM_DEVICE, wq_num);
			if ((desc->opcode == DCE_OPCODE_ENCRYPT ||
				desc->opcode == DCE_OPCODE_DECRYPT) &&
				(desc->operand0 & 0x10)) { /* check for GCM mode */
				// printk(KERN_INFO "Setting up for GCM mode input, %x", desc->operand0);
				iv_size = ((desc->operand3 >> 32) & 0xff);
				aad_size = ((desc->operand3 >> 48) & 0xff);

				desc->operand2 = setup_dma_for_user_buffer(drv_priv, IV,
						NULL, (uint8_t __user *)input->operand2,
						iv_size, DMA_TO_DEVICE, wq_num);
				desc->operand4 = setup_dma_for_user_buffer(drv_priv, AAD,
						NULL, (uint8_t __user *)input->operand4,
						aad_size, DMA_TO_DEVICE, wq_num);
			}
			break;
		case DCE_OPCODE_MEMSET:
			desc->destination = setup_dma_for_user_buffer(drv_priv, DEST,
				&dest_is_list, (uint8_t __user *)input->destination,
				size, DMA_FROM_DEVICE, wq_num);
			break;
		case DCE_OPCODE_COMPRESS:
		case DCE_OPCODE_DECOMPRESS:
		case DCE_OPCODE_COMPRESS_ENCRYPT:
		case DCE_OPCODE_DECRYPT_DECOMPRESS:
			desc->source = setup_dma_for_user_buffer(drv_priv, SRC,
				&src_is_list, (uint8_t __user *)input->source,
				size, DMA_TO_DEVICE, wq_num);
			desc->destination = setup_dma_for_user_buffer(drv_priv, DEST,
				&dest_is_list, (uint8_t __user *)input->destination,
				desc->operand2, DMA_FROM_DEVICE, wq_num);
			break;
		case DCE_OPCODE_LOAD_KEY:
			/* Keys are 32B */
			desc->source = setup_dma_for_user_buffer(drv_priv, SRC,
				&src_is_list, (uint8_t __user *)input->source,
				32, DMA_TO_DEVICE, wq_num);
			break;
		default:
			break;
	}

	if (src_is_list)
		desc->ctrl |= SRC_IS_LIST;
	if (src2_is_list)
		desc->ctrl |= SRC2_IS_LIST;
	if (dest_is_list)
		desc->ctrl |= DEST_IS_LIST;

	desc->completion = setup_dma_for_user_buffer(drv_priv, COMP,
		&src_is_list, (uint8_t __user *)input->completion,
		8, DMA_FROM_DEVICE, wq_num);
}

void dce_reset_descriptor_ring(struct dce_driver_priv *drv_priv, int wq_num) {
	DescriptorRing * ring = get_desc_ring(drv_priv, wq_num);
	memset(ring, 0, sizeof(DescriptorRing));
}

static void setup_memory_for_wq_from_user(struct file * file,
					  int wq_num, UserArea * ua)
{
	struct qemu_dce_ctx *ctx = file->private_data;
	size_t length = ua->numDescs;

	DescriptorRing * ring = get_desc_ring(dce_priv, wq_num);
	int size = length * sizeof(DCEDescriptor);
	/* make sure size is multiple of 4K */
	if ((size < 0x1000) || (__arch_hweight64(size) != 1)) { /* insert error here */}
	int DSCSZ = fls(size) - fls(0x1000);

	// printk(KERN_INFO"%s: DSCSZ is 0x%x\n",__func__, DSCSZ);
	dce_reset_descriptor_ring(dce_priv, wq_num);

	ring->length = length;
	ring->descriptors = ua->descriptors;
	ring->hti = ua->hti;

	dce_priv->WQIT[wq_num].DSCBA = ring->descriptors;
	dce_priv->WQIT[wq_num].DSCSZ = DSCSZ;
	dce_priv->WQIT[wq_num].DSCPTA =	ring->hti;
	/* set the PASID fields in TRANSCTL */
	dce_priv->WQIT[wq_num].TRANSCTL = FIELD_PREP(TRANSCTL_SUPV, 0) |
					  FIELD_PREP(TRANSCTL_PASID_V, 1) |
					  FIELD_PREP(TRANSCTL_PASID, ctx->pasid);


	/* set the enable bit in dce*/
	uint64_t wq_enable = dce_reg_read(dce_priv, DCE_REG_WQENABLE);
	wq_enable |= BIT(wq_num);
	dce_reg_write(dce_priv, DCE_REG_WQENABLE, wq_enable);

	/* mark the WQ as enabled in driver */
	dce_priv->wq[wq_num].enable = true;
	dce_priv->wq[wq_num].type = USER_OWNED_WQ;
}

static void setup_memory_for_wq(int wq_num, KernelQueueReq * kqr)
{
	DescriptorRing * ring = get_desc_ring(dce_priv, wq_num);

	int DSCSZ = 0;

	// Parse KernelQueueReq if provided
	if (kqr) {
		DSCSZ = kqr->DSCSZ;
		dce_priv->wq[wq_num].efd_ctx_valid = kqr->eventfd_vld;
		if (kqr->eventfd_vld)
			dce_priv->wq[wq_num].efd_ctx = eventfd_ctx_fdget(kqr->eventfd);
	}

	/* Supervisor memory setup */
	/* per DCE spec: Actual ring size is computed by: 2^(DSCSZ + 12) */
	size_t length = 0x1000 * (1 << DSCSZ) / sizeof(DCEDescriptor);
	dce_reset_descriptor_ring(dce_priv, wq_num);

	// Allcate the descriptors as coherent DMA memory
	ring->descriptors =
		dma_alloc_coherent(dce_priv->pci_dev, length * sizeof(DCEDescriptor),
			&ring->desc_dma, GFP_KERNEL);

	ring->length = length;
	// printk(KERN_INFO "Allocated wq %u descriptors at 0x%llx\n", wq_num,
	// 	(uint64_t)ring->descriptors);

	ring->hti = dma_alloc_coherent(dce_priv->pci_dev,
		sizeof(HeadTailIndex), &ring->hti_dma, GFP_KERNEL);
	ring->hti->head = 0;
	ring->hti->tail = 0;

	/* allocate the sg_table and hw_addr */
	for(int i = 0; i < NUM_SG_TBLS; i++) {
		ring->dma_direction[i] = kzalloc(length * sizeof(int), GFP_KERNEL);
		ring->sg_tables[i] = kzalloc(length * sizeof(struct sg_table), GFP_KERNEL);
		ring->hw_addr[i] = kzalloc(length * sizeof(DataAddrNode *), GFP_KERNEL);
	}

	/* populate WQITE TODO: only first one for now*/
	dce_priv->WQIT[wq_num].DSCBA = ring->desc_dma;
	dce_priv->WQIT[wq_num].DSCSZ = DSCSZ;
	dce_priv->WQIT[wq_num].DSCPTA = ring->hti_dma;
	dce_priv->WQIT[wq_num].TRANSCTL = FIELD_PREP(TRANSCTL_SUPV, 1);
	/* set the enable bit in dce*/
	uint64_t wq_enable = dce_reg_read(dce_priv, DCE_REG_WQENABLE);
	wq_enable |= BIT(wq_num);
	dce_reg_write(dce_priv, DCE_REG_WQENABLE, wq_enable);

	/* mark the WQ as enabled in driver */
	dce_priv->wq[wq_num].enable = true;
	dce_priv->wq[wq_num].type = KERNEL_WQ;
}

static void free_resources(struct dce_driver_priv *priv, DCEDescriptor * input)
{
	return;
}

static int find_wq_number(struct file * file, struct dce_driver_priv * priv) {
	bool wq_found = false;
	int wq_num = 0;
	for(wq_num = 0; wq_num < NUM_WQ; wq_num++) {
		if (priv->wq[wq_num].owner == file) {
			wq_found = true;
			break;
		}
	}
	/* error out if no WQ found */
	if (!wq_found) return -1;
	return wq_num;
}

static int assign_wq_to_fd(struct file * file, struct dce_driver_priv * priv) {
	/* start from wq num 1 as 0 is reserved for KERNEL_SHARED */
	bool found = false;
	int wq_num;
	mutex_lock(&priv->lock);
	for(wq_num = 1; wq_num < NUM_WQ; wq_num++) {
		if (priv->wq[wq_num].owner == 0) {
			priv->wq[wq_num].owner = file;
			printk(KERN_INFO "Assigning file 0x%lx to wq[%d]\n", file, wq_num);
			found = true;
			break;
		}
	}
	mutex_unlock(&priv->lock);
	/* FIXME: should not reach here, return 0 if not able to assign */
	if (found)
		return wq_num;
	else
		return 0;
}

long dce_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	uint64_t val;
	struct DCEDescriptor descriptor;
	struct qemu_dce_ctx * ctx = file->private_data;
	struct dce_driver_priv *priv = ctx->dev;

	switch (cmd) {
		case RAW_READ: {
			struct AccessInfoRead __user *__access_info;
			struct AccessInfoRead access_info;

			__access_info = (struct AccessInfoRead __user*) arg;
			if (copy_from_user(&access_info, __access_info, sizeof(access_info)))
				return -EFAULT;

			val = ioread64((void __iomem *)(priv->mmio_start + access_info.offset));
			if (copy_to_user(access_info.value, &val, 8)) {
				printk(KERN_INFO "error during ioctl!\n");
			}

			break;
		}

		case RAW_WRITE: {
			struct AccessInfoWrite __user *__access_info;
			struct AccessInfoWrite access_info;

			__access_info =	(struct AccessInfoWrite __user*) arg;
			if (copy_from_user(&access_info, __access_info, sizeof(access_info)))
				return -EFAULT;

			iowrite64(access_info.value, (void __iomem *)(priv->mmio_start + access_info.offset));

			break;
		}

		case REQUEST_KERNEL_WQ: {
			/* FIXME:
			 *	1. put inside some function
			 *	2. check a efd_valid
			 *	3. also add a numDesc for kernel WQ
			 */
			KernelQueueReq __user * __kqr_input;
			KernelQueueReq kqr = {.DSCSZ = 0, .eventfd_vld = true, .eventfd = 0};
			__kqr_input = (KernelQueueReq __user *) arg;
			if (__kqr_input)
				if (copy_from_user(&kqr, __kqr_input, sizeof(KernelQueueReq)))
					return -EFAULT;

			/* WQ shouldn't havve been assigned at this point */
			int wq_num = find_wq_number(file, priv);
			if (wq_num != -1) return -EFAULT;

			/* assign WQ to file descriptor */
			wq_num = assign_wq_to_fd(file, priv);
			// printk(KERN_INFO "Requested kernel managed WQ %d\n", wq_num);

			/* wq_num meaning falling back to shared kernel WQ */
			if (wq_num > 0)
				setup_memory_for_wq(wq_num, &kqr);

			break;
		}

		case SETUP_USER_WQ: {
			/* Check if PASID is enabled */
			if (!priv->sva_enabled)
				return -EFAULT;
			UserArea __user * __UserArea_input;
			UserArea ua;
			__UserArea_input = (struct UserArea __user *) arg;
			if (copy_from_user(&ua, __UserArea_input, sizeof(UserArea)))
				return -EFAULT;

			/* WQ shouldn't havve been assigned at this point */
			int wq_num = find_wq_number(file, priv);
			if (wq_num != -1) return -EFAULT;

			/* assign WQ to file descriptor */
			wq_num = assign_wq_to_fd(file, priv);
			if (wq_num == 0) return -EFAULT;

			/* The WQ is not enabled to be setuped already */
			setup_memory_for_wq_from_user(file, wq_num, &ua);

			break;
		}

		case SUBMIT_DESCRIPTOR: {
			struct DCEDescriptor __user *__descriptor_input;
			struct DCEDescriptor descriptor_input;

			__descriptor_input = (struct DCEDescriptor __user*) arg;
			if (copy_from_user(&descriptor_input, __descriptor_input, sizeof(descriptor_input)))
				return -EFAULT;

			/* Default to WQ 0 (Shared kernel) if not assigned */
			int wq_num = find_wq_number(file, priv);
			if (wq_num == -1)
				wq_num = 0;

			/* Make sure selected WQ is owned by Kernel */
			if (priv->wq[wq_num].type == USER_OWNED_WQ)
				return -EFAULT;

			/* WQ should be enabled at this point */
			if (priv->wq[wq_num].enable == false)
				return -EFAULT;

			parse_descriptor_based_on_opcode(priv, &descriptor, &descriptor_input, wq_num, ctx);

			// printk(KERN_INFO "pushing descriptor thru wq %d with opcode %d!\n",
			// 	wq_num, descriptor.opcode);
			// printk(KERN_INFO "submitting source 0x%lx\n", descriptor.source);
			dce_push_descriptor(priv, &descriptor, wq_num);
		}
	}

	return 0;
}

int dce_mmap(struct file *file, struct vm_area_struct *vma) {
	struct qemu_dce_ctx * ctx = file->private_data;
	struct dce_driver_priv *priv = ctx->dev;

	int wq_num = find_wq_number(file, priv);
	if (wq_num == -1) return -EFAULT;

	unsigned long pfn = phys_to_pfn(priv->mmio_start_phys);
	/* coompute the door bell page with wq num */
	pfn += (wq_num + 1);

	vma->vm_flags |= VM_IO;
	vma->vm_flags |= (VM_DONTEXPAND | VM_DONTDUMP);
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	// printk(KERN_INFO "Mappping wq %d from 0x%lx to 0x%lx\n", wq_num, vma->vm_start,pfn);

	if (io_remap_pfn_range(vma, vma->vm_start, pfn, PAGE_SIZE,
			vma->vm_page_prot)) {
		printk(KERN_INFO "Mapping failed!\n");
		return -EAGAIN;
	}
	// printk(KERN_INFO "mmap completed\n");

	return 0;
}

static const struct file_operations dce_ops = {
	.owner		= THIS_MODULE,
	.open		= dce_ops_open,
	.release	= dce_ops_release,
	.read		= dce_ops_read,
	.write		= dce_ops_write,
	.mmap 		= dce_mmap,
	.unlocked_ioctl	= dce_ioctl
};

static struct class *dce_char_class;

static irqreturn_t handle_dce(int irq, void *dev_id) {
	/* with SVA there is no per-job clean up needed */
	// if (dce_priv->sva_enabled) return IRQ_HANDLED;

	/* FIXME: multiple thread running this? */
	printk(KERN_INFO "Got interrupt %d, work scheduled!\n", irq);
	schedule_work(&dce_priv->clean_up_worker);

	return IRQ_HANDLED;
}


void setup_memory_regions(struct dce_driver_priv * drv_priv)
{
	struct device * dev = drv_priv->pci_dev;
	int err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (err) printk(KERN_INFO "DMA set mask failed: %d\n", err);

	// printk(KERN_INFO"dma_mask: 0x%lx\n",dev->dma_mask);
	/* WQIT is 4KiB */
	drv_priv->WQIT = dma_alloc_coherent(dev, 0x1000,
								  &drv_priv->WQIT_dma, GFP_KERNEL);

	// printk(KERN_INFO "Writing to DCE_REG_WQITBA!\n");
	dce_reg_write(drv_priv, DCE_REG_WQITBA,
				 (uint64_t) drv_priv->WQIT_dma);
}

static int dce_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int bar, err;

	// printk(KERN_INFO " in %s\n", __func__);
	err = pci_enable_sriov(pdev, DCE_NR_VIRTFN);

	u16 vendor, device;
	// unsigned long mmio_start,mmio_len;
	struct dce_driver_priv *drv_priv;
	struct device* dev = &pdev->dev;
	struct cdev *cdev;

	pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor);
	pci_read_config_word(pdev, PCI_DEVICE_ID, &device);
	pci_write_config_byte(pdev, PCI_COMMAND, PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
	// printk(KERN_INFO "Device vaid: 0x%X pid: 0x%X\n", vendor, device);

	err = pci_enable_device(pdev);
	if (err) goto disable_device_and_fail;

	bar = pci_select_bars(pdev, IORESOURCE_MEM);
	// printk(KERN_INFO "io bar: 0x%X\n", bar);

	err = pci_request_selected_regions(pdev, bar, DEVICE_NAME);
	if (err) goto disable_device_and_fail;


	drv_priv = kzalloc_node(sizeof(struct dce_driver_priv), GFP_KERNEL,
			     dev_to_node(dev));
	if (!drv_priv) goto disable_device_and_fail;
	dce_priv = drv_priv;

	drv_priv->pdev = pdev;
	drv_priv->pci_dev = dev;

	drv_priv->mmio_start_phys = pci_resource_start(pdev, 0);
	// mmio_len   = pci_resource_len  (pdev, 0);

	if (iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_SVA)) {
	// FIXME: Enable for testing non-SVA
	// if (1) {
		dev_warn(dev, "DCE:Unable to turn on user SVA feature.\n");
		drv_priv->sva_enabled = false;
	} else {
		dev_info(dev, "DCE:SVA feature enabled.\n");
		drv_priv->sva_enabled = true;
	}

	// initialize the child device
	dev = &drv_priv->dev;

	device_initialize(dev);
	dev->class = dce_char_class;
	dev->parent = &pdev->dev;

	dev->devt = MKDEV(MAJOR(dev_num), 0);
	dev_set_name(dev, "dce");
	cdev = &drv_priv->cdev;
	cdev_init(cdev, &dce_ops);
	cdev->owner = THIS_MODULE;

	drv_priv->mmio_start = (uint64_t)pci_iomap(pdev, 0, 0);

	pci_set_drvdata(pdev, drv_priv);

	/* priv mem regions setup */
	setup_memory_regions(drv_priv);

	err = cdev_device_add(&drv_priv->cdev, &drv_priv->dev);
	if (err) {
		printk(KERN_INFO "cdev add failed\n");
	}

	/* MSI setup */
	if (pci_match_id(pci_use_msi, pdev)) {
		dev_info(dev, "Using MSI(-X) interrupts\n");
		pci_set_master(pdev);
		err = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_ALL_TYPES);

		int vec = pci_irq_vector(pdev, 0);
		devm_request_threaded_irq(dev, vec, handle_dce, NULL, IRQF_ONESHOT, DEVICE_NAME, pdev);
	} else {
		dev_warn(dev, "DCE: MSI enable failed\n");
	}

	/* work queue setup */
	INIT_WORK(&drv_priv->clean_up_worker, clean_up_work);

	/* init mutex */
	mutex_init(&drv_priv->lock);

	/* setup WQ 0 for SHARED_KERNEL usage */
	setup_memory_for_wq(0, NULL);
	drv_priv->wq[0].type = SHARED_KERNEL_WQ;

	return 0;

	disable_device_and_fail:
		pci_disable_device(pdev);
		return err;

	free_resources_and_fail:
		pci_disable_device(pdev);
		// free_resources(dev, drv_priv);
		return err;
}

static int dev_sriov_configure(struct pci_dev *dev, int numvfs)
{
        if (numvfs > 0) {
                pci_enable_sriov(dev, numvfs);
                return numvfs;
        }
        if (numvfs == 0) {
                pci_disable_sriov(dev);
                return 0;
        }
		return 0;
}

static void dce_remove(struct pci_dev *pdev)
{
	// free_resources(&pdev->dev, pci_get_drvdata(pdev));
}

static SIMPLE_DEV_PM_OPS(vmd_dev_pm_ops, vmd_suspend, vmd_resume);

static const struct pci_device_id dce_id_table[] = {
	{ PCI_DEVICE(VENDOR_ID, DEVICE_ID) } ,
	{0, },
};
MODULE_DEVICE_TABLE(pci, dce_id_table);

static struct pci_driver dce_driver = {
	.name     = DEVICE_NAME,
	.id_table = dce_id_table,
	.probe    = dce_probe,
	.remove   = dce_remove,
	.sriov_configure = dev_sriov_configure,
	.driver	= {
		.pm = &vmd_dev_pm_ops,
	},
};

static char *pci_char_devnode(struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, DEVICE_NAME);
}

static int __init dce_driver_init(void)
{
	int err;
	err = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
	if (err) return -err;

	dce_char_class = class_create(THIS_MODULE, DEVICE_NAME);
	if (IS_ERR(dce_char_class)) {
		err = PTR_ERR(dce_char_class);
		return err;
	}

	dce_char_class->devnode = pci_char_devnode;

	err = pci_register_driver(&dce_driver);
	return err;
}

static void __exit dce_driver_exit(void)
{
	pci_unregister_driver(&dce_driver);
}

MODULE_LICENSE("GPL");

module_init(dce_driver_init);
module_exit(dce_driver_exit);

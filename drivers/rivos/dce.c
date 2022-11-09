
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

#include "dce.h"

static dev_t dev_num;

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

	struct dce_driver_priv* dce_priv =
		container_of(work, struct dce_driver_priv, clean_up_worker);

	/* getting per queue interrupt status */
	uint64_t irq_sts = dce_reg_read(dce_priv, DCE_REG_WQIRQSTS);
	// printk(KERN_INFO "Doing important cleaning up work! IRQSTS: 0x%lx\n", irq_sts);

	for(int wq_num = 0; wq_num < NUM_WQ; wq_num++) {
		/* break early if we are done */
		if (!irq_sts) break;
		if (irq_sts & BIT(wq_num)) {
			mutex_lock(&dce_priv->wq[wq_num].wq_clean_lock);
			DescriptorRing * ring = get_desc_ring(dce_priv, wq_num);
			/* Atomic read ? */
			int head = ring->hti->head;
			int curr = ring->clean_up_index;

			while(curr < head) {
				// Position in queue
				int qi = (curr % ring->length);
				// printk(KERN_INFO "curr :%d, head: %d\n", curr, head);
				/* for every clean up, notify user via eventfd when applicable
				 * TODO: Find out an optimal policy for eventfd */
				if (dce_priv->wq[wq_num].efd_ctx_valid) {
					// printk(KERN_INFO "eventfd signalling 0x%lx\n", (uint64_t)dce_priv->wq[wq_num].efd_ctx);
					eventfd_signal(dce_priv->wq[wq_num].efd_ctx, 1);
				}
				curr++;
			}
			ring->clean_up_index = curr;
			irq_sts &= ~BIT(wq_num);
			mutex_unlock(&dce_priv->wq[wq_num].wq_clean_lock);
		}
	}

	/* What if the value changed? */
	dce_reg_write(dce_priv, DCE_REG_WQIRQSTS, 0);
}

struct submitter_dce_ctx {
	struct dce_driver_priv *dev;
	struct iommu_sva *sva;
	int wq_num;
	unsigned int pasid;
};

int dce_ops_open(struct inode *inode, struct file *file)
{
	struct dce_driver_priv *dev = container_of(inode->i_cdev, struct dce_driver_priv, cdev);
	struct submitter_dce_ctx * ctx;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->dev = dev;
	ctx->sva = NULL;
	ctx->pasid = 0;
	ctx->wq_num = -1;

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
	else {
		return -EFAULT;
	}

	/* keep sva context linked to the file */
	file->private_data = ctx;

	return 0;
}

int dce_ops_release(struct inode *inode, struct file *file)
{
	struct submitter_dce_ctx *ctx = file->private_data;
	struct dce_driver_priv *priv = ctx->dev;

	int wq_num = ctx->wq_num;
	{
		struct work_queue* wq = priv->wq+wq_num;
		/* release gets called when all references to the file are dropped
		 * There should not be multiple calls to release if the fd was cloned on fork
		 * as a result, for user and owned kernel queues, we can always tear down
		 * data structures on call to release */
		if(wq->type == KERNEL_WQ || wq->type == USER_OWNED_WQ){
			/*TODO: Deal with running jobs, what is the policy? */
			printk(KERN_INFO "Unassigning file handle 0x%lx from slot %u\n", file, wq_num);
			/* clean up the descriptor ring */
			DescriptorRing * ring = get_desc_ring(priv, wq_num);
			if (ring->desc_dma) { /* only set for kernel queues */
				dma_free_coherent(priv->pci_dev, (ring->length * sizeof(DCEDescriptor)),
					ring->descriptors, ring->desc_dma);
				dma_free_coherent(priv->pci_dev, sizeof(HeadTailIndex),
					ring->hti, ring->hti_dma);
			}
			/* clean up the WQITE*/
			memset(&priv->WQIT[wq_num], 0, sizeof(WQITE));

			/* Clear the enable bit in dce */
			mutex_lock(&priv->dce_reg_lock);
			uint64_t wq_enable = dce_reg_read(priv, DCE_REG_WQENABLE);
			wq_enable &= (~BIT(wq_num));
			dce_reg_write(priv, DCE_REG_WQENABLE, wq_enable);
			mutex_unlock(&priv->dce_reg_lock);

			/* mark the WQ as disabled in driver */
			priv->wq[wq_num].type = DISABLED;

			/* Clean up the eventfd ctx */
			if (priv->wq[wq_num].efd_ctx_valid)
				eventfd_ctx_put(priv->wq[wq_num].efd_ctx);

			priv->wq[wq_num].efd_ctx_valid = false;
			priv->wq[wq_num].efd_ctx = 0;
		}
	}
	if (ctx->sva) {
		iommu_sva_unbind_device(ctx->sva);
	}
	kfree(ctx);
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
	mutex_lock(&priv->wq[wq_num].wq_tail_lock);
	DescriptorRing * ring = get_desc_ring(priv, wq_num);
	uint64_t tail_idx = ring->hti->tail;
	uint64_t head_idx = ring->hti->head;
	if (tail_idx == head_idx + 63) {
		/* TODO: ring is full, handle it, with the right size even better */
	}
	uint64_t base = ring->descriptors;
	int num_desc_in_wq = get_num_desc_for_wq(priv, wq_num);
	uint8_t * tail_ptr = base + ((tail_idx % num_desc_in_wq) * sizeof(DCEDescriptor));

	// TODO: something here with error handling
	memcpy(tail_ptr, descriptor, sizeof(DCEDescriptor));
	wmb();
	/* increment tail index */
	ring->hti->tail++;
	wmb();
	/* notify DCE */
	uint64_t WQCR_REG = ((wq_num + 1) * PAGE_SIZE) + DCE_REG_WQCR;
	dce_reg_write(priv, WQCR_REG, 1);

	mutex_unlock(&priv->wq[wq_num].wq_tail_lock);
}

static int parse_descriptor_based_on_opcode(
		struct DCEDescriptor * desc, struct DCEDescriptor * input, u32 pasid)
{
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

	// Set the pasid and valid bits
	desc->pasid = pasid;
	desc->ctrl |= PASID_VALID;
	return 0;
}

/* TODO: FIX!! This leaks the mem for descriptors and hti */
void dce_reset_descriptor_ring(struct dce_driver_priv *drv_priv, int wq_num) {
	DescriptorRing * ring = get_desc_ring(drv_priv, wq_num);
	memset(ring, 0, sizeof(DescriptorRing));
}

static void setup_memory_for_wq_from_user(struct file * file,
					  int wq_num, UserArea * ua)
{
	struct submitter_dce_ctx *ctx = file->private_data;
	struct dce_driver_priv * dce_priv = ctx->dev;
	size_t length = ua->numDescs;

	DescriptorRing * ring = get_desc_ring(dce_priv, wq_num);
	int size = length * sizeof(DCEDescriptor);
	/* make sure size is multiple of 4K */
	if ((size < 0x1000) || (__arch_hweight64(size) != 1)) { /* insert error here */}
	int DSCSZ = fls(size) - fls(0x1000);

	// printk(KERN_INFO"%s: DSCSZ is 0x%x\n",__func__, DSCSZ);
	dce_reset_descriptor_ring(dce_priv, wq_num);

	ring->length = length;
	/* TODO: Check alignment for both*/
	ring->descriptors = (DCEDescriptor *)ua->descriptors;
	ring->hti = (HeadTailIndex *)ua->hti;

	dce_priv->WQIT[wq_num].DSCBA = ring->descriptors;
	dce_priv->WQIT[wq_num].DSCSZ = DSCSZ;
	dce_priv->WQIT[wq_num].DSCPTA =	ring->hti;
	/* set the PASID fields in TRANSCTL */
	dce_priv->WQIT[wq_num].TRANSCTL = FIELD_PREP(TRANSCTL_SUPV, 0) |
					  FIELD_PREP(TRANSCTL_PASID_V, 1) |
					  FIELD_PREP(TRANSCTL_PASID, ctx->pasid);

	/* set the enable bit in dce*/
	mutex_lock(&dce_priv->dce_reg_lock);
	uint64_t wq_enable = dce_reg_read(dce_priv, DCE_REG_WQENABLE);
	wq_enable |= BIT(wq_num);
	dce_reg_write(dce_priv, DCE_REG_WQENABLE, wq_enable);
	mutex_unlock(&dce_priv->dce_reg_lock);

	/* mark the WQ as enabled in driver */
	dce_priv->wq[wq_num].type = USER_OWNED_WQ;
}

void setup_memory_for_wq(
		struct dce_driver_priv * dce_priv, int wq_num, KernelQueueReq * kqr)
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
	// TODO: Error handling, alloc DMA can fail
	ring->descriptors =
		dma_alloc_coherent(dce_priv->pci_dev, length * sizeof(DCEDescriptor),
			&ring->desc_dma, GFP_KERNEL);

	ring->length = length;
	// printk(KERN_INFO "Allocated wq %u descriptors at 0x%llx\n", wq_num,
	// 	(uint64_t)ring->descriptors);

	// TODO: Error handling, alloc DMA can fail
	ring->hti = dma_alloc_coherent(dce_priv->pci_dev,
		sizeof(HeadTailIndex), &ring->hti_dma, GFP_KERNEL);
	ring->hti->head = 0;
	ring->hti->tail = 0;

	/* populate WQITE */
	dce_priv->WQIT[wq_num].DSCBA = ring->desc_dma;
	dce_priv->WQIT[wq_num].DSCSZ = DSCSZ;
	dce_priv->WQIT[wq_num].DSCPTA = ring->hti_dma;
	dce_priv->WQIT[wq_num].TRANSCTL = FIELD_PREP(TRANSCTL_SUPV, 1);
	/* set the enable bit in dce*/
	mutex_lock(&dce_priv->dce_reg_lock);
	uint64_t wq_enable = dce_reg_read(dce_priv, DCE_REG_WQENABLE);
	wq_enable |= BIT(wq_num);
	dce_reg_write(dce_priv, DCE_REG_WQENABLE, wq_enable);
	mutex_unlock(&dce_priv->dce_reg_lock);

	/* mark the WQ as enabled in driver */
	dce_priv->wq[wq_num].type = KERNEL_WQ;
}

static void init_wq(struct work_queue* wq){
	wq->type = DISABLED;
	mutex_init(&(wq->wq_tail_lock));
	mutex_init(&(wq->wq_clean_lock));
}

void free_resources(struct device * dev, struct dce_driver_priv *priv)
{
	/* TODO: Free each WQ as well? */
	if (priv->WQIT)
		dma_free_coherent(priv->pci_dev, 0x1000, priv->WQIT, priv->WQIT_dma);
	return;
}

/* return an unused workqueue number or -1*/
static int reserve_unused_wq(struct dce_driver_priv * priv) {
	int ret = -1;
	mutex_lock(&(priv->lock));
	for(int i=0; i<NUM_WQ; ++i){
		struct work_queue* wq = priv->wq+i;
		if(wq->type==DISABLED){
			ret = i;
			wq->type = RESERVED_WQ;
			break;
		}
	}
	mutex_unlock(&(priv->lock));
	return ret;
}

long dce_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	uint64_t val;
	struct DCEDescriptor descriptor;
	struct submitter_dce_ctx * ctx = file->private_data;
	struct dce_driver_priv *priv = ctx->dev;

#ifdef CONFIG_IOMMU_SVA
	/* prevent all ioctl from succeeding if the fd is from a parent process*/
	if(ctx->pasid != current->mm->pasid)
		return -EBADFD;
#endif
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
			/* Check if PASID is enabled */
			if (!priv->sva_enabled)
				return -EFAULT;

			KernelQueueReq __user * __kqr_input;
			KernelQueueReq kqr = {.DSCSZ = 0, .eventfd_vld = false, .eventfd = 0};
			__kqr_input = (KernelQueueReq __user *) arg;
			if (__kqr_input)
				if (copy_from_user(&kqr, __kqr_input, sizeof(KernelQueueReq)))
					return -EFAULT;

			/* WQ shouldn't have been assigned at this point */
			if (ctx->wq_num != -1) return -EFAULT;

			/* allocate a queue to context or fallback to wq 0*/
			{
				int wqnum = reserve_unused_wq(priv);
				if(wqnum<0){ /* no more free queues */
					ctx->wq_num = 0; /*Fallback to shared queue*/
				} else {
					ctx->wq_num = wqnum;
					/* TODO: Refactor, pass only &wq to setup_memory */
					setup_memory_for_wq(priv, wqnum, &kqr);
				}
			}

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
			if (ctx->wq_num != -1) return -EFAULT;

			/* assign workqueue or fail */
			{
				int wqnum = reserve_unused_wq(priv);
				if(wqnum<0){ /* no more free queues */
					ctx->wq_num = -1;
					return -EFAULT; /* TODO: Better error code?*/	
				} else {
					ctx->wq_num = wqnum;
					/* TODO: Refactor, pass only &wq to setup_memory */
					setup_memory_for_wq_from_user(file, ctx->wq_num, &ua);
				}
			}
			break;
		}

		case SUBMIT_DESCRIPTOR: {
			struct DCEDescriptor __user *__descriptor_input;
			struct DCEDescriptor descriptor_input;

			__descriptor_input = (struct DCEDescriptor __user*) arg;
			if (copy_from_user(&descriptor_input, __descriptor_input, sizeof(descriptor_input)))
				return -EFAULT;

			/* Default to WQ 0 (Shared kernel) if not assigned */
			if (ctx->wq_num == -1) ctx->wq_num = 0;

			/* WQ should be enabled at this point */
			if (priv->wq[ctx->wq_num].type == DISABLED)
				return -EFAULT;

			/* Make sure selected WQ is owned by Kernel */
			if (priv->wq[ctx->wq_num].type == USER_OWNED_WQ)
				return -EFAULT;

			if (parse_descriptor_based_on_opcode(&descriptor,
				&descriptor_input, ctx->pasid) < 0) {
				return -EFAULT;
			}

			// printk(KERN_INFO "pushing descriptor thru wq %d with opcode %d!\n",
			// 	wq_num, descriptor.opcode);
			// printk(KERN_INFO "submitting source 0x%lx\n", descriptor.source);
			dce_push_descriptor(priv, &descriptor, ctx->wq_num );
		}
	}

	return 0;
}

int dce_mmap(struct file *file, struct vm_area_struct *vma) {
	struct submitter_dce_ctx * ctx = file->private_data;
	struct dce_driver_priv *priv = ctx->dev;

	if (ctx->wq_num == -1) return -EFAULT;

	unsigned long pfn = phys_to_pfn(priv->mmio_start_phys);
	/* coompute the door bell page with wq num */
	pfn += (ctx->wq_num + 1);

	vma->vm_flags |= VM_IO;
	vma->vm_flags |= (VM_DONTEXPAND | VM_DONTDUMP);
	/* Make sure the door bell does not work with fork() */
	vma->vm_flags |= VM_DONTCOPY;
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
	.owner          = THIS_MODULE,
	.open           = dce_ops_open,
	.release        = dce_ops_release,
	.read           = dce_ops_read,
	.write          = dce_ops_write,
	.mmap           = dce_mmap,
	.unlocked_ioctl = dce_ioctl
};

irqreturn_t handle_dce(int irq, void *dce_priv_p) {

	struct dce_driver_priv *dce_priv=dce_priv_p;

	/* FIXME: multiple thread running this? schedule_work reentrant safe?*/
	printk(KERN_INFO "Got interrupt %d, work scheduled!\n", irq);
	schedule_work(&dce_priv->clean_up_worker);

	return IRQ_HANDLED;
}


int setup_memory_regions(struct dce_driver_priv * drv_priv)
{
	struct device * dev = drv_priv->pci_dev;
	int err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (err) printk(KERN_INFO "DMA set mask failed: %d\n", err);

	// printk(KERN_INFO"dma_mask: 0x%lx\n",dev->dma_mask);
	/* WQIT is 4KiB */
	/* TODO: Error handling, dma_alloc can fail
	 * TODO: check alignement, the idea is to have a page aligned alloc */
	drv_priv->WQIT = dma_alloc_coherent(dev, 0x1000,
								  &drv_priv->WQIT_dma, GFP_KERNEL);

	// printk(KERN_INFO "Writing to DCE_REG_WQITBA!\n");
	if (drv_priv->WQIT_dma & GENMASK(11, 0) != 0) {
		printk(KERN_ERR "DCE: WQITBA[11:0]:0x%lx is not all zero!",
			drv_priv->WQIT_dma);
		dma_free_coherent(drv_priv->pci_dev, 0x1000,
			drv_priv->WQIT, drv_priv->WQIT_dma);
		return -EFAULT;
	}
	dce_reg_write(drv_priv, DCE_REG_WQITBA,
				(uint64_t) drv_priv->WQIT_dma);
	return 0;
}
static struct class *dce_char_class;

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
	//printk(KERN_INFO "Device vaid: 0x%X pid: 0x%X\n", vendor, device);

	err = pci_enable_device(pdev);
	if (err) goto disable_device_and_fail;

	bar = pci_select_bars(pdev, IORESOURCE_MEM);
	// printk(KERN_INFO "io bar: 0x%X\n", bar);

	err = pci_request_selected_regions(pdev, bar, DEVICE_NAME);
	if (err) goto disable_device_and_fail;


	drv_priv = kzalloc_node(sizeof(struct dce_driver_priv), GFP_KERNEL,
			     dev_to_node(dev));
	if (!drv_priv) goto disable_device_and_fail;

	drv_priv->pdev = pdev;
	drv_priv->pci_dev = dev;

	drv_priv->mmio_start_phys = pci_resource_start(pdev, 0);
	// mmio_len   = pci_resource_len  (pdev, 0);

	if (iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_SVA)) {
		drv_priv->sva_enabled = false;
		dev_err(dev, "DCE:Unable to turn on user SVA feature. Device disabled\n");
		goto disable_device_and_fail;
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
	err = setup_memory_regions(drv_priv);
	if (err)
		goto disable_device_and_fail;

	err = cdev_device_add(&drv_priv->cdev, &drv_priv->dev);
	if (err) {
		printk(KERN_ERR "DCE: cdev add failed\n");
		goto free_resources_and_fail;
	}

	/* MSI setup */
	if (pci_match_id(pci_use_msi, pdev)) {
		dev_info(dev, "Using MSI(-X) interrupts\n");
		printk(KERN_INFO"dev->msix_enabled: %d\n", pdev->msi_enabled);
		pci_set_master(pdev);
		err = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_ALL_TYPES);
		int vec = pci_irq_vector(pdev, 0);
		printk(KERN_INFO"err: %d, IRQ vector is %d\n",err, vec);

		/* auto frees on device detach, nice */
		devm_request_threaded_irq(dev, vec, handle_dce, NULL, IRQF_ONESHOT, DEVICE_NAME, drv_priv);
	} else {
		dev_warn(dev, "DCE: MSI enable failed\n");
	}

	/* work queue setup */
	INIT_WORK(&drv_priv->clean_up_worker, clean_up_work);

	/* init mutex */
	mutex_init(&drv_priv->lock);
	mutex_init(&drv_priv->dce_reg_lock);

	for (int i = 0; i < NUM_WQ; i++) {
		init_wq(drv_priv->wq+i);
	}

	/* setup WQ 0 for SHARED_KERNEL usage */
	setup_memory_for_wq(drv_priv, 0, NULL);
	drv_priv->wq[0].type = SHARED_KERNEL_WQ;

	return 0;

	free_resources_and_fail:
		free_resources(dev, drv_priv);

	disable_device_and_fail:
		pci_disable_device(pdev);
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
	free_resources(&pdev->dev, pci_get_drvdata(pdev));
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
	if (err) return err;

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

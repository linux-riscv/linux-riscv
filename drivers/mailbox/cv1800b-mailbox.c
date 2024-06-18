// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/device.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kfifo.h>
#include <linux/mailbox_controller.h>
#include <linux/mailbox_client.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#define MAILBOX_MAX_CHAN 0x0008
#define MAILBOX_DONE_OFFSET 0x0002
#define MAILBOX_CONTEXT_SIZE 0x0040
#define MAILBOX_CONTEXT_OFFSET 0x0400

#define MBOX_EN_REG(cpu) (cpu << 2)
#define MBOX_DONE_REG(cpu) ((cpu << 2) + MAILBOX_DONE_OFFSET)

#define MBOX_SET_CLR_REG(cpu) (0x10 + (cpu << 4))
#define MBOX_SET_INT_REG(cpu) (0x18 + (cpu << 4))

#define MBOX_SET_REG 0x60

struct cv1800b_mbox {
	struct mbox_controller mbox;
	struct mbox_chan chans[MAILBOX_MAX_CHAN];
	u64 *content[MAILBOX_MAX_CHAN];
	void __iomem *mbox_base;
	int sendto;
	int recvid;
};

static irqreturn_t cv1800b_mbox_isr(int irq, void *dev_id)
{
	struct cv1800b_mbox *mbox = (struct cv1800b_mbox *)dev_id;
	size_t i;

	for (i = 0; i < MAILBOX_MAX_CHAN; i++) {
		if (mbox->content[i]) {
			mbox_chan_received_data(&mbox->chans[i],
						mbox->content[i]);
			mbox->content[i] = NULL;
			return IRQ_HANDLED;
		}
	}
	return IRQ_NONE;
}

static irqreturn_t cv1800b_mbox_irq(int irq, void *dev_id)
{
	struct cv1800b_mbox *mbox = (struct cv1800b_mbox *)dev_id;
	u8 set, valid;
	u64 *addr;
	size_t i;

	set = readb(mbox->mbox_base + MBOX_SET_INT_REG(mbox->recvid));

	if (!set)
		return IRQ_NONE;

	for (i = 0; i < MAILBOX_MAX_CHAN; i++) {
		valid = set & (1 << i);
		addr = (u64 *)(mbox->mbox_base + MAILBOX_CONTEXT_OFFSET) + i;
		if (valid) {
			mbox->content[i] = addr;
			writeb(valid, mbox->mbox_base +
					      MBOX_SET_CLR_REG(mbox->recvid));
			writeb(~valid,
			       mbox->mbox_base + MBOX_EN_REG(mbox->recvid));
			return IRQ_WAKE_THREAD;
		}
	}

	return IRQ_NONE;
}

static int cv1800b_mbox_send_data(struct mbox_chan *chan, void *data)
{
	struct cv1800b_mbox *mbox = dev_get_drvdata(chan->mbox->dev);
	int idx = (int)chan->con_priv;
	u8 en, valid;
	u64 *addr = (u64 *)(mbox->mbox_base + MAILBOX_CONTEXT_OFFSET) + idx;

	memcpy_toio(addr, data, 8);

	valid = 1 << idx;
	writeb(valid, mbox->mbox_base + MBOX_SET_CLR_REG(mbox->sendto));
	en = readb(mbox->mbox_base + MBOX_EN_REG(mbox->sendto));
	writeb(en | valid, mbox->mbox_base + MBOX_EN_REG(mbox->sendto));
	writeb(valid, mbox->mbox_base + MBOX_SET_REG);

	return 0;
}

static bool cv1800b_last_tx_done(struct mbox_chan *chan)
{
	return true;
}

static const struct mbox_chan_ops cv1800b_mbox_chan_ops = {
	.send_data = cv1800b_mbox_send_data,
	.last_tx_done = cv1800b_last_tx_done,
};

static const struct of_device_id cv1800b_mbox_of_match[] = {
	{ .compatible = "sophgo,cv1800b-mailbox", },
	{},
};
MODULE_DEVICE_TABLE(of, cv1800b_mbox_of_match);

static int cv1800b_mbox_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct cv1800b_mbox *mb;
	int irq, idx, err, cpu;

	if (!dev->of_node)
		return -ENODEV;

	mb = devm_kzalloc(dev, sizeof(*mb), GFP_KERNEL);
	if (!mb)
		return -ENOMEM;

	mb->mbox_base = devm_of_iomap(dev, dev->of_node, 0, NULL);
	if (IS_ERR(mb->mbox_base))
		return dev_err_probe(dev, PTR_ERR(mb->mbox_base),
				     "Failed to map resource\n");

	err = of_property_read_s32(dev->of_node, "sendto", &cpu);
	if (err)
		return dev_err_probe(dev, err,
				     "Failed to find <sendto> in of_node\n");

	mb->sendto = cpu;

	err = of_property_read_s32(dev->of_node, "recvid", &cpu);
	if (err) {
		return dev_err_probe(dev, err,
				     "Failed to find <recvid> in of_node\n");
	}
	mb->recvid = cpu;

	mb->mbox.dev = dev;
	mb->mbox.num_chans = MAILBOX_MAX_CHAN;
	mb->mbox.chans = mb->chans;
	mb->mbox.ops = &cv1800b_mbox_chan_ops;
	mb->mbox.txdone_poll = true;

	irq = platform_get_irq_byname(pdev, "mailbox");
	err = devm_request_threaded_irq(dev, irq, cv1800b_mbox_irq,
					cv1800b_mbox_isr, IRQF_ONESHOT,
					dev_name(&pdev->dev), mb);
	if (err < 0)
		return dev_err_probe(dev, err, "Failed to register irq\n");

	for (idx = 0; idx < MAILBOX_MAX_CHAN; idx++)
		mb->mbox.chans[idx].con_priv = (void *)idx;

	err = devm_mbox_controller_register(dev, &mb->mbox);
	if (err)
		return dev_err_probe(dev, err, "Failed to register mailbox\n");

	platform_set_drvdata(pdev, mb);
	return 0;
}

static struct platform_driver cv1800b_mbox_driver = {
	.driver = {
		.name = "cv1800b-mbox",
		.of_match_table = cv1800b_mbox_of_match,
	},
	.probe	= cv1800b_mbox_probe,
};

module_platform_driver(cv1800b_mbox_driver);

MODULE_DESCRIPTION("cv1800b mailbox driver");
MODULE_LICENSE("GPL");

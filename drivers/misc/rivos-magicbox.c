// SPDX-License-Identifier: GPL-2.0-only

#include <linux/fs.h>
#include <linux/io.h>
#include <linux/types.h>
#include <linux/debugfs.h>
#include <linux/reboot.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/notifier.h>
#include <linux/panic_notifier.h>
#include <linux/platform_device.h>

#include <asm/csr.h>
#include <asm/smp.h>

#define MAGICBOX_EXIT_OFFSET	0x0
#define MAGICBOX_DUMP_OFFSET	0x4

struct rivos_magicbox {
	struct device *dev;
	struct dentry *debugfs_root;
	void *regs;
	struct notifier_block panic_nb;
	struct notifier_block reboot_nb;
	struct notifier_block restart_nb;
};

static void dump_perf_counter(void *info)
{
	unsigned long time = csr_read(CSR_TIME);
	unsigned long instret = csr_read(CSR_INSTRET);
	int cpu = smp_processor_id();

	pr_err("[CPU %d, HART %ld] time: %ld, instret: %ld\n",
	       cpu, cpuid_to_hartid_map(cpu), time, instret);
}

static void magicbox_exit(struct rivos_magicbox *mb, u32 exit)
{
	if (exit == 1)
		on_each_cpu(dump_perf_counter, NULL, 1);

	writel(exit, mb->regs + MAGICBOX_EXIT_OFFSET);
}

static int exit_set(void *data, u64 val)
{
	struct rivos_magicbox *mb = data;

	magicbox_exit(mb, val);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(magicbox_exit_fops, NULL, exit_set, "%llu\n");

static int dump_checkpoint_set(void *data, u64 val)
{
	struct rivos_magicbox *mb = data;

	writel(BIT(0), mb->regs + MAGICBOX_DUMP_OFFSET);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(magicbox_checkpoint_fops, NULL, dump_checkpoint_set, "%llu\n");

static int dump_stat_set(void *data, u64 val)
{
	struct rivos_magicbox *mb = data;

	writel(BIT(1), mb->regs + MAGICBOX_DUMP_OFFSET);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(magicbox_stat_fops, NULL, dump_stat_set, "%llu\n");

static int magicbox_panic_notifier(struct notifier_block *nb,
				   unsigned long code, void *unused)
{
	struct rivos_magicbox *mb = container_of(nb, struct rivos_magicbox, panic_nb);

	magicbox_exit(mb, 0xDEADBEEF);

	return NOTIFY_DONE;
}
static int magicbox_reboot_notifier(struct notifier_block *nb,
				    unsigned long action, void *unused)
{
	struct rivos_magicbox *mb = container_of(nb, struct rivos_magicbox, panic_nb);

	magicbox_exit(mb, 0xDEAD0000 | action);

	return NOTIFY_DONE;
}

static int rivos_magicbox_probe(struct platform_device *pdev)
{
	struct rivos_magicbox *mb;

	mb = devm_kzalloc(&pdev->dev, sizeof(*mb), GFP_KERNEL);
	if (!mb)
		return -ENOMEM;

	mb->regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(mb->regs))
		return PTR_ERR(mb->regs);

	mb->debugfs_root = debugfs_create_dir("magicbox", NULL);

	debugfs_create_file("exit", 0222, mb->debugfs_root, mb, &magicbox_exit_fops);
	debugfs_create_file("dump_checkpoint", 0222, mb->debugfs_root, mb, &magicbox_checkpoint_fops);
	debugfs_create_file("dump_stat", 0222, mb->debugfs_root, mb, &magicbox_stat_fops);

	mb->panic_nb.notifier_call = magicbox_panic_notifier,
	atomic_notifier_chain_register(&panic_notifier_list, &mb->panic_nb);

	mb->reboot_nb.notifier_call = magicbox_reboot_notifier,
	register_reboot_notifier(&mb->reboot_nb);

	platform_set_drvdata(pdev, mb);

	pr_info("Magicbox driver probed\n");

	return 0;

}

static void rivos_magicbox_remove(struct platform_device *pdev)
{
	struct rivos_magicbox *mb = platform_get_drvdata(pdev);

	debugfs_remove_recursive(mb->debugfs_root);
	atomic_notifier_chain_unregister(&panic_notifier_list, &mb->panic_nb);
	unregister_reboot_notifier(&mb->reboot_nb);
}

static const struct of_device_id rivos_magicbox_match_table[] = {
	{ .compatible = "rivos,magicbox", },
	{}
};

MODULE_DEVICE_TABLE(of, rivos_magicbox_match_table);

static struct platform_driver rivos_magicbox_driver = {
	.driver	= {
		.name = "rivos_magicbox",
		.of_match_table	= rivos_magicbox_match_table,
	},
	.probe = rivos_magicbox_probe,
	.remove_new = rivos_magicbox_remove,
};

module_platform_driver(rivos_magicbox_driver);

MODULE_DESCRIPTION("RIVOS Magicbox driver");
MODULE_LICENSE("GPL v2");

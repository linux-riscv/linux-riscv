/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _RIVOS_PWC_H
#define _RIVOS_PWC_H

#include <linux/auxiliary_bus.h>
#include <linux/device.h>
#include <linux/idr.h>
#include <linux/ioport.h>
#include <linux/pci.h>
#include <linux/spinlock.h>

enum rivos_pwc_dvsec_id {
	DVSEC_ID_CHIPLET_THERMAL = 0x0101,
	DVSEC_ID_CHIPLET_POWER = 0x0102,
	DVSEC_ID_DIMM_THERMAL = 0x0104,
	DVSEC_ID_DIMM_POWER = 0x0105,
	DVSEC_ID_DPA_THERMAL = 0x0106,
	DVSEC_ID_DPA_POWER = 0x0107,
	DVSEC_ID_DPA_PERF = 0x0108,
	DVSEC_ID_HBM_THERMAL = 0x0109,
	DVSEC_ID_HBM_POWER = 0x010A,
	DVSEC_ID_SOC_THERMAL = 0x010B,
	DVSEC_ID_SOC_POWER = 0x010C,
};

struct rivos_pwc_dvsec_desc {
	enum rivos_pwc_dvsec_id id;
	unsigned int reg_size;
	int it_index;
	const char *name;
};

struct rivos_pwc {
	void __iomem *base;
	spinlock_t lock;
	struct ida auxdev_ida;
	u8 chiplet_id;
	u8 soc_id;
	u8 chiplet_type;
	u8 soc_config;
};

struct rivos_pwc_dvsec_dev {
	struct auxiliary_device auxdev;
	struct pci_dev *pcidev;
	struct resource resource;
	void *priv_data;
	size_t priv_data_size;
	int irq;
	struct rivos_pwc *pwc;
	const struct rivos_pwc_dvsec_desc *rpd_dev;
};

static inline struct rivos_pwc_dvsec_dev *dev_to_rpd_dev(struct device *dev)
{
	return container_of(dev, struct rivos_pwc_dvsec_dev, auxdev.dev);
}

static inline struct rivos_pwc_dvsec_dev *auxdev_to_rpd_dev(struct auxiliary_device *auxdev)
{
	return container_of(auxdev, struct rivos_pwc_dvsec_dev, auxdev);
}

void rivos_pwc_irq_ack(struct rivos_pwc_dvsec_dev *rpd_dev);

#endif /* _RIVOS_PWC_H */

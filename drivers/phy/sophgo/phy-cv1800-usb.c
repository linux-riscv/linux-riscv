// SPDX-License-Identifier: GPL-2.0-only
/*
 * USB PHY driver for Sophgo CV1800 SoCs.
 *
 * Copyright 2024 Yao Zi <ziyao@disroot.org>
 */

#include <linux/clk.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/phy/phy.h>

#define CV1800_REG04				0x04
#define CV1800_REG14				0x14
#define  CV1800_REG14_UTMI_OVERRIDE		BIT(0)
#define  CV1800_REG14_OPMODE_MASK		(0x3 << 1)
#define  CV1800_REG14_OPMODE_SHIFT		1
#define  CV1800_REG14_XCVRSEL_MASK		(0x3 << 3)
#define  CV1800_REG14_XCVRSEL_SHIFT		3
#define  CV1800_REG14_TERMSEL			BIT(5)
#define  CV1800_REG14_DPPULLDOWN		BIT(6)
#define  CV1800_REG14_DMPULLDOWN		BIT(7)
#define  CV1800_REG14_UTMI_RESET		BIT(8)
#define CV1800_REG20				0x20
#define  CV1800_REG20_BC_EN			BIT(0)
#define  CV1800_REG20_DCD_EN			BIT(1)
#define  CV1800_REG20_DP_CMP_EN			BIT(2)
#define  CV1800_REG20_DM_CMP_EN			BIT(3)
#define  CV1800_REG20_VDP_SRC_EN		BIT(4)
#define  CV1800_REG20_VDM_SRC_EN		BIT(5)
#define  CV1800_REG20_CHG_DET			BIT(16)
#define  CV1800_REG20_DP_DET			BIT(17)

#define CV1800_PIN_ID_OVERWRITE_EN		BIT(6)
#define CV1800_PIN_ID_OVERWRITE_VALUE(v)	((v) << 7)

enum cv1800_usb_phy_role {
	CV1800_USB_PHY_HOST	= 0,
	CV1800_USB_PHY_DEVICE	= 1,
};

struct cv1800_usb_phy_priv {
	void __iomem *regs;
	void __iomem *pinreg;
	struct clk *clk_apb;
	struct clk *clk_125m;
	struct clk *clk_33k;
	struct clk *clk_12m;
	enum cv1800_usb_phy_role role;
};

static void
cv1800_usb_phy_set_role(struct cv1800_usb_phy_priv *priv,
			enum cv1800_usb_phy_role role)
{
	writel(CV1800_PIN_ID_OVERWRITE_EN | CV1800_PIN_ID_OVERWRITE_VALUE(role),
	       priv->pinreg);
}

static int cv1800_usb_phy_init(struct phy *phy)
{
	struct cv1800_usb_phy_priv *priv = phy_get_drvdata(phy);
	int ret = 0;

	ret = clk_prepare_enable(priv->clk_apb);
	if (ret)
		return ret;

	ret = clk_prepare_enable(priv->clk_125m);
	if (ret)
		goto err_clk_125m;

	ret = clk_prepare_enable(priv->clk_33k);
	if (ret)
		goto err_clk_33k;

	ret = clk_prepare_enable(priv->clk_12m);
	if (ret)
		goto err_clk_12m;

	writel(0xa, priv->regs + CV1800_REG04);		/* magic number	*/
	writel(0, priv->regs + CV1800_REG14);
	writel(0, priv->regs + CV1800_REG20);

	cv1800_usb_phy_set_role(priv, priv->role);

	return 0;

err_clk_12m:
	clk_disable_unprepare(priv->clk_33k);
err_clk_33k:
	clk_disable_unprepare(priv->clk_125m);
err_clk_125m:
	clk_disable_unprepare(priv->clk_apb);

	return ret;
}

static int cv1800_usb_phy_exit(struct phy *phy)
{
	struct cv1800_usb_phy_priv *priv = phy_get_drvdata(phy);

	clk_disable_unprepare(priv->clk_33k);
	clk_disable_unprepare(priv->clk_125m);
	clk_disable_unprepare(priv->clk_apb);

	return 0;
}

static const struct phy_ops cv1800_usb_phy_ops = {
	.init = cv1800_usb_phy_init,
	.exit = cv1800_usb_phy_exit,
};

static int
cv1800b_usb_phy_parse_dt(struct cv1800_usb_phy_priv *priv, struct device *dev)
{
	const char *role;

	if (!of_property_read_string(dev->of_node, "dr_role", &role)) {
		if (!strcmp(role, "host")) {
			priv->role = CV1800_USB_PHY_HOST;
		} else if (!strcmp(role, "device")) {
			priv->role = CV1800_USB_PHY_DEVICE;
		} else {
			dev_err(dev, "invalid dr_role %s", role);
			return -EINVAL;
		}
	} else {
		priv->role = CV1800_USB_PHY_DEVICE;
	}

	return 0;
}

static int cv1800_usb_phy_probe(struct platform_device *pdev)
{
	struct cv1800_usb_phy_priv *priv;
	struct phy_provider *provider;
	struct device *dev = &pdev->dev;
	struct phy *phy;
	int ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	ret = cv1800b_usb_phy_parse_dt(priv, dev);
	if (ret)
		return dev_err_probe(dev, ret, "failed to parse dt");

	priv->regs = devm_platform_ioremap_resource_byname(pdev, "phy");
	if (IS_ERR(priv->regs))
		return dev_err_probe(dev, PTR_ERR(priv->regs),
				     "failed to map phy registers");

	priv->pinreg = devm_platform_ioremap_resource_byname(pdev, "pin");
	if (IS_ERR(priv->pinreg))
		return dev_err_probe(dev, PTR_ERR(priv->pinreg),
				     "failed to map pin register");

	priv->clk_apb = devm_clk_get(dev, "apb");
	if (IS_ERR(priv->clk_apb))
		return dev_err_probe(dev, PTR_ERR(priv->clk_apb),
				     "failed to get apb clock");

	priv->clk_125m = devm_clk_get(dev, "125m");
	if (IS_ERR(priv->clk_125m))
		return dev_err_probe(dev, PTR_ERR(priv->clk_125m),
				     "failed to get 125m clock");

	priv->clk_33k = devm_clk_get(dev, "33k");
	if (IS_ERR(priv->clk_33k))
		return dev_err_probe(dev, PTR_ERR(priv->clk_33k),
				     "failed to get 33k clock");

	priv->clk_12m = devm_clk_get(dev, "12m");
	if (IS_ERR(priv->clk_12m))
		return dev_err_probe(dev, PTR_ERR(priv->clk_12m),
				     "failed to get 12m clock");

	phy = devm_phy_create(dev, NULL, &cv1800_usb_phy_ops);
	if (IS_ERR(phy))
		return dev_err_probe(dev, PTR_ERR(phy),
				     "cannot create phy");

	provider = devm_of_phy_provider_register(dev, of_phy_simple_xlate);

	phy_set_drvdata(phy, priv);

	return PTR_ERR_OR_ZERO(provider);
}

static const struct of_device_id cv1800_usb_phy_of_match_table[] = {
	{ .compatible = "sophgo,cv1800-usb-phy" },
	{ },
};

static struct platform_driver cv1800_usb_phy_platform_driver = {
	.driver = {
		.name = "cv1800-usb-phy",
		.of_match_table = cv1800_usb_phy_of_match_table,
	},
	.probe = cv1800_usb_phy_probe,
};

module_platform_driver(cv1800_usb_phy_platform_driver);

MODULE_DESCRIPTION("Sophgo CV1800 USB PHY Driver");
MODULE_AUTHOR("Yao Zi <ziyao@disroot.org>");
MODULE_LICENSE("GPL");

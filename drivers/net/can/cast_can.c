// SPDX-License-Identifier: GPL-2.0
/*
 * CAST Controller Area Network Host Controller Driver
 *
 * Copyright (c) 2022-2023 StarFive Technology Co., Ltd.
 */

#include <linux/can/dev.h>
#include <linux/can/error.h>
#include <linux/clk.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/of_device.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/reset.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/types.h>

#define DRIVER_NAME "cast_can"

/* CAN registers set */
enum ccan_device_reg {
	CCAN_RUBF_OFFSET           =   0x00,	/* Receive Buffer Registers 0x00-0x4f */
	CCAN_RUBF_ID_OFFSET        =   0x00,
	CCAN_RBUF_CTL_OFFSET       =   0x04,
	CCAN_RBUF_DATA_OFFSET      =   0x08,
	CCAN_TBUF_OFFSET           =   0x50,	/* Transmit Buffer Registers 0x50-0x97 */
	CCAN_TBUF_ID_OFFSET        =   0x50,
	CCAN_TBUF_CTL_OFFSET       =   0x54,
	CCAN_TBUF_DATA_OFFSET      =   0x58,
	CCAN_TTS_OFFSET            =   0x98,	/* Transmission Time Stamp 0x98-0x9f */
	CCAN_CFG_STAT_OFFSET       =   0xa0,
	CCAN_TCMD_OFFSET           =   0xa1,
	CCAN_TCTRL_OFFSET          =   0xa2,
	CCAN_RCTRL_OFFSET          =   0xa3,
	CCAN_RTIE_OFFSET           =   0xa4,
	CCAN_RTIF_OFFSET           =   0xa5,
	CCAN_ERRINT_OFFSET         =   0xa6,
	CCAN_LIMIT_OFFSET          =   0xa7,
	CCAN_S_SEG_1_OFFSET        =   0xa8,
	CCAN_S_SEG_2_OFFSET        =   0xa9,
	CCAN_S_SJW_OFFSET          =   0xaa,
	CCAN_S_PRESC_OFFSET        =   0xab,
	CCAN_F_SEG_1_OFFSET        =   0xac,
	CCAN_F_SEG_2_OFFSET        =   0xad,
	CCAN_F_SJW_OFFSET          =   0xae,
	CCAN_F_PRESC_OFFSET        =   0xaf,
	CCAN_EALCAP_OFFSET         =   0xb0,
	CCAN_RECNT_OFFSET          =   0xb2,
	CCAN_TECNT_OFFSET          =   0xb3,
};

enum ccan_reg_bitchange {
	CCAN_SET_RST_MASK         =   0x80,	/* Set Reset Bit */
	CCAN_OFF_RST_MASK         =   0x7f,	/* Reset Off Bit */
	CCAN_SET_FULLCAN_MASK     =   0x10,	/* set TTTBM as 1->full TTCAN mode */
	CCAN_OFF_FULLCAN_MASK     =   0xef,	/* set TTTBM as 0->separate PTB and STB mode */
	CCAN_SET_FIFO_MASK        =   0x20,	/* set TSMODE as 1->FIFO mode */
	CCAN_OFF_FIFO_MASK        =   0xdf,	/* set TSMODE as 0->Priority mode */
	CCAN_SET_TSONE_MASK       =   0x04,
	CCAN_OFF_TSONE_MASK       =   0xfb,
	CCAN_SET_TSALL_MASK       =   0x02,
	CCAN_OFF_TSALL_MASK       =   0xfd,
	CCAN_LBMEMOD_MASK         =   0x40,	/* set loop back mode, external */
	CCAN_LBMIMOD_MASK         =   0x20,	/* set loopback internal mode */
	CCAN_SET_BUSOFF_MASK      =   0x01,
	CCAN_OFF_BUSOFF_MASK      =   0xfe,
	CCAN_SET_TTSEN_MASK       =   0x80,	/* set ttsen, tts update enable */
	CCAN_SET_BRS_MASK         =   0x10,	/* can fd Bit Rate Switch mask */
	CCAN_OFF_BRS_MASK         =   0xef,
	CCAN_SET_EDL_MASK         =   0x20,	/* Extended Data Length */
	CCAN_OFF_EDL_MASK         =   0xdf,
	CCAN_SET_DLC_MASK         =   0x0f,
	CCAN_SET_TENEXT_MASK      =   0x40,
	CCAN_SET_IDE_MASK         =   0x80,
	CCAN_OFF_IDE_MASK         =   0x7f,
	CCAN_SET_RTR_MASK         =   0x40,
	CCAN_OFF_RTR_MASK         =   0xbf,
	CCAN_INTR_ALL_MASK        =   0xff,	/* all interrupts enable mask */
	CCAN_SET_RIE_MASK         =   0x80,
	CCAN_OFF_RIE_MASK         =   0x7f,
	CCAN_SET_RFIE_MASK        =   0x20,
	CCAN_OFF_RFIE_MASK        =   0xdf,
	CCAN_SET_RAFIE_MASK       =   0x10,
	CCAN_OFF_RAFIE_MASK       =   0xef,
	CCAN_SET_EIE_MASK         =   0x02,
	CCAN_OFF_EIE_MASK         =   0xfd,
	CCAN_TASCTIVE_MASK        =   0x02,
	CCAN_RASCTIVE_MASK        =   0x04,
	CCAN_SET_TBSEL_MASK       =   0x80,	/* message writen in STB */
	CCAN_OFF_TBSEL_MASK       =   0x7f,	/* message writen in PTB */
	CCAN_SET_STBY_MASK        =   0x20,
	CCAN_OFF_STBY_MASK        =   0xdf,
	CCAN_SET_TPE_MASK         =   0x10,	/* Transmit primary enable */
	CCAN_SET_TPA_MASK         =   0x08,
	CCAN_SET_SACK_MASK        =   0x80,
	CCAN_SET_RREL_MASK        =   0x10,
	CCAN_RSTAT_NOT_EMPTY_MASK =   0x03,
	CCAN_SET_RIF_MASK         =   0x80,
	CCAN_OFF_RIF_MASK         =   0x7f,
	CCAN_SET_RAFIF_MASK       =   0x10,
	CCAN_SET_RFIF_MASK        =   0x20,
	CCAN_SET_TPIF_MASK        =   0x08,	/* Transmission Primary Interrupt Flag */
	CCAN_SET_TSIF_MASK        =   0x04,
	CCAN_SET_EIF_MASK         =   0x02,
	CCAN_SET_AIF_MASK         =   0x01,
	CCAN_SET_EWARN_MASK       =   0x80,
	CCAN_SET_EPASS_MASK       =   0x40,
	CCAN_SET_EPIE_MASK        =   0x20,
	CCAN_SET_EPIF_MASK        =   0x10,
	CCAN_SET_ALIE_MASK        =   0x08,
	CCAN_SET_ALIF_MASK        =   0x04,
	CCAN_SET_BEIE_MASK        =   0x02,
	CCAN_SET_BEIF_MASK        =   0x01,
	CCAN_OFF_EPIE_MASK        =   0xdf,
	CCAN_OFF_BEIE_MASK        =   0xfd,
	CCAN_SET_AFWL_MASK        =   0x40,
	CCAN_SET_EWL_MASK         =   0x0b,
	CCAN_SET_KOER_MASK        =   0xe0,
	CCAN_SET_BIT_ERROR_MASK   =   0x20,
	CCAN_SET_FORM_ERROR_MASK  =   0x40,
	CCAN_SET_STUFF_ERROR_MASK =   0x60,
	CCAN_SET_ACK_ERROR_MASK   =   0x80,
	CCAN_SET_CRC_ERROR_MASK   =   0xa0,
	CCAN_SET_OTH_ERROR_MASK   =   0xc0,
};

/* seg1,seg2,sjw,prescaler all have 8 bits */
#define BITS_OF_BITTIMING_REG		8

/* in can_bittiming strucure every field has 32 bits---->u32 */
#define FBITS_IN_BITTIMING_STR		32
#define SEG_1_SHIFT			0
#define SEG_2_SHIFT			8
#define SJW_SHIFT			16
#define PRESC_SHIFT			24

/* TTSEN bit used for 32 bit register read or write */
#define TTSEN_8_32_SHIFT		24
#define RTR_32_8_SHIFT			24

/* transmit mode */
#define XMIT_FULL			0
#define XMIT_SEP_FIFO			1
#define XMIT_SEP_PRIO			2
#define XMIT_PTB_MODE			3

enum cast_can_type {
	CAST_CAN_TYPE_CAN = 0,
	CAST_CAN_TYPE_CANFD,
};

struct ccan_priv {
	struct can_priv can;
	struct napi_struct napi;
	struct device *dev;
	struct regmap *reg_syscon;
	void __iomem *reg_base;
	u32 (*read_reg)(const struct ccan_priv *priv, enum ccan_device_reg reg);
	void (*write_reg)(const struct ccan_priv *priv, enum ccan_device_reg reg, u32 val);
	struct clk *can_clk;
	struct clk *host_clk;
	struct clk *timer_clk;
	u32 tx_mode;
	struct reset_control *resets;
	u32 cantype;
	bool is_starfive;
};

struct cast_can_data {
	enum cast_can_type cantype;
	const struct can_bittiming_const *bittime_const;
	int (*starfive_parse_dt)(struct ccan_priv *priv);
};

static struct can_bittiming_const ccan_bittiming_const = {
	.name = DRIVER_NAME,
	.tseg1_min = 2,
	.tseg1_max = 16,
	.tseg2_min = 2,
	.tseg2_max = 8,
	.sjw_max = 4,
	.brp_min = 1,
	.brp_max = 256,
	.brp_inc = 1,
};

static struct can_bittiming_const ccan_bittiming_const_canfd = {
	.name = DRIVER_NAME,
	.tseg1_min = 2,
	.tseg1_max = 64,
	.tseg2_min = 2,
	.tseg2_max = 16,
	.sjw_max = 16,
	.brp_min = 1,
	.brp_max = 256,
	.brp_inc = 1,
};

static struct can_bittiming_const ccan_data_bittiming_const_canfd = {
	.name = DRIVER_NAME,
	.tseg1_min = 1,
	.tseg1_max = 16,
	.tseg2_min = 2,
	.tseg2_max = 8,
	.sjw_max = 8,
	.brp_min = 1,
	.brp_max = 256,
	.brp_inc = 1,
};

static void ccan_write_reg_le(const struct ccan_priv *priv,
			      enum ccan_device_reg reg, u32 val)
{
	iowrite32(val, priv->reg_base + reg);
}

static u32 ccan_read_reg_le(const struct ccan_priv *priv,
			    enum ccan_device_reg reg)
{
	return ioread32(priv->reg_base + reg);
}

static inline unsigned char ccan_ioread8(const void  *addr)
{
	void  *addr_down;
	union val {
		u8 val_8[4];
		u32 val_32;
	} val;
	u32 offset = 0;

	addr_down = (void  *)ALIGN_DOWN((unsigned long)addr, 4);
	offset = addr - addr_down;
	val.val_32 = ioread32(addr_down);

	return val.val_8[offset];
}

static inline void ccan_iowrite8(unsigned char value, void  *addr)
{
	void  *addr_down;
	union val {
		u8 val_8[4];
		u32 val_32;
	} val;
	u8 offset = 0;

	addr_down = (void *)ALIGN_DOWN((unsigned long)addr, 4);
	offset = addr - addr_down;
	val.val_32 = ioread32(addr_down);
	val.val_8[offset] = value;
	iowrite32(val.val_32, addr_down);
}

static void ccan_reigister_set_bit(const struct ccan_priv *priv,
				   enum ccan_device_reg reg,
				   enum ccan_reg_bitchange mask)
{
	void  *addr_down;
	union val {
		u8 val_8[4];
		u32 val_32;
	} val;
	u8 offset = 0;

	addr_down = (void *)ALIGN_DOWN((unsigned long)(priv->reg_base + reg), 4);
	offset = (priv->reg_base + reg) - addr_down;
	val.val_32 = ioread32(addr_down);
	val.val_8[offset] |= mask;
	iowrite32(val.val_32, addr_down);
}

static void ccan_reigister_off_bit(const struct ccan_priv *priv,
				   enum ccan_device_reg reg,
				   enum ccan_reg_bitchange mask)
{
	void  *addr_down;
	union val {
		u8 val_8[4];
		u32 val_32;
	} val;
	u8 offset = 0;

	addr_down = (void *)ALIGN_DOWN((unsigned long)(priv->reg_base + reg), 4);
	offset = (priv->reg_base + reg) - addr_down;
	val.val_32 = ioread32(addr_down);
	val.val_8[offset] &= mask;
	iowrite32(val.val_32, addr_down);
}

static int ccan_device_driver_bittime_configuration(struct net_device *ndev)
{
	struct ccan_priv *priv = netdev_priv(ndev);
	struct can_bittiming *bt = &priv->can.bittiming;
	struct can_bittiming *dbt = &priv->can.data_bittiming;
	u32 reset_test, bittiming_temp, data_bittiming;

	reset_test = ccan_ioread8(priv->reg_base + CCAN_CFG_STAT_OFFSET);

	if (!(reset_test & CCAN_SET_RST_MASK)) {
		netdev_alert(ndev, "Not in reset mode, cannot set bit timing\n");
		return -EPERM;
	}

	bittiming_temp = ((bt->phase_seg1 + bt->prop_seg + 1 - 2) << SEG_1_SHIFT) |
			 ((bt->phase_seg2 - 1) << SEG_2_SHIFT) |
			 ((bt->sjw - 1) << SJW_SHIFT) |
			 ((bt->brp - 1) << PRESC_SHIFT);

	/* Check the bittime parameter */
	if ((((int)(bt->phase_seg1 + bt->prop_seg + 1) - 2) < 0) ||
	    (((int)(bt->phase_seg2) - 1) < 0) ||
	    (((int)(bt->sjw) - 1) < 0) ||
	    (((int)(bt->brp) - 1) < 0))
		return -EINVAL;

	priv->write_reg(priv, CCAN_S_SEG_1_OFFSET, bittiming_temp);

	if (priv->cantype == CAST_CAN_TYPE_CANFD) {
		data_bittiming = ((dbt->phase_seg1 + dbt->prop_seg + 1 - 2) << SEG_1_SHIFT) |
				 ((dbt->phase_seg2 - 1) << SEG_2_SHIFT) |
				 ((dbt->sjw - 1) << SJW_SHIFT) |
				 ((dbt->brp - 1) << PRESC_SHIFT);

		if ((((int)(dbt->phase_seg1 + dbt->prop_seg + 1) - 2) < 0) ||
		    (((int)(dbt->phase_seg2) - 1) < 0) ||
		    (((int)(dbt->sjw) - 1) < 0) ||
		    (((int)(dbt->brp) - 1) < 0))
			return -EINVAL;

		priv->write_reg(priv, CCAN_F_SEG_1_OFFSET, data_bittiming);
	}

	ccan_reigister_off_bit(priv, CCAN_CFG_STAT_OFFSET, CCAN_OFF_RST_MASK);

	netdev_dbg(ndev, "Slow bit rate: %08x\n", priv->read_reg(priv, CCAN_S_SEG_1_OFFSET));
	netdev_dbg(ndev, "Fast bit rate: %08x\n", priv->read_reg(priv, CCAN_F_SEG_1_OFFSET));

	return 0;
}

int ccan_get_freebuffer(struct ccan_priv *priv)
{
	/* Get next transmit buffer */
	ccan_reigister_set_bit(priv, CCAN_TCTRL_OFFSET, CCAN_SET_TENEXT_MASK);

	if (ccan_ioread8(priv->reg_base + CCAN_TCTRL_OFFSET) & CCAN_SET_TENEXT_MASK)
		return -EPERM;

	return 0;
}

static void ccan_tx_interrupt(struct net_device *ndev, u8 isr)
{
	struct ccan_priv *priv = netdev_priv(ndev);

	/* wait till transmission of the PTB or STB finished */
	while (isr & (CCAN_SET_TPIF_MASK | CCAN_SET_TSIF_MASK)) {
		if (isr & CCAN_SET_TPIF_MASK)
			ccan_reigister_set_bit(priv, CCAN_RTIF_OFFSET, CCAN_SET_TPIF_MASK);

		if (isr & CCAN_SET_TSIF_MASK)
			ccan_reigister_set_bit(priv, CCAN_RTIF_OFFSET, CCAN_SET_TSIF_MASK);

		isr = ccan_ioread8(priv->reg_base + CCAN_RTIF_OFFSET);
	}
	netif_wake_queue(ndev);
}

static int ccan_rx(struct net_device *ndev)
{
	struct ccan_priv *priv = netdev_priv(ndev);
	struct net_device_stats *stats = &ndev->stats;
	struct can_frame *cf;
	struct sk_buff *skb;
	u32 can_id;
	u8  dlc, control, rx_status;

	rx_status = ccan_ioread8(priv->reg_base + CCAN_RCTRL_OFFSET);

	if (!(rx_status & CCAN_RSTAT_NOT_EMPTY_MASK))
		return 0;

	control = ccan_ioread8(priv->reg_base + CCAN_RBUF_CTL_OFFSET);
	can_id = priv->read_reg(priv, CCAN_RUBF_ID_OFFSET);
	dlc = ccan_ioread8(priv->reg_base + CCAN_RBUF_CTL_OFFSET) & CCAN_SET_DLC_MASK;

	skb = alloc_can_skb(ndev, (struct can_frame **)&cf);
	if (!skb) {
		stats->rx_dropped++;
		return 0;
	}
	cf->can_dlc = can_cc_dlc2len(dlc);

	/* change the CANFD id into socketcan id format */
	cf->can_id = can_id;
	if (control & CCAN_SET_IDE_MASK)
		cf->can_id |= CAN_EFF_FLAG;
	else
		cf->can_id &= ~CAN_EFF_FLAG;

	if (control & CCAN_SET_RTR_MASK)
		cf->can_id |= CAN_RTR_FLAG;

	if (!(control & CCAN_SET_RTR_MASK)) {
		*((u32 *)(cf->data + 0)) = priv->read_reg(priv, CCAN_RBUF_DATA_OFFSET);
		*((u32 *)(cf->data + 4)) = priv->read_reg(priv, CCAN_RBUF_DATA_OFFSET + 4);
	}

	ccan_reigister_set_bit(priv, CCAN_RCTRL_OFFSET, CCAN_SET_RREL_MASK);
	stats->rx_bytes += can_fd_dlc2len(cf->can_dlc);
	stats->rx_packets++;
	netif_receive_skb(skb);

	return 1;
}

static int ccanfd_rx(struct net_device *ndev)
{
	struct ccan_priv *priv = netdev_priv(ndev);
	struct net_device_stats *stats = &ndev->stats;
	struct canfd_frame *cf;
	struct sk_buff *skb;
	u32 can_id;
	u8  dlc, control, rx_status;
	int i;

	rx_status = ccan_ioread8(priv->reg_base + CCAN_RCTRL_OFFSET);

	if (!(rx_status & CCAN_RSTAT_NOT_EMPTY_MASK))
		return 0;

	control = ccan_ioread8(priv->reg_base + CCAN_RBUF_CTL_OFFSET);
	can_id = priv->read_reg(priv, CCAN_RUBF_ID_OFFSET);
	dlc = ccan_ioread8(priv->reg_base + CCAN_RBUF_CTL_OFFSET) & CCAN_SET_DLC_MASK;

	if (control & CCAN_SET_EDL_MASK)
		/* allocate sk_buffer for canfd frame */
		skb = alloc_canfd_skb(ndev, &cf);
	else
		/* allocate sk_buffer for can frame */
		skb = alloc_can_skb(ndev, (struct can_frame **)&cf);

	if (!skb) {
		stats->rx_dropped++;
		return 0;
	}

	/* change the CANFD or CAN2.0 data into socketcan data format */
	if (control & CCAN_SET_EDL_MASK)
		cf->len = can_fd_dlc2len(dlc);
	else
		cf->len = can_cc_dlc2len(dlc);

	/* change the CANFD id into socketcan id format */
	cf->can_id = can_id;
	if (control & CCAN_SET_IDE_MASK)
		cf->can_id |= CAN_EFF_FLAG;
	else
		cf->can_id &= ~CAN_EFF_FLAG;

	if (!(control & CCAN_SET_EDL_MASK))
		if (control & CCAN_SET_RTR_MASK)
			cf->can_id |= CAN_RTR_FLAG;

	/* CANFD frames handed over to SKB */
	if (control & CCAN_SET_EDL_MASK) {
		for (i = 0; i < cf->len; i += 4)
			*((u32 *)(cf->data + i)) = priv->read_reg(priv, CCAN_RBUF_DATA_OFFSET + i);
	} else {
		/* skb reads the received datas, if the RTR bit not set */
		if (!(control & CCAN_SET_RTR_MASK)) {
			*((u32 *)(cf->data + 0)) = priv->read_reg(priv, CCAN_RBUF_DATA_OFFSET);
			*((u32 *)(cf->data + 4)) = priv->read_reg(priv, CCAN_RBUF_DATA_OFFSET + 4);
		}
	}

	ccan_reigister_set_bit(priv, CCAN_RCTRL_OFFSET, CCAN_SET_RREL_MASK);

	stats->rx_bytes += cf->len;
	stats->rx_packets++;
	netif_receive_skb(skb);

	return 1;
}

static int ccan_rx_poll(struct napi_struct *napi, int quota)
{
	struct net_device *ndev = napi->dev;
	struct ccan_priv *priv = netdev_priv(ndev);
	int work_done = 0;
	u8 rx_status = 0, control = 0;

	control = ccan_ioread8(priv->reg_base + CCAN_RBUF_CTL_OFFSET);
	rx_status = ccan_ioread8(priv->reg_base + CCAN_RCTRL_OFFSET);

	/* clear receive interrupt and deal with all the received frames */
	while ((rx_status & CCAN_RSTAT_NOT_EMPTY_MASK) && (work_done < quota)) {
		if (control & CCAN_SET_EDL_MASK)
			work_done += ccanfd_rx(ndev);
		else
			work_done += ccan_rx(ndev);

		control = ccan_ioread8(priv->reg_base + CCAN_RBUF_CTL_OFFSET);
		rx_status = ccan_ioread8(priv->reg_base + CCAN_RCTRL_OFFSET);
	}

	napi_complete(napi);
	ccan_reigister_set_bit(priv, CCAN_RTIE_OFFSET, CCAN_SET_RIE_MASK);

	return work_done;
}

static void ccan_rxfull_interrupt(struct net_device *ndev, u8 isr)
{
	struct ccan_priv *priv = netdev_priv(ndev);

	if (isr & CCAN_SET_RAFIF_MASK)
		ccan_reigister_set_bit(priv, CCAN_RTIF_OFFSET, CCAN_SET_RAFIF_MASK);

	if (isr & (CCAN_SET_RAFIF_MASK | CCAN_SET_RFIF_MASK))
		ccan_reigister_set_bit(priv, CCAN_RTIF_OFFSET,
				       (CCAN_SET_RAFIF_MASK | CCAN_SET_RFIF_MASK));
}

static int set_ccan_xmit_mode(struct net_device *ndev)
{
	struct ccan_priv *priv = netdev_priv(ndev);

	switch (priv->tx_mode) {
	case XMIT_FULL:
		ccan_reigister_set_bit(priv, CCAN_TCTRL_OFFSET, CCAN_SET_FULLCAN_MASK);
		break;
	case XMIT_SEP_FIFO:
		ccan_reigister_off_bit(priv, CCAN_TCTRL_OFFSET, CCAN_OFF_FULLCAN_MASK);
		ccan_reigister_set_bit(priv, CCAN_TCTRL_OFFSET, CCAN_SET_FIFO_MASK);
		ccan_reigister_off_bit(priv, CCAN_TCMD_OFFSET, CCAN_SET_TBSEL_MASK);
		break;
	case XMIT_SEP_PRIO:
		ccan_reigister_off_bit(priv, CCAN_TCTRL_OFFSET, CCAN_OFF_FULLCAN_MASK);
		ccan_reigister_off_bit(priv, CCAN_TCTRL_OFFSET, CCAN_OFF_FIFO_MASK);
		ccan_reigister_off_bit(priv, CCAN_TCMD_OFFSET, CCAN_SET_TBSEL_MASK);
		break;
	case XMIT_PTB_MODE:
		ccan_reigister_off_bit(priv, CCAN_TCMD_OFFSET, CCAN_OFF_TBSEL_MASK);
		break;
	default:
		break;
	}
	return 0;
}

static netdev_tx_t ccan_driver_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct ccan_priv *priv = netdev_priv(ndev);
	struct canfd_frame *cf = (struct canfd_frame *)skb->data;
	struct net_device_stats *stats = &ndev->stats;
	u32 ttsen, id, ctl, addr_off;
	int i;

	priv->tx_mode = XMIT_PTB_MODE;

	if (can_dropped_invalid_skb(ndev, skb))
		return NETDEV_TX_OK;

	switch (priv->tx_mode) {
	case XMIT_FULL:
		return NETDEV_TX_BUSY;
	case XMIT_PTB_MODE:
		set_ccan_xmit_mode(ndev);
		ccan_reigister_off_bit(priv, CCAN_TCMD_OFFSET, CCAN_OFF_STBY_MASK);

		if (cf->can_id & CAN_EFF_FLAG) {
			id = cf->can_id & CAN_EFF_MASK;
			ttsen = 0 << TTSEN_8_32_SHIFT;
			id |= ttsen;
		} else {
			id = cf->can_id & CAN_SFF_MASK;
			ttsen = 0 << TTSEN_8_32_SHIFT;
			id |= ttsen;
		}

		ctl = can_fd_len2dlc(cf->len);

		/* transmit can fd frame */
		if (priv->cantype == CAST_CAN_TYPE_CANFD) {
			if (can_is_canfd_skb(skb)) {
				if (cf->can_id & CAN_EFF_FLAG)
					ctl |= CCAN_SET_IDE_MASK;
				else
					ctl &= CCAN_OFF_IDE_MASK;

				if (cf->flags & CANFD_BRS)
					ctl |= CCAN_SET_BRS_MASK;

				ctl |= CCAN_SET_EDL_MASK;

				addr_off = CCAN_TBUF_DATA_OFFSET;

				for (i = 0; i < cf->len; i += 4) {
					priv->write_reg(priv, addr_off,
							*((u32 *)(cf->data + i)));
					addr_off += 4;
				}
			} else {
				ctl &= (CCAN_OFF_EDL_MASK | CCAN_OFF_BRS_MASK);

				if (cf->can_id & CAN_EFF_FLAG)
					ctl |= CCAN_SET_IDE_MASK;
				else
					ctl &= CCAN_OFF_IDE_MASK;

				if (cf->can_id & CAN_RTR_FLAG) {
					ctl |= CCAN_SET_RTR_MASK;
					priv->write_reg(priv,
						CCAN_TBUF_ID_OFFSET, id);
					priv->write_reg(priv,
						CCAN_TBUF_CTL_OFFSET, ctl);
				} else {
					ctl &= CCAN_OFF_RTR_MASK;
					addr_off = CCAN_TBUF_DATA_OFFSET;
					priv->write_reg(priv, addr_off,
							*((u32 *)(cf->data + 0)));
					priv->write_reg(priv, addr_off + 4,
							*((u32 *)(cf->data + 4)));
				}
			}
			priv->write_reg(priv, CCAN_TBUF_ID_OFFSET, id);
			priv->write_reg(priv, CCAN_TBUF_CTL_OFFSET, ctl);
			addr_off = CCAN_TBUF_DATA_OFFSET;
		} else {
			ctl &= (CCAN_OFF_EDL_MASK | CCAN_OFF_BRS_MASK);

			if (cf->can_id & CAN_EFF_FLAG)
				ctl |= CCAN_SET_IDE_MASK;
			else
				ctl &= CCAN_OFF_IDE_MASK;

			if (cf->can_id & CAN_RTR_FLAG) {
				ctl |= CCAN_SET_RTR_MASK;
				priv->write_reg(priv, CCAN_TBUF_ID_OFFSET, id);
				priv->write_reg(priv, CCAN_TBUF_CTL_OFFSET, ctl);
			} else {
				ctl &= CCAN_OFF_RTR_MASK;
				priv->write_reg(priv, CCAN_TBUF_ID_OFFSET, id);
				priv->write_reg(priv, CCAN_TBUF_CTL_OFFSET, ctl);
				addr_off = CCAN_TBUF_DATA_OFFSET;
				priv->write_reg(priv, addr_off,
						*((u32 *)(cf->data + 0)));
				priv->write_reg(priv, addr_off + 4,
						*((u32 *)(cf->data + 4)));
			}
		}
		ccan_reigister_set_bit(priv, CCAN_TCMD_OFFSET, CCAN_SET_TPE_MASK);
		stats->tx_bytes += cf->len;
		break;
	default:
		break;
	}

	if (!(ndev->flags & IFF_ECHO) || (skb->protocol != htons(ETH_P_CAN) &&
					  skb->protocol != htons(ETH_P_CANFD))) {
		kfree_skb(skb);
		return 0;
	}

	skb = can_create_echo_skb(skb);
	if (!skb)
		return -ENOMEM;

	/* make settings for echo to reduce code in irq context */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->dev = ndev;

	skb_tx_timestamp(skb);

	return NETDEV_TX_OK;
}

static int set_reset_mode(struct net_device *ndev)
{
	struct ccan_priv *priv = netdev_priv(ndev);
	u8 ret;

	ret = ccan_ioread8(priv->reg_base + CCAN_CFG_STAT_OFFSET);
	ret |= CCAN_SET_RST_MASK;
	ccan_iowrite8(ret, priv->reg_base + CCAN_CFG_STAT_OFFSET);

	return 0;
}

static void ccan_driver_stop(struct net_device *ndev)
{
	struct ccan_priv *priv = netdev_priv(ndev);
	int ret;

	ret = set_reset_mode(ndev);
	if (ret)
		netdev_err(ndev, "Mode resetting failed!\n");

	priv->can.state = CAN_STATE_STOPPED;
}

static int ccan_driver_close(struct net_device *ndev)
{
	struct ccan_priv *priv = netdev_priv(ndev);

	netif_stop_queue(ndev);
	napi_disable(&priv->napi);
	ccan_driver_stop(ndev);

	close_candev(ndev);

	return 0;
}

static enum can_state get_of_chip_status(struct net_device *ndev)
{
	struct ccan_priv *priv = netdev_priv(ndev);
	u8 can_stat, eir;

	can_stat = ccan_ioread8(priv->reg_base + CCAN_CFG_STAT_OFFSET);
	eir = ccan_ioread8(priv->reg_base + CCAN_ERRINT_OFFSET);

	if (can_stat & CCAN_SET_BUSOFF_MASK)
		return CAN_STATE_BUS_OFF;

	if ((eir & CCAN_SET_EPASS_MASK) && ~(can_stat & CCAN_SET_BUSOFF_MASK))
		return CAN_STATE_ERROR_PASSIVE;

	if (eir & CCAN_SET_EWARN_MASK && ~(eir & CCAN_SET_EPASS_MASK))
		return CAN_STATE_ERROR_WARNING;

	if (~(eir & CCAN_SET_EPASS_MASK))
		return CAN_STATE_ERROR_ACTIVE;

	return CAN_STATE_ERROR_ACTIVE;
}

static void ccan_error_interrupt(struct net_device *ndev, u8 isr, u8 eir)
{
	struct ccan_priv *priv = netdev_priv(ndev);
	struct net_device_stats *stats = &ndev->stats;
	struct can_frame *cf;
	struct sk_buff *skb;
	u8 koer, recnt = 0, tecnt = 0, can_stat = 0;

	skb = alloc_can_err_skb(ndev, &cf);

	koer = ccan_ioread8(priv->reg_base + CCAN_EALCAP_OFFSET) & CCAN_SET_KOER_MASK;
	recnt = ccan_ioread8(priv->reg_base + CCAN_RECNT_OFFSET);
	tecnt = ccan_ioread8(priv->reg_base + CCAN_TECNT_OFFSET);

	/*Read can status*/
	can_stat = ccan_ioread8(priv->reg_base + CCAN_CFG_STAT_OFFSET);

	/* Bus off --->active error mode */
	if ((isr & CCAN_SET_EIF_MASK) && priv->can.state == CAN_STATE_BUS_OFF)
		priv->can.state = get_of_chip_status(ndev);

	/* State selection */
	if (can_stat & CCAN_SET_BUSOFF_MASK) {
		priv->can.state = get_of_chip_status(ndev);
		priv->can.can_stats.bus_off++;
		ccan_reigister_set_bit(priv, CCAN_CFG_STAT_OFFSET, CCAN_SET_BUSOFF_MASK);
		can_bus_off(ndev);
		if (skb)
			cf->can_id |= CAN_ERR_BUSOFF;

	} else if ((eir & CCAN_SET_EPASS_MASK) && ~(can_stat & CCAN_SET_BUSOFF_MASK)) {
		priv->can.state = get_of_chip_status(ndev);
		priv->can.can_stats.error_passive++;
		if (skb) {
			cf->can_id |= CAN_ERR_CRTL;
			cf->data[1] |= (recnt > 127) ? CAN_ERR_CRTL_RX_PASSIVE : 0;
			cf->data[1] |= (tecnt > 127) ? CAN_ERR_CRTL_TX_PASSIVE : 0;
			cf->data[6] = tecnt;
			cf->data[7] = recnt;
		}
	} else if (eir & CCAN_SET_EWARN_MASK && ~(eir & CCAN_SET_EPASS_MASK)) {
		priv->can.state = get_of_chip_status(ndev);
		priv->can.can_stats.error_warning++;
		if (skb) {
			cf->can_id |= CAN_ERR_CRTL;
			cf->data[1] |= (recnt > 95) ? CAN_ERR_CRTL_RX_WARNING : 0;
			cf->data[1] |= (tecnt > 95) ? CAN_ERR_CRTL_TX_WARNING : 0;
			cf->data[6] = tecnt;
			cf->data[7] = recnt;
		}
	}

	/* Check for in protocol defined error interrupt */
	if (eir & CCAN_SET_BEIF_MASK) {
		if (skb)
			cf->can_id |= CAN_ERR_BUSERROR | CAN_ERR_PROT;

		if (koer == CCAN_SET_BIT_ERROR_MASK) {
			stats->tx_errors++;
			if (skb)
				cf->data[2] = CAN_ERR_PROT_BIT;
		} else if (koer == CCAN_SET_FORM_ERROR_MASK) {
			stats->rx_errors++;
			if (skb)
				cf->data[2] = CAN_ERR_PROT_FORM;
		} else if (koer == CCAN_SET_STUFF_ERROR_MASK) {
			stats->rx_errors++;
			if (skb)
				cf->data[3] = CAN_ERR_PROT_STUFF;
		} else if (koer == CCAN_SET_ACK_ERROR_MASK) {
			stats->tx_errors++;
			if (skb)
				cf->data[2] = CAN_ERR_PROT_LOC_ACK;
		} else if (koer == CCAN_SET_CRC_ERROR_MASK) {
			stats->rx_errors++;
			if (skb)
				cf->data[2] = CAN_ERR_PROT_LOC_CRC_SEQ;
		}
		priv->can.can_stats.bus_error++;
	}

	if (skb) {
		stats->rx_packets++;
		stats->rx_bytes += cf->can_dlc;
		netif_rx(skb);
	}

	netdev_dbg(ndev, "Recnt is 0x%02x", ccan_ioread8(priv->reg_base + CCAN_RECNT_OFFSET));
	netdev_dbg(ndev, "Tecnt is 0x%02x", ccan_ioread8(priv->reg_base + CCAN_TECNT_OFFSET));
}

static irqreturn_t ccan_interrupt(int irq, void *dev_id)
{
	struct net_device *ndev = (struct net_device *)dev_id;
	struct ccan_priv *priv = netdev_priv(ndev);
	u8 isr, eir;
	u8 isr_handled = 0, eir_handled = 0;

	/* read the value of interrupt status register */
	isr = ccan_ioread8(priv->reg_base + CCAN_RTIF_OFFSET);

	/* read the value of error interrupt register */
	eir = ccan_ioread8(priv->reg_base + CCAN_ERRINT_OFFSET);

	/* Check for Tx interrupt and Processing it */
	if (isr & (CCAN_SET_TPIF_MASK | CCAN_SET_TSIF_MASK)) {
		ccan_tx_interrupt(ndev, isr);
		isr_handled |= (CCAN_SET_TPIF_MASK | CCAN_SET_TSIF_MASK);
	}

	if (isr & (CCAN_SET_RAFIF_MASK | CCAN_SET_RFIF_MASK)) {
		ccan_rxfull_interrupt(ndev, isr);
		isr_handled |= (CCAN_SET_RAFIF_MASK | CCAN_SET_RFIF_MASK);
	}

	/* Check Rx interrupt and Processing the receive interrupt routine */
	if (isr & CCAN_SET_RIF_MASK) {
		ccan_reigister_off_bit(priv, CCAN_RTIE_OFFSET, CCAN_OFF_RIE_MASK);
		ccan_reigister_set_bit(priv, CCAN_RTIF_OFFSET, CCAN_SET_RIF_MASK);

		napi_schedule(&priv->napi);
		isr_handled |= CCAN_SET_RIF_MASK;
	}

	if ((isr & CCAN_SET_EIF_MASK) |
	    (eir & (CCAN_SET_EPIF_MASK | CCAN_SET_BEIF_MASK))) {
		/* reset EPIF and BEIF. Reset EIF */
		ccan_reigister_set_bit(priv, CCAN_ERRINT_OFFSET,
				       eir & (CCAN_SET_EPIF_MASK | CCAN_SET_BEIF_MASK));
		ccan_reigister_set_bit(priv, CCAN_RTIF_OFFSET,
				       isr & CCAN_SET_EIF_MASK);

		ccan_error_interrupt(ndev, isr, eir);

		isr_handled |= CCAN_SET_EIF_MASK;
		eir_handled |= (CCAN_SET_EPIF_MASK | CCAN_SET_BEIF_MASK);
	}

	if (isr_handled == 0 && eir_handled == 0) {
		netdev_err(ndev, "Unhandled interrupt!\n");
		return IRQ_NONE;
	}

	return IRQ_HANDLED;
}

static int ccan_chip_start(struct net_device *ndev)
{
	struct ccan_priv *priv = netdev_priv(ndev);
	int err;
	u8 ret;

	err = set_reset_mode(ndev);
	if (err) {
		netdev_err(ndev, "Mode resetting failed!\n");
		return err;
	}

	err = ccan_device_driver_bittime_configuration(ndev);
	if (err) {
		netdev_err(ndev, "Bittime setting failed!\n");
		return err;
	}

	/* Set Almost Full Warning Limit */
	ccan_reigister_set_bit(priv, CCAN_LIMIT_OFFSET, CCAN_SET_AFWL_MASK);

	/* Programmable Error Warning Limit = (EWL+1)*8. Set EWL=11->Error Warning=96 */
	ccan_reigister_set_bit(priv, CCAN_LIMIT_OFFSET, CCAN_SET_EWL_MASK);

	/* Interrupts enable */
	ccan_iowrite8(CCAN_INTR_ALL_MASK, priv->reg_base + CCAN_RTIE_OFFSET);

	/* Error Interrupts enable(Error Passive and Bus Error) */
	ccan_reigister_set_bit(priv, CCAN_ERRINT_OFFSET, CCAN_SET_EPIE_MASK);

	ret = ccan_ioread8(priv->reg_base + CCAN_CFG_STAT_OFFSET);

	/* Check whether it is loopback mode or normal mode */
	if (priv->can.ctrlmode & CAN_CTRLMODE_LOOPBACK)
		ret |= CCAN_LBMIMOD_MASK;
	else
		ret &= ~(CCAN_LBMEMOD_MASK | CCAN_LBMIMOD_MASK);

	ccan_iowrite8(ret, priv->reg_base + CCAN_CFG_STAT_OFFSET);

	priv->can.state = CAN_STATE_ERROR_ACTIVE;

	return 0;
}

static int  ccan_do_set_mode(struct net_device *ndev, enum can_mode mode)
{
	int ret;

	switch (mode) {
	case CAN_MODE_START:
		ret = ccan_chip_start(ndev);
		if (ret) {
			netdev_err(ndev, "Could not start CAN device !\n");
			return ret;
		}
		netif_wake_queue(ndev);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}

static int ccan_driver_open(struct net_device *ndev)
{
	struct ccan_priv *priv = netdev_priv(ndev);
	int ret;

	/* Set chip into reset mode */
	ret = set_reset_mode(ndev);
	if (ret) {
		netdev_err(ndev, "Mode resetting failed!\n");
		return ret;
	}

	/* Common open */
	ret = open_candev(ndev);
	if (ret)
		return ret;

	/* Register interrupt handler */
	ret = devm_request_irq(priv->dev, ndev->irq, ccan_interrupt, IRQF_SHARED,
			       ndev->name, ndev);
	if (ret) {
		netdev_err(ndev, "Request_irq err: %d\n", ret);
		goto err;
	}

	ret = ccan_chip_start(ndev);
	if (ret) {
		netdev_err(ndev, "Could not start CAN device !\n");
		goto err;
	}

	napi_enable(&priv->napi);
	netif_start_queue(ndev);

	return 0;

err:
	close_candev(ndev);
	return ret;
}

static int ccan_starfive_parse_dt(struct ccan_priv *priv)
{
	struct of_phandle_args args;
	u32 syscon_mask, syscon_shift;
	u32 syscon_offset, regval;
	int ret;

	ret = of_parse_phandle_with_fixed_args(priv->dev->of_node,
					       "starfive,sys-syscon", 3, 0, &args);
	if (ret) {
		dev_err(priv->dev, "Failed to parse starfive,sys-syscon\n");
		return -EINVAL;
	}

	priv->reg_syscon = syscon_node_to_regmap(args.np);
	of_node_put(args.np);
	if (IS_ERR(priv->reg_syscon))
		return PTR_ERR(priv->reg_syscon);

	syscon_offset = args.args[0];
	syscon_shift  = args.args[1];
	syscon_mask   = args.args[2];

	/* enable can2.0/canfd function */
	regval = priv->cantype << syscon_shift;
	ret = regmap_update_bits(priv->reg_syscon, syscon_offset, syscon_mask, regval);
	if (ret)
		return ret;

	priv->is_starfive = true;

	return 0;
}

static const struct net_device_ops ccan_netdev_ops = {
	.ndo_open = ccan_driver_open,
	.ndo_stop = ccan_driver_close,
	.ndo_start_xmit = ccan_driver_start_xmit,
	.ndo_change_mtu = can_change_mtu,
};

static const struct cast_can_data ccan_can_data = {
	.cantype = CAST_CAN_TYPE_CAN,
	.bittime_const = &ccan_bittiming_const,
};

static const struct cast_can_data ccan_canfd_data = {
	.cantype = CAST_CAN_TYPE_CANFD,
	.bittime_const = &ccan_bittiming_const_canfd,
};

static const struct cast_can_data sfcan_can_data = {
	.cantype = CAST_CAN_TYPE_CAN,
	.bittime_const = &ccan_bittiming_const,
	.starfive_parse_dt = ccan_starfive_parse_dt,
};

static const struct of_device_id ccan_of_match[] = {
	{ .compatible = "cast,can", .data = &ccan_can_data },
	{ .compatible = "cast,canfd", .data = &ccan_canfd_data },
	{ .compatible = "starfive,can", .data = &sfcan_can_data },
	{ /* end of list */ },
};
MODULE_DEVICE_TABLE(of, ccan_of_match);

static int ccan_driver_probe(struct platform_device *pdev)
{
	struct net_device *ndev;
	struct ccan_priv *priv;
	const struct of_device_id *id;
	const struct cast_can_data *ddata;
	void __iomem *addr;
	int ret;

	addr = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(addr)) {
		ret = PTR_ERR(addr);
		goto exit;
	}

	id = of_match_device(ccan_of_match, &pdev->dev);
	if (id && id->data)
		ddata = id->data;

	ndev = alloc_candev(sizeof(struct ccan_priv), 1);
	if (!ndev) {
		ret = -ENOMEM;
		goto exit;
	}

	priv = netdev_priv(ndev);
	priv->dev = &pdev->dev;
	priv->is_starfive = false;

	if (ddata) {
		if (ddata->starfive_parse_dt) {
			ret = ccan_starfive_parse_dt(priv);
			if (ret)
				goto free_exit;
		}
	}

	priv->can_clk = devm_clk_get_enabled(&pdev->dev, "can_clk");
	if (IS_ERR(priv->can_clk)) {
		ret = dev_err_probe(&pdev->dev, PTR_ERR(priv->can_clk),
				    "Device clock not found\n");
		goto free_exit;
	}

	priv->host_clk = devm_clk_get_enabled(&pdev->dev, "apb_clk");
	if (IS_ERR(priv->host_clk)) {
		ret = dev_err_probe(&pdev->dev, PTR_ERR(priv->host_clk),
				    "Host clock not found\n");
		goto free_exit;
	}

	priv->timer_clk = devm_clk_get_enabled(&pdev->dev, "timer_clk");
	if (IS_ERR(priv->timer_clk)) {
		ret = dev_err_probe(&pdev->dev, PTR_ERR(priv->timer_clk),
				    "Timer clock not found\n");
		goto free_exit;
	}

	priv->resets = devm_reset_control_array_get_exclusive(&pdev->dev);
	if (IS_ERR(priv->resets)) {
		ret = dev_err_probe(&pdev->dev, PTR_ERR(priv->resets),
				    "Failed to get CAN resets");
		goto clk_exit;
	}

	ret = reset_control_deassert(priv->resets);
	if (ret)
		goto clk_exit;

	priv->can.do_set_mode = ccan_do_set_mode;
	priv->can.bittiming_const = ddata->bittime_const;
	priv->cantype = ddata->cantype;

	if (priv->cantype == CAST_CAN_TYPE_CANFD) {
		priv->can.ctrlmode_supported = CAN_CTRLMODE_LOOPBACK | CAN_CTRLMODE_FD;
		priv->can.data_bittiming_const = &ccan_data_bittiming_const_canfd;
	} else {
		priv->can.ctrlmode_supported = CAN_CTRLMODE_LOOPBACK;
	}

	priv->reg_base = addr;
	priv->write_reg = ccan_write_reg_le;
	priv->read_reg = ccan_read_reg_le;
	priv->can.clock.freq = clk_get_rate(priv->can_clk);
	ndev->irq = platform_get_irq(pdev, 0);

	/* we support local echo */
	ndev->flags |= IFF_ECHO;
	ndev->netdev_ops = &ccan_netdev_ops;

	platform_set_drvdata(pdev, ndev);
	SET_NETDEV_DEV(ndev, &pdev->dev);

	netif_napi_add_tx_weight(ndev, &priv->napi, ccan_rx_poll, 16);
	ret = register_candev(ndev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to register (err=%d)\n", ret);
		goto reset_exit;
	}

	dev_dbg(&pdev->dev, "Driver registered: regs=%p, irp=%d, clock=%d\n",
		priv->reg_base, ndev->irq, priv->can.clock.freq);

	return 0;

reset_exit:
	reset_control_assert(priv->resets);
clk_exit:
	clk_disable_unprepare(priv->can_clk);
	clk_disable_unprepare(priv->host_clk);
	clk_disable_unprepare(priv->timer_clk);
free_exit:
	free_candev(ndev);
exit:
	return ret;
}

static int ccan_driver_remove(struct platform_device *pdev)
{
	struct net_device *ndev = platform_get_drvdata(pdev);
	struct ccan_priv *priv = netdev_priv(ndev);

	reset_control_assert(priv->resets);
	clk_disable_unprepare(priv->can_clk);
	clk_disable_unprepare(priv->host_clk);
	clk_disable_unprepare(priv->timer_clk);

	unregister_candev(ndev);
	netif_napi_del(&priv->napi);
	free_candev(ndev);

	return 0;
}

static struct platform_driver ccan_driver = {
	.probe          = ccan_driver_probe,
	.remove         = ccan_driver_remove,
	.driver = {
		.name  = DRIVER_NAME,
		.of_match_table = ccan_of_match,
	},
};

module_platform_driver(ccan_driver);

MODULE_DESCRIPTION("CAST CAN Controller Driver");
MODULE_AUTHOR("William Qiu<william.qiu@starfivetech.com");
MODULE_LICENSE("GPL");

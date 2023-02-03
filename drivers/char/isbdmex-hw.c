/* isbdmex-hw
 *
 * ISBDM exerciser driver, hardware interface
 *
 * SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * 3 Feb 2023 mev
 */

#include <linux/io.h>
#include <linux/miscdevice.h>

#include "isbdmex.h"


/* All regs are 64b */
#define ISBDM_CMD_RING_BASE	0
#define ISBDM_CMD_RING_HEAD	8
#define ISBDM_CMD_RING_TAIL	16
#define ISBDM_CMD_RING_CTRL	24
#define ISBDM_RX_RING_BASE	32
#define ISBDM_RX_RING_HEAD	40
#define ISBDM_RX_RING_TAIL	48
#define ISBDM_RX_RING_CTRL	56
#define ISBDM_TX_RING_BASE	64
#define ISBDM_TX_RING_HEAD	72
#define ISBDM_TX_RING_TAIL	80
#define ISBDM_TX_RING_CTRL	88
#define ISBDM_RMBA_BASE		96
#define ISBDM_RMBA_CTRL		104
#define ISBDM_IPSR		112
#define ISBDM_IPMR		120	/* ENABLES */
#define ISBDM_IRCR		128
#define ISBDM_ADMIN		136	/* Mysterieuse */

#define ISBDM_REGW(isbdm, reg, val)	writeq(val, ((isbdm)->base) + (reg))


void	isbdmex_hw_reset(struct isbdm *ii)
{
	/* Clear queue and RBMA enables: */
	ISBDM_REGW(ii, ISBDM_CMD_RING_CTRL,	0);
	ISBDM_REGW(ii, ISBDM_TX_RING_CTRL,	0);
	ISBDM_REGW(ii, ISBDM_RX_RING_CTRL,	0);
	ISBDM_REGW(ii, ISBDM_RMBA_CTRL,		0);
	/* Disable all IRQs */
	ISBDM_REGW(ii, ISBDM_IMPR,		0);
}

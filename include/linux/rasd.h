/*
 * SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __LINUX_RASD_H
#define __LINUX_RASD_H

/* Define RASD control bar registers. */

/*
 * Tail registers for app n where n rages from 0 to 15. Each page holds 64 tail
 * registers corresponding to 64 work queues associated with the app.
 */
#define RASD_AWQ_0_TAIL_PAGE 0
#define RASD_AWQ_TAIL_PAGE(_n) (RASD_AWK_0_TAIL_PAGE + (_n) * 0x1000)
/* Admin queue tail pointer */
#define RASD_ADM_Q_TAIL 0x10000
/* High priority event queue tail */
#define RASD_HP_EV_Q_TAIL 0x11000
/* Low priority event queue tail */
#define RASD_LP_EV_Q_TAIL 0x11008
/* Head registers for app n from 0-15. Each page holds 64 head registers. */
#define RASD_AWQ_0_HEAD_PAGE 0x12000
#define RASD_AWQ_HEAD_PAGE(_n) (RASD_AWK_0_HEAD_PAGE + (_n) * 0x1000)
/* Admin queue head */
#define RASD_ADM_Q_HEAD 0x22000
/* High priority event queue head */
#define RASD_HP_EV_Q_HEAD 0x23008
/* Low priority event queue head */
#define RASD_LP_EV_Q_HEAD 0x23010
/* Work queue n base, where n goes from 0 to 1023 (64 * 16). */
#define RASD_WQ_0_BASE 0x24000
#define RASD_WQ_BASE(_n) (RASD_WQ_0_BASE + (_n) * 8)
/* Admin queue base */
#define RASD_ADM_Q_BASE 0x26000
/* High priority event queue base */
#define RASD_HP_EV_Q_BASE 0x26008
/* Low priority event queue base */
#define RASD_LP_EV_Q_BASE 0x26010
/* Doorbell page for an app n from 0-15. */
#define RASD_AWQ_DRBL_0_PAGE 0x27000
#define RASD_AWQ_DRBL_PAGE(_n) \
	(RASD_AWQ_DRBL_0_PAGE + (_n) * RASD_DRBL_PAGE_SIZE)

/* Admin queue doorbell */
#define RASD_ADM_Q_DRBL 0x37000
/* Available DDR memory in DDR BAR */
#define RASD_DMEM_SIZE 0x38000
/* Available HBM in HBM BAR */
#define RASD_HMEM_SIZE 0x38008

/* Define the size of a doorbell page. */
#define RASD_DRBL_PAGE_SIZE 0x1000
#endif

/*
 * SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __RIVOS_DOE_H
#define __RIVOS_DOE_H

#include <linux/types.h>

/* Define Rivos vendor-specific DOE protocols/features. */
#define RIVOS_DOE_ISBDM 0x01

/* Define sub-object types within the ISBDM feature. */
#define RIVOS_DOE_ISBDM_STATUS 0x00

struct rivos_doe_isbdm_header {
        /* See RIVOS_DOE_ISBDM_* defintions */
        u8 type;
        u8 reserved[3];
};

/* Define the connection status. Requester/responder imply "connected". */
#define RIVOS_DOE_ISBDM_STATUS_DISCONNECTED 0x0
#define RIVOS_DOE_ISBDM_STATUS_REQUESTER 0x01
#define RIVOS_DOE_ISBDM_STATUS_RESPONDER 0x02

struct rivos_doe_isbdm_status {
        /* Common header for the ISBDM protocol. */
        struct rivos_doe_isbdm_header hdr;
        /* The requester ID of the ISBDM instance being described. */
        u32 rid;
        /* The status of the device connection. */
        u8 state;
        u8 reserved[3];
};

#endif /* __RIVOS_DOE_H */


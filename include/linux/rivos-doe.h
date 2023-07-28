/*
 * SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __RIVOS_DOE_H
#define __RIVOS_DOE_H

#include <linux/types.h>

/* Define Rivos vendor-specific DOE protocols/features. */
/* FIDL interface */
#define RIVOS_DOE_ROT_FIDL 0x01

/* Define FIDL ordinals */
/* No-op ping */
#define RIVOS_FIDL_ORD_PING 0x3ec777eba052f8c5
/* ISBDM status message */
#define RIVOS_FIDL_ORD_ISBDM_STATUS 0x878d212793a2ede

/* The current value for the flags and magic value. */
#define RIVOS_FIDL_FLAGS_MAGIC 0x02000001

/* FIDL wire format header. */
struct rivos_fidl_header {
        /* Transaction ID. */
        __le32 txn_id;
        /* Flags and magic value, set to RIVOS_FIDL_FLAGS_MAGIC. */
        __le32 flags_magic;
        /* The ordinal: a FIDL-defined 64-bit hash of the message format. */
        __le64 ordinal;
};

/* Define the connection status. Requester/responder imply "connected". */
#define RIVOS_DOE_ISBDM_STATUS_DISCONNECTED 0x0
#define RIVOS_DOE_ISBDM_STATUS_CONNECTED_AS_UPSTREAM 0x01
#define RIVOS_DOE_ISBDM_STATUS_CONNECTED_AS_DOWNSTREAM 0x02

struct rivos_doe_isbdm_status {
        /* Common FIDL header. */
        struct rivos_fidl_header hdr;
        /* The requester ID of the ISBDM instance being described. */
        __le32 rid;
        /* The status of the device connection. */
        __le32 state;
};

#endif /* __RIVOS_DOE_H */


/*
 * SPDX-FileCopyrightText: Copyright (c) 2023 by Rivos Inc.
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __RIVOS_DOE_H
#define __RIVOS_DOE_H

#include <linux/types.h>

/* Stuff from enums.h */

/* Used to indicate the general tenor of the response. This could be success or */
/* an error related to the message metadata, such as an unrecognized UID or bad */
/* message length. */
enum response_result {
    RESPONSE_RESULT_SUCCESS = 0x0,
    RESPONSE_RESULT_UNRECOGNIZED_METHOD = 0x1,
    RESPONSE_RESULT_INVALID_MESSAGE_LEN = 0x2,
    RESPONSE_RESULT_UNIMPLEMENTED_METHOD = 0x3,
};

/* Used to indicate the result of reporting IPCs */
enum report_result {
    REPORT_RESULT_SUCCESS = 0x0,
};

/* Defines the possible connection states the ISBDM notifies RoT about */
enum isbdm_connection_state {
    ISBDM_CONNECTION_STATE_DISCONNECTED = 0x0,
    ISBDM_CONNECTION_STATE_CONNECTED_AS_UPSTREAM = 0x1,
    ISBDM_CONNECTION_STATE_CONNECTED_AS_DOWNSTREAM = 0x2,
};

enum category_id {
    CATEGORY_ASSET_MANAGEMENT = 0x414d4754,
    CATEGORY_COMMON = 0x434f4d4e,
    CATEGORY_CPU = 0x4350555f,
    CATEGORY_DDR_INIT = 0x44445249,
    CATEGORY_DDR_TRAINING = 0x44445254,
    CATEGORY_DUC = 0x4455435f,
    CATEGORY_FILESYSTEM = 0x46494c45,
    CATEGORY_MEMORY = 0x4d454d53,
    CATEGORY_PERFORMANCE = 0x50455246,
    CATEGORY_POWER = 0x504f5752,
    CATEGORY_POWER_PWC = 0x50505743,
    CATEGORY_REPORTING = 0x52505254,
    CATEGORY_SECURITY = 0x53454355,
    CATEGORY_TELEMETRY_PWC = 0x54505743,
    CATEGORY_UPDATE = 0x55504454,
};

/* Stuff from rot.h */

/* All ridl request objects have this header */
struct ridl_request_header {
    uint32_t category;
    uint32_t method;
} __attribute__ ((packed));

/* All ridl response objects have this header */
struct ridl_response_header {
    uint32_t category;
    uint32_t method;
    enum response_result status : 32;
} __attribute__ ((packed));

/* List of all MessageIds */
enum rot_message_id {
    ASSET_ATTRIBUTES = 0x41545452,
    ATTESTATION_EVIDENCE = 0x41545354,
    AUTHENTICATE = 0x41555448,
    AVAILABLE_HARTS = 0x48525453,
    CHECK_SYSTEM_CONFIG = 0x53595343,
    CREDIT_BALANCE = 0x424c4e43,
    DELETE_FILE = 0x44454c45,
    EXIT_LRAM_MODE = 0x45584c52,
    FILE_SIZE = 0x53495a45,
    ISBDM_STATUS = 0x49534253,
    LOAD_ASSET = 0x4c4f4144,
    LOAD_DDR_TRAINING_DATA = 0x54524454,
    LOAD_DDR_TRAINING_FW = 0x54524657,
    LOAD_DUC_SECOND_STAGE = 0x44554332,
    MEMORY_LAYOUT = 0x4d454d4c,
    PING = 0x50494e47,
    RANDOM_SEED = 0x53454544,
    READ_FILE = 0x52454144,
    RESET_PWC = 0x52505743,
    RUNNING = 0x52554e53,
    SENTINEL_FW_STATUS = 0x53454657,
    SHUTDOWN_PWC = 0x53505743,
    START_AGENT = 0x53544147,
    START_DDR_TRAINING = 0x53545254,
    UPDATE = 0x55445054,
    UPDATE_CREDIT_BALANCE = 0x5550424c,
    WRITE_FILE = 0x57524954,
};

/* Sent by ISBDM driver to the RoT when the connection status has changed on an */
/* ISBDM device. */
struct isbdm_status_request {
    uint32_t rid;
    enum isbdm_connection_state state : 32;
} __attribute__ ((packed));

struct isbdm_status_request_wrapper {
    struct ridl_request_header hdr;
    struct isbdm_status_request data;
} __attribute__ ((packed));

/* Sent by ISBDM driver to the RoT when the connection status has changed on an */
/* ISBDM device. */
struct isbdm_status_response {
    enum report_result result : 32;
} __attribute__ ((packed));

struct isbdm_status_response_wrapper {
    struct ridl_response_header hdr;
    struct isbdm_status_response data;
} __attribute__ ((packed));

/* Define Rivos vendor-specific DOE protocols/features. */
/* RIDL interface */
#define RIVOS_DOE_ROT_SERVICE_ID 0x00

#endif /* __RIVOS_DOE_H */


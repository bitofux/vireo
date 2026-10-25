/*
 * PROJECT : VIREO
 * FILE    : node_remove.h
 * BRIEF   : NODE_REMOVE complete-frame codec; no delete transaction.
 */
#ifndef VIREO_PROTOCOL_NODE_REMOVE_H
#define VIREO_PROTOCOL_NODE_REMOVE_H

#include <stddef.h>
#include <stdint.h>
#include <vireo/base/result.h>
#include <vireo/protocol/protocol.h>

#define VIREO_NODE_REMOVE_TLV_NODE_ID UINT16_C(0x0401)
#define VIREO_NODE_REMOVE_TLV_IDEMPOTENCY_KEY UINT16_C(0x0420)
#define VIREO_NODE_REMOVE_KEY_SIZE ((size_t)16)
#define VIREO_NODE_REMOVE_REQUEST_BODY_SIZE ((size_t)32)
#define VIREO_NODE_REMOVE_REQUEST_FRAME_SIZE ((size_t)64)
#define VIREO_NODE_REMOVE_RESPONSE_BODY_SIZE ((size_t)32)
#define VIREO_NODE_REMOVE_RESPONSE_FRAME_MAX ((size_t)64)

typedef struct vireo_node_remove_request {
    uint32_t sequence;
    uint32_t session_handle;
    uint64_t node_id;
    unsigned char idempotency_key[VIREO_NODE_REMOVE_KEY_SIZE];
} vireo_node_remove_request_t;

typedef struct vireo_node_remove_response {
    vireo_status_t status;
    uint32_t sequence;
    uint32_t session_handle;
    uint64_t node_id;
    unsigned char idempotency_key[VIREO_NODE_REMOVE_KEY_SIZE];
} vireo_node_remove_response_t;

typedef enum vireo_node_remove_issue {
    VIREO_NODE_REMOVE_ISSUE_NONE = 0,
    VIREO_NODE_REMOVE_ISSUE_HEADER = 1,
    VIREO_NODE_REMOVE_ISSUE_ENVELOPE = 2,
    VIREO_NODE_REMOVE_ISSUE_CRC = 3,
    VIREO_NODE_REMOVE_ISSUE_FIELDS = 4,
    VIREO_NODE_REMOVE_ISSUE_VALUE = 5
} vireo_node_remove_issue_t;

vireo_result_t vireo_node_remove_request_encode(const vireo_node_remove_request_t *value,
    unsigned char *wire, size_t capacity, size_t *out_size);
vireo_result_t vireo_node_remove_request_decode(const unsigned char *wire, size_t wire_size,
    vireo_node_remove_request_t *out, vireo_node_remove_issue_t *issue);
vireo_result_t vireo_node_remove_response_encode(const vireo_node_remove_response_t *value,
    unsigned char *wire, size_t capacity, size_t *out_size);
vireo_result_t vireo_node_remove_response_decode(const unsigned char *wire, size_t wire_size,
    vireo_node_remove_response_t *out, vireo_node_remove_issue_t *issue);

#endif

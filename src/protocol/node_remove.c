/*
 * PROJECT : VIREO
 * FILE    : node_remove.c
 * BRIEF   : NODE_REMOVE complete-frame codec; no delete transaction.
 */
#include <vireo/protocol/node_remove.h>
#include <vireo/protocol/codec.h>
#include <vireo/protocol/tlv.h>
#include <errno.h>
#include <string.h>

static vireo_tlv_rule_t const request_rules[] = {
    {VIREO_NODE_REMOVE_TLV_NODE_ID, 8, 8, VIREO_TLV_VALUE_U64, true, false},
    {VIREO_NODE_REMOVE_TLV_IDEMPOTENCY_KEY, 16, 16, VIREO_TLV_VALUE_BYTES, true, false}
};
static vireo_tlv_rule_t const response_rules[] = {
    {VIREO_NODE_REMOVE_TLV_NODE_ID, 8, 8, VIREO_TLV_VALUE_U64, true, false},
    {VIREO_NODE_REMOVE_TLV_IDEMPOTENCY_KEY, 16, 16, VIREO_TLV_VALUE_BYTES, true, false}
};

static bool key_zero(unsigned char const *key) {
    for (size_t i = 0; i < VIREO_NODE_REMOVE_KEY_SIZE; ++i)
        if (key[i] != 0) return false;
    return true;
}

static bool status_allowed(vireo_status_t status) {
    switch (status) {
    case VIREO_STATUS_OK: case VIREO_STATUS_BAD_REQUEST: case VIREO_STATUS_UNSUPPORTED:
    case VIREO_STATUS_CRC_MISMATCH: case VIREO_STATUS_BODY_TOO_LARGE:
    case VIREO_STATUS_INVALID_FLAGS: case VIREO_STATUS_DUPLICATE_REQUEST:
    case VIREO_STATUS_RATE_LIMITED: case VIREO_STATUS_UNAUTHORIZED: case VIREO_STATUS_NOT_FOUND:
    case VIREO_STATUS_FORBIDDEN: case VIREO_STATUS_INVALID_PATH: case VIREO_STATUS_CONFLICT:
    case VIREO_STATUS_DIRECTORY_NOT_EMPTY: case VIREO_STATUS_BUSY:
    case VIREO_STATUS_INTERNAL_ERROR: case VIREO_STATUS_DB_ERROR:
    case VIREO_STATUS_TIMEOUT: case VIREO_STATUS_OVERLOADED: case VIREO_STATUS_UNAVAILABLE:
        return true;
    default: return false;
    }
}

static vireo_result_t finish(vireo_result_t rc, int saved) { errno = saved; return rc; }

static vireo_result_t reject(vireo_node_remove_issue_t *issue, vireo_node_remove_issue_t value) {
    *issue = value;
    return VIREO_RESULT_PROTOCOL;
}

static vireo_result_t publish(vireo_protocol_header_t *header, unsigned char *frame, size_t size,
                              unsigned char *wire, size_t *out_size) {
    vireo_result_t rc = vireo_protocol_header_encode(header, frame, VIREO_PROTOCOL_HEADER_SIZE);
    if (rc == VIREO_OK)
        rc = vireo_protocol_frame_crc32c_calculate(frame, VIREO_PROTOCOL_HEADER_SIZE,
            frame + VIREO_PROTOCOL_HEADER_SIZE, size - VIREO_PROTOCOL_HEADER_SIZE, &header->crc32c);
    if (rc == VIREO_OK) rc = vireo_protocol_header_encode(header, frame, VIREO_PROTOCOL_HEADER_SIZE);
    if (rc == VIREO_OK) { memcpy(wire, frame, size); *out_size = size; }
    return rc;
}

static vireo_result_t schema(unsigned char const *body, size_t size, bool response,
                             vireo_node_remove_issue_t *issue) {
    unsigned char seen[2];
    vireo_tlv_issue_t ti;
    vireo_result_t rc = vireo_tlv_schema_validate(body, size,
        response ? response_rules : request_rules, 2U, VIREO_TLV_UNKNOWN_REJECT,
        seen, sizeof seen, &ti);
    if (rc != VIREO_OK) *issue = VIREO_NODE_REMOVE_ISSUE_FIELDS;
    return rc;
}

static vireo_result_t envelope(unsigned char const *wire, size_t size, bool response,
                               vireo_protocol_header_t *header, vireo_node_remove_issue_t *issue) {
    if (size < VIREO_PROTOCOL_HEADER_SIZE) return reject(issue, VIREO_NODE_REMOVE_ISSUE_HEADER);
    if (response ? (size != VIREO_PROTOCOL_HEADER_SIZE && size != VIREO_NODE_REMOVE_RESPONSE_FRAME_MAX) :
        (size != VIREO_NODE_REMOVE_REQUEST_FRAME_SIZE))
        return reject(issue, VIREO_NODE_REMOVE_ISSUE_ENVELOPE);
    vireo_protocol_codec_issue_t ci;
    if (vireo_protocol_header_decode(wire, size, header, &ci) != VIREO_OK ||
        (response ? vireo_protocol_response_header_validate(header, &ci) :
                    vireo_protocol_request_header_validate(header, &ci)) != VIREO_OK)
        return reject(issue, VIREO_NODE_REMOVE_ISSUE_HEADER);
    if (header->command != VIREO_COMMAND_NODE_REMOVE || header->task_handle != 0 ||
        header->flags != (response ? VIREO_PROTOCOL_FLAG_RESPONSE : 0) ||
        size != VIREO_PROTOCOL_HEADER_SIZE + header->body_len ||
        (response && (!status_allowed(header->status) ||
            (header->status == VIREO_STATUS_OK ?
                (header->session_handle == 0 || header->body_len != VIREO_NODE_REMOVE_RESPONSE_BODY_SIZE) :
                (header->session_handle != 0 || header->body_len != 0)))))
        return reject(issue, VIREO_NODE_REMOVE_ISSUE_ENVELOPE);
    if (vireo_protocol_frame_crc32c_verify(wire, VIREO_PROTOCOL_HEADER_SIZE,
            wire + VIREO_PROTOCOL_HEADER_SIZE, header->body_len, &ci) != VIREO_OK)
        return reject(issue, VIREO_NODE_REMOVE_ISSUE_CRC);
    return VIREO_OK;
}

static vireo_result_t read_fields(unsigned char const *body, size_t size, uint64_t *node_id,
                                  unsigned char *key) {
    vireo_tlv_reader_t reader;
    vireo_result_t rc = vireo_tlv_reader_init(&reader, body, size);
    while (rc == VIREO_OK && reader.offset < reader.size) {
        vireo_tlv_view_t field;
        vireo_tlv_issue_t ti;
        rc = vireo_tlv_reader_next(&reader, &field, &ti);
        if (rc != VIREO_OK) break;
        if (field.type == VIREO_NODE_REMOVE_TLV_NODE_ID)
            rc = vireo_tlv_view_read_u64(&field, node_id);
        else if (field.type == VIREO_NODE_REMOVE_TLV_IDEMPOTENCY_KEY)
            memcpy(key, field.value, VIREO_NODE_REMOVE_KEY_SIZE);
        else
            rc = VIREO_RESULT_PROTOCOL;
    }
    return rc;
}

vireo_result_t vireo_node_remove_request_encode(vireo_node_remove_request_t const *value,
    unsigned char *wire, size_t capacity, size_t *out_size) {
    int const saved = errno;
    if (value == NULL || wire == NULL || out_size == NULL || value->sequence == 0 ||
        value->node_id == 0 || key_zero(value->idempotency_key))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, saved);
    unsigned char frame[VIREO_NODE_REMOVE_REQUEST_FRAME_SIZE];
    vireo_tlv_writer_t writer;
    vireo_result_t rc = vireo_tlv_writer_init(&writer, frame + VIREO_PROTOCOL_HEADER_SIZE,
                                              VIREO_NODE_REMOVE_REQUEST_BODY_SIZE);
    if (rc == VIREO_OK) rc = vireo_tlv_writer_put_u64(&writer, VIREO_NODE_REMOVE_TLV_NODE_ID, value->node_id);
    if (rc == VIREO_OK) rc = vireo_tlv_writer_put(&writer, VIREO_NODE_REMOVE_TLV_IDEMPOTENCY_KEY,
                                                   value->idempotency_key, VIREO_NODE_REMOVE_KEY_SIZE);
    vireo_node_remove_issue_t issue;
    if (rc == VIREO_OK) {
        rc = schema(frame + VIREO_PROTOCOL_HEADER_SIZE, VIREO_NODE_REMOVE_REQUEST_BODY_SIZE, false, &issue);
        if (rc == VIREO_RESULT_PROTOCOL) rc = VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (rc != VIREO_OK) return finish(rc, saved);
    if (capacity < VIREO_NODE_REMOVE_REQUEST_FRAME_SIZE) return finish(VIREO_RESULT_RANGE, saved);
    vireo_protocol_header_t header = {.command = VIREO_COMMAND_NODE_REMOVE,
        .body_len = VIREO_NODE_REMOVE_REQUEST_BODY_SIZE, .sequence = value->sequence,
        .session_handle = value->session_handle};
    return finish(publish(&header, frame, VIREO_NODE_REMOVE_REQUEST_FRAME_SIZE, wire, out_size), saved);
}

vireo_result_t vireo_node_remove_request_decode(unsigned char const *wire, size_t wire_size,
    vireo_node_remove_request_t *out, vireo_node_remove_issue_t *issue) {
    int const saved = errno;
    if (issue != NULL) *issue = VIREO_NODE_REMOVE_ISSUE_NONE;
    if (wire == NULL || out == NULL || issue == NULL) return finish(VIREO_RESULT_INVALID_ARGUMENT, saved);
    vireo_protocol_header_t header;
    vireo_result_t rc = envelope(wire, wire_size, false, &header, issue);
    if (rc == VIREO_OK) rc = schema(wire + VIREO_PROTOCOL_HEADER_SIZE, header.body_len, false, issue);
    if (rc != VIREO_OK) return finish(VIREO_RESULT_PROTOCOL, saved);
    vireo_node_remove_request_t next;
    memset(&next, 0, sizeof next);
    next.sequence = header.sequence; next.session_handle = header.session_handle;
    rc = read_fields(wire + VIREO_PROTOCOL_HEADER_SIZE, header.body_len, &next.node_id, next.idempotency_key);
    if (rc != VIREO_OK) return finish(reject(issue, VIREO_NODE_REMOVE_ISSUE_FIELDS), saved);
    if (next.node_id == 0 || key_zero(next.idempotency_key))
        return finish(reject(issue, VIREO_NODE_REMOVE_ISSUE_VALUE), saved);
    memcpy(out, &next, sizeof next);
    return finish(VIREO_OK, saved);
}

vireo_result_t vireo_node_remove_response_encode(vireo_node_remove_response_t const *value,
    unsigned char *wire, size_t capacity, size_t *out_size) {
    int const saved = errno;
    if (value == NULL || wire == NULL || out_size == NULL || value->sequence == 0 || !status_allowed(value->status) ||
        (value->status == VIREO_STATUS_OK ?
            (value->session_handle == 0 || value->node_id == 0 || key_zero(value->idempotency_key)) :
            (value->session_handle != 0 || value->node_id != 0 || !key_zero(value->idempotency_key))))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, saved);
    size_t const size = value->status == VIREO_STATUS_OK ? VIREO_NODE_REMOVE_RESPONSE_FRAME_MAX : VIREO_PROTOCOL_HEADER_SIZE;
    if (capacity < size) return finish(VIREO_RESULT_RANGE, saved);
    unsigned char frame[VIREO_NODE_REMOVE_RESPONSE_FRAME_MAX];
    memset(frame, 0, sizeof frame);
    vireo_result_t rc = VIREO_OK;
    if (value->status == VIREO_STATUS_OK) {
        vireo_tlv_writer_t writer;
        rc = vireo_tlv_writer_init(&writer, frame + VIREO_PROTOCOL_HEADER_SIZE,
                                   VIREO_NODE_REMOVE_RESPONSE_BODY_SIZE);
        if (rc == VIREO_OK) rc = vireo_tlv_writer_put_u64(&writer, VIREO_NODE_REMOVE_TLV_NODE_ID, value->node_id);
        if (rc == VIREO_OK) rc = vireo_tlv_writer_put(&writer, VIREO_NODE_REMOVE_TLV_IDEMPOTENCY_KEY,
                                                       value->idempotency_key, VIREO_NODE_REMOVE_KEY_SIZE);
    }
    vireo_protocol_header_t header = {.command = VIREO_COMMAND_NODE_REMOVE,
        .flags = VIREO_PROTOCOL_FLAG_RESPONSE, .status = value->status,
        .body_len = (uint32_t)(size - VIREO_PROTOCOL_HEADER_SIZE), .sequence = value->sequence,
        .session_handle = value->session_handle};
    if (rc == VIREO_OK) rc = publish(&header, frame, size, wire, out_size);
    return finish(rc, saved);
}

vireo_result_t vireo_node_remove_response_decode(unsigned char const *wire, size_t wire_size,
    vireo_node_remove_response_t *out, vireo_node_remove_issue_t *issue) {
    int const saved = errno;
    if (issue != NULL) *issue = VIREO_NODE_REMOVE_ISSUE_NONE;
    if (wire == NULL || out == NULL || issue == NULL) return finish(VIREO_RESULT_INVALID_ARGUMENT, saved);
    vireo_protocol_header_t header;
    vireo_result_t rc = envelope(wire, wire_size, true, &header, issue);
    if (rc != VIREO_OK) return finish(rc, saved);
    vireo_node_remove_response_t next;
    memset(&next, 0, sizeof next);
    next.status = header.status; next.sequence = header.sequence; next.session_handle = header.session_handle;
    if (header.status == VIREO_STATUS_OK) {
        rc = schema(wire + VIREO_PROTOCOL_HEADER_SIZE, header.body_len, true, issue);
        if (rc != VIREO_OK) return finish(VIREO_RESULT_PROTOCOL, saved);
        rc = read_fields(wire + VIREO_PROTOCOL_HEADER_SIZE, header.body_len,
                         &next.node_id, next.idempotency_key);
        if (rc != VIREO_OK) return finish(reject(issue, VIREO_NODE_REMOVE_ISSUE_FIELDS), saved);
        if (next.node_id == 0 || key_zero(next.idempotency_key))
            return finish(reject(issue, VIREO_NODE_REMOVE_ISSUE_VALUE), saved);
    }
    memcpy(out, &next, sizeof next);
    return finish(VIREO_OK, saved);
}

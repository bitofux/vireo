/* PROJECT : VIREO; FILE : test_node_remove.c; BRIEF : NODE_REMOVE codec contract. */
#include <vireo/protocol/node_remove.h>
#include <vireo/protocol/codec.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "line %d: %s\n", __LINE__, #expr); return 1; } } while (0)
#define CALL(expr, expected) do { errno = EDOM; vireo_result_t rc_ = (expr); CHECK(rc_ == (expected)); CHECK(errno == EDOM); } while (0)

static void put32(unsigned char *p, uint32_t value) {
    p[0] = (unsigned char)(value >> 24); p[1] = (unsigned char)(value >> 16);
    p[2] = (unsigned char)(value >> 8); p[3] = (unsigned char)value;
}
static void put16(unsigned char *p, uint16_t value) {
    p[0] = (unsigned char)(value >> 8); p[1] = (unsigned char)value;
}
static int repair(unsigned char *wire, size_t size) {
    uint32_t crc;
    put32(wire + VIREO_PROTOCOL_BODY_LENGTH_OFFSET, (uint32_t)(size - VIREO_PROTOCOL_HEADER_SIZE));
    if (vireo_protocol_frame_crc32c_calculate(wire, VIREO_PROTOCOL_HEADER_SIZE,
        wire + VIREO_PROTOCOL_HEADER_SIZE, size - VIREO_PROTOCOL_HEADER_SIZE, &crc) != VIREO_OK) return 1;
    put32(wire + VIREO_PROTOCOL_CRC32C_OFFSET, crc);
    return 0;
}

static int request_round_trip(void) {
    vireo_node_remove_request_t value = {.sequence = 7, .session_handle = 9, .node_id = 20};
    for (size_t i = 0; i < sizeof value.idempotency_key; ++i) value.idempotency_key[i] = (unsigned char)(i + 1);
    unsigned char wire[64], old[64]; size_t size = 999;
    CALL(vireo_node_remove_request_encode(&value, wire, sizeof wire - 1, &size), VIREO_RESULT_RANGE);
    CHECK(size == 999);
    memset(wire, 0xa5, sizeof wire); memcpy(old, wire, sizeof wire);
    CALL(vireo_node_remove_request_encode(&value, wire, sizeof wire, &size), VIREO_OK);
    CHECK(size == 64 && wire[6] == 0x04 && wire[7] == 0x04);
    vireo_node_remove_request_t decoded; vireo_node_remove_issue_t issue;
    CALL(vireo_node_remove_request_decode(wire, size, &decoded, &issue), VIREO_OK);
    CHECK(issue == VIREO_NODE_REMOVE_ISSUE_NONE && memcmp(&decoded, &value, sizeof value) == 0);
    wire[28] ^= 1;
    memcpy(&decoded, old, sizeof decoded); issue = VIREO_NODE_REMOVE_ISSUE_NONE;
    CALL(vireo_node_remove_request_decode(wire, size, &decoded, &issue), VIREO_RESULT_PROTOCOL);
    CHECK(issue == VIREO_NODE_REMOVE_ISSUE_CRC && memcmp(&decoded, old, sizeof decoded) == 0);
    return 0;
}

static int response_round_trip(void) {
    vireo_node_remove_response_t value = {.status = VIREO_STATUS_OK, .sequence = 7,
        .session_handle = 9, .node_id = 20};
    for (size_t i = 0; i < sizeof value.idempotency_key; ++i) value.idempotency_key[i] = (unsigned char)(i + 1);
    unsigned char wire[64]; size_t size = 0;
    CALL(vireo_node_remove_response_encode(&value, wire, sizeof wire, &size), VIREO_OK);
    CHECK(size == 64 && wire[8] == 0 && wire[9] == 1);
    vireo_node_remove_response_t decoded; vireo_node_remove_issue_t issue;
    CALL(vireo_node_remove_response_decode(wire, size, &decoded, &issue), VIREO_OK);
    CHECK(issue == VIREO_NODE_REMOVE_ISSUE_NONE && memcmp(&decoded, &value, sizeof value) == 0);
    value = (vireo_node_remove_response_t){.status = VIREO_STATUS_TIMEOUT, .sequence = 7};
    CALL(vireo_node_remove_response_encode(&value, wire, sizeof wire, &size), VIREO_OK);
    CHECK(size == 32);
    CALL(vireo_node_remove_response_decode(wire, size, &decoded, &issue), VIREO_OK);
    CHECK(decoded.status == VIREO_STATUS_TIMEOUT && decoded.session_handle == 0 && decoded.node_id == 0);
    value = (vireo_node_remove_response_t){.status = VIREO_STATUS_DIRECTORY_NOT_EMPTY, .sequence = 7};
    CALL(vireo_node_remove_response_encode(&value, wire, sizeof wire, &size), VIREO_OK);
    CHECK(size == 32);
    CALL(vireo_node_remove_response_decode(wire, size, &decoded, &issue), VIREO_OK);
    CHECK(decoded.status == VIREO_STATUS_DIRECTORY_NOT_EMPTY && decoded.session_handle == 0 &&
          decoded.node_id == 0);
    vireo_node_remove_response_t old, out;
    memset(&out, 0xa5, sizeof out); memcpy(&old, &out, sizeof out);
    put16(wire + VIREO_PROTOCOL_STATUS_OFFSET, UINT16_MAX); CHECK(repair(wire, size) == 0);
    CALL(vireo_node_remove_response_decode(wire, size, &out, &issue), VIREO_RESULT_PROTOCOL);
    CHECK(issue == VIREO_NODE_REMOVE_ISSUE_HEADER && memcmp(&out, &old, sizeof out) == 0);
    return 0;
}

static int malformed_frames(void) {
    vireo_node_remove_request_t value = {.sequence = 1, .session_handle = 1, .node_id = 2};
    memset(value.idempotency_key, 1, sizeof value.idempotency_key);
    unsigned char wire[64]; size_t size;
    CALL(vireo_node_remove_request_encode(&value, wire, sizeof wire, &size), VIREO_OK);
    vireo_node_remove_request_t old, out; memset(&out, 0xa5, sizeof out); memcpy(&old, &out, sizeof out);
    wire[6] = 0x04; wire[7] = 0x03; CHECK(repair(wire, size) == 0);
    vireo_node_remove_issue_t issue;
    CALL(vireo_node_remove_request_decode(wire, size, &out, &issue), VIREO_RESULT_PROTOCOL);
    CHECK(issue == VIREO_NODE_REMOVE_ISSUE_ENVELOPE || issue == VIREO_NODE_REMOVE_ISSUE_HEADER);
    CHECK(memcmp(&out, &old, sizeof out) == 0);
    CALL(vireo_node_remove_request_decode(wire, size - 1, &out, &issue), VIREO_RESULT_PROTOCOL);
    CHECK(issue == VIREO_NODE_REMOVE_ISSUE_ENVELOPE);

    CALL(vireo_node_remove_request_encode(&value, wire, sizeof wire, &size), VIREO_OK);
    unsigned char first[12]; memcpy(first, wire + 32, sizeof first);
    memmove(wire + 32, wire + 44, 20); memcpy(wire + 52, first, sizeof first);
    CHECK(repair(wire, size) == 0);
    CALL(vireo_node_remove_request_decode(wire, size, &out, &issue), VIREO_OK);
    CHECK(out.node_id == value.node_id &&
          memcmp(out.idempotency_key, value.idempotency_key, sizeof out.idempotency_key) == 0);

    CALL(vireo_node_remove_request_encode(&value, wire, sizeof wire, &size), VIREO_OK);
    put16(wire + 44, VIREO_NODE_REMOVE_TLV_NODE_ID); CHECK(repair(wire, size) == 0);
    memcpy(&old, &out, sizeof out);
    CALL(vireo_node_remove_request_decode(wire, size, &out, &issue), VIREO_RESULT_PROTOCOL);
    CHECK(issue == VIREO_NODE_REMOVE_ISSUE_FIELDS && memcmp(&out, &old, sizeof out) == 0);
    value.node_id = 0;
    CALL(vireo_node_remove_request_encode(&value, wire, sizeof wire, &size), VIREO_RESULT_INVALID_ARGUMENT);
    value.node_id = 2; memset(value.idempotency_key, 0, sizeof value.idempotency_key);
    CALL(vireo_node_remove_request_encode(&value, wire, sizeof wire, &size), VIREO_RESULT_INVALID_ARGUMENT);
    return 0;
}

int main(void) {
    if (request_round_trip() != 0 || response_round_trip() != 0 || malformed_frames() != 0) return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

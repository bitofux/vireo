/* PROJECT : VIREO; FILE : fuzz_node_remove.c; AUTHOR : bitofux; DATE : 2026-10-25;
 * BRIEF : 双方向NODE_REMOVE有限输入入口，不进入普通CTest。 */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <vireo/protocol/node_remove.h>
#include <vireo/protocol/codec.h>

#ifdef VIREO_FUZZ_NODE_REMOVE_RESPONSE
typedef vireo_node_remove_response_t value_t;
#define DECODE vireo_node_remove_response_decode
#define ENCODE vireo_node_remove_response_encode
#else
typedef vireo_node_remove_request_t value_t;
#define DECODE vireo_node_remove_request_decode
#define ENCODE vireo_node_remove_request_encode
#endif

int LLVMFuzzerTestOneInput(uint8_t const *data, size_t size);

static void check(unsigned char const *data, size_t size) {
    value_t value, before;
    memset(&value, 0xa5, sizeof value);
    memcpy(&before, &value, sizeof before);
    vireo_node_remove_issue_t issue = VIREO_NODE_REMOVE_ISSUE_VALUE;
    errno = EDOM;
    vireo_result_t rc = DECODE(data, size, &value, &issue);
    assert(errno == EDOM);
    if (rc != VIREO_OK) {
        assert(rc == VIREO_RESULT_PROTOCOL && issue != VIREO_NODE_REMOVE_ISSUE_NONE);
        assert(memcmp(&before, &value, sizeof value) == 0);
        return;
    }
    assert(value.sequence != 0 && issue == VIREO_NODE_REMOVE_ISSUE_NONE);
    unsigned char wire[64], again[64], old[64];
    memset(wire, 0xa5, sizeof wire);
    memcpy(old, wire, sizeof old);
    size_t n = 999, n2 = 888;
    errno = EDOM;
    assert(ENCODE(&value, wire, sizeof wire, &n) == VIREO_OK && errno == EDOM);
    assert((n == 32 || n == 64) && memcmp(wire + n, old + n, sizeof wire - n) == 0);
    value_t copy;
    errno = EDOM;
    assert(DECODE(wire, n, &copy, &issue) == VIREO_OK && errno == EDOM);
    errno = EDOM;
    assert(ENCODE(&copy, again, sizeof again, &n2) == VIREO_OK && errno == EDOM);
    assert(n == n2 && memcmp(wire, again, n) == 0);
    memcpy(old, wire, sizeof wire);
    n2 = 888;
    errno = EDOM;
    assert(ENCODE(&value, wire, n - 1, &n2) == VIREO_RESULT_RANGE && errno == EDOM);
    assert(n2 == 888 && memcmp(wire, old, sizeof wire) == 0);
}

static void host(unsigned char const *data, size_t size) {
    if (size < 32)
        return;
    value_t value = {0};
    value.sequence = data[0] | ((uint32_t)data[1] << 8);
    value.session_handle = data[2] | ((uint32_t)data[3] << 8);
#ifdef VIREO_FUZZ_NODE_REMOVE_RESPONSE
    static vireo_status_t const statuses[] = {
        VIREO_STATUS_OK, VIREO_STATUS_BAD_REQUEST, VIREO_STATUS_UNSUPPORTED,
        VIREO_STATUS_CRC_MISMATCH, VIREO_STATUS_BODY_TOO_LARGE, VIREO_STATUS_INVALID_FLAGS,
        VIREO_STATUS_DUPLICATE_REQUEST, VIREO_STATUS_RATE_LIMITED, VIREO_STATUS_UNAUTHORIZED,
        VIREO_STATUS_NOT_FOUND, VIREO_STATUS_FORBIDDEN, VIREO_STATUS_INVALID_PATH,
        VIREO_STATUS_CONFLICT, VIREO_STATUS_DIRECTORY_NOT_EMPTY, VIREO_STATUS_BUSY,
        VIREO_STATUS_INTERNAL_ERROR, VIREO_STATUS_DB_ERROR, VIREO_STATUS_TIMEOUT,
        VIREO_STATUS_OVERLOADED, VIREO_STATUS_UNAVAILABLE
    };
    value.status = statuses[data[4] % (sizeof statuses / sizeof statuses[0])];
    if (data[7] == 255)
        value.status = UINT16_MAX;
    value.session_handle = value.status == VIREO_STATUS_OK ? value.session_handle | 1U : 0;
#endif
    for (size_t i = 0; i < sizeof value.idempotency_key; ++i)
        value.idempotency_key[i] = data[i + 8];
    value.node_id = 0;
    for (size_t i = 0; i < sizeof value.node_id; ++i)
        value.node_id = (value.node_id << 8) | data[i + 24];
#ifdef VIREO_FUZZ_NODE_REMOVE_RESPONSE
    if (value.status == VIREO_STATUS_OK) {
#else
    {
#endif
        value.node_id |= 1;
        value.idempotency_key[0] |= 1;
    }
#ifdef VIREO_FUZZ_NODE_REMOVE_RESPONSE
    else {
        value.node_id = 0;
        memset(value.idempotency_key, 0, sizeof value.idempotency_key);
    }
#endif
    unsigned char wire[64], old[64];
    memset(wire, 0xa5, sizeof wire);
    memcpy(old, wire, sizeof old);
    size_t n = 999, capacity = (size_t)data[5] + data[6];
    if (capacity > sizeof wire)
        capacity = sizeof wire;
    errno = EDOM;
    vireo_result_t rc = ENCODE(&value, wire, capacity, &n);
    assert(errno == EDOM);
    if (rc == VIREO_OK) {
        assert(n <= capacity && memcmp(wire + n, old + n, sizeof wire - n) == 0);
        check(wire, n);
    } else {
        assert(rc == VIREO_RESULT_INVALID_ARGUMENT || rc == VIREO_RESULT_RANGE);
        assert(n == 999 && memcmp(wire, old, sizeof wire) == 0);
    }
}

int LLVMFuzzerTestOneInput(uint8_t const *data, size_t size) {
    check(data, size);
    host(data, size);
    /* 修复包络和CRC，让随机body进入TLV和值检查；原样分支保留。 */
    if (size == 32 || size == 64) {
        unsigned char wire[64];
        memcpy(wire, data, size);
        vireo_protocol_header_t h = {.command = VIREO_COMMAND_NODE_REMOVE,
            .sequence = 1, .session_handle = 2, .body_len = (uint32_t)(size - 32)};
#ifdef VIREO_FUZZ_NODE_REMOVE_RESPONSE
        h.flags = VIREO_PROTOCOL_FLAG_RESPONSE;
        if (size == 32) {
            h.status = VIREO_STATUS_DIRECTORY_NOT_EMPTY;
            h.session_handle = 0;
        }
#endif
        assert(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK);
        assert(vireo_protocol_frame_crc32c_calculate(wire, 32, wire + 32,
                                                   size - 32, &h.crc32c) == VIREO_OK);
        assert(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK);
        check(wire, size);
    }
    return 0;
}

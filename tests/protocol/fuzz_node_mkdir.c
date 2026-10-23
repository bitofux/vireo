/* PROJECT : VIREO; FILE : fuzz_node_mkdir.c; AUTHOR : bitofux; DATE : 2026-10-23;
 * BRIEF : 双方向libFuzzer入口，不进入普通CTest；原始/修复CRC帧及宿主值变异。 */
#include <vireo/protocol/node_mkdir.h>
#include <vireo/protocol/codec.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#ifdef VIREO_FUZZ_NODE_MKDIR_RESPONSE
typedef vireo_node_mkdir_response_t value_t;
#define DECODE vireo_node_mkdir_response_decode
#define ENCODE vireo_node_mkdir_response_encode
#else
typedef vireo_node_mkdir_request_t value_t;
#define DECODE vireo_node_mkdir_request_decode
#define ENCODE vireo_node_mkdir_request_encode
#endif
int LLVMFuzzerTestOneInput(uint8_t const *data, size_t size);

/** @brief 借用任意有效输入；失败对象含padding保持，成功规范编码稳定。 */
static void check(unsigned char const *data, size_t size) {
    value_t value, before;
    memset(&value, 0xa5, sizeof value); memcpy(&before, &value, sizeof before);
    vireo_node_mkdir_issue_t issue = VIREO_NODE_MKDIR_ISSUE_VALUE;
    errno = EDOM;
    vireo_result_t rc = DECODE(data, size, &value, &issue);
    assert(errno == EDOM);
    if (rc != VIREO_OK) {
        assert(rc == VIREO_RESULT_PROTOCOL && issue != VIREO_NODE_MKDIR_ISSUE_NONE);
        assert(memcmp(&before, &value, sizeof value) == 0);
        return;
    }
    assert(value.sequence != 0 && issue == VIREO_NODE_MKDIR_ISSUE_NONE);
    unsigned char wire[400], again[400], old[400];
    memset(wire, 0xa5, sizeof wire); memcpy(old, wire, sizeof old);
    size_t n = 999, n2 = 888;
    errno = EDOM; assert(ENCODE(&value, wire, sizeof wire, &n) == VIREO_OK && errno == EDOM);
    assert(n >= 32 && n <= 323 && memcmp(wire + n, old + n, sizeof wire - n) == 0);
    value_t copy;
    errno = EDOM; assert(DECODE(wire, n, &copy, &issue) == VIREO_OK && errno == EDOM);
    errno = EDOM; assert(ENCODE(&copy, again, sizeof again, &n2) == VIREO_OK && errno == EDOM);
    assert(n == n2 && memcmp(wire, again, n) == 0);
    memcpy(old, wire, sizeof wire); n2 = 888;
    errno = EDOM; assert(ENCODE(&value, wire, n - 1, &n2) == VIREO_RESULT_RANGE && errno == EDOM);
    assert(n2 == 888 && memcmp(wire, old, sizeof wire) == 0);
}

/** @brief 显式构造定义良好的整数/字节，不把随机内存强转为宿主对象。 */
static void host(unsigned char const *data, size_t size) {
    if (size < 32) return;
    value_t value = {0};
    value.sequence = data[0]; value.session_handle = data[1];
#ifdef VIREO_FUZZ_NODE_MKDIR_RESPONSE
    static uint16_t const statuses[] = {0,1001,1002,1004,1005,1006,1007,1008,1101,1201,
        1202,1203,1206,1901,1902,1904,1906,1907,1908,1,1392};
    value.status = statuses[data[2] % (sizeof statuses / sizeof statuses[0])];
    for (size_t i = 0; i < 8; ++i) value.node_id = (value.node_id << 8) | data[i + 3];
#else
    for (size_t i = 0; i < 8; ++i) value.parent_id = (value.parent_id << 8) | data[i + 3];
    value.name_length = (size_t)data[11] + (data[12] & 1U);
    for (size_t i = 0; i < 255 && i + 32 < size; ++i) value.name[i] = data[i + 32];
#endif
    for (size_t i = 0; i < 16; ++i) value.idempotency_key[i] = (data[13] & 1U) ? data[i + 14] : 0;
    unsigned char wire[400], old[400]; memset(wire, 0xa5, sizeof wire); memcpy(old, wire, sizeof old);
    size_t n = 999, capacity = (size_t)data[30] + data[31];
    if (capacity > sizeof wire) capacity = sizeof wire;
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
    check(data, size); host(data, size);
    if (size >= 32 && size <= 323) {
        unsigned char wire[323]; memcpy(wire, data, size);
        vireo_protocol_header_t h = {.command=VIREO_COMMAND_NODE_MKDIR, .sequence=1,
            .session_handle=2, .body_len=(uint32_t)(size - 32)};
#ifdef VIREO_FUZZ_NODE_MKDIR_RESPONSE
        h.flags = VIREO_PROTOCOL_FLAG_RESPONSE;
        /* 修复包络/CRC后仍覆盖合法错误帧的解析路径。 */
        if (size == 32) { h.status = VIREO_STATUS_TIMEOUT; h.session_handle = 0; }
#endif
        assert(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK);
        assert(vireo_protocol_frame_crc32c_calculate(wire, 32, wire + 32, size - 32, &h.crc32c) == VIREO_OK);
        assert(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK);
        check(wire, size);
    }
    return 0;
}

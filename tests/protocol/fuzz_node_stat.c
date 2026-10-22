/* 同一harness分别编译request/response两个libFuzzer入口，不进入普通CTest。
 * 原始帧与修复envelope/CRC的帧都送parser；检查发布原子性与规范编码稳定性。 */
#include <vireo/protocol/node_stat.h>
#include <vireo/protocol/codec.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#ifdef VIREO_FUZZ_NODE_STAT_RESPONSE
typedef vireo_node_stat_response_t value_t;
#define DECODE vireo_node_stat_response_decode
#define ENCODE vireo_node_stat_response_encode
#else
typedef vireo_node_stat_request_t value_t;
#define DECODE vireo_node_stat_request_decode
#define ENCODE vireo_node_stat_request_encode
#endif
int LLVMFuzzerTestOneInput(uint8_t const *data, size_t size);

/** @brief 借用任意有效data/size，不保存；失败out含padding保持，成功编码须规范稳定。 */
static void check(unsigned char const *data, size_t size) {
    value_t v, old; memset(&v, 0xa5, sizeof v); memcpy(&old, &v, sizeof old);
    vireo_node_stat_issue_t issue = VIREO_NODE_STAT_ISSUE_VALUE;
    errno = EDOM; vireo_result_t rc = DECODE(data, size, &v, &issue); assert(errno == EDOM);
    if (rc != VIREO_OK) {
        assert(rc == VIREO_RESULT_PROTOCOL && issue != VIREO_NODE_STAT_ISSUE_NONE);
        assert(memcmp(&v, &old, sizeof v) == 0); return;
    }
    assert(issue == VIREO_NODE_STAT_ISSUE_NONE && v.sequence != 0);
    unsigned char wire[500], again[500], before[500]; memset(wire, 0xa5, sizeof wire); memcpy(before, wire, sizeof wire);
    size_t n = 888, n2 = 999;
    errno = EDOM; assert(ENCODE(&v, wire, sizeof wire, &n) == VIREO_OK); assert(errno == EDOM);
    assert(n >= 32 && n <= 393 && memcmp(wire + n, before + n, sizeof wire - n) == 0);
    value_t copy; assert(DECODE(wire, n, &copy, &issue) == VIREO_OK);
    assert(ENCODE(&copy, again, sizeof again, &n2) == VIREO_OK && n == n2 && memcmp(wire, again, n) == 0);
    memcpy(before, wire, sizeof wire); n2 = 999; errno = EDOM;
    assert(ENCODE(&v, wire, n - 1, &n2) == VIREO_RESULT_RANGE && errno == EDOM);
    assert(n2 == 999 && memcmp(before, wire, sizeof wire) == 0);
}

/** @brief 按字节构造定义良好的宿主值；不把随机位解释成bool或padding。 */
static void host(unsigned char const *data, size_t size) {
    if (size < 32) return;
    value_t v = {0}; v.sequence = data[0]; v.session_handle = data[1];
#ifdef VIREO_FUZZ_NODE_STAT_RESPONSE
    static uint16_t const statuses[] = {0, 1001, 1101, 1201, 1901, 1902, 1906, 1907, 1908, 1, 1392, 1904};
    v.status = statuses[data[2] % (sizeof statuses / sizeof statuses[0])];
    v.metadata.node_id = data[3]; v.metadata.has_parent = (data[4] & 1U) != 0;
    v.metadata.parent_id = data[5]; v.metadata.name_length = (size_t)data[6] + (data[7] & 1U);
    v.metadata.type = data[8] % 4U; v.metadata.size = data[9];
    v.metadata.created_at_ms = data[10]; v.metadata.updated_at_ms = data[11];
    v.metadata.has_object_hash = (data[12] & 1U) != 0;
    for (size_t i = 0; i < 255 && i + 32 < size; ++i) v.metadata.name[i] = data[i + 32];
    for (size_t i = 0; i < 32; ++i) v.metadata.object_hash[i] = (data[13] & 1U) != 0 ? data[i] : 0;
#else
    for (size_t i = 0; i < 8; ++i) v.node_id = (v.node_id << 8) | data[i + 2];
#endif
    unsigned char wire[500], old[500]; memset(wire, 0xa5, sizeof wire); memcpy(old, wire, sizeof old);
    size_t n = 999, capacity = (size_t)data[30] * 2;
    errno = EDOM; vireo_result_t rc = ENCODE(&v, wire, capacity, &n); assert(errno == EDOM);
    if (rc == VIREO_OK) { assert(n <= capacity); check(wire, n); assert(memcmp(wire + n, old + n, sizeof wire - n) == 0); }
    else {
        assert(rc == VIREO_RESULT_INVALID_ARGUMENT || rc == VIREO_RESULT_RANGE);
        assert(n == 999 && memcmp(wire, old, sizeof wire) == 0);
    }
}

int LLVMFuzzerTestOneInput(uint8_t const *data, size_t size) {
    check(data, size); host(data, size);
    if (size >= 32 && size <= 393) {
        unsigned char wire[393]; memcpy(wire, data, size);
        vireo_protocol_header_t h = {.command = VIREO_COMMAND_NODE_STAT, .sequence = 1,
            .session_handle = 2, .body_len = (uint32_t)(size - 32)};
#ifdef VIREO_FUZZ_NODE_STAT_RESPONSE
        h.flags = VIREO_PROTOCOL_FLAG_RESPONSE;
#endif
        assert(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK);
        assert(vireo_protocol_frame_crc32c_calculate(wire, 32, wire + 32, size - 32, &h.crc32c) == VIREO_OK);
        assert(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK);
        check(wire, size);
    }
    return 0;
}

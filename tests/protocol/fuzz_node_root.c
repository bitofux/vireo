/*
 * PROJECT : VIREO
 * FILE    : fuzz_node_root.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-22
 * BRIEF   : NODE_ROOT双方向libFuzzer入口；原始帧、修复CRC帧和宿主值边界。
 */
#include <vireo/protocol/node_root.h>
#include <vireo/protocol/codec.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#ifdef VIREO_FUZZ_NODE_ROOT_RESPONSE
typedef vireo_node_root_response_t value_t;
#define DECODE vireo_node_root_response_decode
#define ENCODE vireo_node_root_response_encode
#else
typedef vireo_node_root_request_t value_t;
#define DECODE vireo_node_root_request_decode
#define ENCODE vireo_node_root_request_encode
#endif

int LLVMFuzzerTestOneInput(uint8_t const *data, size_t size);

/**
 * @brief 原始或修复后的任意帧验证失败发布/errno与成功规范往返
 * @param[in] data 必需size字节稳定输入，仅借至返回。
 * @param[in] size 实际长度；decoder必须先检查上限。
 * @note 不持有地址；断言失败由libFuzzer保存输入，无外部资源。
 */
static void check(unsigned char const *data, size_t size) {
    value_t value, old;
    memset(&value, 0xa5, sizeof value); memcpy(&old, &value, sizeof old);
    vireo_node_root_issue_t issue = VIREO_NODE_ROOT_ISSUE_VALUE;
    errno = EDOM;
    vireo_result_t const result = DECODE(data, size, &value, &issue);
    assert(errno == EDOM);
    if (result != VIREO_OK) {
        assert(result == VIREO_RESULT_PROTOCOL && issue != VIREO_NODE_ROOT_ISSUE_NONE);
        assert(memcmp(&old, &value, sizeof old) == 0);
        return;
    }
    assert(issue == VIREO_NODE_ROOT_ISSUE_NONE && value.sequence != 0);
    unsigned char wire[64], before[64], again[64]; size_t n = 999, m = 998;
    memset(wire, 0xa5, sizeof wire); memcpy(before, wire, sizeof before);
    assert(ENCODE(&value, wire, sizeof wire, &n) == VIREO_OK && errno == EDOM);
    assert((n == 32 || n == 44) && memcmp(wire + n, before + n, sizeof wire - n) == 0);
    value_t copy;
    assert(DECODE(wire, n, &copy, &issue) == VIREO_OK && errno == EDOM);
    assert(ENCODE(&copy, again, sizeof again, &m) == VIREO_OK && errno == EDOM);
    assert(n == m && memcmp(wire, again, n) == 0);
    memcpy(before, wire, sizeof before); m = 998;
    assert(ENCODE(&value, wire, n - 1, &m) == VIREO_RESULT_RANGE && errno == EDOM);
    assert(m == 998 && memcmp(wire, before, sizeof wire) == 0);
}

/**
 * @brief 逐字节构造定义良好的宿主整数，不把随机结构体padding解释成值
 * @param[in] data 必需size字节输入，至少20字节时构造宿主边界。
 * @param[in] size 实际可读长度，仅借至返回。
 * @note 失败保持整个wire和长度；无动态资源。
 */
static void host(unsigned char const *data, size_t size) {
    if (size < 20) return;
    value_t value = {0};
    for (size_t i = 0; i < 4; ++i) {
        value.sequence = (value.sequence << 8) | data[i];
        value.session_handle = (value.session_handle << 8) | data[i + 4];
    }
#ifdef VIREO_FUZZ_NODE_ROOT_RESPONSE
    value.status = (uint16_t)(((uint16_t)data[8] << 8) | data[9]);
    for (size_t i = 0; i < 8; ++i) value.root_node_id = (value.root_node_id << 8) | data[i + 10];
#endif
    unsigned char wire[64], old[64]; size_t n = 999, capacity = data[19] % 65U;
    memset(wire, 0xa5, sizeof wire); memcpy(old, wire, sizeof old);
    errno = EDOM;
    vireo_result_t const result = ENCODE(&value, wire, capacity, &n);
    assert(errno == EDOM);
    if (result == VIREO_OK) {
        assert(n <= capacity && memcmp(wire + n, old + n, sizeof wire - n) == 0);
        check(wire, n);
    } else {
        assert(result == VIREO_RESULT_INVALID_ARGUMENT || result == VIREO_RESULT_RANGE);
        assert(n == 999 && memcmp(wire, old, sizeof wire) == 0);
    }
}

int LLVMFuzzerTestOneInput(uint8_t const *data, size_t size) {
    check(data, size); host(data, size);
    if (size >= 32 && size <= 44) {
        unsigned char wire[44]; memcpy(wire, data, size);
        vireo_protocol_header_t header = {.command = VIREO_COMMAND_NODE_ROOT,
            .sequence = 1, .session_handle = 2, .body_len = (uint32_t)(size - 32)};
#ifdef VIREO_FUZZ_NODE_ROOT_RESPONSE
        static uint16_t const statuses[] = {0, 1101, 1902, 1908, 1201, 1, 65535};
        header.flags = VIREO_PROTOCOL_FLAG_RESPONSE;
        header.status = statuses[data[0] % (sizeof statuses / sizeof statuses[0])];
        if (header.status != 0) header.session_handle = 0;
#endif
        assert(vireo_protocol_header_encode(&header, wire, 32) == VIREO_OK);
        assert(vireo_protocol_frame_crc32c_calculate(wire, 32, wire + 32,
            size - 32, &header.crc32c) == VIREO_OK);
        assert(vireo_protocol_header_encode(&header, wire, 32) == VIREO_OK);
        check(wire, size);
    }
    return 0;
}

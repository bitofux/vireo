/*
 * PROJECT : VIREO
 * FILE    : fuzz_node_list.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-22
 * BRIEF   : NODE_LIST双方向libFuzzer入口；原始帧、修复CRC帧和宿主值边界。
 */
#include <vireo/protocol/node_list.h>
#include <vireo/protocol/codec.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#ifdef VIREO_FUZZ_NODE_LIST_RESPONSE
typedef vireo_node_list_response_t value_t;
#define DECODE vireo_node_list_response_decode
#define ENCODE vireo_node_list_response_encode
#else
typedef vireo_node_list_request_t value_t;
#define DECODE vireo_node_list_request_decode
#define ENCODE vireo_node_list_request_encode
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
    vireo_node_list_issue_t issue = VIREO_NODE_LIST_ISSUE_VALUE;
    errno = EDOM;
    vireo_result_t const result = DECODE(data, size, &value, &issue);
    assert(errno == EDOM);
    if (result != VIREO_OK) {
        assert(result == VIREO_RESULT_PROTOCOL && issue != VIREO_NODE_LIST_ISSUE_NONE);
        assert(memcmp(&old, &value, sizeof old) == 0);
        return;
    }
    assert(issue == VIREO_NODE_LIST_ISSUE_NONE && value.sequence != 0);
    unsigned char wire[23511], before[23511], again[23511]; size_t n = 999, m = 998;
    memset(wire, 0xa5, sizeof wire); memcpy(before, wire, sizeof before);
    assert(ENCODE(&value, wire, sizeof wire, &n) == VIREO_OK && errno == EDOM);
    assert((n >= 32 && n <= 23510) && memcmp(wire + n, before + n, sizeof wire - n) == 0);
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
    for (size_t i=0; i<4; ++i) {
        value.sequence=(value.sequence<<8)|data[i];
        value.session_handle=(value.session_handle<<8)|data[i+4];
    }
    value.directory_id=42; value.page_size=(uint16_t)(data[8]%64U+1U);
#ifdef VIREO_FUZZ_NODE_LIST_RESPONSE
    value.count=data[9]%(value.page_size+1U);
    value.has_more=(data[10]&1U)!=0;
    if (value.has_more) value.count=value.page_size;
    for (size_t i=0;i<value.count;++i) {
        vireo_node_list_entry_t *e=&value.entries[i];
        e->node_id=100+(uint64_t)i;e->parent_id=42;
        e->name_length=(size_t)data[11]+1U; /* 256 is deliberately invalid */
        memset(e->name,data[12],sizeof e->name);
        e->type=(uint16_t)(data[13]%3U);
        e->has_object_hash=e->type==VIREO_NODE_LIST_FILE;
        e->updated_at_ms=data[14];e->created_at_ms=data[15];
    }
#else
    value.has_page_token=(data[9]&1U)!=0;
    if (value.has_page_token) memset(value.page_token,data[10],sizeof value.page_token);
#endif
    unsigned char wire[23511], old[23511]; size_t n=999;
    size_t const capacity=((size_t)data[18]*256U+data[19])%23512U;
    memset(wire,0xa5,sizeof wire);memcpy(old,wire,sizeof old);errno=EDOM;
    vireo_result_t const rc=ENCODE(&value,wire,capacity,&n);
    assert(errno==EDOM);
    if (rc==VIREO_OK) {
        assert(n<=capacity && memcmp(wire+n,old+n,sizeof wire-n)==0);
        check(wire,n);
    } else {
        assert(rc==VIREO_RESULT_INVALID_ARGUMENT || rc==VIREO_RESULT_RANGE);
        assert(n==999 && memcmp(wire,old,sizeof wire)==0);
    }
}

int LLVMFuzzerTestOneInput(uint8_t const *data, size_t size) {
    check(data, size); host(data, size);
    if (size >= 32 && size <= 23510) {
        unsigned char wire[23510]; memcpy(wire, data, size);
        vireo_protocol_header_t header = {.command = VIREO_COMMAND_NODE_LIST,
            .sequence = 1, .session_handle = 2, .body_len = (uint32_t)(size - 32)};
#ifdef VIREO_FUZZ_NODE_LIST_RESPONSE
        static uint16_t const statuses[] = {0, 1101, 1902, 1908, 1201, 1, 65535};
        header.flags = (uint16_t)(VIREO_PROTOCOL_FLAG_RESPONSE | ((data[1]&1U)!=0 ? VIREO_PROTOCOL_FLAG_MORE : 0));
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

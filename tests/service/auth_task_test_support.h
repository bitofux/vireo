/* PROJECT : VIREO
 * FILE : auth_task_test_support.h
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 两个本模块测试共用的固定非秘密请求样本构造。
 */
#ifndef VIREO_TEST_AUTH_TASK_SUPPORT_H
#define VIREO_TEST_AUTH_TASK_SUPPORT_H
#include <vireo/service/auth_task.h>
#include <vireo/protocol/codec.h>
#include <vireo/protocol/tlv.h>
#include <vireo/base/secure_clear.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(call, expected) do { errno = EDOM; vireo_result_t test_rc_ = (call); \
    if (test_rc_ != (expected)) { fprintf(stderr, "line %d result %d expected %d\n", \
        __LINE__, (int)test_rc_, (int)(expected)); abort(); } assert(errno == EDOM); } while (0)

/** 构造固定schema完整帧；只供测试，不作为生产编码器。 */
static size_t frame(unsigned char wire[156], bool login, uint32_t sequence, bool wrong)
{
    vireo_tlv_writer_t writer;
    assert(vireo_tlv_writer_init(&writer, wire + 32, 124) == VIREO_OK);
    assert(vireo_tlv_writer_put(&writer, 1, (uint8_t const *)"Alice_7", 7) == VIREO_OK);
    assert(vireo_tlv_writer_put(&writer, 2, (uint8_t const *)(wrong ? "Incorrect" : "Correct!7"), 9) == VIREO_OK);
    if (login) {
        unsigned char const device[16] = {0};
        assert(vireo_tlv_writer_put(&writer, 3, device, 16) == VIREO_OK);
    }
    vireo_protocol_header_t header = {.command = login ? VIREO_COMMAND_LOGIN : VIREO_COMMAND_REGISTER,
        .sequence = sequence, .body_len = (uint32_t)writer.used};
    assert(vireo_protocol_header_encode(&header, wire, 32) == VIREO_OK);
    assert(vireo_protocol_frame_crc32c_calculate(wire, 32, wire + 32, writer.used, &header.crc32c) == VIREO_OK);
    assert(vireo_protocol_header_encode(&header, wire, 32) == VIREO_OK);
    return 32 + writer.used;
}

/** 可信测试上下文使用故意不同的sequence/instance/audit ID及两种时间域。 */
static vireo_auth_task_context_t task_context(uint32_t sequence, uint64_t instance, bool login)
{
    vireo_auth_task_context_t c = {.request_id = {1}, .now_ns = 99,
        .occurred_at_ms = login ? 2000 : 1000, .expires_at_ms = login ? 5000 : 0, .latency_us = 13};
    assert(vireo_task_route_make(1, 0, 1, sequence, &c.metadata.route) == VIREO_OK);
    assert(vireo_task_metadata_make(c.metadata.route, instance, login ? 101 : 100, 100, &c.metadata) == VIREO_OK);
    c.request_id[15] = (unsigned char)instance;
    return c;
}
#endif

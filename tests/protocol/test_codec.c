/*
 * PROJECT : VIREO
 * FILE    : test_codec.c
 * AUTHOR  : bitofux
 * DATE    : 2026-08-25
 * BRIEF   : 测试 vireo v1 protocol codec
 * -- 验证宿主语义 header 与固定 32 字节 wire header 的显式编解码
 * -- 验证固定 framing 与请求、响应基础语义
 * -- 验证 CRC-32C 的冻结覆盖范围和确定性 golden vectors
 * -- 验证无效参数、长度边界、具体 issue 和失败时输出保持
 * -- 验证公共函数不会修改 errno
 */

#include <vireo/protocol/codec.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vireo/base/result.h>
#include <vireo/protocol/protocol.h>

#define VIREO_TEST_ARRAY_COUNT(array) (sizeof(array) / sizeof(array[0]))

_Static_assert(CHAR_BIT == 8, "vireo codec tests require 8-bit bytes");

_Static_assert(VIREO_PROTOCOL_HEADER_SIZE == UINT32_C(32),
               "vireo codec tests require fixed 32-byte header");

_Static_assert(VIREO_PROTOCOL_CRC32C_OFFSET == UINT32_C(28),
               "vireo codec tests require CRC-32C at offset 28");

/* 比较实际 vireo_result_t 与预期结果 */
static int expect_result(char const *case_name, vireo_result_t actual, vireo_result_t expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected result %d, got %d\n", case_name, (int)expected, (int)actual);

    return 1;
}

/* 比较实际 codec issue 与预期 issue */
static int expect_issue(char const *case_name, vireo_protocol_codec_issue_t actual,
                        vireo_protocol_codec_issue_t expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected codec issue %d, got %d\n", case_name, (int)expected, (int)actual);

    return 1;
}

/* 比较实际 uint32_t 与预期值 */
static int expect_u32(char const *case_name, uint32_t actual, uint32_t expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr,
            "%s: expected uint32_t %" PRIu32 " (0x%08" PRIX32 "), got %" PRIu32 " (0x%08" PRIX32
            ")\n",
            case_name, expected, expected, actual, actual);

    return 1;
}

/* 比较两个只读字节区域 */
static int expect_bytes(char const *case_name, uint8_t const *actual, uint8_t const *expected,
                        size_t size) {
    for (size_t index = 0; index < size; ++index) {
        if (actual[index] == expected[index]) {
            continue;
        }

        fprintf(stderr, "%s: byte %zu expected 0x%02X, got 0x%02X\n", case_name, index,
                (unsigned int)expected[index], (unsigned int)actual[index]);

        return 1;
    }

    return 0;
}

/* 比较实际 uint16_t 与预期值 */
static int expect_u16(char const *case_name, uint16_t actual, uint16_t expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr,
            "%s: expected uint16_t %" PRIu16 " (0x%04" PRIX16 "), got %" PRIu16 " (0x%04" PRIX16
            ")\n",
            case_name, expected, expected, actual, actual);

    return 1;
}

/* 比较 errno 的实际值与预期值 */
static int expect_errno_value(char const *case_name, int actual, int expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected errno %d, got %d\n", case_name, expected, actual);

    return 1;
}

/* 构造一份 codec 基础请求语义的header */
static vireo_protocol_header_t make_valid_request_header(void) {
    vireo_protocol_header_t header = {.command = VIREO_COMMAND_PING,
                                      .flags = UINT16_C(0),
                                      .status = VIREO_PROTOCOL_REQUEST_STATUS,
                                      .body_len = UINT32_C(0),
                                      .sequence = UINT32_C(1),
                                      .session_handle = VIREO_PROTOCOL_NO_SESSION_HANDLE,
                                      .task_handle = VIREO_PROTOCOL_NO_TASK_HANDLE,
                                      .crc32c = UINT32_C(0)};

    return header;
}

/* 构造一份 codec 基础响应语义的header */
static vireo_protocol_header_t make_valid_response_header(void) {
    vireo_protocol_header_t header = {
        .command = VIREO_COMMAND_PING,
        .flags = VIREO_PROTOCOL_FLAG_RESPONSE,
        .status = VIREO_STATUS_ACCEPTED,
        .body_len = UINT32_C(0),
        .sequence = UINT32_C(1),
        .session_handle = VIREO_PROTOCOL_NO_SESSION_HANDLE,
        .task_handle = VIREO_PROTOCOL_NO_TASK_HANDLE,
        .crc32c = UINT32_C(0),
    };

    return header;
}

/* 验证宿主语义 header 被编码为确定性的 32 字节 golden vector */
static int test_header_encode_golden(void) {
    // 期望编码成功后的 wire buffer 中元素的值
    static uint8_t const expected_wire[VIREO_PROTOCOL_HEADER_SIZE] = {
        0x56, 0x49, 0x52, 0x45, 0x01, 0x20, 0x12, 0x34, 0x56, 0x78, 0x9A,
        0xBC, 0x00, 0x01, 0x02, 0x03, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    };

    // 临时构建需要编码的 header
    vireo_protocol_header_t header = {
        .command = UINT16_C(0x1234),
        .flags = UINT16_C(0x5678),
        .status = UINT16_C(0x9ABC),
        .body_len = UINT32_C(0x00010203),
        .sequence = UINT32_C(0x11223344),
        .session_handle = UINT32_C(0x55667788),
        .task_handle = UINT32_C(0x99AABBCC),
        .crc32c = UINT32_C(0xDDEEFF00),
    };

    uint8_t wire[VIREO_PROTOCOL_HEADER_SIZE];
    memset(wire, 0xA5, sizeof(wire));

    errno = EACCES;
    vireo_result_t result = vireo_protocol_header_encode(&header, wire, sizeof(wire));
    int actual_errno = errno;

    int failures = expect_result("header encode golden result", result, VIREO_OK);
    failures += expect_errno_value("header encode golden errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures +=
            expect_bytes("header encode golden bytes", wire, expected_wire, sizeof(expected_wire));
    }

    return failures;
}

/* 验证header encode 的空指针错误和失败输出保持 */
static int test_header_encode_invalid_arguments(void) {
    vireo_protocol_header_t header = make_valid_request_header();
    uint8_t wire[VIREO_PROTOCOL_HEADER_SIZE];
    uint8_t expected_wire[VIREO_PROTOCOL_HEADER_SIZE];

    memset(wire, 0xA5, sizeof(wire));
    memset(expected_wire, 0xA5, sizeof(expected_wire));

    errno = EACCES;
    vireo_result_t result = vireo_protocol_header_encode(NULL, wire, sizeof(wire));
    int actual_errno = errno;

    int failures =
        expect_result("header encode null header result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_errno_value("header encode null header errno", actual_errno, EACCES);
    failures +=
        expect_bytes("header encode null header output keep", wire, expected_wire, sizeof(wire));

    errno = EACCES;
    result = vireo_protocol_header_encode(&header, NULL, sizeof(expected_wire));
    actual_errno = errno;

    failures +=
        expect_result("header encode null wire result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_errno_value("header encode null wire errno", actual_errno, EACCES);

    return failures;
}

/* 验证 header encode 的容量和 body 长度边界 */
static int test_header_encode_range_boundaries(void) {
    // 定义 header 支持的最大 body_len
    static uint8_t const expected_max_body_len[VIREO_PROTOCOL_BODY_LENGTH_SIZE] = {0x01, 0x00, 0x00,
                                                                                   0x00};

    // 构造一个请求消息头部
    vireo_protocol_header_t header = make_valid_request_header();
    uint8_t wire[VIREO_PROTOCOL_HEADER_SIZE];
    uint8_t expected_unchanged[VIREO_PROTOCOL_HEADER_SIZE];

    memset(wire, 0xA5, sizeof(wire));
    memset(expected_unchanged, 0xA5, sizeof(expected_unchanged));

    header.body_len = VIREO_PROTOCOL_MAX_BODY_SIZE;

    errno = EACCES;
    vireo_result_t result = vireo_protocol_header_encode(&header, wire, sizeof(wire));
    int actual_errno = errno;

    int failures = expect_result("header encode max body result", result, VIREO_OK);
    failures += expect_errno_value("header encode max body errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures +=
            expect_bytes("header encode max body bytes", wire + VIREO_PROTOCOL_BODY_LENGTH_OFFSET,
                         expected_max_body_len, sizeof(expected_max_body_len));
    }

    memset(wire, 0xA5, sizeof(wire));
    header.body_len = UINT32_C(0);

    errno = EACCES;
    result = vireo_protocol_header_encode(&header, wire, sizeof(wire) - 1U);
    actual_errno = errno;

    failures += expect_result("header encode short capacity result", result, VIREO_RESULT_RANGE);
    failures += expect_errno_value("header encode short capacity errno", actual_errno, EACCES);

    failures +=
        expect_bytes("header encode short capacity bytes", wire, expected_unchanged, sizeof(wire));

    header.body_len = VIREO_PROTOCOL_MAX_BODY_SIZE + UINT32_C(1);
    memset(wire, 0xA5, sizeof(wire));

    errno = EACCES;
    result = vireo_protocol_header_encode(&header, wire, sizeof(wire));
    actual_errno = errno;

    failures += expect_result("header encode oversized body result", result, VIREO_RESULT_RANGE);
    failures += expect_errno_value("header encode oversized body errno", actual_errno, EACCES);

    failures +=
        expect_bytes("header encode oversize body bytes", wire, expected_unchanged, sizeof(wire));

    return failures;
}

/* 验证header encode 在容量大于 32 时不修改尾部区域 */
static int test_header_encode_larger_capacity_tail_keep(void) {
    // 构造一个请求数据包的头部
    vireo_protocol_header_t header = make_valid_request_header();

    uint8_t wire[VIREO_PROTOCOL_HEADER_SIZE + UINT8_C(8)];
    uint8_t expected_tail[UINT8_C(8)];

    memset(wire, 0xA5, sizeof(wire));
    memset(expected_tail, 0xA5, sizeof(expected_tail));

    errno = EACCES;

    vireo_result_t result = vireo_protocol_header_encode(&header, wire, sizeof(wire));
    int actual_errno = errno;
    int failures = expect_result("header encode larger capacity result", result, VIREO_OK);
    failures += expect_errno_value("header encode larger capacity errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures +=
            expect_bytes("header encode larger capacity tail keep",
                         wire + VIREO_PROTOCOL_HEADER_SIZE, expected_tail, sizeof(expected_tail));
    }

    return failures;
}

/* 验证确定性 32 字节 wire header 被显式解码为宿主语义字段 */
static int test_header_decode_golden(void) {
    static uint8_t const wire[VIREO_PROTOCOL_HEADER_SIZE] = {
        0x56, 0x49, 0x52, 0x45, 0x01, 0x20, 0x12, 0x34, 0x56, 0x78, 0x9A,
        0xBC, 0x00, 0x01, 0x02, 0x03, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    };

    vireo_protocol_header_t header = {0};
    vireo_protocol_codec_issue_t issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    vireo_result_t result = vireo_protocol_header_decode(wire, sizeof(wire), &header, &issue);
    int actual_errno = errno;
    int failures = expect_result("header decode golden result", result, VIREO_OK);
    failures += expect_issue("header decode golden issue", issue, VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    failures += expect_errno_value("header decode golden errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures += expect_u16("header decode golden command", header.command, UINT16_C(0x1234));
        failures += expect_u16("header decode golden flags", header.flags, UINT16_C(0x5678));
        failures += expect_u16("header decode golden status", header.status, UINT16_C(0x9ABC));
        failures +=
            expect_u32("header decode golden body_len", header.body_len, UINT32_C(0x00010203));
        failures +=
            expect_u32("header decode golden sequence", header.sequence, UINT32_C(0x11223344));
        failures += expect_u32("header decode golden session_handle", header.session_handle,
                               UINT32_C(0x55667788));
        failures += expect_u32("header decode golden task_handle", header.task_handle,
                               UINT32_C(0x99AABBCC));
        failures += expect_u32("header decode golden crc32c", header.crc32c, UINT32_C(0xDDEEFF00));
    }

    return failures;
}

/* 逐字段比较两个宿主语义 header */
static int expect_header(char const *case_name, vireo_protocol_header_t const *actual,
                         vireo_protocol_header_t const *expected) {
    if (actual->command != expected->command) {
        fprintf(stderr,
                "%s: expected command %" PRIu16 " (0x%04" PRIX16 "), got %" PRIu16 " (0x%04" PRIX16
                ")\n",
                case_name, expected->command, expected->command, actual->command, actual->command);

        return 1;
    }

    if (actual->flags != expected->flags) {
        fprintf(stderr,
                "%s: expected flags %" PRIu16 " (0x%04" PRIX16 "), got %" PRIu16 " (0x%04" PRIX16
                ")\n",
                case_name, expected->flags, expected->flags, actual->flags, actual->flags);

        return 1;
    }

    if (actual->status != expected->status) {
        fprintf(stderr,
                "%s: expected status %" PRIu16 " (0x%04" PRIX16 "), got %" PRIu16 " (0x%04" PRIX16
                ")\n",
                case_name, expected->status, expected->status, actual->status, actual->status);

        return 1;
    }

    if (actual->body_len != expected->body_len) {
        fprintf(stderr,
                "%s: expected body_len %" PRIu32 " (0x%08" PRIX32 "), got %" PRIu32 " (0x%08" PRIX32
                ")\n",
                case_name, expected->body_len, expected->body_len, actual->body_len,
                actual->body_len);

        return 1;
    }

    if (actual->sequence != expected->sequence) {
        fprintf(stderr,
                "%s: expected sequence %" PRIu32 " (0x%08" PRIX32 "), got %" PRIu32 " (0x%08" PRIX32
                ")\n",
                case_name, expected->sequence, expected->sequence, actual->sequence,
                actual->sequence);

        return 1;
    }

    if (actual->session_handle != expected->session_handle) {
        fprintf(stderr,
                "%s: expected session_handle %" PRIu32 " (0x%08" PRIX32 "), got %" PRIu32
                " (0x%08" PRIX32 ")\n",
                case_name, expected->session_handle, expected->session_handle,
                actual->session_handle, actual->session_handle);

        return 1;
    }

    if (actual->task_handle != expected->task_handle) {
        fprintf(stderr,
                "%s: expected task_handle %" PRIu32 " (0x%08" PRIX32 "), got %" PRIu32
                " (0x%08" PRIX32 ")\n",
                case_name, expected->task_handle, expected->task_handle, actual->task_handle,
                actual->task_handle);

        return 1;
    }

    if (actual->crc32c != expected->crc32c) {
        fprintf(stderr,
                "%s: expected crc32c %" PRIu32 " (0x%08" PRIX32 "), got %" PRIu32 " (0x%08" PRIX32
                ")\n",
                case_name, expected->crc32c, expected->crc32c, actual->crc32c, actual->crc32c);

        return 1;
    }

    return 0;
}

/* 验证 header decode 的空指针错误、issue 初始化和输出保持 */
static int test_header_decode_invalid_arguments(void) {
    static uint8_t const wire[VIREO_PROTOCOL_HEADER_SIZE] = {
        0x56, 0x49, 0x52, 0x45, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    vireo_protocol_header_t expected_header = {.command = UINT16_C(0xA1A2),
                                               .flags = UINT16_C(0xB1B2),
                                               .status = UINT16_C(0xC1C2),
                                               .body_len = UINT32_C(0xD1D2D3D4),
                                               .sequence = UINT32_C(0xE1E2E3E4),
                                               .session_handle = UINT32_C(0xF1F2F3F4),
                                               .task_handle = UINT32_C(0x01020304),
                                               .crc32c = UINT32_C(0x11223344)};
    vireo_protocol_header_t header = expected_header;

    vireo_protocol_codec_issue_t issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    vireo_result_t result = vireo_protocol_header_decode(NULL, sizeof(wire), &header, &issue);
    int actual_errno = errno;

    int failures =
        expect_result("header decode null wire result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures +=
        expect_issue("header decode null wire issue", issue, VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    failures += expect_errno_value("header decode null wire errno", actual_errno, EACCES);
    failures += expect_header("header decode null wire output keep", &header, &expected_header);

    errno = EACCES;
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;
    result = vireo_protocol_header_decode(wire, sizeof(wire), NULL, &issue);
    actual_errno = errno;

    failures += expect_result("header decode null out_header result", result,
                              VIREO_RESULT_INVALID_ARGUMENT);
    failures +=
        expect_issue("header decode null out_header issue", issue, VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    failures += expect_errno_value("header decode null out_header errno", actual_errno, EACCES);

    header = expected_header;
    errno = EACCES;
    result = vireo_protocol_header_decode(wire, sizeof(wire), &header, NULL);
    actual_errno = errno;

    failures +=
        expect_result("header decode null out_issue result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_errno_value("header decode null out_issue errno", actual_errno, EACCES);
    failures +=
        expect_header("header decode null out_issue output keep", &header, &expected_header);

    return failures;
}

/* 验证 header decode 的 wire size 边界 */
static int test_header_decode_wire_size_boundaries(void) {
    static uint8_t const wire[VIREO_PROTOCOL_HEADER_SIZE + UINT8_C(1)] = {
        0x56, 0x49, 0x52, 0x45, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA5,
    };

    vireo_protocol_header_t const expected_unchanged = {
        .command = UINT16_C(0xA1A2),
        .flags = UINT16_C(0xB1B2),
        .status = UINT16_C(0xC1C2),
        .body_len = UINT32_C(0xD1D2D3D4),
        .sequence = UINT32_C(0xE1E2E3E4),
        .session_handle = UINT32_C(0xF1F2F3F4),
        .task_handle = UINT32_C(0x01020304),
        .crc32c = UINT32_C(0x11223344),
    };

    vireo_protocol_header_t const expected_decoded = {
        .command = VIREO_COMMAND_PING,
        .flags = UINT16_C(0),
        .status = VIREO_PROTOCOL_REQUEST_STATUS,
        .body_len = UINT32_C(0),
        .sequence = UINT32_C(1),
        .session_handle = VIREO_PROTOCOL_NO_SESSION_HANDLE,
        .task_handle = VIREO_PROTOCOL_NO_TASK_HANDLE,
        .crc32c = UINT32_C(0)};

    vireo_protocol_header_t header = expected_unchanged;
    vireo_protocol_codec_issue_t issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    vireo_result_t result = vireo_protocol_header_decode(
        wire, (size_t)VIREO_PROTOCOL_HEADER_SIZE - 1U, &header, &issue);
    int actual_errno = errno;

    int failures = expect_result("header decode short wire result", result, VIREO_RESULT_RANGE);
    failures +=
        expect_issue("header decode short wire issue", issue, VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    failures += expect_errno_value("header decode short wire errno", actual_errno, EACCES);

    failures += expect_header("header decode short wire output keep", &header, &expected_unchanged);

    header = expected_unchanged;
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_protocol_header_decode(wire, sizeof(wire), &header, &issue);
    actual_errno = errno;

    failures += expect_result("header decode larger wire result", result, VIREO_OK);

    failures +=
        expect_issue("header decode larger wire issue", issue, VIREO_PROTOCOL_CODEC_ISSUE_NONE);

    failures += expect_errno_value("header decode larger wire errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures += expect_header("header decode larger wire fields", &header, &expected_decoded);
    }
    return failures;
}

/* 验证header decode 的固定 framing 错误和失败输出保持 */
static int test_header_decode_invalid_framing(void) {
    static uint8_t const valid_wire[VIREO_PROTOCOL_HEADER_SIZE] = {
        0x56, 0x49, 0x52, 0x45, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    vireo_protocol_header_t const expected_unchanged = {.command = UINT16_C(0xA1A2),
                                                        .flags = UINT16_C(0xB1B2),
                                                        .status = UINT16_C(0xC1C2),
                                                        .body_len = UINT32_C(0xD1D2D3D4),
                                                        .sequence = UINT32_C(0xE1E2E3E4),
                                                        .session_handle = UINT32_C(0xF1F2F3F4),
                                                        .task_handle = UINT32_C(0x01020304),
                                                        .crc32c = UINT32_C(0x11223344)};

    uint8_t wire[VIREO_PROTOCOL_HEADER_SIZE];
    vireo_protocol_header_t header = expected_unchanged;
    vireo_protocol_codec_issue_t issue;

    memcpy(wire, valid_wire, sizeof(wire));
    wire[VIREO_PROTOCOL_MAGIC_OFFSET] = UINT8_C(0);

    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;
    errno = EACCES;
    vireo_result_t result = vireo_protocol_header_decode(wire, sizeof(wire), &header, &issue);
    int actual_errno = errno;
    int failures =
        expect_result("header decode invalid magic result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("header decode invalid magic issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_INVALID_MAGIC);
    failures += expect_errno_value("header decode invalid magic errno", actual_errno, EACCES);
    failures +=
        expect_header("header decode invalid magic output keep", &header, &expected_unchanged);

    memcpy(wire, valid_wire, sizeof(wire));
    wire[VIREO_PROTOCOL_VERSION_OFFSET] = (uint8_t)(VIREO_PROTOCOL_VERSION + UINT8_C(1));
    header = expected_unchanged;
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_protocol_header_decode(wire, sizeof(wire), &header, &issue);
    actual_errno = errno;

    failures +=
        expect_result("header decode version mismatch result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("header decode version mismatch issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_VERSION_MISMATCH);
    failures += expect_errno_value("header decode version mismatch errno", actual_errno, EACCES);
    failures +=
        expect_header("header decode version mismatch output keep", &header, &expected_unchanged);

    memcpy(wire, valid_wire, sizeof(wire));
    wire[VIREO_PROTOCOL_HEADER_LENGTH_OFFSET] = (uint8_t)(VIREO_PROTOCOL_HEADER_SIZE - UINT8_C(1));
    header = expected_unchanged;
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_protocol_header_decode(wire, sizeof(wire), &header, &issue);
    actual_errno = errno;
    failures +=
        expect_result("header decode invalid header length result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("header decode invalid header length issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_INVALID_HEADER_LENGTH);
    failures +=
        expect_errno_value("header decode invalid header length errno", actual_errno, EACCES);
    failures += expect_header("header decode invalid header length output keep", &header,
                              &expected_unchanged);

    memcpy(wire, valid_wire, sizeof(wire));
    wire[VIREO_PROTOCOL_BODY_LENGTH_OFFSET] = UINT8_C(0x01);
    wire[VIREO_PROTOCOL_BODY_LENGTH_OFFSET + UINT8_C(1)] = UINT8_C(0x00);
    wire[VIREO_PROTOCOL_BODY_LENGTH_OFFSET + UINT8_C(2)] = UINT8_C(0x00);
    wire[VIREO_PROTOCOL_BODY_LENGTH_OFFSET + UINT8_C(3)] = UINT8_C(0x01);
    header = expected_unchanged;
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_protocol_header_decode(wire, sizeof(wire), &header, &issue);
    actual_errno = errno;

    failures += expect_result("header decode oversized body result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("header decode oversized body issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_BODY_TOO_LARGE);
    failures += expect_errno_value("header decode oversized body errno", actual_errno, EACCES);
    failures +=
        expect_header("header decode oversized body output keep", &header, &expected_unchanged);

    return failures;
}

/* 验证 header decode 接收恰好等于 body 硬上限的值 */
static int test_header_decode_max_body_boundary(void) {
    static uint8_t const wire[VIREO_PROTOCOL_HEADER_SIZE] = {
        0x56, 0x49, 0x52, 0x45, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    vireo_protocol_header_t header = {0};
    vireo_protocol_codec_issue_t issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    vireo_result_t result = vireo_protocol_header_decode(wire, sizeof(wire), &header, &issue);
    int actual_errno = errno;

    int failures = expect_result("header decode max body result", result, VIREO_OK);
    failures +=
        expect_issue("header decode max body issue", issue, VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    failures += expect_errno_value("header decode max body errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures += expect_u32("header decode max body length", header.body_len,
                               VIREO_PROTOCOL_MAX_BODY_SIZE);
    }

    return failures;
}

/* 验证合法请求 header 和 request validator 的空指针契约 */
static int test_request_header_validate_success_and_invalid_arguments(void) {
    vireo_protocol_header_t header = make_valid_request_header();
    vireo_protocol_codec_issue_t issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    vireo_result_t result = vireo_protocol_request_header_validate(&header, &issue);
    int actual_errno = errno;

    int failures = expect_result("request validate success result", result, VIREO_OK);
    failures +=
        expect_issue("request validate success issue", issue, VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    failures += expect_errno_value("request validate success errno", actual_errno, EACCES);

    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_protocol_request_header_validate(NULL, &issue);
    actual_errno = errno;

    failures +=
        expect_result("request validate null header result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures +=
        expect_issue("request validate null header issue", issue, VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    failures += expect_errno_value("request validate null header errno", actual_errno, EACCES);

    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_protocol_request_header_validate(&header, NULL);
    actual_errno = errno;

    failures +=
        expect_result("request validate null issue result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_errno_value("request validate null issue errno", actual_errno, EACCES);

    return failures;
}

/* 验证 request validator 的公共基础规则 */
static int test_request_header_validate_common_rules(void) {
    vireo_protocol_header_t header = make_valid_request_header();
    vireo_protocol_codec_issue_t issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    // 1. 将 body_len 的值设置成所允许的最大值
    header.body_len = VIREO_PROTOCOL_MAX_BODY_SIZE;

    errno = EACCES;
    vireo_result_t result = vireo_protocol_request_header_validate(&header, &issue);
    int actual_errno = errno;

    int failures = expect_result("request validate max body result", result, VIREO_OK);
    failures +=
        expect_issue("request validate max body issue", issue, VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    failures += expect_errno_value("request validate max body errno", actual_errno, EACCES);

    header = make_valid_request_header();
    // 2. 将 body_len 的值设置成所允许的最大值 + 1
    header.body_len = VIREO_PROTOCOL_MAX_BODY_SIZE + UINT32_C(1);
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_protocol_request_header_validate(&header, &issue);
    actual_errno = errno;

    failures +=
        expect_result("request validate oversized body result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("request validate oversized body issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_BODY_TOO_LARGE);
    failures += expect_errno_value("request validate oversized body errno", actual_errno, EACCES);

    header = make_valid_request_header();
    // 3. 将 flags 设置为未知值
    header.flags = UINT16_C(0x0040);
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_protocol_request_header_validate(&header, &issue);
    actual_errno = errno;

    failures +=
        expect_result("request validate unknown flags result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("request validate unknown flags issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_FLAGS);
    failures += expect_errno_value("request validate unknown flags errno", actual_errno, EACCES);

    header = make_valid_request_header();
    // 4. 将 command 设置为保留命令
    header.command = VIREO_COMMAND_STORAGE_PUT_RESERVED_FIRST;
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_protocol_request_header_validate(&header, &issue);
    actual_errno = errno;

    failures +=
        expect_result("request validate reserved command result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("request validate reserved command issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_RESERVED_COMMAND);
    failures += expect_errno_value("request validate reserved command errno", actual_errno, EACCES);

    header = make_valid_request_header();
    // 5. 将 command 设置为未知命令
    header.command = UINT16_C(0xFFFF);
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_protocol_request_header_validate(&header, &issue);
    actual_errno = errno;

    failures +=
        expect_result("request validate unknown command result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("request validate unknown command issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_COMMAND);
    failures += expect_errno_value("request validate unknown command errno", actual_errno, EACCES);

    header = make_valid_request_header();
    // 6. 将 sequence 设置为 VIREO_PROTOCOL_SEQUENCE_NONE
    header.sequence = VIREO_PROTOCOL_SEQUENCE_NONE;
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_protocol_request_header_validate(&header, &issue);
    actual_errno = errno;

    failures +=
        expect_result("request validate invalid sequence result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("request validate invalid sequence issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_INVALID_SEQUENCE);
    failures += expect_errno_value("request validate invalid sequence errno", actual_errno, EACCES);

    return failures;
}

/* 验证request validator 的请求专属规则 */
static int test_request_header_validate_request_specific_rules(void) {
    vireo_protocol_header_t header = make_valid_request_header();
    vireo_protocol_codec_issue_t issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    // 1. 将 flags 设置为 response
    header.flags = VIREO_PROTOCOL_FLAG_RESPONSE;

    errno = EACCES;
    vireo_result_t result = vireo_protocol_request_header_validate(&header, &issue);
    int actual_errno = errno;

    int failures =
        expect_result("request validate response flag result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("request validate response flag issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_REQUEST_HAS_RESPONSE_FLAG);
    failures += expect_errno_value("request validate response flag errno", actual_errno, EACCES);

    header = make_valid_request_header();
    // 2. 将 flags 设置为响应数据包才可设置的值
    header.flags = VIREO_PROTOCOL_FLAG_MORE;
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_protocol_request_header_validate(&header, &issue);
    actual_errno = errno;

    failures += expect_result("request validate more flag result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("request validate more flag issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_REQUEST_HAS_MORE_FLAG);
    failures += expect_errno_value("request validate more flag errno", actual_errno, EACCES);

    header = make_valid_request_header();
    // 3. 将 status 设置为响应数据包才可设置的值
    header.status = VIREO_STATUS_ACCEPTED;
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_protocol_request_header_validate(&header, &issue);
    actual_errno = errno;

    failures +=
        expect_result("request validate invalid status result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("request validate invalid status issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_INVALID_REQUEST_STATUS);
    failures += expect_errno_value("request validate invalid status errno", actual_errno, EACCES);

    return failures;
}

/* 验证合法响应 header 和 response validator 的空指针契约 */
static int test_response_header_validate_success_and_invalid_arguments(void) {
    vireo_protocol_header_t header = make_valid_response_header();
    vireo_protocol_codec_issue_t issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    vireo_result_t result = vireo_protocol_response_header_validate(&header, &issue);
    int actual_errno = errno;

    int failures = expect_result("response validate success result", result, VIREO_OK);
    failures +=
        expect_issue("response validate success issue", issue, VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    failures += expect_errno_value("response validate success errno", actual_errno, EACCES);

    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;
    errno = EACCES;
    result = vireo_protocol_response_header_validate(NULL, &issue);
    actual_errno = errno;
    failures += expect_result("response validate null header result", result,
                              VIREO_RESULT_INVALID_ARGUMENT);
    failures +=
        expect_issue("response validate null header issue", issue, VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    failures += expect_errno_value("response validate null header errno", actual_errno, EACCES);

    errno = EACCES;
    result = vireo_protocol_response_header_validate(&header, NULL);
    actual_errno = errno;

    failures +=
        expect_result("response validate null issue result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_errno_value("response validate null issue errno", actual_errno, EACCES);

    return failures;
}

/* 验证 response validator 的公共基础规则 */
static int test_response_header_validate_common_rules(void) {
    vireo_protocol_header_t header = make_valid_response_header();
    vireo_protocol_codec_issue_t issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    // 设置当前响应数据包的最大 body 长度为 VIREO_PROTOCOL_MAX_BODY_SIZE
    header.body_len = VIREO_PROTOCOL_MAX_BODY_SIZE;

    errno = EACCES;
    vireo_result_t result = vireo_protocol_response_header_validate(&header, &issue);
    int actual_errno = errno;

    int failures = expect_result("response validate max body result", result, VIREO_OK);
    failures +=
        expect_issue("response validate max body issue", issue, VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    failures += expect_errno_value("response validate max body errno", actual_errno, EACCES);

    header = make_valid_response_header();
    // 设置当前响应数据包的 body 长度超过硬上限 1 字节  VIREO_PROTOCOL_MAX_BODY_SIZE + UINT32_C(1)
    header.body_len = VIREO_PROTOCOL_MAX_BODY_SIZE + UINT32_C(1);
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;
    errno = EACCES;
    result = vireo_protocol_response_header_validate(&header, &issue);
    actual_errno = errno;

    failures +=
        expect_result("response validate oversized body result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("response validate oversized body issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_BODY_TOO_LARGE);
    failures += expect_errno_value("response validate oversized body errno", actual_errno, EACCES);

    header = make_valid_response_header();
    // 设置当前响应数据包的 flag 为未知的 flag
    header.flags |= UINT16_C(0x0040);
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;
    errno = EACCES;
    result = vireo_protocol_response_header_validate(&header, &issue);
    actual_errno = errno;

    failures +=
        expect_result("response validate unknown flags result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("response validate unknown flags issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_FLAGS);
    failures += expect_errno_value("response validate unknown flags errno", actual_errno, EACCES);

    header = make_valid_response_header();
    // 设置当前响应数据包的 command 为保留命令
    header.command = VIREO_COMMAND_STORAGE_PUT_RESERVED_FIRST;
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_protocol_response_header_validate(&header, &issue);
    actual_errno = errno;

    failures +=
        expect_result("response validate reserved command result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("response validate reserved command issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_RESERVED_COMMAND);
    failures +=
        expect_errno_value("response validate reserved command errno", actual_errno, EACCES);

    header = make_valid_response_header();
    // 设置当前响应数据包的 command 为未知命令
    header.command = UINT16_C(0xFFFF);
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_protocol_response_header_validate(&header, &issue);
    actual_errno = errno;

    failures +=
        expect_result("response validate unknown command result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("response validate unknown command issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_COMMAND);
    failures += expect_errno_value("response validate unknown command errno", actual_errno, EACCES);

    header = make_valid_response_header();
    // 设置当前响应数据包的 sequence 为 NONE
    header.sequence = VIREO_PROTOCOL_SEQUENCE_NONE;
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_protocol_response_header_validate(&header, &issue);
    actual_errno = errno;

    failures +=
        expect_result("response validate invalid sequence result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("response validate invalid sequence issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_INVALID_SEQUENCE);
    failures +=
        expect_errno_value("response validate invalid sequence errno", actual_errno, EACCES);

    return failures;
}

/* 验证 response validator 的响应专属规则 */
static int test_response_header_validate_response_specific_rules(void) {
    vireo_protocol_header_t header = make_valid_response_header();
    vireo_protocol_codec_issue_t issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    // 设置当前响应数据包的 flag 为 0，无 response
    header.flags = UINT16_C(0);

    errno = EACCES;
    vireo_result_t result = vireo_protocol_response_header_validate(&header, &issue);
    int actual_errno = errno;

    int failures = expect_result("response validate missing response flag result", result,
                                 VIREO_RESULT_PROTOCOL);
    failures += expect_issue("response validate missing response flag issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_RESPONSE_MISSING_RESPONSE_FLAG);
    failures +=
        expect_errno_value("response validate missing response flag errno", actual_errno, EACCES);

    header = make_valid_response_header();
    // 设置当前响应数据包中的 flag 带有 more flag
    header.flags |= VIREO_PROTOCOL_FLAG_MORE;
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_protocol_response_header_validate(&header, &issue);
    actual_errno = errno;

    failures += expect_result("response validate more flag result", result, VIREO_OK);
    failures +=
        expect_issue("response validate more flag issue", issue, VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    failures += expect_errno_value("response validate more flag errno", actual_errno, EACCES);

    header = make_valid_response_header();
    // 设置当前响应数据包中的 status 为未知状态
    header.status = UINT16_C(0xFFFF);
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_protocol_response_header_validate(&header, &issue);
    actual_errno = errno;

    failures +=
        expect_result("response validate unknown status result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("response validate unknown status issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_RESPONSE_STATUS);
    failures += expect_errno_value("response validate unknown status errno", actual_errno, EACCES);

    return failures;
}

/* 验证固定 wire header 和 body 的确定性 CRC-32C golden vector */
static int test_frame_crc32c_calculate_golden(void) {
    static uint8_t const wire[VIREO_PROTOCOL_HEADER_SIZE] = {
        0x56, 0x49, 0x52, 0x45, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x09, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
    };

    static uint8_t const body[] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
    };

    uint32_t crc32c = UINT32_C(0xA5A5A5A5);

    errno = EACCES;
    vireo_result_t result =
        vireo_protocol_frame_crc32c_calculate(wire, sizeof(wire), body, sizeof(body), &crc32c);
    int actual_errno = errno;

    int failures = expect_result("frame crc32c calculate golden result", result, VIREO_OK);
    failures += expect_errno_value("frame crc32c calculate golden errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures += expect_u32("frame crc32c calculate golden value", crc32c, UINT32_C(0x27F8872E));
    }

    return failures;
}

/* 验证frame CRC-32C calculate 的非法参数和失败输出保持 */
static int test_frame_crc32c_calculate_invalid_arguments(void) {
    static uint8_t const wire[VIREO_PROTOCOL_HEADER_SIZE] = {
        0x56, 0x49, 0x52, 0x45, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    static uint8_t const body[] = {0xA5};

    uint32_t const expected_unchanged = UINT32_C(0xA5A5A5A5);
    uint32_t crc32c = expected_unchanged;

    errno = EACCES;
    vireo_result_t result =
        vireo_protocol_frame_crc32c_calculate(NULL, sizeof(wire), body, sizeof(body), &crc32c);
    int actual_errno = errno;

    int failures = expect_result("frame crc32c calculate null wire result", result,
                                 VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_errno_value("frame crc32c calculate null wire errno", actual_errno, EACCES);
    failures +=
        expect_u32("frame crc32c calculate null wire output keep", crc32c, expected_unchanged);

    crc32c = expected_unchanged;
    errno = EACCES;
    result = vireo_protocol_frame_crc32c_calculate(wire, sizeof(wire), NULL, sizeof(body), &crc32c);
    actual_errno = errno;

    failures += expect_result("frame crc32c calculate null body result", result,
                              VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_errno_value("frame crc32c calculate null body errno", actual_errno, EACCES);
    failures +=
        expect_u32("frame crc32c calculate null body output keep", crc32c, expected_unchanged);

    errno = EACCES;
    result = vireo_protocol_frame_crc32c_calculate(wire, sizeof(wire), body, sizeof(body), NULL);
    actual_errno = errno;

    failures += expect_result("frame crc32c calculate null output result", result,
                              VIREO_RESULT_INVALID_ARGUMENT);
    failures +=
        expect_errno_value("frame crc32c calculate null output errno", actual_errno, EACCES);

    return failures;
}

/* 验证frame CRC-32C calculate 的范围错误和失败输出保持 */
static int test_frame_crc32c_calculate_range_errors(void) {
    static uint8_t const wire[VIREO_PROTOCOL_HEADER_SIZE] = {
        0x56, 0x49, 0x52, 0x45, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    static uint8_t const body[] = {
        0xA5,
    };

    uint32_t const expected_unchanged = UINT32_C(0xA5A5A5A5);
    uint32_t crc32c = expected_unchanged;

    errno = EACCES;
    vireo_result_t result = vireo_protocol_frame_crc32c_calculate(
        wire, (size_t)VIREO_PROTOCOL_HEADER_SIZE - 1U, body, sizeof(body), &crc32c);
    int actual_errno = errno;

    int failures =
        expect_result("frame crc32c calculate short wire result", result, VIREO_RESULT_RANGE);
    failures += expect_errno_value("frame crc32c calculate short wire errno", actual_errno, EACCES);
    failures +=
        expect_u32("frame crc32c calculate short wire output keep", crc32c, expected_unchanged);

    crc32c = expected_unchanged;
    errno = EACCES;
    result = vireo_protocol_frame_crc32c_calculate(
        wire, sizeof(wire), body, (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE + 1U, &crc32c);
    actual_errno = errno;

    failures +=
        expect_result("frame crc32c calculate oversized body result", result, VIREO_RESULT_RANGE);
    failures +=
        expect_errno_value("frame crc32c calculate oversized body errno", actual_errno, EACCES);
    failures +=
        expect_u32("frame crc32c calculate oversized body output keep", crc32c, expected_unchanged);

    crc32c = expected_unchanged;
    errno = EACCES;
    result = vireo_protocol_frame_crc32c_calculate(wire, sizeof(wire), body, (size_t)0, &crc32c);
    actual_errno = errno;

    failures += expect_result("frame crc32c calculate body length mismatch result", result,
                              VIREO_RESULT_RANGE);
    failures += expect_errno_value("frame crc32c calculate body length mismatch errno",
                                   actual_errno, EACCES);
    failures += expect_u32("frame crc32c calculate body length mismatch output keep", crc32c,
                           expected_unchanged);

    return failures;
}

/* 验证 body 为空时的确定性 frame CRC-32C golden vector */
static int test_frame_crc32c_calculate_empty_body(void) {
    static uint8_t const wire[VIREO_PROTOCOL_HEADER_SIZE] = {
        0x56, 0x49, 0x52, 0x45, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
    };

    uint32_t crc32c = UINT32_C(0xA5A5A5A5);

    errno = EACCES;
    vireo_result_t result =
        vireo_protocol_frame_crc32c_calculate(wire, sizeof(wire), NULL, (size_t)0, &crc32c);
    int actual_errno = errno;

    int failures = expect_result("frame crc32c calculate empty body result", result, VIREO_OK);
    failures += expect_errno_value("frame crc32c calculate empty body errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures +=
            expect_u32("frame crc32c calculate empty body value", crc32c, UINT32_C(0x7B0E0D25));
    }

    return failures;
}

/* 验证 stored CRC 字段不参与 frame CRC-32C 计算 */
static int test_frame_crc32c_calculate_excludes_stored_crc(void) {
    static uint8_t const wire_zero_crc[VIREO_PROTOCOL_HEADER_SIZE] = {
        0x56, 0x49, 0x52, 0x45, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    static uint8_t const wire_nonzero_crc[VIREO_PROTOCOL_HEADER_SIZE] = {
        0x56, 0x49, 0x52, 0x45, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
    };

    static uint8_t const body[] = {
        0xA5,
    };

    uint32_t crc_zero = UINT32_C(0x11111111);
    uint32_t crc_nonzero = UINT32_C(0x22222222);

    errno = EACCES;
    vireo_result_t nonzero_result = vireo_protocol_frame_crc32c_calculate(
        wire_nonzero_crc, sizeof(wire_nonzero_crc), body, sizeof(body), &crc_nonzero);
    int nonzero_errno = errno;

    errno = EACCES;
    vireo_result_t zero_result = vireo_protocol_frame_crc32c_calculate(
        wire_zero_crc, sizeof(wire_zero_crc), body, sizeof(body), &crc_zero);
    int zero_errno = errno;

    int failures = expect_result("frame crc32c zero stored crc result", zero_result, VIREO_OK);
    failures += expect_errno_value("frame crc32c zero stored crc errno", zero_errno, EACCES);

    failures += expect_result("frame crc32c nonzero stored crc result", nonzero_result, VIREO_OK);
    failures += expect_errno_value("frame crc32c nonzero stored crc errno", nonzero_errno, EACCES);

    if (zero_result == VIREO_OK && nonzero_result == VIREO_OK) {
        failures += expect_u32("frame crc32c excludes stored crc", crc_nonzero, crc_zero);
    }

    return failures;
}

/* 验证 frame CRC-32C verify 的成功路径和 body 变异 mismatch */
static int test_frame_crc32c_verify_success_and_mismatch(void) {
    static uint8_t const wire[VIREO_PROTOCOL_HEADER_SIZE] = {
        0x56, 0x49, 0x52, 0x45, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x09, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x27, 0xF8, 0x87, 0x2E,
    };

    static uint8_t const empty_body_wire[VIREO_PROTOCOL_HEADER_SIZE] = {
        0x56, 0x49, 0x52, 0x45, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7B, 0x0E, 0x0D, 0x25,
    };
    static uint8_t const body[] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
    };

    static uint8_t const modified_body[] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x38,
    };

    vireo_protocol_codec_issue_t issue = VIREO_PROTOCOL_CODEC_ISSUE_BODY_TOO_LARGE;
    errno = EACCES;
    vireo_result_t result =
        vireo_protocol_frame_crc32c_verify(wire, sizeof(wire), body, sizeof(body), &issue);
    int actual_errno = errno;

    int failures = expect_result("frame crc32c verify success result", result, VIREO_OK);
    failures +=
        expect_issue("frame crc32c verify success issue", issue, VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    failures += expect_errno_value("frame crc32c verify success errno", actual_errno, EACCES);

    issue = VIREO_PROTOCOL_CODEC_ISSUE_BODY_TOO_LARGE;
    errno = EACCES;
    result = vireo_protocol_frame_crc32c_verify(empty_body_wire, sizeof(empty_body_wire), NULL,
                                                (size_t)0, &issue);
    actual_errno = errno;

    failures += expect_result("frame crc32c verify empty body result", result, VIREO_OK);
    failures += expect_issue("frame crc32c verify empty body issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    failures += expect_errno_value("frame crc32c verify empty body errno", actual_errno, EACCES);

    issue = VIREO_PROTOCOL_CODEC_ISSUE_BODY_TOO_LARGE;
    errno = EACCES;
    result = vireo_protocol_frame_crc32c_verify(wire, sizeof(wire), modified_body,
                                                sizeof(modified_body), &issue);
    actual_errno = errno;

    failures += expect_result("frame crc32c verify mismatch result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("frame crc32c verify mismatch issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH);
    failures += expect_errno_value("frame crc32c verify mismatch errno", actual_errno, EACCES);

    return failures;
}

/* 验证 frame CRC-32C verify 的非法参数契约 */
static int test_frame_crc32c_verify_invalid_arguments(void) {
    static uint8_t const wire[VIREO_PROTOCOL_HEADER_SIZE] = {
        0x56, 0x49, 0x52, 0x45, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    static uint8_t const body[] = {
        0xA5,
    };

    vireo_protocol_codec_issue_t issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;
    errno = EACCES;
    vireo_result_t result =
        vireo_protocol_frame_crc32c_verify(NULL, sizeof(wire), body, sizeof(body), &issue);
    int actual_errno = errno;

    int failures = expect_result("frame crc32c verify null wire result", result,
                                 VIREO_RESULT_INVALID_ARGUMENT);
    failures +=
        expect_issue("frame crc32c verify null wire issue", issue, VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    failures += expect_errno_value("frame crc32c verify null wire errno", actual_errno, EACCES);

    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;
    errno = EACCES;
    result = vireo_protocol_frame_crc32c_verify(wire, sizeof(wire), NULL, sizeof(body), &issue);
    actual_errno = errno;

    failures += expect_result("frame crc32c verify null body result", result,
                              VIREO_RESULT_INVALID_ARGUMENT);
    failures +=
        expect_issue("frame crc32c verify null body issue", issue, VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    failures += expect_errno_value("frame crc32c verify null body errno", actual_errno, EACCES);

    errno = EACCES;
    result = vireo_protocol_frame_crc32c_verify(wire, sizeof(wire), body, sizeof(body), NULL);
    actual_errno = errno;

    failures += expect_result("frame crc32c verify null issue result", result,
                              VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_errno_value("frame crc32c verify null issue errno", actual_errno, EACCES);

    return failures;
}

/* 验证 frame CRC-32C verify 的范围错误 */
static int test_frame_crc32c_verify_range_errors(void) {
    static uint8_t const wire[VIREO_PROTOCOL_HEADER_SIZE] = {
        0x56, 0x49, 0x52, 0x45, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    static uint8_t const body[] = {
        0xA5,
    };

    vireo_protocol_codec_issue_t issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;
    errno = EACCES;
    vireo_result_t result = vireo_protocol_frame_crc32c_verify(
        wire, (size_t)VIREO_PROTOCOL_HEADER_SIZE - 1U, body, sizeof(body), &issue);
    int actual_errno = errno;

    int failures =
        expect_result("frame crc32c verify short wire result", result, VIREO_RESULT_RANGE);
    failures += expect_issue("frame crc32c verify short wire issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    failures += expect_errno_value("frame crc32c verify short wire errno", actual_errno, EACCES);

    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;
    errno = EACCES;
    result = vireo_protocol_frame_crc32c_verify(wire, sizeof(wire), body,
                                                (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE + 1U, &issue);
    actual_errno = errno;

    failures +=
        expect_result("frame crc32c verify oversized body result", result, VIREO_RESULT_RANGE);
    failures += expect_issue("frame crc32c verify oversized body issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    failures +=
        expect_errno_value("frame crc32c verify oversized body errno", actual_errno, EACCES);

    errno = EACCES;
    issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;
    result = vireo_protocol_frame_crc32c_verify(wire, sizeof(wire), body, (size_t)0, &issue);
    actual_errno = errno;

    failures += expect_result("frame crc32c verify body length mismatch result", result,
                              VIREO_RESULT_RANGE);
    failures += expect_issue("frame crc32c verify body length mismatch issue", issue,
                             VIREO_PROTOCOL_CODEC_ISSUE_BODY_LENGTH_MISMATCH);
    failures +=
        expect_errno_value("frame crc32c verify body length mismatch errno", actual_errno, EACCES);

    return failures;
}

int main(void) {
    typedef int (*test_function_t)(void);

    static test_function_t const tests[] = {
        test_header_encode_golden,
        test_header_encode_invalid_arguments,
        test_header_encode_range_boundaries,
        test_header_encode_larger_capacity_tail_keep,

        test_header_decode_golden,
        test_header_decode_invalid_arguments,
        test_header_decode_wire_size_boundaries,
        test_header_decode_invalid_framing,
        test_header_decode_max_body_boundary,

        test_request_header_validate_success_and_invalid_arguments,
        test_request_header_validate_common_rules,
        test_request_header_validate_request_specific_rules,

        test_response_header_validate_success_and_invalid_arguments,
        test_response_header_validate_common_rules,
        test_response_header_validate_response_specific_rules,

        test_frame_crc32c_calculate_golden,
        test_frame_crc32c_calculate_invalid_arguments,
        test_frame_crc32c_calculate_range_errors,
        test_frame_crc32c_calculate_empty_body,
        test_frame_crc32c_calculate_excludes_stored_crc,

        test_frame_crc32c_verify_success_and_mismatch,
        test_frame_crc32c_verify_invalid_arguments,
        test_frame_crc32c_verify_range_errors,
    };

    int failures = 0;

    for (size_t index = 0; index < VIREO_TEST_ARRAY_COUNT(tests); ++index) {
        failures += tests[index]();
    }

    if (failures != 0) {
        fprintf(stderr, "test_codec: %d assertion failure(s)\n", failures);
        return EXIT_FAILURE;
    }

    printf("test_codec: all %zu test groups passed\n", VIREO_TEST_ARRAY_COUNT(tests));

    return EXIT_SUCCESS;
}

/*
 * PROJECT : VIREO
 * FILE    : test_tlv.c
 * AUTHOR  : bitofux
 * DATE    : 2026-09-23
 * BRIEF   : 测试通用 tlv writer、reader、整数读取与 schema 验证
 *
 * -- 使用独立写出的确定性 wire 字节验证编码结果
 * -- 验证正常路径、长度边界、截断、错误分类和输出保持
 * -- 验证 UTF-8 与 NAME 的不同规则
 * -- 验证公共接口保持 errno
 */

#include <vireo/protocol/tlv.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vireo/base/result.h>

#define VIREO_TEST_ARRAY_COUNT(array) (sizeof(array) / sizeof((array)[0]))

_Static_assert(CHAR_BIT == 8, "TLV tests require 8-bit bytes");
_Static_assert(VIREO_TLV_TYPE_OFFSET == UINT32_C(0), "unexpected type offset");
_Static_assert(VIREO_TLV_LENGTH_OFFSET == UINT32_C(2), "unexpected length offset");
_Static_assert(VIREO_TLV_HEADER_SIZE == UINT32_C(4), "unexpected TLV header size");
_Static_assert(VIREO_TLV_MAX_VALUE_SIZE == UINT32_C(65535), "unexpected TLV value limit");

/* 比较函数返回值，并在失败时指出测试用例 */
static int expect_result(char const *case_name, vireo_result_t actual, vireo_result_t expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected result %d, got %d\n", case_name, (int)expected, (int)actual);
    return 1;
}

/* 比较具体 TLV issue */
static int expect_issue(char const *case_name, vireo_tlv_issue_t actual,
                        vireo_tlv_issue_t expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected issue %d, got %d\n", case_name, (int)expected, (int)actual);
    return 1;
}

/* 比较 size_t 数值 */
static int expect_size(char const *case_name, size_t actual, size_t expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected size %zu, got %zu\n", case_name, expected, actual);
    return 1;
}

/* 比较一个明确的条件 */
static int expect_true(char const *case_name, bool condition) {
    if (condition) {
        return 0;
    }

    fprintf(stderr, "%s: condition failed\n", case_name);
    return 1;
}

/* 比较两个有明确长度的字节区域 */
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

/*
 * 执行一个 schema 用例。
 * expected_seen 为 NULL 时，不检查工作空间的前 rule_count 字节；
 * 无论结果如何，都检查其余字节未被修改。
 */
static int expect_schema_case(char const *case_name, uint8_t const *data, size_t size,
                              vireo_tlv_rule_t const *rules, size_t rule_count,
                              vireo_tlv_unknown_policy_t policy, vireo_result_t expected_result,
                              vireo_tlv_issue_t expected_issue, uint8_t const *expected_seen) {
    uint8_t seen[4];
    memset(seen, 0xA5, sizeof(seen));

    if (rule_count > sizeof(seen)) {
        fprintf(stderr, "%s: test setup exceeds seen capacity\n", case_name);
        return 1;
    }

    vireo_tlv_issue_t issue = VIREO_TLV_ISSUE_INVALID_NAME;

    errno = EACCES;
    vireo_result_t const result = vireo_tlv_schema_validate(data, size, rules, rule_count, policy,
                                                            seen, sizeof(seen), &issue);
    int const actual_errno = errno;

    int failures = expect_result(case_name, result, expected_result);
    failures += expect_issue(case_name, issue, expected_issue);
    failures += expect_true(case_name, actual_errno == EACCES);

    if (expected_seen != NULL && rule_count != 0U) {
        failures += expect_bytes(case_name, seen, expected_seen, rule_count);
    }

    for (size_t index = rule_count; index < sizeof(seen); ++index) {
        failures += expect_true(case_name, seen[index] == UINT8_C(0xA5));
    }

    return failures;
}

/* 验证 writer 初始化及失败时的输出保持 */
static int test_writer_init(void) {
    uint8_t buffer[8];
    memset(buffer, 0xA5, sizeof(buffer));

    vireo_tlv_writer_t writer = {
        .data = buffer,
        .capacity = 3U,
        .used = 2U,
    };

    errno = EACCES;
    vireo_result_t result = vireo_tlv_writer_init(NULL, buffer, sizeof(buffer));
    int actual_errno = errno;

    int failures = expect_result("writer init null output", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_true("writer init null output errno", actual_errno == EACCES);

    errno = EACCES;
    result = vireo_tlv_writer_init(&writer, NULL, 1U);
    actual_errno = errno;

    failures += expect_result("writer init null data", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_true("writer init null data errno", actual_errno == EACCES);
    failures += expect_true("writer init failure keeps data", writer.data == buffer);
    failures += expect_size("writer init failure keeps capacity", writer.capacity, 3U);
    failures += expect_size("writer init failure keeps used", writer.used, 2U);

    errno = EACCES;
    result = vireo_tlv_writer_init(&writer, NULL, 0U);
    actual_errno = errno;

    failures += expect_result("writer init empty", result, VIREO_OK);
    failures += expect_true("writer init empty errno", actual_errno == EACCES);
    failures += expect_true("writer init empty data", writer.data == NULL);
    failures += expect_size("writer init empty capacity", writer.capacity, 0U);
    failures += expect_size("writer init empty used", writer.used, 0U);

    errno = EACCES;
    result = vireo_tlv_writer_init(&writer, buffer, sizeof(buffer));
    actual_errno = errno;

    failures += expect_result("writer init buffer", result, VIREO_OK);
    failures += expect_true("writer init buffer errno", actual_errno == EACCES);
    failures += expect_true("writer init borrows buffer", writer.data == buffer);
    failures += expect_size("writer init buffer capacity", writer.capacity, sizeof(buffer));
    failures += expect_size("writer init buffer used", writer.used, 0U);

    for (size_t index = 0; index < sizeof(buffer); ++index) {
        failures +=
            expect_true("writer init does not clear buffer", buffer[index] == UINT8_C(0xA5));
    }

    return failures;
}

/* 验证空 value、U16、U32、U64 顺序追加后的确定性字节 */
static int test_writer_golden(void) {
    static uint8_t const expected[] = {
        0x12, 0x34, 0x00, 0x00, 0x10, 0x01, 0x00, 0x02, 0xAB, 0xCD, 0x10,
        0x02, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44, 0x10, 0x03, 0x00, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xA5,
    };

    uint8_t buffer[sizeof(expected)];
    memset(buffer, 0xA5, sizeof(buffer));

    vireo_tlv_writer_t writer = {0};
    int failures = expect_result("writer golden init",
                                 vireo_tlv_writer_init(&writer, buffer, sizeof(buffer)), VIREO_OK);

    errno = EACCES;
    vireo_result_t result = vireo_tlv_writer_put(&writer, UINT16_C(0x1234), NULL, 0U);
    int actual_errno = errno;
    failures += expect_result("writer golden empty value", result, VIREO_OK);
    failures += expect_true("writer golden empty errno", actual_errno == EACCES);

    errno = EACCES;
    result = vireo_tlv_writer_put_u16(&writer, UINT16_C(0x1001), UINT16_C(0xABCD));
    actual_errno = errno;
    failures += expect_result("writer golden u16", result, VIREO_OK);
    failures += expect_true("writer golden u16 errno", actual_errno == EACCES);

    errno = EACCES;
    result = vireo_tlv_writer_put_u32(&writer, UINT16_C(0x1002), UINT32_C(0x11223344));
    actual_errno = errno;
    failures += expect_result("writer golden u32", result, VIREO_OK);
    failures += expect_true("writer golden u32 errno", actual_errno == EACCES);

    errno = EACCES;
    result = vireo_tlv_writer_put_u64(&writer, UINT16_C(0x1003), UINT64_C(0x0102030405060708));
    actual_errno = errno;
    failures += expect_result("writer golden u64", result, VIREO_OK);
    failures += expect_true("writer golden u64 errno", actual_errno == EACCES);

    failures += expect_size("writer golden used", writer.used, sizeof(expected) - 1U);
    failures +=
        expect_bytes("writer golden bytes including tail", buffer, expected, sizeof(expected));

    return failures;
}

/* 验证 writer 参数、长度、容量失败时不修改已有输出 */
static int test_writer_failures(void) {
    static uint8_t const large_value[VIREO_TLV_MAX_VALUE_SIZE + 1U] = {0};

    uint8_t buffer[8];
    uint8_t snapshot[8];
    uint8_t const one[] = {0x5A};

    memset(buffer, 0xA5, sizeof(buffer));

    vireo_tlv_writer_t writer = {0};
    int failures = expect_result("writer failures init",
                                 vireo_tlv_writer_init(&writer, buffer, sizeof(buffer)), VIREO_OK);

    failures +=
        expect_result("writer failures first append",
                      vireo_tlv_writer_put(&writer, UINT16_C(1), one, sizeof(one)), VIREO_OK);

    memcpy(snapshot, buffer, sizeof(snapshot));
    size_t const saved_used = writer.used;

    errno = EACCES;
    vireo_result_t result = vireo_tlv_writer_put(&writer, UINT16_C(2), NULL, 1U);
    int actual_errno = errno;

    failures += expect_result("writer null nonempty value", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_true("writer null value errno", actual_errno == EACCES);
    failures += expect_size("writer null value keeps used", writer.used, saved_used);
    failures += expect_bytes("writer null value keeps bytes", buffer, snapshot, sizeof(buffer));

    uint8_t const four[] = {1, 2, 3, 4};

    result = vireo_tlv_writer_put(&writer, UINT16_C(2), four, sizeof(four));
    failures += expect_result("writer insufficient capacity", result, VIREO_RESULT_RANGE);
    failures += expect_size("writer capacity keeps used", writer.used, saved_used);
    failures += expect_bytes("writer capacity keeps bytes", buffer, snapshot, sizeof(buffer));

    result = vireo_tlv_writer_put(&writer, UINT16_C(2), large_value, sizeof(large_value));
    failures += expect_result("writer oversized value", result, VIREO_RESULT_RANGE);
    failures += expect_size("writer oversized keeps used", writer.used, saved_used);
    failures += expect_bytes("writer oversized keeps bytes", buffer, snapshot, sizeof(buffer));

    vireo_tlv_writer_t const invalid_writer = {
        .data = buffer,
        .capacity = sizeof(buffer),
        .used = sizeof(buffer) + 1U,
    };
    vireo_tlv_writer_t bad = invalid_writer;

    result = vireo_tlv_writer_put(&bad, UINT16_C(3), one, sizeof(one));
    failures += expect_result("writer invalid state", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_size("writer invalid state keeps used", bad.used, invalid_writer.used);
    failures += expect_bytes("writer invalid state keeps bytes", buffer, snapshot, sizeof(buffer));

    result = vireo_tlv_writer_put(NULL, UINT16_C(3), one, sizeof(one));
    failures += expect_result("writer null state", result, VIREO_RESULT_INVALID_ARGUMENT);

    return failures;
}

/* 验证单条 value 的 65535 字节硬边界 */
static int test_writer_max_value(void) {
    static uint8_t value[VIREO_TLV_MAX_VALUE_SIZE];
    static uint8_t buffer[VIREO_TLV_HEADER_SIZE + VIREO_TLV_MAX_VALUE_SIZE + 1U];

    memset(value, 0x5A, sizeof(value));
    memset(buffer, 0xA5, sizeof(buffer));

    vireo_tlv_writer_t writer = {0};
    int failures = expect_result("writer max init",
                                 vireo_tlv_writer_init(&writer, buffer, sizeof(buffer)), VIREO_OK);

    vireo_result_t const result =
        vireo_tlv_writer_put(&writer, UINT16_C(0x1234), value, sizeof(value));

    failures += expect_result("writer max append", result, VIREO_OK);
    failures +=
        expect_size("writer max used", writer.used, (size_t)VIREO_TLV_HEADER_SIZE + sizeof(value));

    static uint8_t const expected_header[] = {
        0x12,
        0x34,
        0xFF,
        0xFF,
    };
    failures += expect_bytes("writer max header", buffer, expected_header, sizeof(expected_header));
    failures +=
        expect_bytes("writer max payload", buffer + VIREO_TLV_HEADER_SIZE, value, sizeof(value));
    failures += expect_true("writer max keeps tail", buffer[sizeof(buffer) - 1U] == UINT8_C(0xA5));

    return failures;
}

/* 验证两条 TLV 的连续读取、借用地址与正常结束 */
static int test_reader_sequence(void) {
    static uint8_t const wire[] = {
        0x12, 0x34, 0x00, 0x02, 0xAA, 0xBB, 0x00, 0x01, 0x00, 0x00,
    };

    vireo_tlv_reader_t reader = {0};
    int failures = expect_result("reader sequence init",
                                 vireo_tlv_reader_init(&reader, wire, sizeof(wire)), VIREO_OK);

    vireo_tlv_view_t view = {0};
    vireo_tlv_issue_t issue = VIREO_TLV_ISSUE_INVALID_NAME;

    errno = EACCES;
    vireo_result_t result = vireo_tlv_reader_next(&reader, &view, &issue);
    int actual_errno = errno;

    failures += expect_result("reader first result", result, VIREO_OK);
    failures += expect_issue("reader first issue", issue, VIREO_TLV_ISSUE_NONE);
    failures += expect_true("reader first errno", actual_errno == EACCES);
    failures += expect_true("reader first type", view.type == UINT16_C(0x1234));
    failures += expect_size("reader first length", view.length, 2U);
    failures += expect_true("reader first borrowed pointer", view.value == wire + 4U);
    failures += expect_size("reader first offset", reader.offset, 6U);

    static uint8_t const first_value[] = {0xAA, 0xBB};
    if (result == VIREO_OK && view.value == wire + 4U && view.length == sizeof(first_value)) {
        failures +=
            expect_bytes("reader first value", view.value, first_value, sizeof(first_value));
    }

    issue = VIREO_TLV_ISSUE_INVALID_NAME;
    result = vireo_tlv_reader_next(&reader, &view, &issue);

    failures += expect_result("reader second result", result, VIREO_OK);
    failures += expect_issue("reader second issue", issue, VIREO_TLV_ISSUE_NONE);
    failures += expect_true("reader second type", view.type == UINT16_C(1));
    failures += expect_size("reader second length", view.length, 0U);
    failures += expect_true("reader empty value pointer", view.value == wire + sizeof(wire));
    failures += expect_size("reader second offset", reader.offset, sizeof(wire));

    vireo_tlv_view_t const saved_view = view;
    issue = VIREO_TLV_ISSUE_INVALID_NAME;
    result = vireo_tlv_reader_next(&reader, &view, &issue);

    failures += expect_result("reader end result", result, VIREO_RESULT_NOT_FOUND);
    failures += expect_issue("reader end issue", issue, VIREO_TLV_ISSUE_NONE);
    failures += expect_size("reader end keeps offset", reader.offset, sizeof(wire));
    failures += expect_true("reader end keeps view type", view.type == saved_view.type);
    failures += expect_true("reader end keeps view pointer", view.value == saved_view.value);
    failures += expect_size("reader end keeps view length", view.length, saved_view.length);

    return failures;
}

/* 验证 reader_init 错误参数，以及 reader_next 的截断诊断和关键输出保持 */
static int test_reader_failures(void) {
    static uint8_t const short_value[] = {
        0x12, 0x34, 0x00, 0x03, 0xAA, 0xBB,
    };
    static uint8_t const complete_then_tail[] = {
        0x00, 0x01, 0x00, 0x00, 0x7F,
    };

    vireo_tlv_reader_t reader = {0};
    int failures =
        expect_result("reader failures init",
                      vireo_tlv_reader_init(&reader, short_value, sizeof(short_value)), VIREO_OK);

    /* reader_init 参数错误时，不得修改已有 reader 状态 */
    vireo_tlv_reader_t init_probe = {
        .data = short_value,
        .size = sizeof(short_value),
        .offset = 2U,
    };

    errno = EACCES;
    vireo_result_t init_result = vireo_tlv_reader_init(NULL, short_value, sizeof(short_value));
    int init_errno = errno;

    failures +=
        expect_result("reader init null output", init_result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_true("reader init null output errno", init_errno == EACCES);

    errno = EACCES;
    init_result = vireo_tlv_reader_init(&init_probe, NULL, 1U);
    init_errno = errno;

    failures +=
        expect_result("reader init null nonempty data", init_result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_true("reader init null data errno", init_errno == EACCES);
    failures += expect_true("reader init failure keeps data", init_probe.data == short_value);
    failures += expect_size("reader init failure keeps size", init_probe.size, sizeof(short_value));
    failures += expect_size("reader init failure keeps offset", init_probe.offset, 2U);

    vireo_tlv_view_t view = {
        .type = UINT16_C(0xFFFF),
        .value = short_value,
        .length = 99U,
    };
    vireo_tlv_issue_t issue = VIREO_TLV_ISSUE_INVALID_NAME;

    vireo_result_t result = vireo_tlv_reader_next(&reader, NULL, &issue);
    failures += expect_result("reader null view", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_issue("reader null view resets issue", issue, VIREO_TLV_ISSUE_NONE);
    failures += expect_size("reader null view keeps offset", reader.offset, 0U);

    result = vireo_tlv_reader_next(&reader, &view, NULL);
    failures += expect_result("reader null issue", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_size("reader null issue keeps offset", reader.offset, 0U);

    issue = VIREO_TLV_ISSUE_INVALID_NAME;
    result = vireo_tlv_reader_next(NULL, &view, &issue);
    failures += expect_result("reader null state", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_issue("reader null state resets issue", issue, VIREO_TLV_ISSUE_NONE);

    for (size_t count = 1U; count < 4U; ++count) {
        failures += expect_result("reader short header init",
                                  vireo_tlv_reader_init(&reader, short_value, count), VIREO_OK);

        issue = VIREO_TLV_ISSUE_INVALID_NAME;
        result = vireo_tlv_reader_next(&reader, &view, &issue);

        failures += expect_result("reader short header result", result, VIREO_RESULT_PROTOCOL);
        failures +=
            expect_issue("reader short header issue", issue, VIREO_TLV_ISSUE_TRUNCATED_HEADER);
        failures += expect_size("reader short header keeps offset", reader.offset, 0U);
        failures += expect_true("reader short header keeps view", view.type == UINT16_C(0xFFFF) &&
                                                                      view.value == short_value &&
                                                                      view.length == 99U);
    }

    failures +=
        expect_result("reader short value init",
                      vireo_tlv_reader_init(&reader, short_value, sizeof(short_value)), VIREO_OK);

    issue = VIREO_TLV_ISSUE_INVALID_NAME;
    result = vireo_tlv_reader_next(&reader, &view, &issue);
    failures += expect_result("reader short value result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("reader short value issue", issue, VIREO_TLV_ISSUE_TRUNCATED_VALUE);
    failures += expect_size("reader short value keeps offset", reader.offset, 0U);
    failures += expect_true("reader short value keeps view", view.type == UINT16_C(0xFFFF) &&
                                                                 view.value == short_value &&
                                                                 view.length == 99U);

    failures += expect_result(
        "reader trailing byte init",
        vireo_tlv_reader_init(&reader, complete_then_tail, sizeof(complete_then_tail)), VIREO_OK);

    result = vireo_tlv_reader_next(&reader, &view, &issue);
    failures += expect_result("reader trailing first item", result, VIREO_OK);
    failures += expect_size("reader trailing first offset", reader.offset, 4U);

    vireo_tlv_view_t const saved_trailing_view = view;

    result = vireo_tlv_reader_next(&reader, &view, &issue);
    failures += expect_result("reader trailing byte result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("reader trailing byte issue", issue, VIREO_TLV_ISSUE_TRUNCATED_HEADER);
    failures += expect_size("reader trailing byte keeps offset", reader.offset, 4U);
    failures += expect_true("reader trailing byte keeps view",
                            view.type == saved_trailing_view.type &&
                                view.value == saved_trailing_view.value &&
                                view.length == saved_trailing_view.length);

    vireo_tlv_reader_t invalid_reader = {
        .data = short_value,
        .size = sizeof(short_value),
        .offset = sizeof(short_value) + 1U,
    };
    issue = VIREO_TLV_ISSUE_INVALID_NAME;
    result = vireo_tlv_reader_next(&invalid_reader, &view, &issue);
    failures += expect_result("reader invalid state", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_issue("reader invalid state issue", issue, VIREO_TLV_ISSUE_NONE);

    return failures;
}

/* 验证 reader 能接收恰好 65535 字节的 value */
static int test_reader_max_value(void) {
    static uint8_t wire[VIREO_TLV_HEADER_SIZE + VIREO_TLV_MAX_VALUE_SIZE];

    wire[0] = UINT8_C(0x12);
    wire[1] = UINT8_C(0x34);
    wire[2] = UINT8_C(0xFF);
    wire[3] = UINT8_C(0xFF);
    memset(wire + VIREO_TLV_HEADER_SIZE, 0x5A, (size_t)VIREO_TLV_MAX_VALUE_SIZE);

    vireo_tlv_reader_t reader = {0};
    int failures = expect_result("reader max init",
                                 vireo_tlv_reader_init(&reader, wire, sizeof(wire)), VIREO_OK);

    vireo_tlv_view_t view = {0};
    vireo_tlv_issue_t issue = VIREO_TLV_ISSUE_INVALID_NAME;

    vireo_result_t const result = vireo_tlv_reader_next(&reader, &view, &issue);

    failures += expect_result("reader max result", result, VIREO_OK);
    failures += expect_issue("reader max issue", issue, VIREO_TLV_ISSUE_NONE);
    failures += expect_true("reader max type", view.type == UINT16_C(0x1234));
    failures += expect_size("reader max length", view.length, (size_t)VIREO_TLV_MAX_VALUE_SIZE);
    failures +=
        expect_true("reader max borrowed pointer", view.value == wire + VIREO_TLV_HEADER_SIZE);
    failures += expect_size("reader max consumed", reader.offset, sizeof(wire));

    if (result == VIREO_OK && view.value == wire + VIREO_TLV_HEADER_SIZE &&
        view.length == (size_t)VIREO_TLV_MAX_VALUE_SIZE) {
        failures += expect_true("reader max first value byte", view.value[0] == UINT8_C(0x5A));
        failures += expect_true("reader max last value byte",
                                view.value[view.length - 1U] == UINT8_C(0x5A));
    }

    return failures;
}

/* 验证三个整数 view 读取接口的宽度、结果和失败输出保持 */
static int test_view_integer_readers(void) {
    static uint8_t const u16_wire[] = {0x12, 0x34};
    static uint8_t const u32_wire[] = {0x12, 0x34, 0x56, 0x78};
    static uint8_t const u64_wire[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    };

    vireo_tlv_view_t view16 = {
        .type = UINT16_C(1),
        .value = u16_wire,
        .length = sizeof(u16_wire),
    };
    vireo_tlv_view_t view32 = {
        .type = UINT16_C(2),
        .value = u32_wire,
        .length = sizeof(u32_wire),
    };
    vireo_tlv_view_t view64 = {
        .type = UINT16_C(3),
        .value = u64_wire,
        .length = sizeof(u64_wire),
    };

    uint16_t value16 = UINT16_C(0xFFFF);
    uint32_t value32 = UINT32_C(0xFFFFFFFF);
    uint64_t value64 = UINT64_C(0xFFFFFFFFFFFFFFFF);

    errno = EACCES;
    vireo_result_t result = vireo_tlv_view_read_u16(&view16, &value16);
    int actual_errno = errno;
    int failures = expect_result("view read u16", result, VIREO_OK);
    failures += expect_true("view read u16 value", value16 == UINT16_C(0x1234));
    failures += expect_true("view read u16 errno", actual_errno == EACCES);

    errno = EACCES;
    result = vireo_tlv_view_read_u32(&view32, &value32);
    actual_errno = errno;
    failures += expect_result("view read u32", result, VIREO_OK);
    failures += expect_true("view read u32 value", value32 == UINT32_C(0x12345678));
    failures += expect_true("view read u32 errno", actual_errno == EACCES);

    errno = EACCES;
    result = vireo_tlv_view_read_u64(&view64, &value64);
    actual_errno = errno;
    failures += expect_result("view read u64", result, VIREO_OK);
    failures += expect_true("view read u64 value", value64 == UINT64_C(0x1122334455667788));
    failures += expect_true("view read u64 errno", actual_errno == EACCES);

    view16.length = 1U;
    result = vireo_tlv_view_read_u16(&view16, &value16);
    failures += expect_result("view u16 wrong width", result, VIREO_RESULT_PROTOCOL);
    failures += expect_true("view u16 failure keeps output", value16 == UINT16_C(0x1234));

    view32.length = 3U;
    result = vireo_tlv_view_read_u32(&view32, &value32);
    failures += expect_result("view u32 wrong width", result, VIREO_RESULT_PROTOCOL);
    failures += expect_true("view u32 failure keeps output", value32 == UINT32_C(0x12345678));

    view64.value = NULL;
    result = vireo_tlv_view_read_u64(&view64, &value64);
    failures +=
        expect_result("view u64 null nonempty value", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures +=
        expect_true("view u64 failure keeps output", value64 == UINT64_C(0x1122334455667788));

    result = vireo_tlv_view_read_u16(NULL, &value16);
    failures += expect_result("view u16 null view", result, VIREO_RESULT_INVALID_ARGUMENT);

    result = vireo_tlv_view_read_u32(&view32, NULL);
    failures += expect_result("view u32 null output", result, VIREO_RESULT_INVALID_ARGUMENT);

    return failures;
}

/* 验证 schema 参数、工作空间容量与规则配置错误 */
static int test_schema_configuration(void) {
    static uint8_t const empty_seen[] = {0xA5, 0xA5};

    vireo_tlv_rule_t const valid_rule = {
        .type = UINT16_C(1),
        .min_length = UINT16_C(0),
        .max_length = UINT16_C(2),
        .value_kind = VIREO_TLV_VALUE_BYTES,
        .required = false,
        .repeatable = false,
    };

    int failures =
        expect_schema_case("schema empty input and empty rules", NULL, 0U, NULL, 0U,
                           VIREO_TLV_UNKNOWN_REJECT, VIREO_OK, VIREO_TLV_ISSUE_NONE, NULL);

    failures += expect_schema_case("schema null data with nonzero size", NULL, 1U, &valid_rule, 1U,
                                   VIREO_TLV_UNKNOWN_REJECT, VIREO_RESULT_INVALID_ARGUMENT,
                                   VIREO_TLV_ISSUE_NONE, empty_seen);

    failures += expect_schema_case("schema null rules with nonzero count", NULL, 0U, NULL, 1U,
                                   VIREO_TLV_UNKNOWN_REJECT, VIREO_RESULT_INVALID_ARGUMENT,
                                   VIREO_TLV_ISSUE_NONE, empty_seen);

    failures += expect_schema_case("schema invalid unknown policy", NULL, 0U, &valid_rule, 1U,
                                   (vireo_tlv_unknown_policy_t)7, VIREO_RESULT_INVALID_ARGUMENT,
                                   VIREO_TLV_ISSUE_NONE, empty_seen);

    vireo_tlv_rule_t bad_range = valid_rule;
    bad_range.min_length = UINT16_C(3);

    failures += expect_schema_case("schema reversed length range", NULL, 0U, &bad_range, 1U,
                                   VIREO_TLV_UNKNOWN_REJECT, VIREO_RESULT_INVALID_ARGUMENT,
                                   VIREO_TLV_ISSUE_NONE, empty_seen);

    vireo_tlv_rule_t bad_kind = valid_rule;
    bad_kind.value_kind = (vireo_tlv_value_kind_t)99;

    failures += expect_schema_case("schema unknown value kind", NULL, 0U, &bad_kind, 1U,
                                   VIREO_TLV_UNKNOWN_REJECT, VIREO_RESULT_INVALID_ARGUMENT,
                                   VIREO_TLV_ISSUE_NONE, empty_seen);

    vireo_tlv_rule_t const duplicate_rules[] = {
        valid_rule,
        valid_rule,
    };

    failures +=
        expect_schema_case("schema duplicate rule type", NULL, 0U, duplicate_rules,
                           VIREO_TEST_ARRAY_COUNT(duplicate_rules), VIREO_TLV_UNKNOWN_REJECT,
                           VIREO_RESULT_INVALID_ARGUMENT, VIREO_TLV_ISSUE_NONE, empty_seen);

    uint8_t seen[2] = {0xA5, 0xA5};
    vireo_tlv_issue_t issue = VIREO_TLV_ISSUE_INVALID_NAME;

    vireo_result_t result = vireo_tlv_schema_validate(NULL, 0U, &valid_rule, 1U,
                                                      VIREO_TLV_UNKNOWN_REJECT, seen, 0U, &issue);

    failures += expect_result("schema short seen capacity", result, VIREO_RESULT_RANGE);
    failures += expect_issue("schema short seen issue", issue, VIREO_TLV_ISSUE_NONE);
    failures += expect_bytes("schema short seen unchanged", seen, empty_seen, sizeof(seen));

    issue = VIREO_TLV_ISSUE_INVALID_NAME;
    result = vireo_tlv_schema_validate(NULL, 0U, &valid_rule, 1U, VIREO_TLV_UNKNOWN_REJECT, NULL,
                                       0U, &issue);

    failures += expect_result("schema null seen", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_issue("schema null seen issue", issue, VIREO_TLV_ISSUE_NONE);

    result =
        vireo_tlv_schema_validate(NULL, 0U, NULL, 0U, VIREO_TLV_UNKNOWN_REJECT, NULL, 0U, NULL);
    failures += expect_result("schema null issue", result, VIREO_RESULT_INVALID_ARGUMENT);

    return failures;
}

/* 验证已知字段、重复字段、未知字段和必填字段 */
static int test_schema_general_rules(void) {
    static uint8_t const valid_wire[] = {
        0x01, 0x01, 0x00, 0x02, 0x12, 0x34, 0x01, 0x02,
        0x00, 0x01, 0x78, 0x01, 0x02, 0x00, 0x01, 0x79,
    };
    static uint8_t const unknown_then_known[] = {
        0xFE, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x02, 0x12, 0x34,
    };
    static uint8_t const duplicate_wire[] = {
        0x01, 0x01, 0x00, 0x02, 0x12, 0x34, 0x01, 0x01, 0x00, 0x02, 0x56, 0x78,
    };
    static uint8_t const unknown_truncated[] = {
        0xFE, 0x00, 0x00, 0x02, 0xAA,
    };
    static uint8_t const short_header[] = {0x01, 0x01};

    static uint8_t const seen_both[] = {1, 1};
    static uint8_t const seen_first[] = {1, 0};
    static uint8_t const seen_none[] = {0, 0};

    vireo_tlv_rule_t const rules[] = {
        {
            .type = UINT16_C(0x0101),
            .min_length = UINT16_C(2),
            .max_length = UINT16_C(2),
            .value_kind = VIREO_TLV_VALUE_U16,
            .required = true,
            .repeatable = false,
        },
        {
            .type = UINT16_C(0x0102),
            .min_length = UINT16_C(1),
            .max_length = UINT16_C(8),
            .value_kind = VIREO_TLV_VALUE_NAME,
            .required = false,
            .repeatable = true,
        },
    };

    size_t const count = VIREO_TEST_ARRAY_COUNT(rules);
    int failures = expect_schema_case("schema known and repeatable fields", valid_wire,
                                      sizeof(valid_wire), rules, count, VIREO_TLV_UNKNOWN_REJECT,
                                      VIREO_OK, VIREO_TLV_ISSUE_NONE, seen_both);

    failures += expect_schema_case("schema unknown skipped", unknown_then_known,
                                   sizeof(unknown_then_known), rules, count, VIREO_TLV_UNKNOWN_SKIP,
                                   VIREO_OK, VIREO_TLV_ISSUE_NONE, seen_first);

    failures += expect_schema_case(
        "schema unknown rejected", unknown_then_known, sizeof(unknown_then_known), rules, count,
        VIREO_TLV_UNKNOWN_REJECT, VIREO_RESULT_PROTOCOL, VIREO_TLV_ISSUE_UNKNOWN_TYPE, seen_none);

    failures +=
        expect_schema_case("schema duplicate known field", duplicate_wire, sizeof(duplicate_wire),
                           rules, count, VIREO_TLV_UNKNOWN_REJECT, VIREO_RESULT_PROTOCOL,
                           VIREO_TLV_ISSUE_DUPLICATE_FIELD, seen_first);

    failures += expect_schema_case("schema required field missing", NULL, 0U, rules, count,
                                   VIREO_TLV_UNKNOWN_REJECT, VIREO_RESULT_PROTOCOL,
                                   VIREO_TLV_ISSUE_MISSING_REQUIRED_FIELD, seen_none);

    failures +=
        expect_schema_case("schema skipped unknown still needs full value", unknown_truncated,
                           sizeof(unknown_truncated), rules, count, VIREO_TLV_UNKNOWN_SKIP,
                           VIREO_RESULT_PROTOCOL, VIREO_TLV_ISSUE_TRUNCATED_VALUE, seen_none);

    failures += expect_schema_case("schema short header", short_header, sizeof(short_header), rules,
                                   count, VIREO_TLV_UNKNOWN_SKIP, VIREO_RESULT_PROTOCOL,
                                   VIREO_TLV_ISSUE_TRUNCATED_HEADER, seen_none);

    return failures;
}

/* 验证长度区间先于内容，以及整数固定宽度要求 */
static int test_schema_length_rules(void) {
    static uint8_t const short_bytes[] = {
        0x00, 0x21, 0x00, 0x01, 0xAA,
    };
    static uint8_t const wide_u32[] = {
        0x00, 0x21, 0x00, 0x03, 0x11, 0x22, 0x33,
    };
    static uint8_t const invalid_utf8_but_too_long[] = {
        0x00, 0x21, 0x00, 0x02, 0xFF, 0xFF,
    };
    static uint8_t const unseen[] = {0};

    vireo_tlv_rule_t rule = {
        .type = UINT16_C(0x0021),
        .min_length = UINT16_C(2),
        .max_length = UINT16_C(4),
        .value_kind = VIREO_TLV_VALUE_BYTES,
        .required = false,
        .repeatable = false,
    };

    int failures = expect_schema_case(
        "schema below minimum length", short_bytes, sizeof(short_bytes), &rule, 1U,
        VIREO_TLV_UNKNOWN_REJECT, VIREO_RESULT_PROTOCOL, VIREO_TLV_ISSUE_INVALID_LENGTH, unseen);

    rule.min_length = UINT16_C(0);
    rule.max_length = UINT16_C(8);
    rule.value_kind = VIREO_TLV_VALUE_U32;

    failures += expect_schema_case("schema u32 wrong fixed width", wide_u32, sizeof(wide_u32),
                                   &rule, 1U, VIREO_TLV_UNKNOWN_REJECT, VIREO_RESULT_PROTOCOL,
                                   VIREO_TLV_ISSUE_INVALID_LENGTH, unseen);

    rule.value_kind = VIREO_TLV_VALUE_UTF8;
    rule.max_length = UINT16_C(1);

    failures +=
        expect_schema_case("schema length before invalid UTF-8", invalid_utf8_but_too_long,
                           sizeof(invalid_utf8_but_too_long), &rule, 1U, VIREO_TLV_UNKNOWN_REJECT,
                           VIREO_RESULT_PROTOCOL, VIREO_TLV_ISSUE_INVALID_LENGTH, unseen);

    return failures;
}

/* 验证 UTF-8 的合法边界与典型非法编码 */
static int test_schema_utf8(void) {
    typedef struct utf8_case {
        char const *name;
        uint8_t bytes[4];
        size_t length;
        vireo_tlv_issue_t expected_issue;
    } utf8_case_t;

    static utf8_case_t const cases[] = {
        {"empty", {0}, 0U, VIREO_TLV_ISSUE_NONE},
        {"ASCII NUL", {0x00}, 1U, VIREO_TLV_ISSUE_NONE},
        {"two byte minimum", {0xC2, 0x80}, 2U, VIREO_TLV_ISSUE_NONE},
        {"three byte minimum", {0xE0, 0xA0, 0x80}, 3U, VIREO_TLV_ISSUE_NONE},
        {"surrogate lower", {0xED, 0x9F, 0xBF}, 3U, VIREO_TLV_ISSUE_NONE},
        {"four byte minimum", {0xF0, 0x90, 0x80, 0x80}, 4U, VIREO_TLV_ISSUE_NONE},
        {"Unicode maximum", {0xF4, 0x8F, 0xBF, 0xBF}, 4U, VIREO_TLV_ISSUE_NONE},
        {"isolated tail", {0x80}, 1U, VIREO_TLV_ISSUE_INVALID_UTF8},
        {"overlong two", {0xC0, 0x80}, 2U, VIREO_TLV_ISSUE_INVALID_UTF8},
        {"overlong three", {0xE0, 0x80, 0x80}, 3U, VIREO_TLV_ISSUE_INVALID_UTF8},
        {"surrogate", {0xED, 0xA0, 0x80}, 3U, VIREO_TLV_ISSUE_INVALID_UTF8},
        {"overlong four", {0xF0, 0x80, 0x80, 0x80}, 4U, VIREO_TLV_ISSUE_INVALID_UTF8},
        {"above maximum", {0xF4, 0x90, 0x80, 0x80}, 4U, VIREO_TLV_ISSUE_INVALID_UTF8},
        {"invalid lead", {0xF5, 0x80, 0x80, 0x80}, 4U, VIREO_TLV_ISSUE_INVALID_UTF8},
        {"truncated sequence", {0xE4, 0xB8}, 2U, VIREO_TLV_ISSUE_INVALID_UTF8},
        {"bad continuation", {0xE4, 0x41, 0x80}, 3U, VIREO_TLV_ISSUE_INVALID_UTF8},
    };

    vireo_tlv_rule_t const rule = {
        .type = UINT16_C(0x0011),
        .min_length = UINT16_C(0),
        .max_length = UINT16_C(4),
        .value_kind = VIREO_TLV_VALUE_UTF8,
        .required = false,
        .repeatable = false,
    };

    int failures = 0;

    for (size_t index = 0; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
        uint8_t wire[8] = {0x00, 0x11, 0x00, 0x00};

        wire[3] = (uint8_t)cases[index].length;
        if (cases[index].length != 0U) {
            memcpy(wire + 4U, cases[index].bytes, cases[index].length);
        }

        uint8_t const seen[] = {
            cases[index].expected_issue == VIREO_TLV_ISSUE_NONE ? UINT8_C(1) : UINT8_C(0),
        };

        failures += expect_schema_case(
            cases[index].name, wire, 4U + cases[index].length, &rule, 1U, VIREO_TLV_UNKNOWN_REJECT,
            cases[index].expected_issue == VIREO_TLV_ISSUE_NONE ? VIREO_OK : VIREO_RESULT_PROTOCOL,
            cases[index].expected_issue, seen);
    }

    return failures;
}

/* 验证合法 UTF-8 与合法 NAME 是两层不同的约束 */
static int test_schema_name(void) {
    typedef struct name_case {
        char const *name;
        uint8_t bytes[8];
        size_t length;
        vireo_tlv_issue_t expected_issue;
    } name_case_t;

    static name_case_t const cases[] = {
        {"plain", {0x66, 0x69, 0x6C, 0x65}, 4U, VIREO_TLV_ISSUE_NONE},
        {"dot prefix", {0x2E, 0x61}, 2U, VIREO_TLV_ISSUE_NONE},
        {"Chinese name", {0xE4, 0xB8, 0xAD}, 3U, VIREO_TLV_ISSUE_NONE},
        {"U+00A0", {0xC2, 0xA0}, 2U, VIREO_TLV_ISSUE_NONE},
        {"empty name", {0}, 0U, VIREO_TLV_ISSUE_INVALID_NAME},
        {"single dot", {0x2E}, 1U, VIREO_TLV_ISSUE_INVALID_NAME},
        {"double dot", {0x2E, 0x2E}, 2U, VIREO_TLV_ISSUE_INVALID_NAME},
        {"slash", {0x61, 0x2F, 0x62}, 3U, VIREO_TLV_ISSUE_INVALID_NAME},
        {"NUL", {0x61, 0x00, 0x62}, 3U, VIREO_TLV_ISSUE_INVALID_NAME},
        {"C0 control", {0x1F}, 1U, VIREO_TLV_ISSUE_INVALID_NAME},
        {"DEL", {0x7F}, 1U, VIREO_TLV_ISSUE_INVALID_NAME},
        {"C1 lower", {0xC2, 0x80}, 2U, VIREO_TLV_ISSUE_INVALID_NAME},
        {"C1 upper", {0xC2, 0x9F}, 2U, VIREO_TLV_ISSUE_INVALID_NAME},
        {"invalid UTF-8", {0xFF}, 1U, VIREO_TLV_ISSUE_INVALID_UTF8},
    };

    vireo_tlv_rule_t const rule = {
        .type = UINT16_C(0x0012),
        .min_length = UINT16_C(0),
        .max_length = UINT16_C(8),
        .value_kind = VIREO_TLV_VALUE_NAME,
        .required = false,
        .repeatable = false,
    };

    int failures = 0;

    for (size_t index = 0; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
        uint8_t wire[12] = {0x00, 0x12, 0x00, 0x00};

        wire[3] = (uint8_t)cases[index].length;
        if (cases[index].length != 0U) {
            memcpy(wire + 4U, cases[index].bytes, cases[index].length);
        }

        uint8_t const seen[] = {
            cases[index].expected_issue == VIREO_TLV_ISSUE_NONE ? UINT8_C(1) : UINT8_C(0),
        };

        failures += expect_schema_case(
            cases[index].name, wire, 4U + cases[index].length, &rule, 1U, VIREO_TLV_UNKNOWN_REJECT,
            cases[index].expected_issue == VIREO_TLV_ISSUE_NONE ? VIREO_OK : VIREO_RESULT_PROTOCOL,
            cases[index].expected_issue, seen);
    }

    return failures;
}

int main(void) {
    typedef int (*test_function_t)(void);

    static test_function_t const tests[] = {
        test_writer_init,          test_writer_golden,        test_writer_failures,
        test_writer_max_value,     test_reader_sequence,      test_reader_failures,
        test_reader_max_value,     test_view_integer_readers, test_schema_configuration,
        test_schema_general_rules, test_schema_length_rules,  test_schema_utf8,
        test_schema_name,
    };

    int failures = 0;

    for (size_t index = 0; index < VIREO_TEST_ARRAY_COUNT(tests); ++index) {
        failures += tests[index]();
    }

    if (failures != 0) {
        fprintf(stderr, "test_tlv: %d assertion failure(s)\n", failures);
        return EXIT_FAILURE;
    }

    printf("test_tlv: all %zu test groups passed\n", VIREO_TEST_ARRAY_COUNT(tests));
    return EXIT_SUCCESS;
}

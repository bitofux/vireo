/*
 * PROJECT : VIREO
 * FILE    : test_chunk.c
 * AUTHOR  : bitofux
 * DATE    : 2026-09-24
 * BRIEF   : 测试 vireo v1 chunk body 编解码与 data CRC-32C
 * -- 验证固定 56 字节元数据布局和显式大端编解码
 * -- 验证原始 data 的 CRC-32C 确定性结果与不匹配诊断
 * -- 验证参数错误、长度边界、容量边界和文件区间溢出
 * -- 验证失败输出保持、输出尾部保持和 data 借用地址
 * -- 验证 BLAKE3 摘要按原始字节搬运，不在本模块中验证
 * -- 验证公共函数不会修改 errno
 */

/*
 * PROJECT : VIREO
 * FILE    : test_chunk.c
 * AUTHOR  : bitofux
 * DATE    : 2026-09-24
 * BRIEF   : 测试 vireo v1 chunk body 编解码与 data CRC-32C
 * -- 验证固定 56 字节元数据布局和确定性 wire golden vectors
 * -- 验证元数据编码、解码及原始 data 的借用视图
 * -- 验证空数据、长度边界、容量不足和文件区间加法溢出
 * -- 验证只覆盖原始 data 的 CRC-32C 计算与校验
 * -- 验证错误分类、具体 issue、失败输出保持和成功时尾部保持
 * -- 验证公共函数不会修改 errno
 */

#include <vireo/protocol/chunk.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vireo/base/result.h>
#include <vireo/protocol/protocol.h>

#define VIREO_TEST_ARRAY_COUNT(array) (sizeof(array) / sizeof((array)[0]))

_Static_assert(CHAR_BIT == 8, "vireo chunk tests require 8-bit bytes");

_Static_assert(VIREO_CHUNK_HEADER_SIZE == UINT32_C(56),
               "vireo chunk tests require fixed 56-byte metadata");

_Static_assert(VIREO_CHUNK_BLAKE3_SIZE == UINT32_C(32),
               "vireo chunk tests require a 32-byte BLAKE3 field");

_Static_assert(VIREO_PROTOCOL_MAX_BODY_SIZE == UINT32_C(16777216),
               "vireo v1 body limit must remain 16777216 bytes");

_Static_assert(VIREO_CHUNK_MAX_DATA_SIZE == UINT32_C(16777160),
               "vireo v1 chunk data limit must remain 16777160 bytes");

_Static_assert(VIREO_CHUNK_INDEX_OFFSET == UINT32_C(0) && VIREO_CHUNK_INDEX_SIZE == UINT32_C(4),
               "chunk index must occupy bytes 0 through 3");

_Static_assert(VIREO_CHUNK_HEADER_LENGTH_OFFSET == UINT32_C(4) &&
                   VIREO_CHUNK_HEADER_LENGTH_SIZE == UINT32_C(4),
               "chunk header length must occupy bytes 4 through 7");

_Static_assert(VIREO_CHUNK_FILE_OFFSET_OFFSET == UINT32_C(8) &&
                   VIREO_CHUNK_FILE_OFFSET_SIZE == UINT32_C(8),
               "chunk file offset must occupy bytes 8 through 15");

_Static_assert(VIREO_CHUNK_DATA_LENGTH_OFFSET == UINT32_C(16) &&
                   VIREO_CHUNK_DATA_LENGTH_SIZE == UINT32_C(4),
               "chunk data length must occupy bytes 16 through 19");

_Static_assert(VIREO_CHUNK_CRC32C_OFFSET == UINT32_C(20) && VIREO_CHUNK_CRC32C_SIZE == UINT32_C(4),
               "chunk data CRC-32C must occupy bytes 20 through 23");

_Static_assert(VIREO_CHUNK_BLAKE3_OFFSET == UINT32_C(24),
               "chunk BLAKE3 field must begin at byte 24");

_Static_assert(VIREO_CHUNK_BLAKE3_OFFSET + VIREO_CHUNK_BLAKE3_SIZE == VIREO_CHUNK_HEADER_SIZE,
               "chunk BLAKE3 field must end at the metadata boundary");

_Static_assert(VIREO_CHUNK_DATA_OFFSET == VIREO_CHUNK_HEADER_SIZE,
               "chunk data must immediately follow the fixed metadata");

/* 比较实际 vireo_result_t 与预期结果 */
static int expect_result(char const *case_name, vireo_result_t actual, vireo_result_t expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected result %d, got %d\n", case_name, (int)expected, (int)actual);

    return 1;
}

/* 比较实际 chunk issue 与预期 issue */
static int expect_issue(char const *case_name, vireo_chunk_issue_t actual,
                        vireo_chunk_issue_t expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected chunk issue %d, got %d\n", case_name, (int)expected, (int)actual);

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

/* 比较实际 size_t 与预期值 */
static int expect_size(char const *case_name, size_t actual, size_t expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected size %zu, got %zu\n", case_name, expected, actual);

    return 1;
}

/* 比较两个只读字节区域，报告第一个不同字节 */
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

/* 比较被测调用后保存的 errno 值与预期值 */
static int expect_errno_value(char const *case_name, int actual, int expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected errno %d, got %d\n", case_name, expected, actual);

    return 1;
}

/* 检查调用者提供的布尔条件是否为真 */
static int expect_true(char const *case_name, bool condition) {
    if (condition) {
        return 0;
    }

    fprintf(stderr, "%s: expected true, got false\n", case_name);

    return 1;
}

/* 逐字段比较两份宿主语义 chunk 元数据 */
static int expect_header(char const *case_name, vireo_chunk_header_t const *actual,
                         vireo_chunk_header_t const *expected) {
    if (actual->chunk_index != expected->chunk_index) {
        fprintf(stderr,
                "%s: expected chunk_index %" PRIu32 " (0x%08" PRIX32 "), got %" PRIu32
                " (0x%08" PRIX32 ")\n",
                case_name, expected->chunk_index, expected->chunk_index, actual->chunk_index,
                actual->chunk_index);

        return 1;
    }

    if (actual->offset != expected->offset) {
        fprintf(stderr,
                "%s: expected offset %" PRIu64 " (0x%016" PRIX64 "), got %" PRIu64 " (0x%016" PRIX64
                ")\n",
                case_name, expected->offset, expected->offset, actual->offset, actual->offset);

        return 1;
    }

    if (actual->data_len != expected->data_len) {
        fprintf(stderr,
                "%s: expected data_len %" PRIu32 " (0x%08" PRIX32 "), got %" PRIu32 " (0x%08" PRIX32
                ")\n",
                case_name, expected->data_len, expected->data_len, actual->data_len,
                actual->data_len);

        return 1;
    }

    if (actual->crc32c != expected->crc32c) {
        fprintf(stderr,
                "%s: expected crc32c %" PRIu32 " (0x%08" PRIX32 "), got %" PRIu32 " (0x%08" PRIX32
                ")\n",
                case_name, expected->crc32c, expected->crc32c, actual->crc32c, actual->crc32c);

        return 1;
    }

    return expect_bytes(case_name, actual->blake3, expected->blake3, sizeof(expected->blake3));
}

/* 构造满足基础结构约束的空 data 元数据；摘要使用全零占位 */
static vireo_chunk_header_t make_valid_header(void) {
    vireo_chunk_header_t const header = {
        .chunk_index = UINT32_C(0),
        .offset = UINT64_C(0),
        .data_len = UINT32_C(0),
        .crc32c = UINT32_C(0),
        .blake3 = {0},
    };

    return header;
}

/* 验证原始 data 的确定性 CRC-32C golden vector */
static int test_data_crc32c_calculate_golden(void) {
    static uint8_t const data[] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
    };

    uint32_t crc32c = UINT32_C(0xA5A5A5A5);

    errno = EACCES;
    vireo_result_t const result = vireo_chunk_data_crc32c_calculate(data, sizeof(data), &crc32c);
    int const actual_errno = errno;

    int failures = expect_result("chunk crc calculate golden result", result, VIREO_OK);
    failures += expect_errno_value("chunk crc calculate golden errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures += expect_u32("chunk crc calculate golden value", crc32c, UINT32_C(0xE3069283));
    }

    return failures;
}

/* 验证零长度输入允许空指针和非空指针，且 CRC-32C 均为零 */
static int test_data_crc32c_calculate_empty_data(void) {
    static uint8_t const data[] = {
        0xA5,
    };

    uint32_t crc32c = UINT32_C(0xA5A5A5A5);

    errno = EACCES;
    vireo_result_t result = vireo_chunk_data_crc32c_calculate(NULL, (size_t)0, &crc32c);
    int actual_errno = errno;

    int failures = expect_result("chunk crc empty null data result", result, VIREO_OK);
    failures += expect_errno_value("chunk crc empty null data errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures += expect_u32("chunk crc empty null data value", crc32c, UINT32_C(0));
    }

    crc32c = UINT32_C(0xA5A5A5A5);

    errno = EACCES;
    result = vireo_chunk_data_crc32c_calculate(data, (size_t)0, &crc32c);
    actual_errno = errno;

    failures += expect_result("chunk crc empty nonnull data result", result, VIREO_OK);
    failures += expect_errno_value("chunk crc empty nonnull data errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures += expect_u32("chunk crc empty nonnull data value", crc32c, UINT32_C(0));
    }

    return failures;
}

/* 验证 CRC 计算的非法参数、errno 保持和失败输出保持 */
static int test_data_crc32c_calculate_invalid_arguments(void) {
    static uint8_t const data[] = {
        0xA5,
    };

    uint32_t const expected_unchanged = UINT32_C(0xA5A5A5A5);
    uint32_t crc32c = expected_unchanged;

    errno = EACCES;
    vireo_result_t result = vireo_chunk_data_crc32c_calculate(NULL, sizeof(data), &crc32c);
    int actual_errno = errno;

    int failures =
        expect_result("chunk crc null nonempty data result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_errno_value("chunk crc null nonempty data errno", actual_errno, EACCES);
    failures += expect_u32("chunk crc null nonempty data output keep", crc32c, expected_unchanged);

    errno = EACCES;
    result = vireo_chunk_data_crc32c_calculate(data, sizeof(data), NULL);
    actual_errno = errno;

    failures +=
        expect_result("chunk crc null output result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_errno_value("chunk crc null output errno", actual_errno, EACCES);

    return failures;
}

/* 验证 CRC 计算拒绝超限长度，并保持输出和 errno */
static int test_data_crc32c_calculate_range_errors(void) {
    static uint8_t const data[] = {
        0xA5,
    };

    uint32_t const expected_unchanged = UINT32_C(0xA5A5A5A5);
    uint32_t crc32c = expected_unchanged;

    errno = EACCES;
    vireo_result_t const result =
        vireo_chunk_data_crc32c_calculate(data, (size_t)VIREO_CHUNK_MAX_DATA_SIZE + 1U, &crc32c);
    int const actual_errno = errno;

    int failures = expect_result("chunk crc oversized data result", result, VIREO_RESULT_RANGE);
    failures += expect_errno_value("chunk crc oversized data errno", actual_errno, EACCES);
    failures += expect_u32("chunk crc oversized data output keep", crc32c, expected_unchanged);

    return failures;
}

/* 验证宿主元数据和原始 data 被编码为确定性的完整 chunk body */
static int test_body_encode_golden(void) {
    static uint8_t const expected_body[] = {
        /* chunk_index */
        0x12,
        0x34,
        0x56,
        0x78,

        /* chunk_header_len = 56 */
        0x00,
        0x00,
        0x00,
        0x38,

        /* offset */
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,

        /* data_len = 3 */
        0x00,
        0x00,
        0x00,
        0x03,

        /* crc32c：按给定值编码 */
        0xA1,
        0xB2,
        0xC3,
        0xD4,

        /* blake3：按原始字节顺序复制 */
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
        0x19,
        0x1A,
        0x1B,
        0x1C,
        0x1D,
        0x1E,
        0x1F,

        /* 原始 data */
        0xAA,
        0xBB,
        0xCC,
    };

    static uint8_t const data[] = {
        0xAA,
        0xBB,
        0xCC,
    };

    vireo_chunk_header_t const header = {
        .chunk_index = UINT32_C(0x12345678),
        .offset = UINT64_C(0x1122334455667788),
        .data_len = UINT32_C(3),
        .crc32c = UINT32_C(0xA1B2C3D4),
        .blake3 =
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            },
    };

    uint8_t body[sizeof(expected_body)];
    size_t body_size = (size_t)777;

    memset(body, 0xA5, sizeof(body));

    errno = EACCES;
    vireo_result_t const result =
        vireo_chunk_body_encode(&header, data, sizeof(data), body, sizeof(body), &body_size);
    int const actual_errno = errno;

    int failures = expect_result("chunk encode golden result", result, VIREO_OK);
    failures += expect_errno_value("chunk encode golden errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures += expect_size("chunk encode golden body size", body_size, sizeof(expected_body));
        failures +=
            expect_bytes("chunk encode golden bytes", body, expected_body, sizeof(expected_body));
    }

    return failures;
}

/* 验证 encode 的非法参数、errno 保持和可观察的失败输出保持 */
static int test_body_encode_invalid_arguments(void) {
    static uint8_t const data[] = {
        0xA5,
    };

    vireo_chunk_header_t header = make_valid_header();
    header.data_len = UINT32_C(1);

    uint8_t body[VIREO_CHUNK_HEADER_SIZE + sizeof(data)];
    uint8_t expected_unchanged[sizeof(body)];

    size_t const expected_size_unchanged = (size_t)777;
    size_t body_size = expected_size_unchanged;

    memset(body, 0xA5, sizeof(body));
    memset(expected_unchanged, 0xA5, sizeof(expected_unchanged));

    /* 1. header 为 NULL */
    errno = EACCES;
    vireo_result_t result =
        vireo_chunk_body_encode(NULL, data, sizeof(data), body, sizeof(body), &body_size);
    int actual_errno = errno;

    int failures =
        expect_result("chunk encode null header result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_errno_value("chunk encode null header errno", actual_errno, EACCES);
    failures +=
        expect_bytes("chunk encode null header body keep", body, expected_unchanged, sizeof(body));
    failures +=
        expect_size("chunk encode null header size keep", body_size, expected_size_unchanged);

    /* 2. data 为 NULL，但 data_size 非零 */
    memset(body, 0xA5, sizeof(body));
    body_size = expected_size_unchanged;

    errno = EACCES;
    result = vireo_chunk_body_encode(&header, NULL, sizeof(data), body, sizeof(body), &body_size);
    actual_errno = errno;

    failures += expect_result("chunk encode null nonempty data result", result,
                              VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_errno_value("chunk encode null nonempty data errno", actual_errno, EACCES);
    failures += expect_bytes("chunk encode null nonempty data body keep", body, expected_unchanged,
                             sizeof(body));
    failures += expect_size("chunk encode null nonempty data size keep", body_size,
                            expected_size_unchanged);

    /* 3. body 为 NULL */
    body_size = expected_size_unchanged;

    errno = EACCES;
    result = vireo_chunk_body_encode(&header, data, sizeof(data), NULL, sizeof(body), &body_size);
    actual_errno = errno;

    failures +=
        expect_result("chunk encode null body result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_errno_value("chunk encode null body errno", actual_errno, EACCES);
    failures += expect_size("chunk encode null body size keep", body_size, expected_size_unchanged);

    /* 4. out_body_size 为 NULL */
    memset(body, 0xA5, sizeof(body));

    errno = EACCES;
    result = vireo_chunk_body_encode(&header, data, sizeof(data), body, sizeof(body), NULL);
    actual_errno = errno;

    failures += expect_result("chunk encode null size output result", result,
                              VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_errno_value("chunk encode null size output errno", actual_errno, EACCES);
    failures += expect_bytes("chunk encode null size output body keep", body, expected_unchanged,
                             sizeof(body));

    return failures;
}

/* 验证 encode 的容量不足、长度不一致及失败输出保持 */
static int test_body_encode_capacity_and_length_errors(void) {
    static uint8_t const data[] = {
        0xAA,
        0xBB,
    };

    vireo_chunk_header_t header = make_valid_header();
    header.data_len = UINT32_C(2);

    uint8_t body[VIREO_CHUNK_HEADER_SIZE + sizeof(data)];
    uint8_t expected_unchanged[sizeof(body)];

    size_t const expected_size_unchanged = (size_t)777;
    size_t body_size = expected_size_unchanged;

    memset(body, 0xA5, sizeof(body));
    memset(expected_unchanged, 0xA5, sizeof(expected_unchanged));

    /* 1. 需要 58 字节，但只声明 57 字节输出容量 */
    errno = EACCES;
    vireo_result_t result =
        vireo_chunk_body_encode(&header, data, sizeof(data), body, sizeof(body) - 1U, &body_size);
    int actual_errno = errno;

    int failures = expect_result("chunk encode short capacity result", result, VIREO_RESULT_RANGE);
    failures += expect_errno_value("chunk encode short capacity errno", actual_errno, EACCES);
    failures += expect_bytes("chunk encode short capacity body keep", body, expected_unchanged,
                             sizeof(body));
    failures +=
        expect_size("chunk encode short capacity size keep", body_size, expected_size_unchanged);

    /* 2. 元数据声明 1 字节，调用参数提供 2 字节 */
    header = make_valid_header();
    header.data_len = UINT32_C(1);
    memset(body, 0xA5, sizeof(body));
    body_size = expected_size_unchanged;

    errno = EACCES;
    result = vireo_chunk_body_encode(&header, data, sizeof(data), body, sizeof(body), &body_size);
    actual_errno = errno;

    failures +=
        expect_result("chunk encode declared length smaller result", result, VIREO_RESULT_RANGE);
    failures +=
        expect_errno_value("chunk encode declared length smaller errno", actual_errno, EACCES);
    failures += expect_bytes("chunk encode declared length smaller body keep", body,
                             expected_unchanged, sizeof(body));
    failures += expect_size("chunk encode declared length smaller size keep", body_size,
                            expected_size_unchanged);

    /* 3. 元数据声明 2 字节，调用参数只提供 1 字节 */
    header = make_valid_header();
    header.data_len = UINT32_C(2);
    memset(body, 0xA5, sizeof(body));
    body_size = expected_size_unchanged;

    errno = EACCES;
    result = vireo_chunk_body_encode(&header, data, (size_t)1, body, sizeof(body), &body_size);
    actual_errno = errno;

    failures +=
        expect_result("chunk encode declared length larger result", result, VIREO_RESULT_RANGE);
    failures +=
        expect_errno_value("chunk encode declared length larger errno", actual_errno, EACCES);
    failures += expect_bytes("chunk encode declared length larger body keep", body,
                             expected_unchanged, sizeof(body));
    failures += expect_size("chunk encode declared length larger size keep", body_size,
                            expected_size_unchanged);

    return failures;
}

/* 验证 encode 拒绝超限 data，即使长度一致且输出容量充足 */
static int test_body_encode_oversized_data(void) {
    static uint8_t const data[(size_t)VIREO_CHUNK_MAX_DATA_SIZE + 1U] = {0};

    static uint8_t body[(size_t)VIREO_CHUNK_HEADER_SIZE + sizeof(data)];

    static uint8_t expected_unchanged[sizeof(body)];

    vireo_chunk_header_t header = make_valid_header();
    header.data_len = VIREO_CHUNK_MAX_DATA_SIZE + UINT32_C(1);

    size_t const expected_size_unchanged = (size_t)777;
    size_t body_size = expected_size_unchanged;

    memset(body, 0xA5, sizeof(body));
    memset(expected_unchanged, 0xA5, sizeof(expected_unchanged));

    errno = EACCES;
    vireo_result_t const result =
        vireo_chunk_body_encode(&header, data, sizeof(data), body, sizeof(body), &body_size);
    int const actual_errno = errno;

    int failures = expect_result("chunk encode oversized data result", result, VIREO_RESULT_RANGE);
    failures += expect_errno_value("chunk encode oversized data errno", actual_errno, EACCES);
    failures += expect_bytes("chunk encode oversized data body keep", body, expected_unchanged,
                             sizeof(body));
    failures +=
        expect_size("chunk encode oversized data size keep", body_size, expected_size_unchanged);

    return failures;
}

/* 验证 encode 拒绝文件区间终点溢出，并保持输出和 errno */
static int test_body_encode_offset_overflow(void) {
    static uint8_t const data[] = {
        0xAA,
        0xBB,
    };

    vireo_chunk_header_t header = make_valid_header();
    header.offset = UINT64_MAX - UINT64_C(1);
    header.data_len = UINT32_C(2);

    uint8_t body[VIREO_CHUNK_HEADER_SIZE + sizeof(data)];
    uint8_t expected_unchanged[sizeof(body)];

    size_t const expected_size_unchanged = (size_t)777;
    size_t body_size = expected_size_unchanged;

    memset(body, 0xA5, sizeof(body));
    memset(expected_unchanged, 0xA5, sizeof(expected_unchanged));

    errno = EACCES;
    vireo_result_t const result =
        vireo_chunk_body_encode(&header, data, sizeof(data), body, sizeof(body), &body_size);
    int const actual_errno = errno;

    int failures =
        expect_result("chunk encode offset overflow result", result, VIREO_RESULT_OVERFLOW);
    failures += expect_errno_value("chunk encode offset overflow errno", actual_errno, EACCES);
    failures += expect_bytes("chunk encode offset overflow body keep", body, expected_unchanged,
                             sizeof(body));
    failures +=
        expect_size("chunk encode offset overflow size keep", body_size, expected_size_unchanged);

    return failures;
}

/* 验证 encode 接受文件区间终点恰好等于 UINT64_MAX */
static int test_body_encode_offset_max_boundary(void) {
    static uint8_t const data[] = {
        0xAA,
        0xBB,
    };

    /* UINT64_MAX - 2，即 0xFFFFFFFFFFFFFFFD */
    static uint8_t const expected_offset[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD,
    };

    vireo_chunk_header_t header = make_valid_header();
    header.offset = UINT64_MAX - UINT64_C(2);
    header.data_len = UINT32_C(2);

    uint8_t body[VIREO_CHUNK_HEADER_SIZE + sizeof(data)];
    size_t body_size = (size_t)777;

    memset(body, 0xA5, sizeof(body));

    errno = EACCES;
    vireo_result_t const result =
        vireo_chunk_body_encode(&header, data, sizeof(data), body, sizeof(body), &body_size);
    int const actual_errno = errno;

    int failures = expect_result("chunk encode max end offset result", result, VIREO_OK);
    failures += expect_errno_value("chunk encode max end offset errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures += expect_size("chunk encode max end offset body size", body_size, sizeof(body));
        failures +=
            expect_bytes("chunk encode max end offset bytes", body + VIREO_CHUNK_FILE_OFFSET_OFFSET,
                         expected_offset, sizeof(expected_offset));
        failures += expect_bytes("chunk encode max end offset data", body + VIREO_CHUNK_DATA_OFFSET,
                                 data, sizeof(data));
    }

    return failures;
}

/* 验证空 data 仍编码为完整的 56 字节 chunk 元数据 */
static int test_body_encode_empty_data(void) {
    static uint8_t const expected_body[] = {
        /* chunk_index = 0 */
        0x00,
        0x00,
        0x00,
        0x00,

        /* chunk_header_len = 56 */
        0x00,
        0x00,
        0x00,
        0x38,

        /* offset = 0 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,

        /* data_len = 0 */
        0x00,
        0x00,
        0x00,
        0x00,

        /* crc32c = 0 */
        0x00,
        0x00,
        0x00,
        0x00,

        /* blake3：基准 header 中的全零占位摘要 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };

    vireo_chunk_header_t const header = make_valid_header();

    uint8_t body[VIREO_CHUNK_HEADER_SIZE];
    size_t body_size = (size_t)777;

    memset(body, 0xA5, sizeof(body));

    errno = EACCES;
    vireo_result_t const result =
        vireo_chunk_body_encode(&header, NULL, (size_t)0, body, sizeof(body), &body_size);
    int const actual_errno = errno;

    int failures = expect_result("chunk encode empty data result", result, VIREO_OK);
    failures += expect_errno_value("chunk encode empty data errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures +=
            expect_size("chunk encode empty data body size", body_size, sizeof(expected_body));
        failures +=
            expect_bytes("chunk encode empty data bytes", body, expected_body, sizeof(body));
    }

    return failures;
}

/* 验证 encode 成功时只写实际 body，不修改多余容量尾部 */
static int test_body_encode_larger_capacity_tail_keep(void) {
    static uint8_t const data[] = {
        0xAA,
        0xBB,
        0xCC,
    };

    vireo_chunk_header_t header = make_valid_header();
    header.data_len = UINT32_C(3);

    uint8_t body[VIREO_CHUNK_HEADER_SIZE + sizeof(data) + 8U];
    uint8_t expected_tail[8];

    size_t const expected_body_size = (size_t)VIREO_CHUNK_HEADER_SIZE + sizeof(data);
    size_t body_size = (size_t)777;

    memset(body, 0xA5, sizeof(body));
    memset(expected_tail, 0xA5, sizeof(expected_tail));

    errno = EACCES;
    vireo_result_t const result =
        vireo_chunk_body_encode(&header, data, sizeof(data), body, sizeof(body), &body_size);
    int const actual_errno = errno;

    int failures = expect_result("chunk encode larger capacity result", result, VIREO_OK);
    failures += expect_errno_value("chunk encode larger capacity errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures +=
            expect_size("chunk encode larger capacity body size", body_size, expected_body_size);
        failures += expect_bytes("chunk encode larger capacity data",
                                 body + VIREO_CHUNK_DATA_OFFSET, data, sizeof(data));
        failures += expect_bytes("chunk encode larger capacity tail keep",
                                 body + expected_body_size, expected_tail, sizeof(expected_tail));
    }

    return failures;
}

/* 验证固定 wire body 被解码为正确元数据和 data 借用视图 */
static int test_body_decode_golden(void) {
    static uint8_t const body[] = {
        /* chunk_index */
        0x12,
        0x34,
        0x56,
        0x78,

        /* chunk_header_len = 56 */
        0x00,
        0x00,
        0x00,
        0x38,

        /* offset */
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,

        /* data_len = 3 */
        0x00,
        0x00,
        0x00,
        0x03,

        /* crc32c：只验证字段解码 */
        0xA1,
        0xB2,
        0xC3,
        0xD4,

        /* blake3：只验证摘要字节复制 */
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
        0x19,
        0x1A,
        0x1B,
        0x1C,
        0x1D,
        0x1E,
        0x1F,

        /* 原始 data */
        0xAA,
        0xBB,
        0xCC,
    };

    static uint8_t const expected_data[] = {
        0xAA,
        0xBB,
        0xCC,
    };

    vireo_chunk_header_t const expected_header = {
        .chunk_index = UINT32_C(0x12345678),
        .offset = UINT64_C(0x1122334455667788),
        .data_len = UINT32_C(3),
        .crc32c = UINT32_C(0xA1B2C3D4),
        .blake3 =
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            },
    };

    vireo_chunk_view_t view = {0};
    vireo_chunk_issue_t issue = VIREO_CHUNK_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    vireo_result_t const result = vireo_chunk_body_decode(body, sizeof(body), &view, &issue);
    int const actual_errno = errno;

    int failures = expect_result("chunk decode golden result", result, VIREO_OK);
    failures += expect_issue("chunk decode golden issue", issue, VIREO_CHUNK_ISSUE_NONE);
    failures += expect_errno_value("chunk decode golden errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures += expect_header("chunk decode golden metadata", &view.header, &expected_header);
        failures += expect_true("chunk decode golden borrowed data pointer",
                                view.data == body + VIREO_CHUNK_DATA_OFFSET);

        if (view.data == body + VIREO_CHUNK_DATA_OFFSET &&
            view.header.data_len == sizeof(expected_data)) {
            failures += expect_bytes("chunk decode golden data bytes", view.data, expected_data,
                                     sizeof(expected_data));
        }
    }

    return failures;
}

/* 验证 decode 的非法参数、issue 初始化和失败视图保持 */
static int test_body_decode_invalid_arguments(void) {
    static uint8_t const body[VIREO_CHUNK_HEADER_SIZE] = {
        /* chunk_index = 0，chunk_header_len = 56 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x38,

        /* offset = 0 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,

        /* data_len = 0，crc32c = 0 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,

        /* 全零占位摘要 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };

    static uint8_t const saved_data[] = {
        0xDE,
        0xAD,
    };

    vireo_chunk_header_t saved_header = make_valid_header();
    saved_header.chunk_index = UINT32_C(0xA1A2A3A4);
    saved_header.offset = UINT64_C(0x1122334455667788);
    saved_header.data_len = UINT32_C(2);
    saved_header.crc32c = UINT32_C(0xB1B2B3B4);
    memset(saved_header.blake3, 0x5A, sizeof(saved_header.blake3));

    vireo_chunk_view_t const expected_unchanged = {
        .header = saved_header,
        .data = saved_data,
    };

    vireo_chunk_view_t view = expected_unchanged;
    vireo_chunk_issue_t issue = VIREO_CHUNK_ISSUE_CRC_MISMATCH;

    /* 1. body 为 NULL */
    errno = EACCES;
    vireo_result_t result = vireo_chunk_body_decode(NULL, sizeof(body), &view, &issue);
    int actual_errno = errno;

    int failures =
        expect_result("chunk decode null body result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_issue("chunk decode null body issue", issue, VIREO_CHUNK_ISSUE_NONE);
    failures += expect_errno_value("chunk decode null body errno", actual_errno, EACCES);
    failures += expect_header("chunk decode null body metadata keep", &view.header,
                              &expected_unchanged.header);
    failures += expect_true("chunk decode null body data pointer keep",
                            view.data == expected_unchanged.data);

    /* 2. out_view 为 NULL */
    issue = VIREO_CHUNK_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_chunk_body_decode(body, sizeof(body), NULL, &issue);
    actual_errno = errno;

    failures +=
        expect_result("chunk decode null view result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_issue("chunk decode null view issue", issue, VIREO_CHUNK_ISSUE_NONE);
    failures += expect_errno_value("chunk decode null view errno", actual_errno, EACCES);

    /* 3. out_issue 为 NULL */
    view = expected_unchanged;

    errno = EACCES;
    result = vireo_chunk_body_decode(body, sizeof(body), &view, NULL);
    actual_errno = errno;

    failures +=
        expect_result("chunk decode null issue result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_errno_value("chunk decode null issue errno", actual_errno, EACCES);
    failures += expect_header("chunk decode null issue metadata keep", &view.header,
                              &expected_unchanged.header);
    failures += expect_true("chunk decode null issue data pointer keep",
                            view.data == expected_unchanged.data);

    return failures;
}

/* 验证 decode 的 body 截断、总长度超限和失败视图保持 */
static int test_body_decode_body_size_errors(void) {
    static uint8_t const body[VIREO_CHUNK_HEADER_SIZE] = {
        /* chunk_index = 0，chunk_header_len = 56 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x38,

        /* offset = 0 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,

        /* data_len = 0，crc32c = 0 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,

        /* 全零占位摘要 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };

    static uint8_t const saved_data[] = {
        0xDE,
        0xAD,
    };

    vireo_chunk_header_t saved_header = make_valid_header();
    saved_header.chunk_index = UINT32_C(0xA1A2A3A4);
    saved_header.offset = UINT64_C(0x1122334455667788);
    saved_header.data_len = UINT32_C(2);
    saved_header.crc32c = UINT32_C(0xB1B2B3B4);
    memset(saved_header.blake3, 0x5A, sizeof(saved_header.blake3));

    vireo_chunk_view_t const expected_unchanged = {
        .header = saved_header,
        .data = saved_data,
    };

    vireo_chunk_view_t view = expected_unchanged;
    vireo_chunk_issue_t issue = VIREO_CHUNK_ISSUE_CRC_MISMATCH;

    /* 1. 完整 body 只有 55 字节，固定元数据被截断 */
    errno = EACCES;
    vireo_result_t result = vireo_chunk_body_decode(body, sizeof(body) - 1U, &view, &issue);
    int actual_errno = errno;

    int failures =
        expect_result("chunk decode truncated body result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("chunk decode truncated body issue", issue,
                             VIREO_CHUNK_ISSUE_TRUNCATED_HEADER);
    failures += expect_errno_value("chunk decode truncated body errno", actual_errno, EACCES);
    failures += expect_header("chunk decode truncated body metadata keep", &view.header,
                              &expected_unchanged.header);
    failures += expect_true("chunk decode truncated body data pointer keep",
                            view.data == expected_unchanged.data);

    /* 2. 完整 body 长度超过协议硬上限 */
    view = expected_unchanged;
    issue = VIREO_CHUNK_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result =
        vireo_chunk_body_decode(body, (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE + 1U, &view, &issue);
    actual_errno = errno;

    failures += expect_result("chunk decode oversized body result", result, VIREO_RESULT_PROTOCOL);
    failures +=
        expect_issue("chunk decode oversized body issue", issue, VIREO_CHUNK_ISSUE_BODY_TOO_LARGE);
    failures += expect_errno_value("chunk decode oversized body errno", actual_errno, EACCES);
    failures += expect_header("chunk decode oversized body metadata keep", &view.header,
                              &expected_unchanged.header);
    failures += expect_true("chunk decode oversized body data pointer keep",
                            view.data == expected_unchanged.data);

    return failures;
}

/* 验证 decode 拒绝错误的固定元数据长度字段，并保持输出视图 */
static int test_body_decode_invalid_header_length(void) {
    static uint8_t const valid_body[VIREO_CHUNK_HEADER_SIZE] = {
        /* chunk_index = 0，chunk_header_len = 56 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x38,

        /* offset = 0 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,

        /* data_len = 0，crc32c = 0 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,

        /* 全零占位摘要 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };

    static uint8_t const saved_data[] = {
        0xDE,
        0xAD,
    };

    vireo_chunk_header_t saved_header = make_valid_header();
    saved_header.chunk_index = UINT32_C(0xA1A2A3A4);
    saved_header.offset = UINT64_C(0x1122334455667788);
    saved_header.data_len = UINT32_C(2);
    saved_header.crc32c = UINT32_C(0xB1B2B3B4);
    memset(saved_header.blake3, 0x5A, sizeof(saved_header.blake3));

    vireo_chunk_view_t const expected_unchanged = {
        .header = saved_header,
        .data = saved_data,
    };

    uint8_t body[sizeof(valid_body)];
    vireo_chunk_view_t view = expected_unchanged;
    vireo_chunk_issue_t issue = VIREO_CHUNK_ISSUE_CRC_MISMATCH;

    /* 1. 实际 body 为 56 字节，字段却声明为 55 */
    memcpy(body, valid_body, sizeof(body));
    body[VIREO_CHUNK_HEADER_LENGTH_OFFSET + 3U] = UINT8_C(0x37);

    errno = EACCES;
    vireo_result_t result = vireo_chunk_body_decode(body, sizeof(body), &view, &issue);
    int actual_errno = errno;

    int failures =
        expect_result("chunk decode smaller header length result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("chunk decode smaller header length issue", issue,
                             VIREO_CHUNK_ISSUE_INVALID_HEADER_LENGTH);
    failures +=
        expect_errno_value("chunk decode smaller header length errno", actual_errno, EACCES);
    failures += expect_header("chunk decode smaller header length metadata keep", &view.header,
                              &expected_unchanged.header);
    failures += expect_true("chunk decode smaller header length data pointer keep",
                            view.data == expected_unchanged.data);

    /* 2. 实际 body 仍为 56 字节，字段却声明为 57 */
    memcpy(body, valid_body, sizeof(body));
    body[VIREO_CHUNK_HEADER_LENGTH_OFFSET + 3U] = UINT8_C(0x39);
    view = expected_unchanged;
    issue = VIREO_CHUNK_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_chunk_body_decode(body, sizeof(body), &view, &issue);
    actual_errno = errno;

    failures +=
        expect_result("chunk decode larger header length result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("chunk decode larger header length issue", issue,
                             VIREO_CHUNK_ISSUE_INVALID_HEADER_LENGTH);
    failures += expect_errno_value("chunk decode larger header length errno", actual_errno, EACCES);
    failures += expect_header("chunk decode larger header length metadata keep", &view.header,
                              &expected_unchanged.header);
    failures += expect_true("chunk decode larger header length data pointer keep",
                            view.data == expected_unchanged.data);

    return failures;
}

/* 验证 decode 拒绝实际 data 比声明长度少或多的完整 body */
static int test_body_decode_body_length_mismatch(void) {
    static uint8_t const body[] = {
        /* chunk_index = 0，chunk_header_len = 56 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x38,

        /* offset = 0 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,

        /* data_len = 3，crc32c = 0 */
        0x00,
        0x00,
        0x00,
        0x03,
        0x00,
        0x00,
        0x00,
        0x00,

        /* 全零占位摘要 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,

        /* 底层数组准备 4 个字节，各场景通过 body_size 限定输入 */
        0xAA,
        0xBB,
        0xCC,
        0xDD,
    };

    static uint8_t const saved_data[] = {
        0xDE,
        0xAD,
    };

    vireo_chunk_header_t saved_header = make_valid_header();
    saved_header.chunk_index = UINT32_C(0xA1A2A3A4);
    saved_header.offset = UINT64_C(0x1122334455667788);
    saved_header.data_len = UINT32_C(2);
    saved_header.crc32c = UINT32_C(0xB1B2B3B4);
    memset(saved_header.blake3, 0x5A, sizeof(saved_header.blake3));

    vireo_chunk_view_t const expected_unchanged = {
        .header = saved_header,
        .data = saved_data,
    };

    vireo_chunk_view_t view = expected_unchanged;
    vireo_chunk_issue_t issue = VIREO_CHUNK_ISSUE_CRC_MISMATCH;

    /* 1. 声明 data 为 3 字节，实际完整 body 只包含 2 字节 data */
    errno = EACCES;
    vireo_result_t result =
        vireo_chunk_body_decode(body, (size_t)VIREO_CHUNK_HEADER_SIZE + 2U, &view, &issue);
    int actual_errno = errno;

    int failures = expect_result("chunk decode short data result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("chunk decode short data issue", issue,
                             VIREO_CHUNK_ISSUE_BODY_LENGTH_MISMATCH);
    failures += expect_errno_value("chunk decode short data errno", actual_errno, EACCES);
    failures += expect_header("chunk decode short data metadata keep", &view.header,
                              &expected_unchanged.header);
    failures +=
        expect_true("chunk decode short data pointer keep", view.data == expected_unchanged.data);

    /* 2. 声明 data 为 3 字节，实际完整 body 却包含 4 字节 data */
    view = expected_unchanged;
    issue = VIREO_CHUNK_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_chunk_body_decode(body, sizeof(body), &view, &issue);
    actual_errno = errno;

    failures += expect_result("chunk decode trailing byte result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("chunk decode trailing byte issue", issue,
                             VIREO_CHUNK_ISSUE_BODY_LENGTH_MISMATCH);
    failures += expect_errno_value("chunk decode trailing byte errno", actual_errno, EACCES);
    failures += expect_header("chunk decode trailing byte metadata keep", &view.header,
                              &expected_unchanged.header);
    failures += expect_true("chunk decode trailing byte data pointer keep",
                            view.data == expected_unchanged.data);

    return failures;
}

/* 验证 decode 拒绝 wire 中超限的 data_len，并保持输出视图 */
static int test_body_decode_oversized_data_length(void) {
    static uint8_t const body[VIREO_CHUNK_HEADER_SIZE] = {
        /* chunk_index = 0，chunk_header_len = 56 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x38,

        /* offset = 0 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,

        /* data_len = MAX + 1，即 0x00FFFFC9；crc32c = 0 */
        0x00,
        0xFF,
        0xFF,
        0xC9,
        0x00,
        0x00,
        0x00,
        0x00,

        /* 全零占位摘要 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };

    static uint8_t const saved_data[] = {
        0xDE,
        0xAD,
    };

    vireo_chunk_header_t saved_header = make_valid_header();
    saved_header.chunk_index = UINT32_C(0xA1A2A3A4);
    saved_header.offset = UINT64_C(0x1122334455667788);
    saved_header.data_len = UINT32_C(2);
    saved_header.crc32c = UINT32_C(0xB1B2B3B4);
    memset(saved_header.blake3, 0x5A, sizeof(saved_header.blake3));

    vireo_chunk_view_t const expected_unchanged = {
        .header = saved_header,
        .data = saved_data,
    };

    vireo_chunk_view_t view = expected_unchanged;
    vireo_chunk_issue_t issue = VIREO_CHUNK_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    vireo_result_t const result = vireo_chunk_body_decode(body, sizeof(body), &view, &issue);
    int const actual_errno = errno;

    int failures =
        expect_result("chunk decode oversized data length result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("chunk decode oversized data length issue", issue,
                             VIREO_CHUNK_ISSUE_DATA_TOO_LARGE);
    failures +=
        expect_errno_value("chunk decode oversized data length errno", actual_errno, EACCES);
    failures += expect_header("chunk decode oversized data length metadata keep", &view.header,
                              &expected_unchanged.header);
    failures += expect_true("chunk decode oversized data length data pointer keep",
                            view.data == expected_unchanged.data);

    return failures;
}

/* 验证 decode 拒绝文件区间终点溢出，并保持输出视图和 errno */
static int test_body_decode_offset_overflow(void) {
    static uint8_t const body[] = {
        /* chunk_index = 0，chunk_header_len = 56 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x38,

        /* offset = UINT64_MAX - 1，即 0xFFFFFFFFFFFFFFFE */
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFE,

        /* data_len = 2，crc32c = 0 */
        0x00,
        0x00,
        0x00,
        0x02,
        0x00,
        0x00,
        0x00,
        0x00,

        /* 全零占位摘要 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,

        /* 原始 data：与声明的 2 字节一致 */
        0xAA,
        0xBB,
    };

    static uint8_t const saved_data[] = {
        0xDE,
        0xAD,
    };

    vireo_chunk_header_t saved_header = make_valid_header();
    saved_header.chunk_index = UINT32_C(0xA1A2A3A4);
    saved_header.offset = UINT64_C(0x1122334455667788);
    saved_header.data_len = UINT32_C(2);
    saved_header.crc32c = UINT32_C(0xB1B2B3B4);
    memset(saved_header.blake3, 0x5A, sizeof(saved_header.blake3));

    vireo_chunk_view_t const expected_unchanged = {
        .header = saved_header,
        .data = saved_data,
    };

    vireo_chunk_view_t view = expected_unchanged;
    vireo_chunk_issue_t issue = VIREO_CHUNK_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    vireo_result_t const result = vireo_chunk_body_decode(body, sizeof(body), &view, &issue);
    int const actual_errno = errno;

    int failures =
        expect_result("chunk decode offset overflow result", result, VIREO_RESULT_PROTOCOL);
    failures +=
        expect_issue("chunk decode offset overflow issue", issue, VIREO_CHUNK_ISSUE_RANGE_OVERFLOW);
    failures += expect_errno_value("chunk decode offset overflow errno", actual_errno, EACCES);
    failures += expect_header("chunk decode offset overflow metadata keep", &view.header,
                              &expected_unchanged.header);
    failures += expect_true("chunk decode offset overflow data pointer keep",
                            view.data == expected_unchanged.data);

    return failures;
}

/* 验证 decode 接受文件区间终点恰好等于 UINT64_MAX */
static int test_body_decode_offset_max_boundary(void) {
    static uint8_t const body[] = {
        /* chunk_index = 0，chunk_header_len = 56 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x38,

        /* offset = UINT64_MAX - 2，即 0xFFFFFFFFFFFFFFFD */
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFD,

        /* data_len = 2，crc32c = 0 */
        0x00,
        0x00,
        0x00,
        0x02,
        0x00,
        0x00,
        0x00,
        0x00,

        /* 全零占位摘要 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,

        /* 原始 data */
        0xAA,
        0xBB,
    };

    static uint8_t const expected_data[] = {
        0xAA,
        0xBB,
    };

    vireo_chunk_header_t expected_header = make_valid_header();
    expected_header.offset = UINT64_MAX - UINT64_C(2);
    expected_header.data_len = UINT32_C(2);

    vireo_chunk_view_t view = {0};
    vireo_chunk_issue_t issue = VIREO_CHUNK_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    vireo_result_t const result = vireo_chunk_body_decode(body, sizeof(body), &view, &issue);
    int const actual_errno = errno;

    int failures = expect_result("chunk decode max end offset result", result, VIREO_OK);
    failures += expect_issue("chunk decode max end offset issue", issue, VIREO_CHUNK_ISSUE_NONE);
    failures += expect_errno_value("chunk decode max end offset errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures +=
            expect_header("chunk decode max end offset metadata", &view.header, &expected_header);
        failures += expect_true("chunk decode max end offset borrowed data pointer",
                                view.data == body + VIREO_CHUNK_DATA_OFFSET);

        if (view.data == body + VIREO_CHUNK_DATA_OFFSET &&
            view.header.data_len == sizeof(expected_data)) {
            failures += expect_bytes("chunk decode max end offset data bytes", view.data,
                                     expected_data, sizeof(expected_data));
        }
    }

    return failures;
}

/* 验证 decode 接受空 data，并返回不可解引用的尾后 data 指针 */
static int test_body_decode_empty_data(void) {
    static uint8_t const body[] = {
        /* chunk_index = 0，chunk_header_len = 56 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x38,

        /* offset = 0 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,

        /* data_len = 0，crc32c = 0 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,

        /* 全零占位摘要 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };

    vireo_chunk_header_t const expected_header = make_valid_header();

    vireo_chunk_view_t view = {0};
    vireo_chunk_issue_t issue = VIREO_CHUNK_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    vireo_result_t const result = vireo_chunk_body_decode(body, sizeof(body), &view, &issue);
    int const actual_errno = errno;

    int failures = expect_result("chunk decode empty data result", result, VIREO_OK);
    failures += expect_issue("chunk decode empty data issue", issue, VIREO_CHUNK_ISSUE_NONE);
    failures += expect_errno_value("chunk decode empty data errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures +=
            expect_header("chunk decode empty data metadata", &view.header, &expected_header);
        failures += expect_true("chunk decode empty data one-past pointer",
                                view.data == body + sizeof(body));
    }

    return failures;
}

/* 验证 decode 接受恰好达到协议上限的完整 chunk body */
static int test_body_decode_max_data_boundary(void) {
    static uint8_t body[VIREO_PROTOCOL_MAX_BODY_SIZE] = {
        /* chunk_index = 0，chunk_header_len = 56 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x38,

        /* offset = 0 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,

        /* data_len = MAX，即 0x00FFFFC8；crc32c = 0 */
        0x00,
        0xFF,
        0xFF,
        0xC8,
        0x00,
        0x00,
        0x00,
        0x00,

        /* 全零占位摘要；后续 data 区域在调用前填充 */
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };

    memset(body + VIREO_CHUNK_DATA_OFFSET, 0x5A, (size_t)VIREO_CHUNK_MAX_DATA_SIZE);

    vireo_chunk_header_t expected_header = make_valid_header();
    expected_header.data_len = VIREO_CHUNK_MAX_DATA_SIZE;

    vireo_chunk_view_t view = {0};
    vireo_chunk_issue_t issue = VIREO_CHUNK_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    vireo_result_t const result = vireo_chunk_body_decode(body, sizeof(body), &view, &issue);
    int const actual_errno = errno;

    int failures = expect_result("chunk decode max data result", result, VIREO_OK);
    failures += expect_issue("chunk decode max data issue", issue, VIREO_CHUNK_ISSUE_NONE);
    failures += expect_errno_value("chunk decode max data errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures += expect_header("chunk decode max data metadata", &view.header, &expected_header);
        failures += expect_true("chunk decode max data borrowed pointer",
                                view.data == body + VIREO_CHUNK_DATA_OFFSET);

        if (view.data == body + VIREO_CHUNK_DATA_OFFSET &&
            view.header.data_len == VIREO_CHUNK_MAX_DATA_SIZE) {
            failures +=
                expect_true("chunk decode max data first byte", view.data[0] == UINT8_C(0x5A));
            failures +=
                expect_true("chunk decode max data last byte",
                            view.data[(size_t)VIREO_CHUNK_MAX_DATA_SIZE - 1U] == UINT8_C(0x5A));
        }
    }

    return failures;
}

/* 验证 encode 接受最大 data，并能使用恰好足够的 body 容量 */
static int test_body_encode_max_data_boundary(void) {
    static uint8_t data[VIREO_CHUNK_MAX_DATA_SIZE];
    static uint8_t body[VIREO_PROTOCOL_MAX_BODY_SIZE];

    static uint8_t const expected_header_length[] = {
        0x00,
        0x00,
        0x00,
        0x38,
    };

    static uint8_t const expected_data_length[] = {
        0x00,
        0xFF,
        0xFF,
        0xC8,
    };

    vireo_chunk_header_t header = make_valid_header();
    header.data_len = VIREO_CHUNK_MAX_DATA_SIZE;

    size_t body_size = (size_t)777;

    memset(data, 0x5A, sizeof(data));
    memset(body, 0xA5, sizeof(body));

    errno = EACCES;
    vireo_result_t const result =
        vireo_chunk_body_encode(&header, data, sizeof(data), body, sizeof(body), &body_size);
    int const actual_errno = errno;

    int failures = expect_result("chunk encode max data result", result, VIREO_OK);
    failures += expect_errno_value("chunk encode max data errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures += expect_size("chunk encode max data body size", body_size, sizeof(body));
        failures += expect_bytes("chunk encode max data header length bytes",
                                 body + VIREO_CHUNK_HEADER_LENGTH_OFFSET, expected_header_length,
                                 sizeof(expected_header_length));
        failures += expect_bytes("chunk encode max data length bytes",
                                 body + VIREO_CHUNK_DATA_LENGTH_OFFSET, expected_data_length,
                                 sizeof(expected_data_length));
        failures += expect_bytes("chunk encode max data bytes", body + VIREO_CHUNK_DATA_OFFSET,
                                 data, sizeof(data));
    }

    return failures;
}

/* 验证 CRC 计算接受最大 data 长度，并得到固定输入的预期结果 */
static int test_data_crc32c_calculate_max_data_boundary(void) {
    static uint8_t const data[VIREO_CHUNK_MAX_DATA_SIZE] = {0};

    uint32_t crc32c = UINT32_C(0xA5A5A5A5);

    errno = EACCES;
    vireo_result_t const result = vireo_chunk_data_crc32c_calculate(data, sizeof(data), &crc32c);
    int const actual_errno = errno;

    int failures = expect_result("chunk crc max data result", result, VIREO_OK);
    failures += expect_errno_value("chunk crc max data errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures += expect_u32("chunk crc max data value", crc32c, UINT32_C(0x94506079));
    }

    return failures;
}

/* 验证 data CRC 校验的成功路径、内容变异和视图保持 */
static int test_data_crc32c_verify_success_and_mismatch(void) {
    static uint8_t const data[] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
    };

    static uint8_t const modified_data[] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x38,
    };

    vireo_chunk_header_t header = make_valid_header();
    header.data_len = UINT32_C(9);
    header.crc32c = UINT32_C(0xE3069283);

    vireo_chunk_view_t view = {
        .header = header,
        .data = data,
    };

    vireo_chunk_issue_t issue = VIREO_CHUNK_ISSUE_DATA_TOO_LARGE;

    /* 1. data 与携带的 CRC 一致 */
    errno = EACCES;
    vireo_result_t result = vireo_chunk_data_crc32c_verify(&view, &issue);
    int actual_errno = errno;

    int failures = expect_result("chunk crc verify success result", result, VIREO_OK);
    failures += expect_issue("chunk crc verify success issue", issue, VIREO_CHUNK_ISSUE_NONE);
    failures += expect_errno_value("chunk crc verify success errno", actual_errno, EACCES);
    failures += expect_header("chunk crc verify success metadata keep", &view.header, &header);
    failures += expect_true("chunk crc verify success data pointer keep", view.data == data);

    /* 2. 只改变 data 内容，长度和携带的 CRC 保持不变 */
    view.header = header;
    view.data = modified_data;
    issue = VIREO_CHUNK_ISSUE_DATA_TOO_LARGE;

    errno = EACCES;
    result = vireo_chunk_data_crc32c_verify(&view, &issue);
    actual_errno = errno;

    failures += expect_result("chunk crc verify mismatch result", result, VIREO_RESULT_PROTOCOL);
    failures +=
        expect_issue("chunk crc verify mismatch issue", issue, VIREO_CHUNK_ISSUE_CRC_MISMATCH);
    failures += expect_errno_value("chunk crc verify mismatch errno", actual_errno, EACCES);
    failures += expect_header("chunk crc verify mismatch metadata keep", &view.header, &header);
    failures +=
        expect_true("chunk crc verify mismatch data pointer keep", view.data == modified_data);

    return failures;
}

/* 验证空 data 的指针形式、CRC 比较和视图保持 */
static int test_data_crc32c_verify_empty_data(void) {
    static uint8_t const data[] = {
        0xA5,
    };

    vireo_chunk_header_t header = make_valid_header();

    vireo_chunk_view_t view = {
        .header = header,
        .data = NULL,
    };

    vireo_chunk_issue_t issue = VIREO_CHUNK_ISSUE_DATA_TOO_LARGE;

    /* 1. data 为 NULL，长度为零，携带的 CRC 为零 */
    errno = EACCES;
    vireo_result_t result = vireo_chunk_data_crc32c_verify(&view, &issue);
    int actual_errno = errno;

    int failures = expect_result("chunk crc verify empty null data result", result, VIREO_OK);
    failures +=
        expect_issue("chunk crc verify empty null data issue", issue, VIREO_CHUNK_ISSUE_NONE);
    failures += expect_errno_value("chunk crc verify empty null data errno", actual_errno, EACCES);
    failures +=
        expect_header("chunk crc verify empty null data metadata keep", &view.header, &header);
    failures += expect_true("chunk crc verify empty null data pointer keep", view.data == NULL);

    /* 2. data 非 NULL，但长度仍为零，不应读取数组中的 0xA5 */
    view.header = header;
    view.data = data;
    issue = VIREO_CHUNK_ISSUE_DATA_TOO_LARGE;

    errno = EACCES;
    result = vireo_chunk_data_crc32c_verify(&view, &issue);
    actual_errno = errno;

    failures += expect_result("chunk crc verify empty nonnull data result", result, VIREO_OK);
    failures +=
        expect_issue("chunk crc verify empty nonnull data issue", issue, VIREO_CHUNK_ISSUE_NONE);
    failures +=
        expect_errno_value("chunk crc verify empty nonnull data errno", actual_errno, EACCES);
    failures +=
        expect_header("chunk crc verify empty nonnull data metadata keep", &view.header, &header);
    failures += expect_true("chunk crc verify empty nonnull data pointer keep", view.data == data);

    /* 3. data 为空，但携带的 CRC 不为零，仍应报告不匹配 */
    header = make_valid_header();
    header.crc32c = UINT32_C(1);
    view.header = header;
    view.data = NULL;
    issue = VIREO_CHUNK_ISSUE_DATA_TOO_LARGE;

    errno = EACCES;
    result = vireo_chunk_data_crc32c_verify(&view, &issue);
    actual_errno = errno;

    failures +=
        expect_result("chunk crc verify empty mismatch result", result, VIREO_RESULT_PROTOCOL);
    failures += expect_issue("chunk crc verify empty mismatch issue", issue,
                             VIREO_CHUNK_ISSUE_CRC_MISMATCH);
    failures += expect_errno_value("chunk crc verify empty mismatch errno", actual_errno, EACCES);
    failures +=
        expect_header("chunk crc verify empty mismatch metadata keep", &view.header, &header);
    failures += expect_true("chunk crc verify empty mismatch data pointer keep", view.data == NULL);

    return failures;
}

/* 验证 CRC 校验的非法参数、issue 初始化和视图保持 */
static int test_data_crc32c_verify_invalid_arguments(void) {
    static uint8_t const data[] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
    };

    vireo_chunk_header_t header = make_valid_header();
    header.data_len = UINT32_C(9);
    header.crc32c = UINT32_C(0xE3069283);

    vireo_chunk_view_t view = {
        .header = header,
        .data = data,
    };

    vireo_chunk_issue_t issue = VIREO_CHUNK_ISSUE_CRC_MISMATCH;

    /* 1. view 为 NULL，但提供有效的 issue 输出 */
    errno = EACCES;
    vireo_result_t result = vireo_chunk_data_crc32c_verify(NULL, &issue);
    int actual_errno = errno;

    int failures =
        expect_result("chunk crc verify null view result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_issue("chunk crc verify null view issue", issue, VIREO_CHUNK_ISSUE_NONE);
    failures += expect_errno_value("chunk crc verify null view errno", actual_errno, EACCES);

    /* 2. out_issue 为 NULL，输入视图仍应保持不变 */
    errno = EACCES;
    result = vireo_chunk_data_crc32c_verify(&view, NULL);
    actual_errno = errno;

    failures +=
        expect_result("chunk crc verify null issue result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_errno_value("chunk crc verify null issue errno", actual_errno, EACCES);
    failures += expect_header("chunk crc verify null issue metadata keep", &view.header, &header);
    failures += expect_true("chunk crc verify null issue data pointer keep", view.data == data);

    /* 3. data 为 NULL，但元数据声明存在九个 data 字节 */
    view.header = header;
    view.data = NULL;
    issue = VIREO_CHUNK_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    result = vireo_chunk_data_crc32c_verify(&view, &issue);
    actual_errno = errno;

    failures += expect_result("chunk crc verify null nonempty data result", result,
                              VIREO_RESULT_INVALID_ARGUMENT);
    failures +=
        expect_issue("chunk crc verify null nonempty data issue", issue, VIREO_CHUNK_ISSUE_NONE);
    failures +=
        expect_errno_value("chunk crc verify null nonempty data errno", actual_errno, EACCES);
    failures +=
        expect_header("chunk crc verify null nonempty data metadata keep", &view.header, &header);
    failures += expect_true("chunk crc verify null nonempty data pointer keep", view.data == NULL);

    return failures;
}

/* 验证 CRC 校验传播超限长度的范围错误，并保持视图和 errno */
static int test_data_crc32c_verify_range_errors(void) {
    static uint8_t const data[(size_t)VIREO_CHUNK_MAX_DATA_SIZE + 1U] = {0};

    vireo_chunk_header_t header = make_valid_header();
    header.data_len = VIREO_CHUNK_MAX_DATA_SIZE + UINT32_C(1);
    header.crc32c = UINT32_C(0xA5A5A5A5);

    vireo_chunk_view_t view = {
        .header = header,
        .data = data,
    };

    vireo_chunk_issue_t issue = VIREO_CHUNK_ISSUE_CRC_MISMATCH;

    errno = EACCES;
    vireo_result_t const result = vireo_chunk_data_crc32c_verify(&view, &issue);
    int const actual_errno = errno;

    int failures =
        expect_result("chunk crc verify oversized data result", result, VIREO_RESULT_RANGE);
    failures +=
        expect_issue("chunk crc verify oversized data issue", issue, VIREO_CHUNK_ISSUE_NONE);
    failures += expect_errno_value("chunk crc verify oversized data errno", actual_errno, EACCES);
    failures +=
        expect_header("chunk crc verify oversized data metadata keep", &view.header, &header);
    failures += expect_true("chunk crc verify oversized data pointer keep", view.data == data);

    return failures;
}

/* 验证 data CRC 不包含 index、offset 和 BLAKE3 摘要字节 */
static int test_data_crc32c_verify_excludes_metadata(void) {
    static uint8_t const data[] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
    };

    vireo_chunk_header_t header = make_valid_header();
    header.data_len = UINT32_C(9);
    header.crc32c = UINT32_C(0xE3069283);

    vireo_chunk_view_t view = {
        .header = header,
        .data = data,
    };

    vireo_chunk_issue_t issue = VIREO_CHUNK_ISSUE_DATA_TOO_LARGE;

    /* 1. 使用基准元数据验证固定 data */
    errno = EACCES;
    vireo_result_t result = vireo_chunk_data_crc32c_verify(&view, &issue);
    int actual_errno = errno;

    int failures = expect_result("chunk crc verify base metadata result", result, VIREO_OK);
    failures += expect_issue("chunk crc verify base metadata issue", issue, VIREO_CHUNK_ISSUE_NONE);
    failures += expect_errno_value("chunk crc verify base metadata errno", actual_errno, EACCES);
    failures += expect_header("chunk crc verify base metadata keep", &view.header, &header);
    failures += expect_true("chunk crc verify base metadata data pointer keep", view.data == data);

    /* 2. 只改变不属于 data CRC 计算输入的元数据 */
    header.chunk_index = UINT32_C(0x12345678);
    header.offset = UINT64_C(0x1122334455667788);
    memset(header.blake3, 0x5A, sizeof(header.blake3));

    view.header = header;
    view.data = data;
    issue = VIREO_CHUNK_ISSUE_DATA_TOO_LARGE;

    errno = EACCES;
    result = vireo_chunk_data_crc32c_verify(&view, &issue);
    actual_errno = errno;

    failures += expect_result("chunk crc verify changed metadata result", result, VIREO_OK);
    failures +=
        expect_issue("chunk crc verify changed metadata issue", issue, VIREO_CHUNK_ISSUE_NONE);
    failures += expect_errno_value("chunk crc verify changed metadata errno", actual_errno, EACCES);
    failures += expect_header("chunk crc verify changed metadata keep", &view.header, &header);
    failures +=
        expect_true("chunk crc verify changed metadata data pointer keep", view.data == data);

    return failures;
}

int main(void) {
    typedef int (*test_function_t)(void);

    static test_function_t const tests[] = {
        test_data_crc32c_calculate_golden,
        test_data_crc32c_calculate_empty_data,
        test_data_crc32c_calculate_invalid_arguments,
        test_data_crc32c_calculate_range_errors,
        test_data_crc32c_calculate_max_data_boundary,

        test_body_encode_golden,
        test_body_encode_invalid_arguments,
        test_body_encode_capacity_and_length_errors,
        test_body_encode_oversized_data,
        test_body_encode_offset_overflow,
        test_body_encode_offset_max_boundary,
        test_body_encode_empty_data,
        test_body_encode_larger_capacity_tail_keep,
        test_body_encode_max_data_boundary,

        test_body_decode_golden,
        test_body_decode_invalid_arguments,
        test_body_decode_body_size_errors,
        test_body_decode_invalid_header_length,
        test_body_decode_body_length_mismatch,
        test_body_decode_oversized_data_length,
        test_body_decode_offset_overflow,
        test_body_decode_offset_max_boundary,
        test_body_decode_empty_data,
        test_body_decode_max_data_boundary,

        test_data_crc32c_verify_success_and_mismatch,
        test_data_crc32c_verify_empty_data,
        test_data_crc32c_verify_invalid_arguments,
        test_data_crc32c_verify_range_errors,
        test_data_crc32c_verify_excludes_metadata,
    };

    int failures = 0;

    for (size_t index = 0; index < VIREO_TEST_ARRAY_COUNT(tests); ++index) {
        failures += tests[index]();
    }

    if (failures != 0) {
        fprintf(stderr, "test_chunk: %d assertion failure(s)\n", failures);
        return EXIT_FAILURE;
    }

    printf("test_chunk: all %zu test groups passed\n", VIREO_TEST_ARRAY_COUNT(tests));

    return EXIT_SUCCESS;
}

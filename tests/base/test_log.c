/*
 * PROJECT : VIREO
 * FILE    : test_log.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-01
 * BRIEF   : 此模块负责：
 * -- 用固定 golden 和独立解码验证日志单行格式与全部字节转义
 * -- 检查日历、字段长度、容量、输出保持、输入保持和 errno 合同
 */
#include <vireo/base/log.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(VIREO_LOG_LEVEL_DEBUG == 0, "DEBUG value");
_Static_assert(VIREO_LOG_LEVEL_INFO == 1, "INFO value");
_Static_assert(VIREO_LOG_LEVEL_WARN == 2, "WARN value");
_Static_assert(VIREO_LOG_LEVEL_ERROR == 3, "ERROR value");

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

static vireo_log_timestamp_t const normal_time = {
    .year = 2026, .month = 10, .day = 1, .hour = 10, .minute = 20, .second = 30,
    .nanosecond = UINT32_C(123456789),
};

static vireo_log_record_t normal_record(void) {
    vireo_log_record_t record = {
        .level = VIREO_LOG_LEVEL_INFO,
        .module = {.data = (uint8_t const *)"storage", .size = 7},
        .connection_id = 42, .generation = 7, .sequence = 103,
        .message = {.data = (uint8_t const *)"chunk accepted", .size = 14},
    };
    return record;
}

/* 独立完整 golden 锁定字段顺序、空 ID、数字及末尾真实 LF。 */
static char const golden[] =
    "2026-10-01T10:20:30.123456789Z level=INFO tid=4127 module=\"storage\""
    " connection_id=42 generation=7 sequence=103 request_id=\"\" task_id=\"\""
    " message=\"chunk accepted\"\n";

/**
 * @brief 检查一个失败调用是否完整保持整个输出缓冲区及长度
 * @param[in] record/time/tid 被测输入；只借用，可用 NULL 测必填参数。
 * @param[in] capacity 不超过本 helper 的实际 buffer 长度。
 * @param[in] expected 期望的失败类别。
 * @return 0 表示所有失败合同成立，1 表示测试失败。
 * @note 内部 buffer 全部字节用 sentinel 初始化；检查不只限于字符串前缀。
 */
static int expect_failure(vireo_log_record_t const *record, vireo_log_timestamp_t const *time,
                          uint64_t tid, size_t capacity, vireo_result_t expected) {
    char buffer[1024];
    char saved[sizeof(buffer)];
    memset(buffer, 0x5A, sizeof(buffer));
    memcpy(saved, buffer, sizeof(buffer));
    size_t size = 987;
    errno = EACCES;
    vireo_result_t result = vireo_log_format(record, time, tid, buffer, capacity, &size);
    CHECK(result == expected);
    CHECK(errno == EACCES);
    CHECK(size == 987);
    CHECK(memcmp(buffer, saved, sizeof(buffer)) == 0);
    return 0;
}

static int check_level_names(void) {
    vireo_log_level_t const levels[] = {VIREO_LOG_LEVEL_DEBUG, VIREO_LOG_LEVEL_INFO,
                                       VIREO_LOG_LEVEL_WARN, VIREO_LOG_LEVEL_ERROR};
    char const *const names[] = {"DEBUG", "INFO", "WARN", "ERROR"};
    for (size_t i = 0; i < 4; ++i) {
        errno = EBUSY;
        char const *name = vireo_log_level_name(levels[i]);
        CHECK(name != NULL && strcmp(name, names[i]) == 0);
        CHECK(name == vireo_log_level_name(levels[i]));
        CHECK(errno == EBUSY);
        vireo_log_record_t record = normal_record();
        record.level = levels[i];
        char buffer[1024];
        size_t size = 0;
        CHECK(vireo_log_format(&record, &normal_time, 1, buffer, sizeof(buffer), &size) == VIREO_OK);
        CHECK(strstr(buffer, names[i]) != NULL);
    }
    CHECK(strcmp(vireo_log_level_name((vireo_log_level_t)-1), "unknown") == 0);
    CHECK(strcmp(vireo_log_level_name((vireo_log_level_t)999), "unknown") == 0);
    return 0;
}

static int check_golden_line(void) {
    vireo_log_record_t record = normal_record();
    char buffer[1024];
    memset(buffer, 0x5A, sizeof(buffer));
    size_t size = 0;
    CHECK(vireo_log_format(&record, &normal_time, 4127, buffer, sizeof(buffer), &size) == VIREO_OK);
    CHECK(size == sizeof(golden) - 1);
    CHECK(memcmp(buffer, golden, sizeof(golden)) == 0);
    CHECK(buffer[size + 1] == (char)0x5A);
    return 0;
}

static int check_special_bytes(void) {
    uint8_t const bytes[] = {'A', '\n', 'B', 0, 'C', '\r', '\t', '"', '\\', 0x1F, 0x7F, 0x80, 0xFF};
    char const escaped[] = "A\\nB\\x00C\\r\\t\\\"\\\\\\x1F\\x7F\\x80\\xFF";
    vireo_log_record_t record = normal_record();
    vireo_log_span_t span = {.data = bytes, .size = sizeof(bytes)};
    record.module = span;
    record.request_id = span;
    record.task_id = span;
    record.message = span;
    char buffer[1024];
    size_t size = 0;
    CHECK(vireo_log_format(&record, &normal_time, 1, buffer, sizeof(buffer), &size) == VIREO_OK);
    char const *cursor = buffer;
    for (size_t i = 0; i < 4; ++i) {
        cursor = strstr(cursor, escaped);
        CHECK(cursor != NULL);
        cursor += strlen(escaped);
    }
    CHECK(strchr(buffer, '\n') == buffer + size - 1);
    CHECK(strchr(buffer, '\r') == NULL && strchr(buffer, '\t') == NULL);
    return 0;
}

/**
 * @brief 独立解码一个完整引号字段，用于全部 256 字节往返断言
 * @param[in] text 指向 formatter 输出的开引号；只读借用。
 * @param[out] decoded 调用者拥有的容量 256 字节的数组。
 * @param[out] out_size 接收已解码长度；只在成功时使用。
 * @return true 表示引号和转义语法完整，false 表示语法或长度非法。
 * @note 解码严格两位 hex；不使用 formatter 内部编码 helper。
 */
static bool decode_field(char const *text, uint8_t decoded[256], size_t *out_size) {
    static char const hex_digits[] = "0123456789ABCDEF";
    if (*text++ != '"') {
        return false;
    }
    size_t size = 0;
    while (*text != '"') {
        if (*text == '\0' || size == 256) {
            return false;
        }
        unsigned int value = (unsigned char)*text++;
        if (value == (unsigned int)'\\') {
            char tag = *text++;
            switch (tag) {
                case 'n': value = 10; break;
                case 'r': value = 13; break;
                case 't': value = 9; break;
                case '"': value = 34; break;
                case '\\': value = 92; break;
                case 'x': {
                    value = 0;
                    for (size_t i = 0; i < 2; ++i) {
                        if (*text == '\0') {
                            return false;
                        }
                        char const *hex = strchr(hex_digits, *text++);
                        if (hex == NULL) {
                            return false;
                        }
                        value = value * 16U + (unsigned int)(hex - hex_digits);
                    }
                    break;
                }
                default: return false;
            }
        } else if (value < 32U || value > 126U) {
            return false;
        }
        decoded[size++] = (uint8_t)value;
    }
    *out_size = size;
    return true;
}

static int check_all_bytes(void) {
    uint8_t bytes[256];
    for (size_t i = 0; i < sizeof(bytes); ++i) {
        bytes[i] = (uint8_t)i;
    }
    vireo_log_record_t record = normal_record();
    record.message = (vireo_log_span_t){.data = bytes, .size = sizeof(bytes)};
    char buffer[2048];
    size_t size = 0;
    CHECK(vireo_log_format(&record, &normal_time, 1, buffer, sizeof(buffer), &size) == VIREO_OK);
    char const *message = strstr(buffer, " message=");
    CHECK(message != NULL);
    uint8_t decoded[256];
    size_t decoded_size = 0;
    CHECK(decode_field(message + 9, decoded, &decoded_size));
    CHECK(decoded_size == sizeof(bytes) && memcmp(bytes, decoded, sizeof(bytes)) == 0);
    /* 所有字节经过日志边界后只有末尾真实 LF；不会包含中间 NUL。 */
    CHECK(strlen(buffer) == size && buffer[size - 1] == '\n');
    CHECK(strchr(buffer, '\n') == buffer + size - 1);
    return 0;
}

static int check_empty_spans(void) {
    vireo_log_record_t record = {.level = VIREO_LOG_LEVEL_DEBUG};
    char const expected[] =
        "2026-10-01T10:20:30.123456789Z level=DEBUG tid=1 module=\"\""
        " connection_id=0 generation=0 sequence=0 request_id=\"\" task_id=\"\" message=\"\"\n";
    char buffer[1024];
    size_t size = 0;
    CHECK(vireo_log_format(&record, &normal_time, 1, buffer, sizeof(buffer), &size) == VIREO_OK);
    CHECK(strcmp(buffer, expected) == 0);
    uint8_t byte = '-';
    record.module.data = &byte;
    record.message.data = &byte;
    record.request_id.data = &byte;
    record.task_id.data = &byte;
    CHECK(vireo_log_format(&record, &normal_time, 1, buffer, sizeof(buffer), &size) == VIREO_OK);
    CHECK(strcmp(buffer, expected) == 0);
    record.request_id.size = 1;
    CHECK(vireo_log_format(&record, &normal_time, 1, buffer, sizeof(buffer), &size) == VIREO_OK);
    CHECK(strstr(buffer, " request_id=\"-\"") != NULL);
    return 0;
}

static int check_integer_limits(void) {
    vireo_log_record_t record = normal_record();
    record.connection_id = UINT64_MAX;
    record.generation = UINT64_MAX;
    record.sequence = UINT32_MAX;
    vireo_log_timestamp_t time = {
        .year = 9999, .month = 12, .day = 31, .hour = 23, .minute = 59, .second = 59,
        .nanosecond = UINT32_C(999999999),
    };
    char const expected[] =
        "9999-12-31T23:59:59.999999999Z level=INFO tid=18446744073709551615 module=\"storage\""
        " connection_id=18446744073709551615 generation=18446744073709551615 sequence=4294967295"
        " request_id=\"\" task_id=\"\" message=\"chunk accepted\"\n";
    char buffer[1024];
    size_t size = 0;
    CHECK(vireo_log_format(&record, &time, UINT64_MAX, buffer, sizeof(buffer), &size) == VIREO_OK);
    CHECK(strcmp(buffer, expected) == 0 && size == sizeof(expected) - 1);
    return 0;
}

static int check_valid_calendar(void) {
    vireo_log_record_t record = normal_record();
    vireo_log_timestamp_t cases[] = {
        {.year = 1970, .month = 1, .day = 1},
        {.year = 2000, .month = 2, .day = 29, .nanosecond = 1},
        {.year = 2024, .month = 2, .day = 29},
        {.year = 2100, .month = 2, .day = 28},
        {.year = 9999, .month = 12, .day = 31, .hour = 23, .minute = 59, .second = 59},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char buffer[1024];
        size_t size = 0;
        CHECK(vireo_log_format(&record, &cases[i], 1, buffer, sizeof(buffer), &size) == VIREO_OK);
        CHECK(strstr(buffer, cases[i].nanosecond == 1 ? ".000000001Z" : ".000000000Z") != NULL);
    }
    uint8_t const days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    for (uint8_t month = 1; month <= 12; ++month) {
        vireo_log_timestamp_t time = {.year = 2026, .month = month, .day = days[month - 1U]};
        char buffer[1024];
        size_t size = 0;
        CHECK(vireo_log_format(&record, &time, 1, buffer, sizeof(buffer), &size) == VIREO_OK);
        ++time.day;
        CHECK(expect_failure(&record, &time, 1, 1024, VIREO_RESULT_RANGE) == 0);
    }
    return 0;
}

static int check_invalid_calendar(void) {
    vireo_log_record_t record = normal_record();
    vireo_log_timestamp_t cases[13];
    for (size_t i = 0; i < 13; ++i) {
        cases[i] = normal_time;
    }
    cases[0].year = 1969;
    cases[1].year = 10000;
    cases[2].month = 0;
    cases[3].month = 13;
    cases[4].day = 0;
    cases[5].day = 32;
    cases[6].month = 2; cases[6].day = 29;
    cases[7].year = 2100; cases[7].month = 2; cases[7].day = 29;
    cases[8].hour = 24;
    cases[9].minute = 60;
    cases[10].second = 60;
    cases[11].nanosecond = UINT32_C(1000000000);
    cases[12].nanosecond = UINT32_MAX;
    for (size_t i = 0; i < 13; ++i) {
        CHECK(expect_failure(&record, &cases[i], 1, 1024, VIREO_RESULT_RANGE) == 0);
    }
    return 0;
}

static int check_invalid_arguments(void) {
    vireo_log_record_t record = normal_record();
    CHECK(expect_failure(NULL, &normal_time, 1, 1024, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    CHECK(expect_failure(&record, NULL, 1, 1024, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    CHECK(expect_failure(&record, &normal_time, 0, 1024, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    record.level = (vireo_log_level_t)-1;
    CHECK(expect_failure(&record, &normal_time, 1, 1024, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    record.level = (vireo_log_level_t)4;
    CHECK(expect_failure(&record, &normal_time, 1, 1024, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    record = normal_record();
    size_t size = 456;
    errno = EDOM;
    CHECK(vireo_log_format(&record, &normal_time, 1, NULL, 0, &size) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(size == 456 && errno == EDOM);
    char buffer[1024];
    memset(buffer, 0x5A, sizeof(buffer));
    CHECK(vireo_log_format(&record, &normal_time, 1, buffer, sizeof(buffer), NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    for (size_t i = 0; i < sizeof(buffer); ++i) {
        CHECK(buffer[i] == (char)0x5A);
    }
    CHECK(errno == EDOM);
    return 0;
}

static int check_span_pointers(void) {
    for (size_t i = 0; i < 4; ++i) {
        vireo_log_record_t record = normal_record();
        vireo_log_span_t *spans[] = {&record.module, &record.request_id, &record.task_id, &record.message};
        *spans[i] = (vireo_log_span_t){.data = NULL, .size = 1};
        CHECK(expect_failure(&record, &normal_time, 1, 1024, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    }
    return 0;
}

static int check_span_limits(void) {
    uint8_t bytes[VIREO_LOG_MAX_MESSAGE_SIZE];
    memset(bytes, 'X', sizeof(bytes));
    size_t const limits[] = {VIREO_LOG_MAX_MODULE_SIZE, VIREO_LOG_MAX_ID_SIZE,
                            VIREO_LOG_MAX_ID_SIZE, VIREO_LOG_MAX_MESSAGE_SIZE};
    for (size_t i = 0; i < 4; ++i) {
        vireo_log_record_t record = normal_record();
        vireo_log_span_t *spans[] = {&record.module, &record.request_id, &record.task_id, &record.message};
        *spans[i] = (vireo_log_span_t){.data = bytes, .size = limits[i]};
        char buffer[VIREO_LOG_MAX_LINE_SIZE + 1];
        size_t size = 0;
        CHECK(vireo_log_format(&record, &normal_time, 1, buffer, sizeof(buffer), &size) == VIREO_OK);
        spans[i]->size = limits[i] + 1;
        CHECK(expect_failure(&record, &normal_time, 1, 1024, VIREO_RESULT_RANGE) == 0);
        /* 超长应先看元数据；这里只提供一个字节，不能因 size 巨大而读取下去。 */
        uint8_t tiny = 0;
        spans[i]->data = &tiny;
        spans[i]->size = SIZE_MAX;
        CHECK(expect_failure(&record, &normal_time, 1, 1024, VIREO_RESULT_RANGE) == 0);
    }
    return 0;
}

static int check_exact_capacity(void) {
    vireo_log_record_t record = normal_record();
    size_t required = sizeof(golden);
    CHECK(expect_failure(&record, &normal_time, 4127, 0, VIREO_RESULT_RANGE) == 0);
    CHECK(expect_failure(&record, &normal_time, 4127, required - 1, VIREO_RESULT_RANGE) == 0);
    char buffer[sizeof(golden) + 1];
    memset(buffer, 0x5A, sizeof(buffer));
    size_t size = 0;
    CHECK(vireo_log_format(&record, &normal_time, 4127, buffer, required, &size) == VIREO_OK);
    CHECK(size == required - 1 && memcmp(buffer, golden, required) == 0);
    CHECK(buffer[required] == (char)0x5A);
    return 0;
}

static int check_repeat_and_input(void) {
    uint8_t message[] = {'A', 0, 'B'};
    vireo_log_record_t record = normal_record();
    record.message = (vireo_log_span_t){.data = message, .size = sizeof(message)};
    unsigned char saved[sizeof(record)];
    memcpy(saved, &record, sizeof(record));
    char first[1024];
    char second[1024];
    size_t first_size = 0;
    size_t second_size = 0;
    CHECK(vireo_log_format(&record, &normal_time, 1, first, sizeof(first), &first_size) == VIREO_OK);
    CHECK(vireo_log_format(&record, &normal_time, 1, second, sizeof(second), &second_size) == VIREO_OK);
    CHECK(first_size == second_size && memcmp(first, second, first_size + 1) == 0);
    CHECK(memcmp(saved, &record, sizeof(record)) == 0);
    CHECK(message[0] == 'A' && message[1] == 0 && message[2] == 'B');
    return 0;
}

static int check_errno(void) {
    vireo_log_record_t record = normal_record();
    int const sentinels[] = {0, EACCES, EDOM, ERANGE};
    for (size_t i = 0; i < sizeof(sentinels) / sizeof(sentinels[0]); ++i) {
        char buffer[1024];
        size_t size = 0;
        errno = sentinels[i];
        CHECK(vireo_log_format(&record, &normal_time, 1, buffer, sizeof(buffer), &size) == VIREO_OK);
        CHECK(errno == sentinels[i]);
        CHECK(vireo_log_format(&record, &normal_time, 1, buffer, 0, &size) == VIREO_RESULT_RANGE);
        CHECK(errno == sentinels[i]);
        CHECK(strcmp(vireo_log_level_name((vireo_log_level_t)999), "unknown") == 0);
        CHECK(errno == sentinels[i]);
    }
    return 0;
}

static int check_maximum_record(void) {
    uint8_t bytes[VIREO_LOG_MAX_MESSAGE_SIZE];
    memset(bytes, 0xFF, sizeof(bytes));
    vireo_log_record_t record = {
        .level = VIREO_LOG_LEVEL_ERROR,
        .module = {.data = bytes, .size = VIREO_LOG_MAX_MODULE_SIZE},
        .connection_id = UINT64_MAX, .generation = UINT64_MAX, .sequence = UINT32_MAX,
        .request_id = {.data = bytes, .size = VIREO_LOG_MAX_ID_SIZE},
        .task_id = {.data = bytes, .size = VIREO_LOG_MAX_ID_SIZE},
        .message = {.data = bytes, .size = VIREO_LOG_MAX_MESSAGE_SIZE},
    };
    char buffer[VIREO_LOG_MAX_LINE_SIZE + 2];
    char saved[sizeof(buffer)];
    memset(buffer, 0x5A, sizeof(buffer));
    size_t size = 0;
    CHECK(vireo_log_format(&record, &normal_time, UINT64_MAX, buffer, sizeof(buffer) - 1, &size) == VIREO_OK);
    CHECK(size <= VIREO_LOG_MAX_LINE_SIZE && strlen(buffer) == size);
    CHECK(buffer[size + 1] == (char)0x5A);
    size_t actual_size = size;
    memset(buffer, 0x5A, sizeof(buffer));
    memcpy(saved, buffer, sizeof(buffer));
    size = 654;
    CHECK(vireo_log_format(&record, &normal_time, UINT64_MAX, buffer, actual_size, &size) == VIREO_RESULT_RANGE);
    CHECK(size == 654 && memcmp(buffer, saved, sizeof(buffer)) == 0);
    CHECK(vireo_log_format(&record, &normal_time, UINT64_MAX, buffer, actual_size + 1, &size) == VIREO_OK);
    CHECK(size == actual_size && buffer[size] == '\0');
    return 0;
}

static int check_injection_boundary(void) {
    vireo_log_record_t record = normal_record();
    uint8_t const malicious[] = "ok\nlevel=ERROR tid=0\r\n\" message=\"secret";
    record.message = (vireo_log_span_t){.data = malicious, .size = sizeof(malicious) - 1};
    char buffer[1024];
    size_t size = 0;
    CHECK(vireo_log_format(&record, &normal_time, 1, buffer, sizeof(buffer), &size) == VIREO_OK);
    CHECK(strchr(buffer, '\n') == buffer + size - 1);
    CHECK(strchr(buffer, '\r') == NULL);
    uint8_t decoded[256];
    size_t decoded_size = 0;
    char const *message = strstr(buffer, " message=");
    CHECK(message != NULL && decode_field(message + 9, decoded, &decoded_size));
    CHECK(decoded_size == sizeof(malicious) - 1);
    CHECK(memcmp(decoded, malicious, decoded_size) == 0);
    return 0;
}

int main(void) {
    int (*const groups[])(void) = {
        check_level_names, check_golden_line, check_special_bytes, check_all_bytes,
        check_empty_spans, check_integer_limits, check_valid_calendar, check_invalid_calendar,
        check_invalid_arguments, check_span_pointers, check_span_limits, check_exact_capacity,
        check_repeat_and_input, check_errno, check_maximum_record, check_injection_boundary,
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); ++i) {
        failures += groups[i]();
    }
    if (failures != 0) {
        fprintf(stderr, "test_log: %d test groups failed\n", failures);
        return EXIT_FAILURE;
    }
    printf("test_log: all %zu test groups passed\n", sizeof(groups) / sizeof(groups[0]));
    return EXIT_SUCCESS;
}

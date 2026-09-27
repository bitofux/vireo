/*
 * PROJECT : VIREO
 * FILE    : test_config.c
 * AUTHOR  : bitofux
 * DATE    : 2026-09-26
 * BRIEF   : 测试 vireo 配置默认值、验证、文字解析、环境覆盖和文件加载
 * -- 验证完整默认配置及所有字段边界
 * -- 验证配置文字的行语法、键值解析、重复字段和错误位置
 * -- 验证显式环境覆盖、重复环境项和来源优先级
 * -- 验证大小与时长单位、IPv4 地址、路径和布尔值约束
 * -- 验证文件加载、错误诊断、失败输出保持和 errno 保持
 * -- 验证公共函数成功后才提交完整配置输出
 */

#define _POSIX_C_SOURCE 200809L

#include <vireo/base/config.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <vireo/base/result.h>

#define VIREO_TEST_ARRAY_COUNT(array) (sizeof(array) / sizeof((array)[0]))

_Static_assert(CHAR_BIT == 8, "vireo config tests require 8-bit bytes");

_Static_assert(VIREO_CONFIG_MAX_TEXT_SIZE == UINT32_C(65536),
               "config text limit must remain 65536 bytes");

_Static_assert(VIREO_CONFIG_MAX_LINE_SIZE == UINT32_C(2048),
               "config line limit must remain 2048 bytes");

_Static_assert(VIREO_CONFIG_MAX_VALUE_SIZE == UINT32_C(1023),
               "config value limit must remain 1023 bytes");

_Static_assert(VIREO_CONFIG_ADDRESS_CAPACITY == UINT32_C(16),
               "config address capacity must remain 16 bytes");

_Static_assert(VIREO_CONFIG_PATH_CAPACITY == UINT32_C(1024),
               "config path capacity must remain 1024 bytes");

_Static_assert(VIREO_CONFIG_MAX_ENVIRONMENT_ITEMS == UINT32_C(9),
               "config environment item limit must remain 9");

_Static_assert(VIREO_CONFIG_FIELD_NONE == 0 && VIREO_CONFIG_FIELD_LISTEN_ADDRESS == 1 &&
                   VIREO_CONFIG_FIELD_LISTEN_PORT == 2 && VIREO_CONFIG_FIELD_MAX_CONNECTIONS == 3 &&
                   VIREO_CONFIG_FIELD_WORKER_COUNT == 4 && VIREO_CONFIG_FIELD_IDLE_TIMEOUT == 5 &&
                   VIREO_CONFIG_FIELD_LOG_TO_STDERR == 6 &&
                   VIREO_CONFIG_FIELD_LOG_MAX_FILE_SIZE == 7 && VIREO_CONFIG_FIELD_DATA_DIR == 8 &&
                   VIREO_CONFIG_FIELD_LOG_DIR == 9,
               "config field values must remain contiguous from 1 through 9");

/* 比较实际 vireo_result_t 与预期结果 */
static int expect_result(char const *case_name, vireo_result_t actual, vireo_result_t expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected result %d, got %d\n", case_name, (int)expected, (int)actual);

    return 1;
}

/* 比较实际配置 issue 与预期 issue */
static int expect_issue(char const *case_name, vireo_config_issue_t actual,
                        vireo_config_issue_t expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected config issue %d, got %d\n", case_name, (int)expected,
            (int)actual);

    return 1;
}

/* 比较实际配置错误来源与预期来源 */
static int expect_source(char const *case_name, vireo_config_source_t actual,
                         vireo_config_source_t expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected config source %d, got %d\n", case_name, (int)expected,
            (int)actual);

    return 1;
}

/* 比较实际配置错误字段与预期字段 */
static int expect_field(char const *case_name, vireo_config_field_t actual,
                        vireo_config_field_t expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected config field %d, got %d\n", case_name, (int)expected,
            (int)actual);

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

/* 比较实际 int 与预期值 */
static int expect_int(char const *case_name, int actual, int expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected int %d, got %d\n", case_name, expected, actual);

    return 1;
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

/* 比较实际 uint64_t 与预期值 */
static int expect_u64(char const *case_name, uint64_t actual, uint64_t expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr,
            "%s: expected uint64_t %" PRIu64 " (0x%016" PRIX64 "), got %" PRIu64 " (0x%016" PRIX64
            ")\n",
            case_name, expected, expected, actual, actual);

    return 1;
}

/* 比较实际 bool 与预期值 */
static int expect_bool(char const *case_name, bool actual, bool expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected bool %s, got %s\n", case_name, expected ? "true" : "false",
            actual ? "true" : "false");

    return 1;
}

/* 比较两个有效的 NUL 终止字符串 */
static int expect_string(char const *case_name, char const *actual, char const *expected) {
    if (strcmp(actual, expected) == 0) {
        return 0;
    }

    fprintf(stderr, "%s: expected string \"%s\", got \"%s\"\n", case_name, expected, actual);

    return 1;
}

/* 比较两个明确长度的只读字节区域，报告第一处差异 */
static int expect_bytes(char const *case_name, void const *actual, void const *expected,
                        size_t size) {
    unsigned char const *actual_bytes = actual;
    unsigned char const *expected_bytes = expected;

    for (size_t index = 0U; index < size; ++index) {
        if (actual_bytes[index] == expected_bytes[index]) {
            continue;
        }

        fprintf(stderr, "%s: byte %zu expected 0x%02X, got 0x%02X\n", case_name, index,
                (unsigned int)expected_bytes[index], (unsigned int)actual_bytes[index]);

        return 1;
    }

    return 0;
}

/* 逐字段比较两份合法的宿主语义配置 */
static int expect_config(char const *case_name, vireo_config_t const *actual,
                         vireo_config_t const *expected) {
    int failures = 0;

    if (strcmp(actual->listen_address, expected->listen_address) != 0) {
        fprintf(stderr, "%s: ", case_name);
        failures +=
            expect_string("listen_address", actual->listen_address, expected->listen_address);
    }

    if (actual->listen_port != expected->listen_port) {
        fprintf(stderr, "%s: ", case_name);
        failures += expect_u16("listen_port", actual->listen_port, expected->listen_port);
    }

    if (actual->max_connections != expected->max_connections) {
        fprintf(stderr, "%s: ", case_name);
        failures +=
            expect_u32("max_connections", actual->max_connections, expected->max_connections);
    }

    if (actual->worker_count != expected->worker_count) {
        fprintf(stderr, "%s: ", case_name);
        failures += expect_u32("worker_count", actual->worker_count, expected->worker_count);
    }

    if (actual->idle_timeout_ms != expected->idle_timeout_ms) {
        fprintf(stderr, "%s: ", case_name);
        failures +=
            expect_u64("idle_timeout_ms", actual->idle_timeout_ms, expected->idle_timeout_ms);
    }

    if (actual->log_to_stderr != expected->log_to_stderr) {
        fprintf(stderr, "%s: ", case_name);
        failures += expect_bool("log_to_stderr", actual->log_to_stderr, expected->log_to_stderr);
    }

    if (actual->log_max_file_size_bytes != expected->log_max_file_size_bytes) {
        fprintf(stderr, "%s: ", case_name);
        failures += expect_u64("log_max_file_size_bytes", actual->log_max_file_size_bytes,
                               expected->log_max_file_size_bytes);
    }

    if (strcmp(actual->data_dir, expected->data_dir) != 0) {
        fprintf(stderr, "%s: ", case_name);
        failures += expect_string("data_dir", actual->data_dir, expected->data_dir);
    }

    if (strcmp(actual->log_dir, expected->log_dir) != 0) {
        fprintf(stderr, "%s: ", case_name);
        failures += expect_string("log_dir", actual->log_dir, expected->log_dir);
    }

    return failures;
}

/* 逐成员比较两份完整的配置错误诊断 */
static int expect_error(char const *case_name, vireo_config_error_t const *actual,
                        vireo_config_error_t const *expected) {
    int failures = 0;

    if (actual->issue != expected->issue) {
        fprintf(stderr, "%s: ", case_name);
        failures += expect_issue("issue", actual->issue, expected->issue);
    }

    if (actual->source != expected->source) {
        fprintf(stderr, "%s: ", case_name);
        failures += expect_source("source", actual->source, expected->source);
    }

    if (actual->field != expected->field) {
        fprintf(stderr, "%s: ", case_name);
        failures += expect_field("field", actual->field, expected->field);
    }

    if (actual->line != expected->line) {
        fprintf(stderr, "%s: ", case_name);
        failures += expect_size("line", actual->line, expected->line);
    }

    if (actual->entry_index != expected->entry_index) {
        fprintf(stderr, "%s: ", case_name);
        failures += expect_size("entry_index", actual->entry_index, expected->entry_index);
    }

    if (actual->system_errno != expected->system_errno) {
        fprintf(stderr, "%s: ", case_name);
        failures += expect_int("system_errno", actual->system_errno, expected->system_errno);
    }

    return failures;
}

/* 构造完整、合法且明显区别于默认值的哨兵配置 */
static vireo_config_t make_sentinel_config(void) {
    vireo_config_t const config = {
        .listen_address = "192.0.2.1",
        .listen_port = UINT16_C(54321),
        .max_connections = UINT32_C(4321),
        .worker_count = UINT32_C(17),
        .idle_timeout_ms = UINT64_C(123456),
        .log_to_stderr = false,
        .log_max_file_size_bytes = UINT64_C(33554432),
        .data_dir = "/sentinel/vireo-data",
        .log_dir = "/sentinel/vireo-log",
    };

    return config;
}

/* 构造所有成员都明显非默认的配置错误哨兵 */
static vireo_config_error_t make_sentinel_error(void) {
    vireo_config_error_t const error = {
        .issue = VIREO_CONFIG_ISSUE_FILE_READ_FAILED,
        .source = VIREO_CONFIG_SOURCE_FILE,
        .field = VIREO_CONFIG_FIELD_LOG_DIR,
        .line = 73U,
        .entry_index = 41U,
        .system_errno = EIO,
    };

    return error;
}

/* 将完整字节区域写入文件描述符，处理短写和 EINTR */
static bool write_all(int file_descriptor, void const *data, size_t size) {
    unsigned char const *bytes = data;
    size_t offset = 0U;

    while (offset < size) {
        ssize_t const written = write(file_descriptor, bytes + offset, size - offset);

        if (written > 0) {
            offset += (size_t)written;
            continue;
        }

        if (written < 0 && errno == EINTR) {
            continue;
        }

        if (written == 0) {
            errno = EIO;
        }

        return false;
    }

    return true;
}

/* 创建并写入临时配置文件；失败时保留主要 errno */
static bool create_temporary_config_file(char *path_template, void const *data, size_t size) {
    int const file_descriptor = mkstemp(path_template);
    if (file_descriptor < 0) {
        return false;
    }

    if (!write_all(file_descriptor, data, size)) {
        int const write_errno = errno;

        (void)close(file_descriptor);
        (void)unlink(path_template);

        errno = write_errno;
        return false;
    }

    if (close(file_descriptor) != 0) {
        int const close_errno = errno;

        /*
         * close 失败后描述符状态不能由本测试 helper 安全假定；
         * 不重试 close，只尽力移除路径。
         */
        (void)unlink(path_template);

        errno = close_errno;
        return false;
    }

    return true;
}

/* 删除临时配置文件；清理失败计为一条测试失败 */
static int remove_temporary_config_file(char const *case_name, char const *path) {
    int const saved_errno = errno;

    if (unlink(path) == 0) {
        errno = saved_errno;
        return 0;
    }

    int const unlink_errno = errno;

    fprintf(stderr,
            "%s: failed to remove temporary config file \"%s\": "
            "errno %d\n",
            case_name, path, unlink_errno);

    errno = saved_errno;
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

/* 验证 defaults 完整覆盖哨兵配置，并保持 errno */
static int test_defaults_success(void) {
    vireo_config_t config = make_sentinel_config();

    vireo_config_t const expected = {
        .listen_address = VIREO_CONFIG_DEFAULT_LISTEN_ADDRESS,
        .listen_port = VIREO_CONFIG_DEFAULT_LISTEN_PORT,
        .max_connections = VIREO_CONFIG_DEFAULT_MAX_CONNECTIONS,
        .worker_count = VIREO_CONFIG_DEFAULT_WORKER_COUNT,
        .idle_timeout_ms = VIREO_CONFIG_DEFAULT_IDLE_TIMEOUT_MS,
        .log_to_stderr = VIREO_CONFIG_DEFAULT_LOG_TO_STDERR,
        .log_max_file_size_bytes = VIREO_CONFIG_DEFAULT_LOG_FILE_SIZE_BYTES,
        .data_dir = VIREO_CONFIG_DEFAULT_DATA_DIR,
        .log_dir = VIREO_CONFIG_DEFAULT_LOG_DIR,
    };

    errno = EACCES;
    vireo_result_t const result = vireo_config_defaults(&config);
    int const actual_errno = errno;

    int failures = expect_result("config defaults success result", result, VIREO_OK);
    failures += expect_int("config defaults success errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures += expect_config("config defaults success output", &config, &expected);
    }

    return failures;
}

/* 验证 defaults 拒绝空输出指针，并保持 errno */
static int test_defaults_invalid_arguments(void) {
    errno = EACCES;
    vireo_result_t const result = vireo_config_defaults(NULL);
    int const actual_errno = errno;

    int failures =
        expect_result("config defaults null output result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_int("config defaults null output errno", actual_errno, EACCES);

    return failures;
}

/* 验证 validate 接受合法配置、清空旧诊断并保持输入和 errno */
static int test_validate_success(void) {
    vireo_config_t const expected_config = make_sentinel_config();
    vireo_config_t config = expected_config;

    vireo_config_error_t error = make_sentinel_error();

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_NONE,
        .source = VIREO_CONFIG_SOURCE_NONE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    errno = EACCES;
    vireo_result_t const result = vireo_config_validate(&config, &error);
    int const actual_errno = errno;

    int failures = expect_result("config validate success result", result, VIREO_OK);
    failures += expect_int("config validate success errno", actual_errno, EACCES);
    failures += expect_config("config validate success input keep", &config, &expected_config);

    if (result == VIREO_OK) {
        failures += expect_error("config validate success error clear", &error, &expected_error);
    }

    return failures;
}

/* 验证 validate 拒绝空参数、填写可用诊断并保持输入和 errno */
static int test_validate_invalid_arguments(void) {
    vireo_config_t const expected_config = make_sentinel_config();
    vireo_config_t config = expected_config;

    vireo_config_error_t error = make_sentinel_error();

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_INVALID_ARGUMENT,
        .source = VIREO_CONFIG_SOURCE_NONE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    /* 1. config 为 NULL，但诊断输出有效 */
    errno = EACCES;
    vireo_result_t result = vireo_config_validate(NULL, &error);
    int actual_errno = errno;

    int failures =
        expect_result("config validate null config result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_error("config validate null config error", &error, &expected_error);
    failures += expect_int("config validate null config errno", actual_errno, EACCES);

    /* 2. config 有效，但诊断输出为 NULL */
    config = expected_config;

    errno = EACCES;
    result = vireo_config_validate(&config, NULL);
    actual_errno = errno;

    failures +=
        expect_result("config validate null error result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_int("config validate null error errno", actual_errno, EACCES);
    failures += expect_config("config validate null error input keep", &config, &expected_config);

    /* 3. config 和诊断输出同时为 NULL */
    errno = EACCES;
    result = vireo_config_validate(NULL, NULL);
    actual_errno = errno;

    failures += expect_result("config validate null config and error result", result,
                              VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_int("config validate null config and error errno", actual_errno, EACCES);

    return failures;
}

/* 验证 validate 拒绝容量内没有 NUL 的监听地址 */
static int test_validate_unterminated_listen_address(void) {
    vireo_config_t config = make_sentinel_config();

    char expected_address[VIREO_CONFIG_ADDRESS_CAPACITY];

    memset(config.listen_address, '1', sizeof(config.listen_address));
    memset(expected_address, '1', sizeof(expected_address));

    vireo_config_error_t error = make_sentinel_error();

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_VALUE_TOO_LONG,
        .source = VIREO_CONFIG_SOURCE_CONFIG,
        .field = VIREO_CONFIG_FIELD_LISTEN_ADDRESS,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    errno = EACCES;
    vireo_result_t const result = vireo_config_validate(&config, &error);
    int const actual_errno = errno;

    int failures =
        expect_result("config validate unterminated address result", result, VIREO_RESULT_RANGE);
    failures += expect_error("config validate unterminated address error", &error, &expected_error);
    failures += expect_int("config validate unterminated address errno", actual_errno, EACCES);
    failures += expect_bytes("config validate unterminated address input keep",
                             config.listen_address, expected_address, sizeof(expected_address));

    return failures;
}

/* 验证 validate 拒绝多种边界明确但内容非法的 IPv4 地址 */
static int test_validate_invalid_listen_addresses(void) {
    static struct {
        char const *case_name;
        char const *address;
    } const cases[] = {
        {
            "config validate empty address",
            "",
        },
        {
            "config validate missing address part",
            "127.0.0",
        },
        {
            "config validate extra address part",
            "127.0.0.1.2",
        },
        {
            "config validate empty address part",
            "127..0.1",
        },
        {
            "config validate address part over 255",
            "256.0.0.1",
        },
        {
            "config validate address leading zero",
            "01.2.3.4",
        },
        {
            "config validate address part too long",
            "1234.0.0.1",
        },
        {
            "config validate address nondigit",
            "127.0.0.a",
        },
        {
            "config validate address trailing character",
            "127.0.0.1x",
        },
        {
            "config validate address trailing dot",
            "1.2.3.4.",
        },
        {
            "config validate address leading space",
            " 127.0.0.1",
        },
        {
            "config validate address trailing space",
            "127.0.0.1 ",
        },
    };

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_INVALID_ADDRESS,
        .source = VIREO_CONFIG_SOURCE_CONFIG,
        .field = VIREO_CONFIG_FIELD_LISTEN_ADDRESS,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    int failures = 0;

    for (size_t index = 0U; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
        vireo_config_t config = make_sentinel_config();

        size_t const address_size = strlen(cases[index].address);

        memset(config.listen_address, 0, sizeof(config.listen_address));
        memcpy(config.listen_address, cases[index].address, address_size);

        vireo_config_t const expected_config = config;

        vireo_config_error_t error = make_sentinel_error();

        errno = EACCES;
        vireo_result_t const result = vireo_config_validate(&config, &error);
        int const actual_errno = errno;

        failures += expect_result(cases[index].case_name, result, VIREO_RESULT_INVALID_ARGUMENT);
        failures += expect_error(cases[index].case_name, &error, &expected_error);
        failures += expect_int(cases[index].case_name, actual_errno, EACCES);
        failures += expect_config(cases[index].case_name, &config, &expected_config);
    }

    return failures;
}

/* 验证 validate 接受所有字段的合法最小值和最大值 */
static int test_validate_boundary_values(void) {
    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_NONE,
        .source = VIREO_CONFIG_SOURCE_NONE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    int failures = 0;

    /* 1. 所有相关字段使用合法最小值 */
    {
        vireo_config_t config = make_sentinel_config();

        memset(config.listen_address, 0, sizeof(config.listen_address));
        memcpy(config.listen_address, "0.0.0.0", sizeof("0.0.0.0"));

        config.listen_port = VIREO_CONFIG_MIN_LISTEN_PORT;
        config.max_connections = VIREO_CONFIG_MIN_MAX_CONNECTIONS;
        config.worker_count = VIREO_CONFIG_MIN_WORKER_COUNT;
        config.idle_timeout_ms = VIREO_CONFIG_MIN_IDLE_TIMEOUT_MS;
        config.log_to_stderr = false;
        config.log_max_file_size_bytes = VIREO_CONFIG_MIN_LOG_FILE_SIZE_BYTES;

        memset(config.data_dir, 0, sizeof(config.data_dir));
        memcpy(config.data_dir, "/", sizeof("/"));

        memset(config.log_dir, 0, sizeof(config.log_dir));
        memcpy(config.log_dir, "/", sizeof("/"));

        vireo_config_t const expected_config = config;

        vireo_config_error_t error = make_sentinel_error();

        errno = EACCES;
        vireo_result_t const result = vireo_config_validate(&config, &error);
        int const actual_errno = errno;

        failures += expect_result("config validate minimum values result", result, VIREO_OK);
        failures += expect_int("config validate minimum values errno", actual_errno, EACCES);
        failures +=
            expect_config("config validate minimum values input keep", &config, &expected_config);

        if (result == VIREO_OK) {
            failures +=
                expect_error("config validate minimum values error clear", &error, &expected_error);
        }
    }

    /* 2. 所有相关字段使用合法最大值 */
    {
        vireo_config_t config = make_sentinel_config();

        memcpy(config.listen_address, "255.255.255.255", sizeof("255.255.255.255"));

        config.listen_port = UINT16_MAX;
        config.max_connections = VIREO_CONFIG_MAX_MAX_CONNECTIONS;
        config.worker_count = VIREO_CONFIG_MAX_WORKER_COUNT;
        config.idle_timeout_ms = VIREO_CONFIG_MAX_IDLE_TIMEOUT_MS;
        config.log_to_stderr = true;
        config.log_max_file_size_bytes = VIREO_CONFIG_MAX_LOG_FILE_SIZE_BYTES;

        vireo_config_t const expected_config = config;

        vireo_config_error_t error = make_sentinel_error();

        errno = EACCES;
        vireo_result_t const result = vireo_config_validate(&config, &error);
        int const actual_errno = errno;

        failures += expect_result("config validate maximum values result", result, VIREO_OK);
        failures += expect_int("config validate maximum values errno", actual_errno, EACCES);
        failures +=
            expect_config("config validate maximum values input keep", &config, &expected_config);

        if (result == VIREO_OK) {
            failures +=
                expect_error("config validate maximum values error clear", &error, &expected_error);
        }
    }

    return failures;
}

/* 验证 validate 拒绝所有数值字段的下界外和上界外取值 */
static int test_validate_numeric_range_errors(void) {
    static struct {
        char const *case_name;
        vireo_config_field_t field;
        uint64_t value;
    } const cases[] = {
        {
            "config validate port below minimum",
            VIREO_CONFIG_FIELD_LISTEN_PORT,
            UINT64_C(0),
        },
        {
            "config validate connections below minimum",
            VIREO_CONFIG_FIELD_MAX_CONNECTIONS,
            (uint64_t)VIREO_CONFIG_MIN_MAX_CONNECTIONS - UINT64_C(1),
        },
        {
            "config validate connections above maximum",
            VIREO_CONFIG_FIELD_MAX_CONNECTIONS,
            (uint64_t)VIREO_CONFIG_MAX_MAX_CONNECTIONS + UINT64_C(1),
        },
        {
            "config validate workers below minimum",
            VIREO_CONFIG_FIELD_WORKER_COUNT,
            (uint64_t)VIREO_CONFIG_MIN_WORKER_COUNT - UINT64_C(1),
        },
        {
            "config validate workers above maximum",
            VIREO_CONFIG_FIELD_WORKER_COUNT,
            (uint64_t)VIREO_CONFIG_MAX_WORKER_COUNT + UINT64_C(1),
        },
        {
            "config validate timeout below minimum",
            VIREO_CONFIG_FIELD_IDLE_TIMEOUT,
            (uint64_t)VIREO_CONFIG_MIN_IDLE_TIMEOUT_MS - UINT64_C(1),
        },
        {
            "config validate timeout above maximum",
            VIREO_CONFIG_FIELD_IDLE_TIMEOUT,
            (uint64_t)VIREO_CONFIG_MAX_IDLE_TIMEOUT_MS + UINT64_C(1),
        },
        {
            "config validate log size below minimum",
            VIREO_CONFIG_FIELD_LOG_MAX_FILE_SIZE,
            (uint64_t)VIREO_CONFIG_MIN_LOG_FILE_SIZE_BYTES - UINT64_C(1),
        },
        {
            "config validate log size above maximum",
            VIREO_CONFIG_FIELD_LOG_MAX_FILE_SIZE,
            (uint64_t)VIREO_CONFIG_MAX_LOG_FILE_SIZE_BYTES + UINT64_C(1),
        },
    };

    int failures = 0;

    for (size_t index = 0U; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
        vireo_config_t config = make_sentinel_config();

        switch (cases[index].field) {
            case VIREO_CONFIG_FIELD_LISTEN_PORT:
                config.listen_port = (uint16_t)cases[index].value;
                break;

            case VIREO_CONFIG_FIELD_MAX_CONNECTIONS:
                config.max_connections = (uint32_t)cases[index].value;
                break;

            case VIREO_CONFIG_FIELD_WORKER_COUNT:
                config.worker_count = (uint32_t)cases[index].value;
                break;

            case VIREO_CONFIG_FIELD_IDLE_TIMEOUT:
                config.idle_timeout_ms = cases[index].value;
                break;

            case VIREO_CONFIG_FIELD_LOG_MAX_FILE_SIZE:
                config.log_max_file_size_bytes = cases[index].value;
                break;

            default:
                failures += expect_true(cases[index].case_name, false);
                continue;
        }

        vireo_config_t const expected_config = config;

        vireo_config_error_t error = make_sentinel_error();

        vireo_config_error_t const expected_error = {
            .issue = VIREO_CONFIG_ISSUE_VALUE_OUT_OF_RANGE,
            .source = VIREO_CONFIG_SOURCE_CONFIG,
            .field = cases[index].field,
            .line = 0U,
            .entry_index = 0U,
            .system_errno = 0,
        };

        errno = EACCES;
        vireo_result_t const result = vireo_config_validate(&config, &error);
        int const actual_errno = errno;

        failures += expect_result(cases[index].case_name, result, VIREO_RESULT_RANGE);
        failures += expect_error(cases[index].case_name, &error, &expected_error);
        failures += expect_int(cases[index].case_name, actual_errno, EACCES);
        failures += expect_config(cases[index].case_name, &config, &expected_config);
    }

    return failures;
}

/* 验证 validate 拒绝容量内没有 NUL 的数据目录和日志目录 */
static int test_validate_unterminated_paths(void) {
    static struct {
        char const *case_name;
        vireo_config_field_t field;
    } const cases[] = {
        {
            "config validate unterminated data dir",
            VIREO_CONFIG_FIELD_DATA_DIR,
        },
        {
            "config validate unterminated log dir",
            VIREO_CONFIG_FIELD_LOG_DIR,
        },
    };

    int failures = 0;

    for (size_t index = 0U; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
        vireo_config_t config = make_sentinel_config();

        char *path = NULL;

        switch (cases[index].field) {
            case VIREO_CONFIG_FIELD_DATA_DIR:
                path = config.data_dir;
                break;

            case VIREO_CONFIG_FIELD_LOG_DIR:
                path = config.log_dir;
                break;

            default:
                failures += expect_true(cases[index].case_name, false);
                continue;
        }

        char expected_path[VIREO_CONFIG_PATH_CAPACITY];

        memset(path, 'a', VIREO_CONFIG_PATH_CAPACITY);
        path[0] = '/';

        memset(expected_path, 'a', sizeof(expected_path));
        expected_path[0] = '/';

        vireo_config_error_t error = make_sentinel_error();

        vireo_config_error_t const expected_error = {
            .issue = VIREO_CONFIG_ISSUE_VALUE_TOO_LONG,
            .source = VIREO_CONFIG_SOURCE_CONFIG,
            .field = cases[index].field,
            .line = 0U,
            .entry_index = 0U,
            .system_errno = 0,
        };

        errno = EACCES;
        vireo_result_t const result = vireo_config_validate(&config, &error);
        int const actual_errno = errno;

        failures += expect_result(cases[index].case_name, result, VIREO_RESULT_RANGE);
        failures += expect_error(cases[index].case_name, &error, &expected_error);
        failures += expect_int(cases[index].case_name, actual_errno, EACCES);
        failures +=
            expect_bytes(cases[index].case_name, path, expected_path, sizeof(expected_path));
    }

    return failures;
}

/* 验证 validate 拒绝两个路径字段中的非法路径内容 */
static int test_validate_invalid_paths(void) {
    static struct {
        char const *case_name;
        vireo_config_field_t field;
        char const *path;
    } const cases[] = {
        {
            "config validate empty data dir",
            VIREO_CONFIG_FIELD_DATA_DIR,
            "",
        },
        {
            "config validate relative data dir",
            VIREO_CONFIG_FIELD_DATA_DIR,
            "relative/path",
        },
        {
            "config validate control data dir",
            VIREO_CONFIG_FIELD_DATA_DIR,
            "/bad"
            "\x1F"
            "path",
        },
        {
            "config validate del data dir",
            VIREO_CONFIG_FIELD_DATA_DIR,
            "/bad"
            "\x7F"
            "path",
        },
        {
            "config validate empty log dir",
            VIREO_CONFIG_FIELD_LOG_DIR,
            "",
        },
        {
            "config validate relative log dir",
            VIREO_CONFIG_FIELD_LOG_DIR,
            "relative/path",
        },
        {
            "config validate control log dir",
            VIREO_CONFIG_FIELD_LOG_DIR,
            "/bad"
            "\x1F"
            "path",
        },
        {
            "config validate del log dir",
            VIREO_CONFIG_FIELD_LOG_DIR,
            "/bad"
            "\x7F"
            "path",
        },
    };

    int failures = 0;

    for (size_t index = 0U; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
        vireo_config_t config = make_sentinel_config();

        char *path = NULL;

        switch (cases[index].field) {
            case VIREO_CONFIG_FIELD_DATA_DIR:
                path = config.data_dir;
                break;

            case VIREO_CONFIG_FIELD_LOG_DIR:
                path = config.log_dir;
                break;

            default:
                failures += expect_true(cases[index].case_name, false);
                continue;
        }

        size_t const path_size = strlen(cases[index].path);

        memset(path, 0, VIREO_CONFIG_PATH_CAPACITY);
        memcpy(path, cases[index].path, path_size);

        char expected_path[VIREO_CONFIG_PATH_CAPACITY];

        memcpy(expected_path, path, sizeof(expected_path));

        vireo_config_error_t error = make_sentinel_error();

        vireo_config_error_t const expected_error = {
            .issue = VIREO_CONFIG_ISSUE_INVALID_PATH,
            .source = VIREO_CONFIG_SOURCE_CONFIG,
            .field = cases[index].field,
            .line = 0U,
            .entry_index = 0U,
            .system_errno = 0,
        };

        errno = EACCES;
        vireo_result_t const result = vireo_config_validate(&config, &error);
        int const actual_errno = errno;

        failures += expect_result(cases[index].case_name, result, VIREO_RESULT_INVALID_ARGUMENT);
        failures += expect_error(cases[index].case_name, &error, &expected_error);
        failures += expect_int(cases[index].case_name, actual_errno, EACCES);
        failures +=
            expect_bytes(cases[index].case_name, path, expected_path, sizeof(expected_path));
    }

    return failures;
}

/* 验证 validate 接受占满全部可用内容容量的两个路径字段 */
static int test_validate_maximum_path_length(void) {
    static struct {
        char const *case_name;
        vireo_config_field_t field;
    } const cases[] = {
        {
            "config validate maximum data dir",
            VIREO_CONFIG_FIELD_DATA_DIR,
        },
        {
            "config validate maximum log dir",
            VIREO_CONFIG_FIELD_LOG_DIR,
        },
    };

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_NONE,
        .source = VIREO_CONFIG_SOURCE_NONE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    int failures = 0;

    for (size_t index = 0U; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
        vireo_config_t config = make_sentinel_config();

        char *path = NULL;

        switch (cases[index].field) {
            case VIREO_CONFIG_FIELD_DATA_DIR:
                path = config.data_dir;
                break;

            case VIREO_CONFIG_FIELD_LOG_DIR:
                path = config.log_dir;
                break;

            default:
                failures += expect_true(cases[index].case_name, false);
                continue;
        }

        memset(path, 'a', VIREO_CONFIG_PATH_CAPACITY);
        path[0] = '/';
        path[VIREO_CONFIG_PATH_CAPACITY - 1U] = '\0';

        char expected_path[VIREO_CONFIG_PATH_CAPACITY];

        memcpy(expected_path, path, sizeof(expected_path));

        vireo_config_error_t error = make_sentinel_error();

        errno = EACCES;
        vireo_result_t const result = vireo_config_validate(&config, &error);
        int const actual_errno = errno;

        failures += expect_result(cases[index].case_name, result, VIREO_OK);
        failures += expect_int(cases[index].case_name, actual_errno, EACCES);
        failures +=
            expect_bytes(cases[index].case_name, path, expected_path, sizeof(expected_path));

        if (result == VIREO_OK) {
            failures += expect_error(cases[index].case_name, &error, &expected_error);
        }
    }

    return failures;
}

/* 验证 parse_text 解析全部字段、常见空白和两种行结束形式 */
static int test_parse_text_success(void) {
    static char const expected_text[] =
        "   # complete vireo configuration\r\n"
        "\t   \n"
        " listen_address = 10.20.30.40 \n"
        "listen_port\t=\t12345\n"
        "max_connections = 2048\n"
        "worker_count = 8\n"
        "idle_timeout = 2m\n"
        "log_to_stderr = true\n"
        "log_max_file_size = 64MiB\n"
        "data_dir = /srv/vireo/data\n"
        "log_dir = /srv/vireo/log";

    char text[sizeof(expected_text)];

    memcpy(text, expected_text, sizeof(text));

    vireo_config_t base = make_sentinel_config();
    vireo_config_t const expected_base = base;

    vireo_config_t output = make_sentinel_config();

    vireo_config_t const expected_output = {
        .listen_address = "10.20.30.40",
        .listen_port = UINT16_C(12345),
        .max_connections = UINT32_C(2048),
        .worker_count = UINT32_C(8),
        .idle_timeout_ms = UINT64_C(120000),
        .log_to_stderr = true,
        .log_max_file_size_bytes = UINT64_C(67108864),
        .data_dir = "/srv/vireo/data",
        .log_dir = "/srv/vireo/log",
    };

    vireo_config_error_t error = make_sentinel_error();

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_NONE,
        .source = VIREO_CONFIG_SOURCE_NONE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    errno = EACCES;
    vireo_result_t const result =
        vireo_config_parse_text(&base, text, sizeof(text) - 1U, &output, &error);
    int const actual_errno = errno;

    int failures = expect_result("config parse text success result", result, VIREO_OK);
    failures += expect_int("config parse text success errno", actual_errno, EACCES);
    failures += expect_config("config parse text success base keep", &base, &expected_base);
    failures +=
        expect_bytes("config parse text success text keep", text, expected_text, sizeof(text));

    if (result == VIREO_OK) {
        failures += expect_config("config parse text success output", &output, &expected_output);
        failures += expect_error("config parse text success error clear", &error, &expected_error);
    }

    return failures;
}

/* 验证空文字和纯注释文字成功继承完整基础配置 */
static int test_parse_text_without_assignments(void) {
    char zero_length_text[] = {
        'X',
    };

    char ignored_text[] =
        "   # first comment\r\n"
        "\t   \n"
        "# final comment";

    struct {
        char const *case_name;
        char *text;
        size_t text_size;
        size_t storage_size;
    } const cases[] = {
        {
            "config parse null empty text",
            NULL,
            0U,
            0U,
        },
        {
            "config parse nonnull zero length text",
            zero_length_text,
            0U,
            sizeof(zero_length_text),
        },
        {
            "config parse comments and whitespace",
            ignored_text,
            sizeof(ignored_text) - 1U,
            sizeof(ignored_text),
        },
    };

    vireo_config_t const base_template = {
        .listen_address = VIREO_CONFIG_DEFAULT_LISTEN_ADDRESS,
        .listen_port = VIREO_CONFIG_DEFAULT_LISTEN_PORT,
        .max_connections = VIREO_CONFIG_DEFAULT_MAX_CONNECTIONS,
        .worker_count = VIREO_CONFIG_DEFAULT_WORKER_COUNT,
        .idle_timeout_ms = VIREO_CONFIG_DEFAULT_IDLE_TIMEOUT_MS,
        .log_to_stderr = VIREO_CONFIG_DEFAULT_LOG_TO_STDERR,
        .log_max_file_size_bytes = VIREO_CONFIG_DEFAULT_LOG_FILE_SIZE_BYTES,
        .data_dir = VIREO_CONFIG_DEFAULT_DATA_DIR,
        .log_dir = VIREO_CONFIG_DEFAULT_LOG_DIR,
    };

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_NONE,
        .source = VIREO_CONFIG_SOURCE_NONE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    int failures = 0;

    for (size_t index = 0U; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
        char expected_text[sizeof(ignored_text)];

        if (cases[index].storage_size != 0U) {
            memcpy(expected_text, cases[index].text, cases[index].storage_size);
        }

        vireo_config_t base = base_template;
        vireo_config_t const expected_base = base;

        vireo_config_t output = make_sentinel_config();

        vireo_config_error_t error = make_sentinel_error();

        errno = EACCES;
        vireo_result_t const result = vireo_config_parse_text(
            &base, cases[index].text, cases[index].text_size, &output, &error);
        int const actual_errno = errno;

        failures += expect_result(cases[index].case_name, result, VIREO_OK);
        failures += expect_int(cases[index].case_name, actual_errno, EACCES);
        failures += expect_config(cases[index].case_name, &base, &expected_base);

        if (cases[index].storage_size != 0U) {
            failures += expect_bytes(cases[index].case_name, cases[index].text, expected_text,
                                     cases[index].storage_size);
        }

        if (result == VIREO_OK) {
            failures += expect_config(cases[index].case_name, &output, &base_template);
            failures += expect_error(cases[index].case_name, &error, &expected_error);
        }
    }

    return failures;
}

/* 验证 parse_text 只覆盖出现的字段，并继承其余基础配置 */
static int test_parse_text_partial_override(void) {
    char text[] = "worker_count = 32\n";

    char expected_text[sizeof(text)];

    memcpy(expected_text, text, sizeof(expected_text));

    vireo_config_t base = make_sentinel_config();
    base.log_to_stderr = true;

    vireo_config_t const expected_base = base;

    vireo_config_t expected_output = base;
    expected_output.worker_count = UINT32_C(32);

    vireo_config_t output = {0};

    vireo_config_error_t error = make_sentinel_error();

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_NONE,
        .source = VIREO_CONFIG_SOURCE_NONE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    errno = EACCES;
    vireo_result_t const result =
        vireo_config_parse_text(&base, text, sizeof(text) - 1U, &output, &error);
    int const actual_errno = errno;

    int failures = expect_result("config parse partial override result", result, VIREO_OK);
    failures += expect_int("config parse partial override errno", actual_errno, EACCES);
    failures += expect_config("config parse partial override base keep", &base, &expected_base);
    failures +=
        expect_bytes("config parse partial override text keep", text, expected_text, sizeof(text));

    if (result == VIREO_OK) {
        failures +=
            expect_config("config parse partial override output", &output, &expected_output);
        failures +=
            expect_error("config parse partial override error clear", &error, &expected_error);
    }

    return failures;
}

/* 验证 parse_text 拒绝非法参数，并保持可观察输入输出 */
static int test_parse_text_invalid_arguments(void) {
    static char const expected_text[] = "worker_count = 32\n";

    static struct {
        char const *case_name;
        bool null_base;
        bool null_text;
        bool null_output;
        bool null_error;
        size_t text_size;
    } const cases[] = {
        {
            "config parse null base",
            true,
            false,
            false,
            false,
            sizeof(expected_text) - 1U,
        },
        {
            "config parse null output",
            false,
            false,
            true,
            false,
            sizeof(expected_text) - 1U,
        },
        {
            "config parse null error",
            false,
            false,
            false,
            true,
            sizeof(expected_text) - 1U,
        },
        {
            "config parse null nonempty text",
            false,
            true,
            false,
            false,
            1U,
        },
    };

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_INVALID_ARGUMENT,
        .source = VIREO_CONFIG_SOURCE_NONE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    int failures = 0;

    for (size_t index = 0U; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
        char text[sizeof(expected_text)];

        memcpy(text, expected_text, sizeof(text));

        vireo_config_t base = make_sentinel_config();
        vireo_config_t const expected_base = base;

        vireo_config_t output = {
            .listen_address = "203.0.113.7",
            .listen_port = UINT16_C(23456),
            .max_connections = UINT32_C(3210),
            .worker_count = UINT32_C(23),
            .idle_timeout_ms = UINT64_C(654321),
            .log_to_stderr = true,
            .log_max_file_size_bytes = UINT64_C(16777216),
            .data_dir = "/output/keep/data",
            .log_dir = "/output/keep/log",
        };
        vireo_config_t const expected_output = output;

        vireo_config_error_t error = make_sentinel_error();

        vireo_config_t const *base_argument = cases[index].null_base ? NULL : &base;
        char const *text_argument = cases[index].null_text ? NULL : text;
        vireo_config_t *output_argument = cases[index].null_output ? NULL : &output;
        vireo_config_error_t *error_argument = cases[index].null_error ? NULL : &error;

        errno = EACCES;
        vireo_result_t const result = vireo_config_parse_text(
            base_argument, text_argument, cases[index].text_size, output_argument, error_argument);
        int const actual_errno = errno;

        failures += expect_result(cases[index].case_name, result, VIREO_RESULT_INVALID_ARGUMENT);
        failures += expect_int(cases[index].case_name, actual_errno, EACCES);

        if (!cases[index].null_base) {
            failures += expect_config(cases[index].case_name, &base, &expected_base);
        }

        if (!cases[index].null_text) {
            failures += expect_bytes(cases[index].case_name, text, expected_text, sizeof(text));
        }

        if (!cases[index].null_output) {
            failures += expect_config(cases[index].case_name, &output, &expected_output);
        }

        if (!cases[index].null_error) {
            failures += expect_error(cases[index].case_name, &error, &expected_error);
        }
    }

    return failures;
}

/* 验证 parse_text 在解析文字前拒绝非法基础配置 */
static int test_parse_text_invalid_base(void) {
    static char const expected_text[] = "worker_count = 32\n";

    char text[sizeof(expected_text)];

    memcpy(text, expected_text, sizeof(text));

    vireo_config_t base = make_sentinel_config();
    base.worker_count = UINT32_C(0);

    vireo_config_t const expected_base = base;

    vireo_config_t output = {
        .listen_address = "203.0.113.7",
        .listen_port = UINT16_C(23456),
        .max_connections = UINT32_C(3210),
        .worker_count = UINT32_C(23),
        .idle_timeout_ms = UINT64_C(654321),
        .log_to_stderr = true,
        .log_max_file_size_bytes = UINT64_C(16777216),
        .data_dir = "/output/keep/data",
        .log_dir = "/output/keep/log",
    };

    vireo_config_t const expected_output = output;

    vireo_config_error_t error = make_sentinel_error();

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_VALUE_OUT_OF_RANGE,
        .source = VIREO_CONFIG_SOURCE_CONFIG,
        .field = VIREO_CONFIG_FIELD_WORKER_COUNT,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    errno = EACCES;
    vireo_result_t const result =
        vireo_config_parse_text(&base, text, sizeof(text) - 1U, &output, &error);
    int const actual_errno = errno;

    int failures = expect_result("config parse invalid base result", result, VIREO_RESULT_RANGE);
    failures += expect_error("config parse invalid base error", &error, &expected_error);
    failures += expect_int("config parse invalid base errno", actual_errno, EACCES);
    failures += expect_config("config parse invalid base keep", &base, &expected_base);
    failures +=
        expect_bytes("config parse invalid base text keep", text, expected_text, sizeof(text));
    failures += expect_config("config parse invalid base output keep", &output, &expected_output);

    return failures;
}

/* 验证 parse_text 拒绝超过总长度上限的配置文字 */
static int test_parse_text_oversized_text(void) {
    static char text[(size_t)VIREO_CONFIG_MAX_TEXT_SIZE + 1U];

    static char expected_text[(size_t)VIREO_CONFIG_MAX_TEXT_SIZE + 1U];

    memset(text, 0x5A, sizeof(text));
    memset(expected_text, 0x5A, sizeof(expected_text));

    vireo_config_t base = make_sentinel_config();
    vireo_config_t const expected_base = base;

    vireo_config_t output = {
        .listen_address = "203.0.113.7",
        .listen_port = UINT16_C(23456),
        .max_connections = UINT32_C(3210),
        .worker_count = UINT32_C(23),
        .idle_timeout_ms = UINT64_C(654321),
        .log_to_stderr = true,
        .log_max_file_size_bytes = UINT64_C(16777216),
        .data_dir = "/output/keep/data",
        .log_dir = "/output/keep/log",
    };

    vireo_config_t const expected_output = output;

    vireo_config_error_t error = make_sentinel_error();

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_TEXT_TOO_LARGE,
        .source = VIREO_CONFIG_SOURCE_TEXT,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    errno = EACCES;
    vireo_result_t const result =
        vireo_config_parse_text(&base, text, sizeof(text), &output, &error);
    int const actual_errno = errno;

    int failures = expect_result("config parse oversized text result", result, VIREO_RESULT_RANGE);
    failures += expect_error("config parse oversized text error", &error, &expected_error);
    failures += expect_int("config parse oversized text errno", actual_errno, EACCES);
    failures += expect_config("config parse oversized text base keep", &base, &expected_base);
    failures +=
        expect_bytes("config parse oversized text input keep", text, expected_text, sizeof(text));
    failures += expect_config("config parse oversized text output keep", &output, &expected_output);

    return failures;
}

/* 验证 parse_text 接受恰好达到总长度上限的合法文字 */
static int test_parse_text_maximum_text_size(void) {
    static char text[(size_t)VIREO_CONFIG_MAX_TEXT_SIZE];

    static char expected_text[(size_t)VIREO_CONFIG_MAX_TEXT_SIZE];

    memset(text, '\n', sizeof(text));
    memset(expected_text, '\n', sizeof(expected_text));

    vireo_config_t base = make_sentinel_config();
    vireo_config_t const expected_base = base;

    vireo_config_t output = {
        .listen_address = "203.0.113.7",
        .listen_port = UINT16_C(23456),
        .max_connections = UINT32_C(3210),
        .worker_count = UINT32_C(23),
        .idle_timeout_ms = UINT64_C(654321),
        .log_to_stderr = true,
        .log_max_file_size_bytes = UINT64_C(16777216),
        .data_dir = "/output/keep/data",
        .log_dir = "/output/keep/log",
    };

    vireo_config_error_t error = make_sentinel_error();

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_NONE,
        .source = VIREO_CONFIG_SOURCE_NONE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    errno = EACCES;
    vireo_result_t const result =
        vireo_config_parse_text(&base, text, sizeof(text), &output, &error);
    int const actual_errno = errno;

    int failures = expect_result("config parse maximum text size result", result, VIREO_OK);
    failures += expect_int("config parse maximum text size errno", actual_errno, EACCES);
    failures += expect_config("config parse maximum text size base keep", &base, &expected_base);
    failures += expect_bytes("config parse maximum text size input keep", text, expected_text,
                             sizeof(text));

    if (result == VIREO_OK) {
        failures += expect_config("config parse maximum text size output", &output, &expected_base);
        failures +=
            expect_error("config parse maximum text size error clear", &error, &expected_error);
    }

    return failures;
}

/* 验证 parse_text 拒绝超长单行，并报告准确行号且不提交半成品 */
static int test_parse_text_line_too_long(void) {
    static char const prefix[] =
        "worker_count = 32\n"
        "# comment\n";

    static char text[(sizeof(prefix) - 1U) + (size_t)VIREO_CONFIG_MAX_LINE_SIZE + 1U];

    static char expected_text[(sizeof(prefix) - 1U) + (size_t)VIREO_CONFIG_MAX_LINE_SIZE + 1U];

    size_t const prefix_size = sizeof(prefix) - 1U;

    memcpy(text, prefix, prefix_size);
    memset(text + prefix_size, 0x5A, sizeof(text) - prefix_size);

    memcpy(expected_text, text, sizeof(text));

    vireo_config_t base = make_sentinel_config();
    vireo_config_t const expected_base = base;

    vireo_config_t output = {
        .listen_address = "203.0.113.7",
        .listen_port = UINT16_C(23456),
        .max_connections = UINT32_C(3210),
        .worker_count = UINT32_C(23),
        .idle_timeout_ms = UINT64_C(654321),
        .log_to_stderr = true,
        .log_max_file_size_bytes = UINT64_C(16777216),
        .data_dir = "/output/keep/data",
        .log_dir = "/output/keep/log",
    };

    vireo_config_t const expected_output = output;

    vireo_config_error_t error = make_sentinel_error();

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_LINE_TOO_LONG,
        .source = VIREO_CONFIG_SOURCE_TEXT,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 3U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    errno = EACCES;
    vireo_result_t const result =
        vireo_config_parse_text(&base, text, sizeof(text), &output, &error);
    int const actual_errno = errno;

    int failures = expect_result("config parse line too long result", result, VIREO_RESULT_RANGE);
    failures += expect_error("config parse line too long error", &error, &expected_error);
    failures += expect_int("config parse line too long errno", actual_errno, EACCES);
    failures += expect_config("config parse line too long base keep", &base, &expected_base);
    failures +=
        expect_bytes("config parse line too long input keep", text, expected_text, sizeof(text));
    failures += expect_config("config parse line too long output keep", &output, &expected_output);

    return failures;
}

/* 验证 parse_text 接受恰好达到单行长度上限的合法注释行 */
static int test_parse_text_maximum_line_size(void) {
    static char const prefix[] = "worker_count = 32\n";

    static char text[(sizeof(prefix) - 1U) + (size_t)VIREO_CONFIG_MAX_LINE_SIZE];

    static char expected_text[(sizeof(prefix) - 1U) + (size_t)VIREO_CONFIG_MAX_LINE_SIZE];

    size_t const prefix_size = sizeof(prefix) - 1U;

    memcpy(text, prefix, prefix_size);

    text[prefix_size] = '#';

    memset(text + prefix_size + 1U, 0x5A, sizeof(text) - prefix_size - 1U);

    memcpy(expected_text, text, sizeof(text));

    vireo_config_t base = make_sentinel_config();
    vireo_config_t const expected_base = base;

    vireo_config_t expected_output = base;
    expected_output.worker_count = UINT32_C(32);

    vireo_config_t output = {
        .listen_address = "203.0.113.7",
        .listen_port = UINT16_C(23456),
        .max_connections = UINT32_C(3210),
        .worker_count = UINT32_C(23),
        .idle_timeout_ms = UINT64_C(654321),
        .log_to_stderr = true,
        .log_max_file_size_bytes = UINT64_C(16777216),
        .data_dir = "/output/keep/data",
        .log_dir = "/output/keep/log",
    };

    vireo_config_error_t error = make_sentinel_error();

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_NONE,
        .source = VIREO_CONFIG_SOURCE_NONE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    errno = EACCES;
    vireo_result_t const result =
        vireo_config_parse_text(&base, text, sizeof(text), &output, &error);
    int const actual_errno = errno;

    int failures = expect_result("config parse maximum line size result", result, VIREO_OK);
    failures += expect_int("config parse maximum line size errno", actual_errno, EACCES);
    failures += expect_config("config parse maximum line size base keep", &base, &expected_base);
    failures += expect_bytes("config parse maximum line size input keep", text, expected_text,
                             sizeof(text));

    if (result == VIREO_OK) {
        failures +=
            expect_config("config parse maximum line size output", &output, &expected_output);
        failures +=
            expect_error("config parse maximum line size error clear", &error, &expected_error);
    }

    return failures;
}

/* 验证 parse_text 拒绝配置行中的控制字节和 DEL */
static int test_parse_text_invalid_characters(void) {
    static char const prefix[] =
        "worker_count = 32\n"
        "# comment\n"
        "log_dir = /tmp";

    static struct {
        char const *case_name;
        unsigned char invalid_byte;
    } const cases[] = {
        {
            "config parse embedded nul",
            0x00U,
        },
        {
            "config parse bare carriage return",
            0x0DU,
        },
        {
            "config parse control byte upper boundary",
            0x1FU,
        },
        {
            "config parse delete byte",
            0x7FU,
        },
    };

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_INVALID_CHARACTER,
        .source = VIREO_CONFIG_SOURCE_TEXT,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 3U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    int failures = 0;

    for (size_t index = 0U; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
        char text[(sizeof(prefix) - 1U) + 1U];

        char expected_text[sizeof(text)];

        size_t const prefix_size = sizeof(prefix) - 1U;

        memcpy(text, prefix, prefix_size);

        text[prefix_size] = (char)cases[index].invalid_byte;

        memcpy(expected_text, text, sizeof(text));

        vireo_config_t base = make_sentinel_config();
        vireo_config_t const expected_base = base;

        vireo_config_t output = {
            .listen_address = "203.0.113.7",
            .listen_port = UINT16_C(23456),
            .max_connections = UINT32_C(3210),
            .worker_count = UINT32_C(23),
            .idle_timeout_ms = UINT64_C(654321),
            .log_to_stderr = true,
            .log_max_file_size_bytes = UINT64_C(16777216),
            .data_dir = "/output/keep/data",
            .log_dir = "/output/keep/log",
        };

        vireo_config_t const expected_output = output;

        vireo_config_error_t error = make_sentinel_error();

        errno = EACCES;
        vireo_result_t const result =
            vireo_config_parse_text(&base, text, sizeof(text), &output, &error);
        int const actual_errno = errno;

        failures += expect_result(cases[index].case_name, result, VIREO_RESULT_INVALID_ARGUMENT);
        failures += expect_error(cases[index].case_name, &error, &expected_error);
        failures += expect_int(cases[index].case_name, actual_errno, EACCES);
        failures += expect_config(cases[index].case_name, &base, &expected_base);
        failures += expect_bytes(cases[index].case_name, text, expected_text, sizeof(text));
        failures += expect_config(cases[index].case_name, &output, &expected_output);
    }

    return failures;
}

/* 验证普通配置行的结构错误和准确行号 */
static int test_parse_text_structure_errors(void) {
    static struct {
        char const *case_name;
        char const *last_line;
        vireo_config_issue_t issue;
    } const cases[] = {
        {
            "config parse missing separator",
            "log_dir /tmp/vireo",
            VIREO_CONFIG_ISSUE_MISSING_SEPARATOR,
        },
        {
            "config parse empty key",
            "   = 64",
            VIREO_CONFIG_ISSUE_EMPTY_KEY,
        },
        {
            "config parse unknown key",
            "unknown_key = 64",
            VIREO_CONFIG_ISSUE_UNKNOWN_KEY,
        },
    };

    static char const prefix[] =
        "worker_count = 32\n"
        "# comment\n";

    int failures = 0;

    for (size_t index = 0U; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
        char text[128];
        char expected_text[sizeof(text)];

        size_t const prefix_size = sizeof(prefix) - 1U;
        size_t const last_line_size = strlen(cases[index].last_line);
        size_t const text_size = prefix_size + last_line_size;

        memcpy(text, prefix, prefix_size);
        memcpy(text + prefix_size, cases[index].last_line, last_line_size);
        memcpy(expected_text, text, text_size);

        vireo_config_t base = make_sentinel_config();
        vireo_config_t const expected_base = base;

        vireo_config_t output = {
            .listen_address = "203.0.113.7",
            .listen_port = UINT16_C(23456),
            .max_connections = UINT32_C(3210),
            .worker_count = UINT32_C(23),
            .idle_timeout_ms = UINT64_C(654321),
            .log_to_stderr = true,
            .log_max_file_size_bytes = UINT64_C(16777216),
            .data_dir = "/output/keep/data",
            .log_dir = "/output/keep/log",
        };
        vireo_config_t const expected_output = output;

        vireo_config_error_t error = make_sentinel_error();

        vireo_config_error_t const expected_error = {
            .issue = cases[index].issue,
            .source = VIREO_CONFIG_SOURCE_TEXT,
            .field = VIREO_CONFIG_FIELD_NONE,
            .line = 3U,
            .entry_index = 0U,
            .system_errno = 0,
        };

        errno = EACCES;
        vireo_result_t const result =
            vireo_config_parse_text(&base, text, text_size, &output, &error);
        int const actual_errno = errno;

        failures += expect_result(cases[index].case_name, result, VIREO_RESULT_INVALID_ARGUMENT);
        failures += expect_error(cases[index].case_name, &error, &expected_error);
        failures += expect_int(cases[index].case_name, actual_errno, EACCES);
        failures += expect_config(cases[index].case_name, &base, &expected_base);
        failures += expect_bytes(cases[index].case_name, text, expected_text, text_size);
        failures += expect_config(cases[index].case_name, &output, &expected_output);
    }

    return failures;
}

/* 验证同一次文字解析拒绝重复键且不提交前值 */
static int test_parse_text_duplicate_key(void) {
    static char const expected_text[] =
        "worker_count = 32\n"
        "# comment\n"
        "worker_count = 64";

    char text[sizeof(expected_text)];
    memcpy(text, expected_text, sizeof(text));

    vireo_config_t base = make_sentinel_config();
    vireo_config_t const expected_base = base;

    vireo_config_t output = {
        .listen_address = "203.0.113.7",
        .listen_port = UINT16_C(23456),
        .max_connections = UINT32_C(3210),
        .worker_count = UINT32_C(23),
        .idle_timeout_ms = UINT64_C(654321),
        .log_to_stderr = true,
        .log_max_file_size_bytes = UINT64_C(16777216),
        .data_dir = "/output/keep/data",
        .log_dir = "/output/keep/log",
    };
    vireo_config_t const expected_output = output;

    vireo_config_error_t error = make_sentinel_error();

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_DUPLICATE_KEY,
        .source = VIREO_CONFIG_SOURCE_TEXT,
        .field = VIREO_CONFIG_FIELD_WORKER_COUNT,
        .line = 3U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    errno = EACCES;
    vireo_result_t const result =
        vireo_config_parse_text(&base, text, sizeof(text) - 1U, &output, &error);
    int const actual_errno = errno;

    int failures =
        expect_result("config parse duplicate key result", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_error("config parse duplicate key error", &error, &expected_error);
    failures += expect_int("config parse duplicate key errno", actual_errno, EACCES);
    failures += expect_config("config parse duplicate key base keep", &base, &expected_base);
    failures +=
        expect_bytes("config parse duplicate key input keep", text, expected_text, sizeof(text));
    failures += expect_config("config parse duplicate key output keep", &output, &expected_output);

    return failures;
}

/* 验证值长度上限的成功边界和首个失败边界 */
static int test_parse_text_value_length_boundaries(void) {
    static char const key[] = "data_dir = ";

    int failures = 0;

    /* 1. 路径值恰好 1023 字节，目标数组仍可追加 NUL */
    {
        static char text[(sizeof(key) - 1U) + (size_t)VIREO_CONFIG_MAX_VALUE_SIZE];
        static char expected_text[sizeof(text)];

        size_t const key_size = sizeof(key) - 1U;

        memcpy(text, key, key_size);
        text[key_size] = '/';
        memset(text + key_size + 1U, 'a', sizeof(text) - key_size - 1U);
        memcpy(expected_text, text, sizeof(text));

        vireo_config_t base = make_sentinel_config();
        vireo_config_t const expected_base = base;

        vireo_config_t expected_output = base;
        expected_output.data_dir[0] = '/';
        memset(expected_output.data_dir + 1U, 'a', sizeof(expected_output.data_dir) - 2U);
        expected_output.data_dir[sizeof(expected_output.data_dir) - 1U] = '\0';

        vireo_config_t output = make_sentinel_config();
        output.worker_count = UINT32_C(23);

        vireo_config_error_t error = make_sentinel_error();
        vireo_config_error_t const expected_error = {
            .issue = VIREO_CONFIG_ISSUE_NONE,
            .source = VIREO_CONFIG_SOURCE_NONE,
            .field = VIREO_CONFIG_FIELD_NONE,
            .line = 0U,
            .entry_index = 0U,
            .system_errno = 0,
        };

        errno = EACCES;
        vireo_result_t const result =
            vireo_config_parse_text(&base, text, sizeof(text), &output, &error);
        int const actual_errno = errno;

        failures += expect_result("config parse maximum value size result", result, VIREO_OK);
        failures += expect_int("config parse maximum value size errno", actual_errno, EACCES);
        failures +=
            expect_config("config parse maximum value size base keep", &base, &expected_base);
        failures += expect_bytes("config parse maximum value size input keep", text, expected_text,
                                 sizeof(text));

        if (result == VIREO_OK) {
            failures +=
                expect_config("config parse maximum value size output", &output, &expected_output);
            failures += expect_error("config parse maximum value size error clear", &error,
                                     &expected_error);
        }
    }

    /* 2. 值达到 1024 字节，必须在复制前拒绝并保持输出 */
    {
        static char text[(sizeof(key) - 1U) + (size_t)VIREO_CONFIG_MAX_VALUE_SIZE + 1U];
        static char expected_text[sizeof(text)];

        size_t const key_size = sizeof(key) - 1U;

        memcpy(text, key, key_size);
        text[key_size] = '/';
        memset(text + key_size + 1U, 'a', sizeof(text) - key_size - 1U);
        memcpy(expected_text, text, sizeof(text));

        vireo_config_t base = make_sentinel_config();
        vireo_config_t const expected_base = base;

        vireo_config_t output = {
            .listen_address = "203.0.113.7",
            .listen_port = UINT16_C(23456),
            .max_connections = UINT32_C(3210),
            .worker_count = UINT32_C(23),
            .idle_timeout_ms = UINT64_C(654321),
            .log_to_stderr = true,
            .log_max_file_size_bytes = UINT64_C(16777216),
            .data_dir = "/output/keep/data",
            .log_dir = "/output/keep/log",
        };
        vireo_config_t const expected_output = output;

        vireo_config_error_t error = make_sentinel_error();
        vireo_config_error_t const expected_error = {
            .issue = VIREO_CONFIG_ISSUE_VALUE_TOO_LONG,
            .source = VIREO_CONFIG_SOURCE_TEXT,
            .field = VIREO_CONFIG_FIELD_DATA_DIR,
            .line = 1U,
            .entry_index = 0U,
            .system_errno = 0,
        };

        errno = EACCES;
        vireo_result_t const result =
            vireo_config_parse_text(&base, text, sizeof(text), &output, &error);
        int const actual_errno = errno;

        failures +=
            expect_result("config parse oversized value result", result, VIREO_RESULT_RANGE);
        failures += expect_error("config parse oversized value error", &error, &expected_error);
        failures += expect_int("config parse oversized value errno", actual_errno, EACCES);
        failures += expect_config("config parse oversized value base keep", &base, &expected_base);
        failures += expect_bytes("config parse oversized value input keep", text, expected_text,
                                 sizeof(text));
        failures +=
            expect_config("config parse oversized value output keep", &output, &expected_output);
    }

    return failures;
}

/* 验证各类字段值的语法错误及字段定位 */
static int test_parse_text_value_syntax_errors(void) {
    static struct {
        char const *case_name;
        char const *last_line;
        vireo_config_issue_t issue;
        vireo_config_field_t field;
    } const cases[] = {
        {
            "config parse empty value",
            "listen_port = \t ",
            VIREO_CONFIG_ISSUE_EMPTY_VALUE,
            VIREO_CONFIG_FIELD_LISTEN_PORT,
        },
        {
            "config parse invalid integer",
            "listen_port = +80",
            VIREO_CONFIG_ISSUE_INVALID_INTEGER,
            VIREO_CONFIG_FIELD_LISTEN_PORT,
        },
        {
            "config parse invalid boolean",
            "log_to_stderr = TRUE",
            VIREO_CONFIG_ISSUE_INVALID_BOOLEAN,
            VIREO_CONFIG_FIELD_LOG_TO_STDERR,
        },
        {
            "config parse invalid duration unit",
            "idle_timeout = 10 ms",
            VIREO_CONFIG_ISSUE_INVALID_UNIT,
            VIREO_CONFIG_FIELD_IDLE_TIMEOUT,
        },
        {
            "config parse invalid size unit",
            "log_max_file_size = 10MB",
            VIREO_CONFIG_ISSUE_INVALID_UNIT,
            VIREO_CONFIG_FIELD_LOG_MAX_FILE_SIZE,
        },
        {
            "config parse invalid address value",
            "listen_address = 01.2.3.4",
            VIREO_CONFIG_ISSUE_INVALID_ADDRESS,
            VIREO_CONFIG_FIELD_LISTEN_ADDRESS,
        },
        {
            "config parse invalid path value",
            "data_dir = relative/path",
            VIREO_CONFIG_ISSUE_INVALID_PATH,
            VIREO_CONFIG_FIELD_DATA_DIR,
        },
    };

    static char const prefix[] =
        "worker_count = 32\n"
        "# comment\n";

    int failures = 0;

    for (size_t index = 0U; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
        char text[160];
        char expected_text[sizeof(text)];

        size_t const prefix_size = sizeof(prefix) - 1U;
        size_t const last_line_size = strlen(cases[index].last_line);
        size_t const text_size = prefix_size + last_line_size;

        memcpy(text, prefix, prefix_size);
        memcpy(text + prefix_size, cases[index].last_line, last_line_size);
        memcpy(expected_text, text, text_size);

        vireo_config_t base = make_sentinel_config();
        vireo_config_t const expected_base = base;

        vireo_config_t output = {
            .listen_address = "203.0.113.7",
            .listen_port = UINT16_C(23456),
            .max_connections = UINT32_C(3210),
            .worker_count = UINT32_C(23),
            .idle_timeout_ms = UINT64_C(654321),
            .log_to_stderr = true,
            .log_max_file_size_bytes = UINT64_C(16777216),
            .data_dir = "/output/keep/data",
            .log_dir = "/output/keep/log",
        };
        vireo_config_t const expected_output = output;

        vireo_config_error_t error = make_sentinel_error();
        vireo_config_error_t const expected_error = {
            .issue = cases[index].issue,
            .source = VIREO_CONFIG_SOURCE_TEXT,
            .field = cases[index].field,
            .line = 3U,
            .entry_index = 0U,
            .system_errno = 0,
        };

        errno = EACCES;
        vireo_result_t const result =
            vireo_config_parse_text(&base, text, text_size, &output, &error);
        int const actual_errno = errno;

        failures += expect_result(cases[index].case_name, result, VIREO_RESULT_INVALID_ARGUMENT);
        failures += expect_error(cases[index].case_name, &error, &expected_error);
        failures += expect_int(cases[index].case_name, actual_errno, EACCES);
        failures += expect_config(cases[index].case_name, &base, &expected_base);
        failures += expect_bytes(cases[index].case_name, text, expected_text, text_size);
        failures += expect_config(cases[index].case_name, &output, &expected_output);
    }

    return failures;
}

/* 验证数值字段的范围错误和 uint64_t 溢出 */
static int test_parse_text_numeric_range_and_overflow(void) {
    static struct {
        char const *case_name;
        char const *text;
        vireo_result_t result;
        vireo_config_issue_t issue;
        vireo_config_field_t field;
    } const cases[] = {
        {
            "config parse port below minimum",
            "listen_port = 0",
            VIREO_RESULT_RANGE,
            VIREO_CONFIG_ISSUE_VALUE_OUT_OF_RANGE,
            VIREO_CONFIG_FIELD_LISTEN_PORT,
        },
        {
            "config parse connections above maximum",
            "max_connections = 65537",
            VIREO_RESULT_RANGE,
            VIREO_CONFIG_ISSUE_VALUE_OUT_OF_RANGE,
            VIREO_CONFIG_FIELD_MAX_CONNECTIONS,
        },
        {
            "config parse workers above maximum",
            "worker_count = 257",
            VIREO_RESULT_RANGE,
            VIREO_CONFIG_ISSUE_VALUE_OUT_OF_RANGE,
            VIREO_CONFIG_FIELD_WORKER_COUNT,
        },
        {
            "config parse timeout above maximum",
            "idle_timeout = 86400001ms",
            VIREO_RESULT_RANGE,
            VIREO_CONFIG_ISSUE_VALUE_OUT_OF_RANGE,
            VIREO_CONFIG_FIELD_IDLE_TIMEOUT,
        },
        {
            "config parse log size above maximum",
            "log_max_file_size = 2GiB",
            VIREO_RESULT_RANGE,
            VIREO_CONFIG_ISSUE_VALUE_OUT_OF_RANGE,
            VIREO_CONFIG_FIELD_LOG_MAX_FILE_SIZE,
        },
        {
            "config parse decimal accumulation overflow",
            "listen_port = 18446744073709551616",
            VIREO_RESULT_OVERFLOW,
            VIREO_CONFIG_ISSUE_NUMERIC_OVERFLOW,
            VIREO_CONFIG_FIELD_LISTEN_PORT,
        },
        {
            "config parse duration multiplication overflow",
            "idle_timeout = 18446744073709551615m",
            VIREO_RESULT_OVERFLOW,
            VIREO_CONFIG_ISSUE_NUMERIC_OVERFLOW,
            VIREO_CONFIG_FIELD_IDLE_TIMEOUT,
        },
        {
            "config parse size multiplication overflow",
            "log_max_file_size = 18446744073709551615GiB",
            VIREO_RESULT_OVERFLOW,
            VIREO_CONFIG_ISSUE_NUMERIC_OVERFLOW,
            VIREO_CONFIG_FIELD_LOG_MAX_FILE_SIZE,
        },
    };

    int failures = 0;

    for (size_t index = 0U; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
        size_t const text_size = strlen(cases[index].text);

        char text[128];
        char expected_text[sizeof(text)];

        memcpy(text, cases[index].text, text_size);
        memcpy(expected_text, text, text_size);

        vireo_config_t base = make_sentinel_config();
        vireo_config_t const expected_base = base;

        vireo_config_t output = {
            .listen_address = "203.0.113.7",
            .listen_port = UINT16_C(23456),
            .max_connections = UINT32_C(3210),
            .worker_count = UINT32_C(23),
            .idle_timeout_ms = UINT64_C(654321),
            .log_to_stderr = true,
            .log_max_file_size_bytes = UINT64_C(16777216),
            .data_dir = "/output/keep/data",
            .log_dir = "/output/keep/log",
        };
        vireo_config_t const expected_output = output;

        vireo_config_error_t error = make_sentinel_error();
        vireo_config_error_t const expected_error = {
            .issue = cases[index].issue,
            .source = VIREO_CONFIG_SOURCE_TEXT,
            .field = cases[index].field,
            .line = 1U,
            .entry_index = 0U,
            .system_errno = 0,
        };

        errno = EACCES;
        vireo_result_t const result =
            vireo_config_parse_text(&base, text, text_size, &output, &error);
        int const actual_errno = errno;

        failures += expect_result(cases[index].case_name, result, cases[index].result);
        failures += expect_error(cases[index].case_name, &error, &expected_error);
        failures += expect_int(cases[index].case_name, actual_errno, EACCES);
        failures += expect_config(cases[index].case_name, &base, &expected_base);
        failures += expect_bytes(cases[index].case_name, text, expected_text, text_size);
        failures += expect_config(cases[index].case_name, &output, &expected_output);
    }

    return failures;
}

/* 验证大小与时长单位的全部成功换算形式 */
static int test_parse_text_unit_conversions(void) {
    static struct {
        char const *case_name;
        char const *text;
        bool duration;
        uint64_t expected_value;
    } const cases[] = {
        {
            "config parse duration without suffix",
            "idle_timeout = 1500",
            true,
            UINT64_C(1500),
        },
        {
            "config parse duration milliseconds",
            "idle_timeout = 1500ms",
            true,
            UINT64_C(1500),
        },
        {
            "config parse duration seconds",
            "idle_timeout = 2s",
            true,
            UINT64_C(2000),
        },
        {
            "config parse duration minutes",
            "idle_timeout = 1m",
            true,
            UINT64_C(60000),
        },
        {
            "config parse size without suffix",
            "log_max_file_size = 1048576",
            false,
            UINT64_C(1048576),
        },
        {
            "config parse size bytes suffix",
            "log_max_file_size = 1048576B",
            false,
            UINT64_C(1048576),
        },
        {
            "config parse size kibibytes",
            "log_max_file_size = 1024KiB",
            false,
            UINT64_C(1048576),
        },
        {
            "config parse size mebibytes",
            "log_max_file_size = 1MiB",
            false,
            UINT64_C(1048576),
        },
        {
            "config parse size gibibytes",
            "log_max_file_size = 1GiB",
            false,
            UINT64_C(1073741824),
        },
    };

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_NONE,
        .source = VIREO_CONFIG_SOURCE_NONE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    int failures = 0;

    for (size_t index = 0U; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
        size_t const text_size = strlen(cases[index].text);

        char text[96];
        char expected_text[sizeof(text)];
        memcpy(text, cases[index].text, text_size);
        memcpy(expected_text, text, text_size);

        vireo_config_t base = make_sentinel_config();
        vireo_config_t const expected_base = base;

        vireo_config_t expected_output = base;
        if (cases[index].duration) {
            expected_output.idle_timeout_ms = cases[index].expected_value;
        } else {
            expected_output.log_max_file_size_bytes = cases[index].expected_value;
        }

        vireo_config_t output = make_sentinel_config();
        output.worker_count = UINT32_C(23);

        vireo_config_error_t error = make_sentinel_error();

        errno = EACCES;
        vireo_result_t const result =
            vireo_config_parse_text(&base, text, text_size, &output, &error);
        int const actual_errno = errno;

        failures += expect_result(cases[index].case_name, result, VIREO_OK);
        failures += expect_int(cases[index].case_name, actual_errno, EACCES);
        failures += expect_config(cases[index].case_name, &base, &expected_base);
        failures += expect_bytes(cases[index].case_name, text, expected_text, text_size);

        if (result == VIREO_OK) {
            failures += expect_config(cases[index].case_name, &output, &expected_output);
            failures += expect_error(cases[index].case_name, &error, &expected_error);
        }
    }

    return failures;
}

/* 验证第一个等号分隔和值中的井号不是行尾注释 */
static int test_parse_text_first_separator_and_inline_hash(void) {
    static char const expected_text[] = "data_dir = /srv/vireo=a#b";

    char text[sizeof(expected_text)];
    memcpy(text, expected_text, sizeof(text));

    vireo_config_t base = make_sentinel_config();
    vireo_config_t const expected_base = base;

    vireo_config_t expected_output = base;
    memcpy(expected_output.data_dir, "/srv/vireo=a#b", sizeof("/srv/vireo=a#b"));

    vireo_config_t output = make_sentinel_config();
    output.worker_count = UINT32_C(23);

    vireo_config_error_t error = make_sentinel_error();
    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_NONE,
        .source = VIREO_CONFIG_SOURCE_NONE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    errno = EACCES;
    vireo_result_t const result =
        vireo_config_parse_text(&base, text, sizeof(text) - 1U, &output, &error);
    int const actual_errno = errno;

    int failures = expect_result("config parse first separator result", result, VIREO_OK);
    failures += expect_int("config parse first separator errno", actual_errno, EACCES);
    failures += expect_config("config parse first separator base keep", &base, &expected_base);
    failures +=
        expect_bytes("config parse first separator input keep", text, expected_text, sizeof(text));

    if (result == VIREO_OK) {
        failures += expect_config("config parse first separator output", &output, &expected_output);
        failures +=
            expect_error("config parse first separator error clear", &error, &expected_error);
    }

    return failures;
}

/* 验证九个环境字段、裁剪规则和最大项数成功边界 */
static int test_apply_environment_success(void) {
    static vireo_config_environment_t const environment[] = {
        {
            "VIREO_LISTEN_ADDRESS",
            " 10.20.30.40 ",
        },
        {
            "VIREO_LISTEN_PORT",
            "\t12345\t",
        },
        {
            "VIREO_MAX_CONNECTIONS",
            "2048",
        },
        {
            "VIREO_WORKER_COUNT",
            "8",
        },
        {
            "VIREO_IDLE_TIMEOUT",
            "2m",
        },
        {
            "VIREO_LOG_TO_STDERR",
            "true",
        },
        {
            "VIREO_LOG_MAX_FILE_SIZE",
            "64MiB",
        },
        {
            "VIREO_DATA_DIR",
            "/srv/vireo/data",
        },
        {
            "VIREO_LOG_DIR",
            "/srv/vireo/log",
        },
    };

    vireo_config_t base = make_sentinel_config();
    vireo_config_t const expected_base = base;

    vireo_config_t output = make_sentinel_config();
    output.worker_count = UINT32_C(23);

    vireo_config_t const expected_output = {
        .listen_address = "10.20.30.40",
        .listen_port = UINT16_C(12345),
        .max_connections = UINT32_C(2048),
        .worker_count = UINT32_C(8),
        .idle_timeout_ms = UINT64_C(120000),
        .log_to_stderr = true,
        .log_max_file_size_bytes = UINT64_C(67108864),
        .data_dir = "/srv/vireo/data",
        .log_dir = "/srv/vireo/log",
    };

    vireo_config_error_t error = make_sentinel_error();
    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_NONE,
        .source = VIREO_CONFIG_SOURCE_NONE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    errno = EACCES;
    vireo_result_t const result = vireo_config_apply_environment(
        &base, environment, VIREO_TEST_ARRAY_COUNT(environment), &output, &error);
    int const actual_errno = errno;

    int failures = expect_result("config environment success result", result, VIREO_OK);
    failures += expect_int("config environment success errno", actual_errno, EACCES);
    failures += expect_config("config environment success base keep", &base, &expected_base);

    if (result == VIREO_OK) {
        failures += expect_config("config environment success output", &output, &expected_output);
        failures += expect_error("config environment success error clear", &error, &expected_error);
    }

    return failures;
}

/* 验证零个环境项允许空数组或非空数组指针 */
static int test_apply_environment_empty(void) {
    static vireo_config_environment_t const unused[] = {
        {
            "VIREO_WORKER_COUNT",
            "32",
        },
    };

    static struct {
        char const *case_name;
        vireo_config_environment_t const *environment;
    } const cases[] = {
        {
            "config environment null empty list",
            NULL,
        },
        {
            "config environment nonnull empty list",
            unused,
        },
    };

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_NONE,
        .source = VIREO_CONFIG_SOURCE_NONE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    int failures = 0;

    for (size_t index = 0U; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
        vireo_config_t base = make_sentinel_config();
        vireo_config_t const expected_base = base;

        vireo_config_t output = {
            .listen_address = "203.0.113.7",
            .listen_port = UINT16_C(23456),
            .max_connections = UINT32_C(3210),
            .worker_count = UINT32_C(23),
            .idle_timeout_ms = UINT64_C(654321),
            .log_to_stderr = true,
            .log_max_file_size_bytes = UINT64_C(16777216),
            .data_dir = "/output/keep/data",
            .log_dir = "/output/keep/log",
        };

        vireo_config_error_t error = make_sentinel_error();

        errno = EACCES;
        vireo_result_t const result =
            vireo_config_apply_environment(&base, cases[index].environment, 0U, &output, &error);
        int const actual_errno = errno;

        failures += expect_result(cases[index].case_name, result, VIREO_OK);
        failures += expect_int(cases[index].case_name, actual_errno, EACCES);
        failures += expect_config(cases[index].case_name, &base, &expected_base);

        if (result == VIREO_OK) {
            failures += expect_config(cases[index].case_name, &output, &expected_base);
            failures += expect_error(cases[index].case_name, &error, &expected_error);
        }
    }

    return failures;
}

/* 验证 apply_environment 的公共非法参数合同 */
static int test_apply_environment_invalid_arguments(void) {
    static vireo_config_environment_t const environment[] = {
        {
            "VIREO_WORKER_COUNT",
            "32",
        },
    };

    static struct {
        char const *case_name;
        bool null_base;
        bool null_environment;
        bool null_output;
        bool null_error;
        size_t environment_count;
    } const cases[] = {
        {
            "config environment null base",
            true,
            false,
            false,
            false,
            1U,
        },
        {
            "config environment null nonempty array",
            false,
            true,
            false,
            false,
            1U,
        },
        {
            "config environment null output",
            false,
            false,
            true,
            false,
            1U,
        },
        {
            "config environment null error",
            false,
            false,
            false,
            true,
            1U,
        },
    };

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_INVALID_ARGUMENT,
        .source = VIREO_CONFIG_SOURCE_NONE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    int failures = 0;

    for (size_t index = 0U; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
        vireo_config_t base = make_sentinel_config();
        vireo_config_t const expected_base = base;

        vireo_config_t output = {
            .listen_address = "203.0.113.7",
            .listen_port = UINT16_C(23456),
            .max_connections = UINT32_C(3210),
            .worker_count = UINT32_C(23),
            .idle_timeout_ms = UINT64_C(654321),
            .log_to_stderr = true,
            .log_max_file_size_bytes = UINT64_C(16777216),
            .data_dir = "/output/keep/data",
            .log_dir = "/output/keep/log",
        };
        vireo_config_t const expected_output = output;

        vireo_config_error_t error = make_sentinel_error();

        vireo_config_t const *base_argument = cases[index].null_base ? NULL : &base;
        vireo_config_environment_t const *environment_argument =
            cases[index].null_environment ? NULL : environment;
        vireo_config_t *output_argument = cases[index].null_output ? NULL : &output;
        vireo_config_error_t *error_argument = cases[index].null_error ? NULL : &error;

        errno = EACCES;
        vireo_result_t const result = vireo_config_apply_environment(
            base_argument, environment_argument, cases[index].environment_count, output_argument,
            error_argument);
        int const actual_errno = errno;

        failures += expect_result(cases[index].case_name, result, VIREO_RESULT_INVALID_ARGUMENT);
        failures += expect_int(cases[index].case_name, actual_errno, EACCES);

        if (!cases[index].null_base) {
            failures += expect_config(cases[index].case_name, &base, &expected_base);
        }

        if (!cases[index].null_output) {
            failures += expect_config(cases[index].case_name, &output, &expected_output);
        }

        if (!cases[index].null_error) {
            failures += expect_error(cases[index].case_name, &error, &expected_error);
        }
    }

    return failures;
}

/* 验证环境覆盖不能修复非法基础配置 */
static int test_apply_environment_invalid_base(void) {
    static vireo_config_environment_t const environment[] = {
        {
            "VIREO_WORKER_COUNT",
            "32",
        },
    };

    vireo_config_t base = make_sentinel_config();
    base.worker_count = UINT32_C(0);
    vireo_config_t const expected_base = base;

    vireo_config_t output = {
        .listen_address = "203.0.113.7",
        .listen_port = UINT16_C(23456),
        .max_connections = UINT32_C(3210),
        .worker_count = UINT32_C(23),
        .idle_timeout_ms = UINT64_C(654321),
        .log_to_stderr = true,
        .log_max_file_size_bytes = UINT64_C(16777216),
        .data_dir = "/output/keep/data",
        .log_dir = "/output/keep/log",
    };
    vireo_config_t const expected_output = output;

    vireo_config_error_t error = make_sentinel_error();
    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_VALUE_OUT_OF_RANGE,
        .source = VIREO_CONFIG_SOURCE_CONFIG,
        .field = VIREO_CONFIG_FIELD_WORKER_COUNT,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    errno = EACCES;
    vireo_result_t const result = vireo_config_apply_environment(
        &base, environment, VIREO_TEST_ARRAY_COUNT(environment), &output, &error);
    int const actual_errno = errno;

    int failures =
        expect_result("config environment invalid base result", result, VIREO_RESULT_RANGE);
    failures += expect_error("config environment invalid base error", &error, &expected_error);
    failures += expect_int("config environment invalid base errno", actual_errno, EACCES);
    failures += expect_config("config environment invalid base keep", &base, &expected_base);
    failures +=
        expect_config("config environment invalid base output keep", &output, &expected_output);

    return failures;
}

/* 验证环境项数量、空成员、未知名称和重复名称 */
static int test_apply_environment_item_errors(void) {
    int failures = 0;

    /* 1. 项数超过接口上限，必须在读取数组成员前拒绝 */
    {
        static vireo_config_environment_t const
            environment[(size_t)VIREO_CONFIG_MAX_ENVIRONMENT_ITEMS + 1U] = {
                {"VIREO_WORKER_COUNT", "32"}, {"VIREO_WORKER_COUNT", "32"},
                {"VIREO_WORKER_COUNT", "32"}, {"VIREO_WORKER_COUNT", "32"},
                {"VIREO_WORKER_COUNT", "32"}, {"VIREO_WORKER_COUNT", "32"},
                {"VIREO_WORKER_COUNT", "32"}, {"VIREO_WORKER_COUNT", "32"},
                {"VIREO_WORKER_COUNT", "32"}, {"VIREO_WORKER_COUNT", "32"},
        };

        vireo_config_t base = make_sentinel_config();
        vireo_config_t const expected_base = base;

        vireo_config_t output = {
            .listen_address = "203.0.113.7",
            .listen_port = UINT16_C(23456),
            .max_connections = UINT32_C(3210),
            .worker_count = UINT32_C(23),
            .idle_timeout_ms = UINT64_C(654321),
            .log_to_stderr = true,
            .log_max_file_size_bytes = UINT64_C(16777216),
            .data_dir = "/output/keep/data",
            .log_dir = "/output/keep/log",
        };
        vireo_config_t const expected_output = output;

        vireo_config_error_t error = make_sentinel_error();
        vireo_config_error_t const expected_error = {
            .issue = VIREO_CONFIG_ISSUE_TOO_MANY_ENVIRONMENT_ITEMS,
            .source = VIREO_CONFIG_SOURCE_ENVIRONMENT,
            .field = VIREO_CONFIG_FIELD_NONE,
            .line = 0U,
            .entry_index = 0U,
            .system_errno = 0,
        };

        errno = EACCES;
        vireo_result_t const result = vireo_config_apply_environment(
            &base, environment, VIREO_TEST_ARRAY_COUNT(environment), &output, &error);
        int const actual_errno = errno;

        failures +=
            expect_result("config environment too many items result", result, VIREO_RESULT_RANGE);
        failures +=
            expect_error("config environment too many items error", &error, &expected_error);
        failures += expect_int("config environment too many items errno", actual_errno, EACCES);
        failures +=
            expect_config("config environment too many items base keep", &base, &expected_base);
        failures += expect_config("config environment too many items output keep", &output,
                                  &expected_output);
    }

    /* 2. 项级错误发生在第二项或第三项，并保持完整输出 */
    {
        static struct {
            char const *case_name;
            char const *second_name;
            char const *second_value;
            size_t environment_count;
            vireo_config_issue_t issue;
            vireo_config_field_t field;
            size_t entry_index;
        } const cases[] = {
            {
                "config environment null name",
                NULL,
                "true",
                2U,
                VIREO_CONFIG_ISSUE_INVALID_ARGUMENT,
                VIREO_CONFIG_FIELD_NONE,
                2U,
            },
            {
                "config environment null value",
                "VIREO_LOG_TO_STDERR",
                NULL,
                2U,
                VIREO_CONFIG_ISSUE_INVALID_ARGUMENT,
                VIREO_CONFIG_FIELD_NONE,
                2U,
            },
            {
                "config environment unknown name",
                "VIREO_UNKNOWN",
                "true",
                2U,
                VIREO_CONFIG_ISSUE_UNKNOWN_ENVIRONMENT,
                VIREO_CONFIG_FIELD_NONE,
                2U,
            },
            {
                "config environment duplicate name",
                "VIREO_LOG_TO_STDERR",
                "true",
                3U,
                VIREO_CONFIG_ISSUE_DUPLICATE_ENVIRONMENT,
                VIREO_CONFIG_FIELD_WORKER_COUNT,
                3U,
            },
        };

        for (size_t index = 0U; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
            vireo_config_environment_t const environment[] = {
                {
                    "VIREO_WORKER_COUNT",
                    "32",
                },
                {
                    cases[index].second_name,
                    cases[index].second_value,
                },
                {
                    "VIREO_WORKER_COUNT",
                    "64",
                },
            };

            vireo_config_t base = make_sentinel_config();
            vireo_config_t const expected_base = base;

            vireo_config_t output = {
                .listen_address = "203.0.113.7",
                .listen_port = UINT16_C(23456),
                .max_connections = UINT32_C(3210),
                .worker_count = UINT32_C(23),
                .idle_timeout_ms = UINT64_C(654321),
                .log_to_stderr = true,
                .log_max_file_size_bytes = UINT64_C(16777216),
                .data_dir = "/output/keep/data",
                .log_dir = "/output/keep/log",
            };
            vireo_config_t const expected_output = output;

            vireo_config_error_t error = make_sentinel_error();
            vireo_config_error_t const expected_error = {
                .issue = cases[index].issue,
                .source = VIREO_CONFIG_SOURCE_ENVIRONMENT,
                .field = cases[index].field,
                .line = 0U,
                .entry_index = cases[index].entry_index,
                .system_errno = 0,
            };

            errno = EACCES;
            vireo_result_t const result = vireo_config_apply_environment(
                &base, environment, cases[index].environment_count, &output, &error);
            int const actual_errno = errno;

            failures +=
                expect_result(cases[index].case_name, result, VIREO_RESULT_INVALID_ARGUMENT);
            failures += expect_error(cases[index].case_name, &error, &expected_error);
            failures += expect_int(cases[index].case_name, actual_errno, EACCES);
            failures += expect_config(cases[index].case_name, &base, &expected_base);
            failures += expect_config(cases[index].case_name, &output, &expected_output);
        }
    }

    return failures;
}

/* 验证环境字段值错误、条目位置和事务性 */
static int test_apply_environment_value_errors(void) {
    static struct {
        char const *case_name;
        char const *name;
        char const *value;
        vireo_result_t result;
        vireo_config_issue_t issue;
        vireo_config_field_t field;
    } const cases[] = {
        {
            "config environment empty value",
            "VIREO_LOG_DIR",
            " \t ",
            VIREO_RESULT_INVALID_ARGUMENT,
            VIREO_CONFIG_ISSUE_EMPTY_VALUE,
            VIREO_CONFIG_FIELD_LOG_DIR,
        },
        {
            "config environment invalid integer",
            "VIREO_LISTEN_PORT",
            "+80",
            VIREO_RESULT_INVALID_ARGUMENT,
            VIREO_CONFIG_ISSUE_INVALID_INTEGER,
            VIREO_CONFIG_FIELD_LISTEN_PORT,
        },
        {
            "config environment invalid boolean",
            "VIREO_LOG_TO_STDERR",
            "TRUE",
            VIREO_RESULT_INVALID_ARGUMENT,
            VIREO_CONFIG_ISSUE_INVALID_BOOLEAN,
            VIREO_CONFIG_FIELD_LOG_TO_STDERR,
        },
        {
            "config environment invalid unit",
            "VIREO_IDLE_TIMEOUT",
            "10 ms",
            VIREO_RESULT_INVALID_ARGUMENT,
            VIREO_CONFIG_ISSUE_INVALID_UNIT,
            VIREO_CONFIG_FIELD_IDLE_TIMEOUT,
        },
        {
            "config environment invalid address",
            "VIREO_LISTEN_ADDRESS",
            "01.2.3.4",
            VIREO_RESULT_INVALID_ARGUMENT,
            VIREO_CONFIG_ISSUE_INVALID_ADDRESS,
            VIREO_CONFIG_FIELD_LISTEN_ADDRESS,
        },
        {
            "config environment invalid path",
            "VIREO_DATA_DIR",
            "relative/path",
            VIREO_RESULT_INVALID_ARGUMENT,
            VIREO_CONFIG_ISSUE_INVALID_PATH,
            VIREO_CONFIG_FIELD_DATA_DIR,
        },
        {
            "config environment value out of range",
            "VIREO_MAX_CONNECTIONS",
            "0",
            VIREO_RESULT_RANGE,
            VIREO_CONFIG_ISSUE_VALUE_OUT_OF_RANGE,
            VIREO_CONFIG_FIELD_MAX_CONNECTIONS,
        },
        {
            "config environment numeric overflow",
            "VIREO_LISTEN_PORT",
            "18446744073709551616",
            VIREO_RESULT_OVERFLOW,
            VIREO_CONFIG_ISSUE_NUMERIC_OVERFLOW,
            VIREO_CONFIG_FIELD_LISTEN_PORT,
        },
    };

    int failures = 0;

    for (size_t index = 0U; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
        vireo_config_environment_t const environment[] = {
            {
                "VIREO_WORKER_COUNT",
                "32",
            },
            {
                cases[index].name,
                cases[index].value,
            },
        };

        vireo_config_t base = make_sentinel_config();
        vireo_config_t const expected_base = base;

        vireo_config_t output = {
            .listen_address = "203.0.113.7",
            .listen_port = UINT16_C(23456),
            .max_connections = UINT32_C(3210),
            .worker_count = UINT32_C(23),
            .idle_timeout_ms = UINT64_C(654321),
            .log_to_stderr = true,
            .log_max_file_size_bytes = UINT64_C(16777216),
            .data_dir = "/output/keep/data",
            .log_dir = "/output/keep/log",
        };
        vireo_config_t const expected_output = output;

        vireo_config_error_t error = make_sentinel_error();
        vireo_config_error_t const expected_error = {
            .issue = cases[index].issue,
            .source = VIREO_CONFIG_SOURCE_ENVIRONMENT,
            .field = cases[index].field,
            .line = 0U,
            .entry_index = 2U,
            .system_errno = 0,
        };

        errno = EACCES;
        vireo_result_t const result = vireo_config_apply_environment(
            &base, environment, VIREO_TEST_ARRAY_COUNT(environment), &output, &error);
        int const actual_errno = errno;

        failures += expect_result(cases[index].case_name, result, cases[index].result);
        failures += expect_error(cases[index].case_name, &error, &expected_error);
        failures += expect_int(cases[index].case_name, actual_errno, EACCES);
        failures += expect_config(cases[index].case_name, &base, &expected_base);
        failures += expect_config(cases[index].case_name, &output, &expected_output);
    }

    /* 1024 字节的环境值在目标字段解析前由统一值上限拒绝 */
    {
        static char oversized_value[(size_t)VIREO_CONFIG_MAX_VALUE_SIZE + 2U];

        memset(oversized_value, 'a', (size_t)VIREO_CONFIG_MAX_VALUE_SIZE + 1U);
        oversized_value[(size_t)VIREO_CONFIG_MAX_VALUE_SIZE + 1U] = '\0';

        vireo_config_environment_t const environment[] = {
            {
                "VIREO_WORKER_COUNT",
                "32",
            },
            {
                "VIREO_LOG_DIR",
                oversized_value,
            },
        };

        vireo_config_t base = make_sentinel_config();
        vireo_config_t const expected_base = base;

        vireo_config_t output = {
            .listen_address = "203.0.113.7",
            .listen_port = UINT16_C(23456),
            .max_connections = UINT32_C(3210),
            .worker_count = UINT32_C(23),
            .idle_timeout_ms = UINT64_C(654321),
            .log_to_stderr = true,
            .log_max_file_size_bytes = UINT64_C(16777216),
            .data_dir = "/output/keep/data",
            .log_dir = "/output/keep/log",
        };
        vireo_config_t const expected_output = output;

        vireo_config_error_t error = make_sentinel_error();
        vireo_config_error_t const expected_error = {
            .issue = VIREO_CONFIG_ISSUE_VALUE_TOO_LONG,
            .source = VIREO_CONFIG_SOURCE_ENVIRONMENT,
            .field = VIREO_CONFIG_FIELD_LOG_DIR,
            .line = 0U,
            .entry_index = 2U,
            .system_errno = 0,
        };

        errno = EACCES;
        vireo_result_t const result = vireo_config_apply_environment(
            &base, environment, VIREO_TEST_ARRAY_COUNT(environment), &output, &error);
        int const actual_errno = errno;

        failures +=
            expect_result("config environment oversized value result", result, VIREO_RESULT_RANGE);
        failures +=
            expect_error("config environment oversized value error", &error, &expected_error);
        failures += expect_int("config environment oversized value errno", actual_errno, EACCES);
        failures +=
            expect_config("config environment oversized value base keep", &base, &expected_base);
        failures += expect_config("config environment oversized value output keep", &output,
                                  &expected_output);
    }

    return failures;
}

/* 验证跳过文件时加载默认值和显式环境覆盖 */
static int test_load_without_file(void) {
    vireo_config_t const defaults = {
        .listen_address = VIREO_CONFIG_DEFAULT_LISTEN_ADDRESS,
        .listen_port = VIREO_CONFIG_DEFAULT_LISTEN_PORT,
        .max_connections = VIREO_CONFIG_DEFAULT_MAX_CONNECTIONS,
        .worker_count = VIREO_CONFIG_DEFAULT_WORKER_COUNT,
        .idle_timeout_ms = VIREO_CONFIG_DEFAULT_IDLE_TIMEOUT_MS,
        .log_to_stderr = VIREO_CONFIG_DEFAULT_LOG_TO_STDERR,
        .log_max_file_size_bytes = VIREO_CONFIG_DEFAULT_LOG_FILE_SIZE_BYTES,
        .data_dir = VIREO_CONFIG_DEFAULT_DATA_DIR,
        .log_dir = VIREO_CONFIG_DEFAULT_LOG_DIR,
    };

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_NONE,
        .source = VIREO_CONFIG_SOURCE_NONE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    int failures = 0;

    /* 1. 没有文件也没有环境项，结果就是完整默认配置 */
    {
        vireo_config_t output = make_sentinel_config();
        vireo_config_error_t error = make_sentinel_error();

        errno = EACCES;
        vireo_result_t const result = vireo_config_load(NULL, NULL, 0U, &output, &error);
        int const actual_errno = errno;

        failures += expect_result("config load defaults result", result, VIREO_OK);
        failures += expect_int("config load defaults errno", actual_errno, EACCES);

        if (result == VIREO_OK) {
            failures += expect_config("config load defaults output", &output, &defaults);
            failures += expect_error("config load defaults error clear", &error, &expected_error);
        }
    }

    /* 2. 跳过文件，但环境覆盖仍在默认配置之上生效 */
    {
        static vireo_config_environment_t const environment[] = {
            {
                "VIREO_WORKER_COUNT",
                "32",
            },
            {
                "VIREO_LOG_DIR",
                "/env/vireo/log",
            },
        };

        vireo_config_t expected_output = defaults;
        expected_output.worker_count = UINT32_C(32);
        memcpy(expected_output.log_dir, "/env/vireo/log", sizeof("/env/vireo/log"));

        vireo_config_t output = make_sentinel_config();
        vireo_config_error_t error = make_sentinel_error();

        errno = EACCES;
        vireo_result_t const result = vireo_config_load(
            NULL, environment, VIREO_TEST_ARRAY_COUNT(environment), &output, &error);
        int const actual_errno = errno;

        failures += expect_result("config load environment only result", result, VIREO_OK);
        failures += expect_int("config load environment only errno", actual_errno, EACCES);

        if (result == VIREO_OK) {
            failures +=
                expect_config("config load environment only output", &output, &expected_output);
            failures +=
                expect_error("config load environment only error clear", &error, &expected_error);
        }
    }

    return failures;
}

/* 验证默认值、文件和环境覆盖的固定优先级 */
static int test_load_file_and_environment_precedence(void) {
    static char const file_text[] =
        "listen_port = 10001\n"
        "worker_count = 8\n"
        "log_to_stderr = false\n"
        "data_dir = /file/vireo/data\n";

    static vireo_config_environment_t const environment[] = {
        {
            "VIREO_WORKER_COUNT",
            "32",
        },
        {
            "VIREO_LOG_TO_STDERR",
            "true",
        },
        {
            "VIREO_LOG_DIR",
            "/env/vireo/log",
        },
    };

    char path_template[] = "/tmp/vireo-config-success-XXXXXX";

    if (!create_temporary_config_file(path_template, file_text, sizeof(file_text) - 1U)) {
        fprintf(stderr,
                "config load precedence: failed to create temporary file: "
                "errno %d\n",
                errno);
        return 1;
    }

    vireo_config_t const expected_output = {
        .listen_address = VIREO_CONFIG_DEFAULT_LISTEN_ADDRESS,
        .listen_port = UINT16_C(10001),
        .max_connections = VIREO_CONFIG_DEFAULT_MAX_CONNECTIONS,
        .worker_count = UINT32_C(32),
        .idle_timeout_ms = VIREO_CONFIG_DEFAULT_IDLE_TIMEOUT_MS,
        .log_to_stderr = true,
        .log_max_file_size_bytes = VIREO_CONFIG_DEFAULT_LOG_FILE_SIZE_BYTES,
        .data_dir = "/file/vireo/data",
        .log_dir = "/env/vireo/log",
    };

    vireo_config_t output = make_sentinel_config();
    vireo_config_error_t error = make_sentinel_error();
    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_NONE,
        .source = VIREO_CONFIG_SOURCE_NONE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    errno = EACCES;
    vireo_result_t const result = vireo_config_load(
        path_template, environment, VIREO_TEST_ARRAY_COUNT(environment), &output, &error);
    int const actual_errno = errno;

    int failures = expect_result("config load precedence result", result, VIREO_OK);
    failures += expect_int("config load precedence errno", actual_errno, EACCES);

    if (result == VIREO_OK) {
        failures += expect_config("config load precedence output", &output, &expected_output);
        failures += expect_error("config load precedence error clear", &error, &expected_error);
    }

    failures += remove_temporary_config_file("config load precedence cleanup", path_template);

    return failures;
}

/* 验证 config_load 的公共非法参数合同 */
static int test_load_invalid_arguments(void) {
    static vireo_config_environment_t const environment[] = {
        {
            "VIREO_WORKER_COUNT",
            "32",
        },
    };

    static struct {
        char const *case_name;
        char const *file_path;
        bool null_environment;
        bool null_output;
        bool null_error;
    } const cases[] = {
        {
            "config load empty file path",
            "",
            false,
            false,
            false,
        },
        {
            "config load null nonempty environment",
            NULL,
            true,
            false,
            false,
        },
        {
            "config load null output",
            NULL,
            false,
            true,
            false,
        },
        {
            "config load null error",
            NULL,
            false,
            false,
            true,
        },
    };

    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_INVALID_ARGUMENT,
        .source = VIREO_CONFIG_SOURCE_NONE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    int failures = 0;

    for (size_t index = 0U; index < VIREO_TEST_ARRAY_COUNT(cases); ++index) {
        vireo_config_t output = {
            .listen_address = "203.0.113.7",
            .listen_port = UINT16_C(23456),
            .max_connections = UINT32_C(3210),
            .worker_count = UINT32_C(23),
            .idle_timeout_ms = UINT64_C(654321),
            .log_to_stderr = true,
            .log_max_file_size_bytes = UINT64_C(16777216),
            .data_dir = "/output/keep/data",
            .log_dir = "/output/keep/log",
        };
        vireo_config_t const expected_output = output;

        vireo_config_error_t error = make_sentinel_error();

        vireo_config_environment_t const *environment_argument =
            cases[index].null_environment ? NULL : environment;
        vireo_config_t *output_argument = cases[index].null_output ? NULL : &output;
        vireo_config_error_t *error_argument = cases[index].null_error ? NULL : &error;

        errno = EACCES;
        vireo_result_t const result =
            vireo_config_load(cases[index].file_path, environment_argument,
                              VIREO_TEST_ARRAY_COUNT(environment), output_argument, error_argument);
        int const actual_errno = errno;

        failures += expect_result(cases[index].case_name, result, VIREO_RESULT_INVALID_ARGUMENT);
        failures += expect_int(cases[index].case_name, actual_errno, EACCES);

        if (!cases[index].null_output) {
            failures += expect_config(cases[index].case_name, &output, &expected_output);
        }

        if (!cases[index].null_error) {
            failures += expect_error(cases[index].case_name, &error, &expected_error);
        }
    }

    return failures;
}

/* 验证指定但不存在的文件报告 ENOENT */
static int test_load_missing_file(void) {
    char path_template[] = "/tmp/vireo-config-missing-XXXXXX";

    if (!create_temporary_config_file(path_template, NULL, 0U)) {
        fprintf(stderr,
                "config load missing file: failed to reserve path: "
                "errno %d\n",
                errno);
        return 1;
    }

    if (remove_temporary_config_file("config load missing file setup", path_template) != 0) {
        return 1;
    }

    vireo_config_t output = {
        .listen_address = "203.0.113.7",
        .listen_port = UINT16_C(23456),
        .max_connections = UINT32_C(3210),
        .worker_count = UINT32_C(23),
        .idle_timeout_ms = UINT64_C(654321),
        .log_to_stderr = true,
        .log_max_file_size_bytes = UINT64_C(16777216),
        .data_dir = "/output/keep/data",
        .log_dir = "/output/keep/log",
    };
    vireo_config_t const expected_output = output;

    vireo_config_error_t error = make_sentinel_error();
    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_FILE_OPEN_FAILED,
        .source = VIREO_CONFIG_SOURCE_FILE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = ENOENT,
    };

    errno = EACCES;
    vireo_result_t const result = vireo_config_load(path_template, NULL, 0U, &output, &error);
    int const actual_errno = errno;

    int failures = expect_result("config load missing file result", result, VIREO_RESULT_NOT_FOUND);
    failures += expect_error("config load missing file error", &error, &expected_error);
    failures += expect_int("config load missing file errno", actual_errno, EACCES);
    failures += expect_config("config load missing file output keep", &output, &expected_output);

    return failures;
}

/* 在 Linux 上验证目录读取失败的 FILE_READ_FAILED */
static int test_load_file_read_failure(void) {
    vireo_config_t output = {
        .listen_address = "203.0.113.7",
        .listen_port = UINT16_C(23456),
        .max_connections = UINT32_C(3210),
        .worker_count = UINT32_C(23),
        .idle_timeout_ms = UINT64_C(654321),
        .log_to_stderr = true,
        .log_max_file_size_bytes = UINT64_C(16777216),
        .data_dir = "/output/keep/data",
        .log_dir = "/output/keep/log",
    };
    vireo_config_t const expected_output = output;

    vireo_config_error_t error = make_sentinel_error();
    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_FILE_READ_FAILED,
        .source = VIREO_CONFIG_SOURCE_FILE,
        .field = VIREO_CONFIG_FIELD_NONE,
        .line = 0U,
        .entry_index = 0U,
        .system_errno = EISDIR,
    };

    errno = EACCES;
    vireo_result_t const result = vireo_config_load("/", NULL, 0U, &output, &error);
    int const actual_errno = errno;

    int failures =
        expect_result("config load directory read failure result", result, VIREO_RESULT_IO);
    failures += expect_error("config load directory read failure error", &error, &expected_error);
    failures += expect_int("config load directory read failure errno", actual_errno, EACCES);
    failures +=
        expect_config("config load directory read failure output keep", &output, &expected_output);

    return failures;
}

/* 验证文件内容错误不会被环境覆盖修复 */
static int test_load_file_error_precedes_environment(void) {
    static char const file_text[] = "worker_count = 0\n";

    static vireo_config_environment_t const environment[] = {
        {
            "VIREO_WORKER_COUNT",
            "32",
        },
    };

    char path_template[] = "/tmp/vireo-config-invalid-XXXXXX";

    if (!create_temporary_config_file(path_template, file_text, sizeof(file_text) - 1U)) {
        fprintf(stderr,
                "config load file error precedence: temporary file failed: "
                "errno %d\n",
                errno);
        return 1;
    }

    vireo_config_t output = {
        .listen_address = "203.0.113.7",
        .listen_port = UINT16_C(23456),
        .max_connections = UINT32_C(3210),
        .worker_count = UINT32_C(23),
        .idle_timeout_ms = UINT64_C(654321),
        .log_to_stderr = true,
        .log_max_file_size_bytes = UINT64_C(16777216),
        .data_dir = "/output/keep/data",
        .log_dir = "/output/keep/log",
    };
    vireo_config_t const expected_output = output;

    vireo_config_error_t error = make_sentinel_error();
    vireo_config_error_t const expected_error = {
        .issue = VIREO_CONFIG_ISSUE_VALUE_OUT_OF_RANGE,
        .source = VIREO_CONFIG_SOURCE_TEXT,
        .field = VIREO_CONFIG_FIELD_WORKER_COUNT,
        .line = 1U,
        .entry_index = 0U,
        .system_errno = 0,
    };

    errno = EACCES;
    vireo_result_t const result = vireo_config_load(
        path_template, environment, VIREO_TEST_ARRAY_COUNT(environment), &output, &error);
    int const actual_errno = errno;

    int failures =
        expect_result("config load file error precedence result", result, VIREO_RESULT_RANGE);
    failures += expect_error("config load file error precedence error", &error, &expected_error);
    failures += expect_int("config load file error precedence errno", actual_errno, EACCES);
    failures +=
        expect_config("config load file error precedence output keep", &output, &expected_output);

    failures +=
        remove_temporary_config_file("config load file error precedence cleanup", path_template);

    return failures;
}

/* 验证配置文件恰好 64 KiB 与多一个字节的边界 */
static int test_load_file_size_boundaries(void) {
    static char maximum_text[(size_t)VIREO_CONFIG_MAX_TEXT_SIZE];
    static char oversized_text[(size_t)VIREO_CONFIG_MAX_TEXT_SIZE + 1U];

    memset(maximum_text, '\n', sizeof(maximum_text));
    memset(oversized_text, '\n', sizeof(oversized_text));

    int failures = 0;

    /* 1. fread 得到恰好 65536 字节，应解析成功 */
    {
        char path_template[] = "/tmp/vireo-config-maximum-XXXXXX";

        if (!create_temporary_config_file(path_template, maximum_text, sizeof(maximum_text))) {
            fprintf(stderr,
                    "config load maximum file: temporary file failed: "
                    "errno %d\n",
                    errno);
            return failures + 1;
        }

        vireo_config_t const expected_output = {
            .listen_address = VIREO_CONFIG_DEFAULT_LISTEN_ADDRESS,
            .listen_port = VIREO_CONFIG_DEFAULT_LISTEN_PORT,
            .max_connections = VIREO_CONFIG_DEFAULT_MAX_CONNECTIONS,
            .worker_count = VIREO_CONFIG_DEFAULT_WORKER_COUNT,
            .idle_timeout_ms = VIREO_CONFIG_DEFAULT_IDLE_TIMEOUT_MS,
            .log_to_stderr = VIREO_CONFIG_DEFAULT_LOG_TO_STDERR,
            .log_max_file_size_bytes = VIREO_CONFIG_DEFAULT_LOG_FILE_SIZE_BYTES,
            .data_dir = VIREO_CONFIG_DEFAULT_DATA_DIR,
            .log_dir = VIREO_CONFIG_DEFAULT_LOG_DIR,
        };

        vireo_config_t output = make_sentinel_config();
        vireo_config_error_t error = make_sentinel_error();
        vireo_config_error_t const expected_error = {
            .issue = VIREO_CONFIG_ISSUE_NONE,
            .source = VIREO_CONFIG_SOURCE_NONE,
            .field = VIREO_CONFIG_FIELD_NONE,
            .line = 0U,
            .entry_index = 0U,
            .system_errno = 0,
        };

        errno = EACCES;
        vireo_result_t const result = vireo_config_load(path_template, NULL, 0U, &output, &error);
        int const actual_errno = errno;

        failures += expect_result("config load maximum file result", result, VIREO_OK);
        failures += expect_int("config load maximum file errno", actual_errno, EACCES);

        if (result == VIREO_OK) {
            failures += expect_config("config load maximum file output", &output, &expected_output);
            failures +=
                expect_error("config load maximum file error clear", &error, &expected_error);
        }

        failures += remove_temporary_config_file("config load maximum file cleanup", path_template);
    }

    /* 2. fread 能读出第 65537 字节，应报告整份文字过大 */
    {
        char path_template[] = "/tmp/vireo-config-oversized-XXXXXX";

        if (!create_temporary_config_file(path_template, oversized_text, sizeof(oversized_text))) {
            fprintf(stderr,
                    "config load oversized file: temporary file failed: "
                    "errno %d\n",
                    errno);
            return failures + 1;
        }

        vireo_config_t output = {
            .listen_address = "203.0.113.7",
            .listen_port = UINT16_C(23456),
            .max_connections = UINT32_C(3210),
            .worker_count = UINT32_C(23),
            .idle_timeout_ms = UINT64_C(654321),
            .log_to_stderr = true,
            .log_max_file_size_bytes = UINT64_C(16777216),
            .data_dir = "/output/keep/data",
            .log_dir = "/output/keep/log",
        };
        vireo_config_t const expected_output = output;

        vireo_config_error_t error = make_sentinel_error();
        vireo_config_error_t const expected_error = {
            .issue = VIREO_CONFIG_ISSUE_TEXT_TOO_LARGE,
            .source = VIREO_CONFIG_SOURCE_TEXT,
            .field = VIREO_CONFIG_FIELD_NONE,
            .line = 0U,
            .entry_index = 0U,
            .system_errno = 0,
        };

        errno = EACCES;
        vireo_result_t const result = vireo_config_load(path_template, NULL, 0U, &output, &error);
        int const actual_errno = errno;

        failures += expect_result("config load oversized file result", result, VIREO_RESULT_RANGE);
        failures += expect_error("config load oversized file error", &error, &expected_error);
        failures += expect_int("config load oversized file errno", actual_errno, EACCES);
        failures +=
            expect_config("config load oversized file output keep", &output, &expected_output);

        failures +=
            remove_temporary_config_file("config load oversized file cleanup", path_template);
    }

    return failures;
}

/* 按依赖顺序运行全部配置测试组 */
int main(void) {
    typedef int (*test_function_t)(void);

    static test_function_t const tests[] = {
        test_defaults_success,
        test_defaults_invalid_arguments,

        test_validate_success,
        test_validate_invalid_arguments,
        test_validate_unterminated_listen_address,
        test_validate_invalid_listen_addresses,
        test_validate_boundary_values,
        test_validate_numeric_range_errors,
        test_validate_unterminated_paths,
        test_validate_invalid_paths,
        test_validate_maximum_path_length,

        test_parse_text_success,
        test_parse_text_without_assignments,
        test_parse_text_partial_override,
        test_parse_text_invalid_arguments,
        test_parse_text_invalid_base,
        test_parse_text_oversized_text,
        test_parse_text_maximum_text_size,
        test_parse_text_line_too_long,
        test_parse_text_maximum_line_size,
        test_parse_text_invalid_characters,
        test_parse_text_structure_errors,
        test_parse_text_duplicate_key,
        test_parse_text_value_length_boundaries,
        test_parse_text_value_syntax_errors,
        test_parse_text_numeric_range_and_overflow,
        test_parse_text_unit_conversions,
        test_parse_text_first_separator_and_inline_hash,

        test_apply_environment_success,
        test_apply_environment_empty,
        test_apply_environment_invalid_arguments,
        test_apply_environment_invalid_base,
        test_apply_environment_item_errors,
        test_apply_environment_value_errors,

        test_load_without_file,
        test_load_file_and_environment_precedence,
        test_load_invalid_arguments,
        test_load_missing_file,
        test_load_file_read_failure,
        test_load_file_error_precedes_environment,
        test_load_file_size_boundaries,
    };

    int failures = 0;

    for (size_t index = 0U; index < VIREO_TEST_ARRAY_COUNT(tests); ++index) {
        failures += tests[index]();
    }

    if (failures != 0) {
        fprintf(stderr, "test_config: %d assertion failure(s)\n", failures);
        return EXIT_FAILURE;
    }

    printf("test_config: all %zu test groups passed\n", VIREO_TEST_ARRAY_COUNT(tests));

    return EXIT_SUCCESS;
}

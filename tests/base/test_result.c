/*
 * PROJECT : VIREO
 * FILE    : test_result.c
 * AUTHOR  : bitofux
 * DATE    : 2026-08-03
 * BRIEF   : 测试base下的vireo_result
 * -- 验证 vireo_result_t 的枚举值
 * -- 验证所有已知结果的名称、说明和 retryable 分类
 * -- 验证未知结果的安全处理
 * -- 验证查询函数不会修改errno
 */
#include <vireo/base/result.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 编译期断言
_Static_assert(VIREO_OK == 0, "VIREO_OK value changed");
_Static_assert(VIREO_RESULT_INVALID_ARGUMENT == 1, "VIREO_RESULT_INVALID_ARGUMENT value changed");
_Static_assert(VIREO_RESULT_RANGE == 2, "VIREO_RESULT_RANGE value changed");
_Static_assert(VIREO_RESULT_OVERFLOW == 3, "VIREO_RESULT_OVERFLOW value changed");
_Static_assert(VIREO_RESULT_NO_MEMORY == 4, "VIREO_RESULT_NO_MEMORY value changed");
_Static_assert(VIREO_RESULT_NOT_FOUND == 5, "VIREO_RESULT_NOT_FOUND value changed");
_Static_assert(VIREO_RESULT_BUSY == 6, "VIREO_RESULT_BUSY value changed");
_Static_assert(VIREO_RESULT_TIMEOUT == 7, "VIREO_RESULT_TIMEOUT value changed");
_Static_assert(VIREO_RESULT_CANCELLED == 8, "VIREO_RESULT_CANCELLED value changed");
_Static_assert(VIREO_RESULT_IO == 9, "VIREO_RESULT_IO value changed");
_Static_assert(VIREO_RESULT_PROTOCOL == 10, "VIREO_RESULT_PROTOCOL value changed");
_Static_assert(VIREO_RESULT_DATABASE == 11, "VIREO_RESULT_DATABASE value changed");
_Static_assert(VIREO_RESULT_INTERNAL == 12, "VIREO_RESULT_INTERNAL value changed");

// 创建一个结构体
typedef struct {
    vireo_result_t result;
    char const *name;
    char const *description;
    bool retryable;
} result_case_t;

// 创建一个result_case_t静态数组
static result_case_t const result_case[] = {
    {.result = VIREO_OK, .name = "ok", .description = "success", .retryable = false},
    {.result = VIREO_RESULT_INVALID_ARGUMENT,
     .name = "invalid_argument",
     .description = "invalid argument",
     .retryable = false},
    {.result = VIREO_RESULT_RANGE,
     .name = "range",
     .description = "value out of range",
     .retryable = false},
    {.result = VIREO_RESULT_OVERFLOW,
     .name = "overflow",
     .description = "arithmetic overflow",
     .retryable = false},
    {.result = VIREO_RESULT_NO_MEMORY,
     .name = "no_memory",
     .description = "memory allocation failed",
     .retryable = false},
    {
        .result = VIREO_RESULT_NOT_FOUND,
        .name = "not_found",
        .description = "resource not found",
        .retryable = false,
    },
    {.result = VIREO_RESULT_BUSY,
     .name = "busy",
     .description = "resource busy",
     .retryable = true},
    {.result = VIREO_RESULT_TIMEOUT,
     .name = "timeout",
     .description = "operation timed out",
     .retryable = true},
    {.result = VIREO_RESULT_CANCELLED,
     .name = "cancelled",
     .description = "operation cancelled",
     .retryable = false},
    {.result = VIREO_RESULT_IO,
     .name = "io",
     .description = "I/O operation failed",
     .retryable = false},
    {.result = VIREO_RESULT_PROTOCOL,
     .name = "protocol",
     .description = "protocol error",
     .retryable = false},
    {.result = VIREO_RESULT_DATABASE,
     .name = "database",
     .description = "database error",
     .retryable = false},
    {.result = VIREO_RESULT_INTERNAL,
     .name = "internal",
     .description = "internal error",
     .retryable = false}

};

/*
 * 检查result_case数组中各个元素中的result成员对应的name、description、retryable
 * 是否与初始定义相同
 */
static int check_known_results(void) {
    int failures = 0;

    // 获取数组长度
    size_t length = sizeof(result_case) / sizeof(result_case[0]);

    // 数组遍历
    for (size_t i = 0; i < length; ++i) {
        // 获取数组中数据元素的地址
        result_case_t const *test_case = &result_case[i];

        // 获取name
        char const *actual_name = vireo_result_name(test_case->result);
        // 获取description
        char const *actual_description = vireo_result_description(test_case->result);
        // 获取retryable
        bool actual_retryable = vireo_result_is_retryable(test_case->result);

        // 将获取的name与当前元素中的name成员进行比较
        if (actual_name == NULL) {
            fprintf(stderr, "result %d returned a NULL name\n", (int)test_case->result);
            ++failures;
        } else if (strcmp(actual_name, test_case->name) != 0) {
            fprintf(stderr, "result %d error! actual_name: %s\n", (int)test_case->result,
                    actual_name);
            ++failures;
        }

        // 将获取到的description与当前元素中的description成员比较
        if (actual_description == NULL) {
            fprintf(stderr, "result %d returned a NULL description\n", test_case->result);
            ++failures;
        } else if (strcmp(actual_description, test_case->description) != 0) {
            fprintf(stderr, "result %d error! actual_description: %s\n", (int)test_case->result,
                    actual_description);
            ++failures;
        }

        // 将获取到的retryable与当前元素中的retryable成员比较
        if (actual_retryable != test_case->retryable) {
            fprintf(stderr, "result %d error! actual_retryable: %d\n", (int)test_case->result,
                    actual_retryable);
            ++failures;
        }
    }

    return failures;
}

/*
 * 检查未定义的result枚举值是否被标记为false
 * name是否返回unknown
 * description是否返回unknown result
 */

static int check_unknown_results(vireo_result_t result) {
    int failures = 0;

    char const *test_name = vireo_result_name(result);
    char const *test_description = vireo_result_description(result);
    bool test_retryable = vireo_result_is_retryable(result);

    if (test_name == NULL || strcmp(test_name, "unknown") != 0) {
        fprintf(stderr, "unknown result %d returned an invalid name\n", (int)result);
        ++failures;
    }

    if (test_description == NULL || strcmp(test_description, "unknown result") != 0) {
        fprintf(stderr, "unknown result %d returned an invalid description\n", (int)result);
        ++failures;
    }

    if (test_retryable) {
        fprintf(stderr, "unknown result %d was marked retryable\n", (int)result);
        ++failures;
    }
    return failures;
}

// 测试调用vireo_result开头的函数不会修改errno
static int check_error_preservation(void) {
    int failures = 0;

    // 设置errno的初始值，它是可以被指定的
    errno = EACCES;
    // 调用vireo_result_name函数
    (void)vireo_result_name(VIREO_RESULT_BUSY);
    // 获取errno的值
    int actual_errno = errno;
    // 检查此时actual_errno的值是否与EACCES相等
    if (actual_errno != EACCES) {
        fprintf(stderr, "vireo_result_name changed errno!\n");
        ++failures;
    }

    // 重置errno的值
    errno = EACCES;
    // 调用vireo_result_description函数
    (void)vireo_result_description(VIREO_RESULT_CANCELLED);
    // 获取errno的值
    actual_errno = errno;
    // 检查此时actual_errno的值是否与EACCES相等
    if (actual_errno != EACCES) {
        fprintf(stderr, "vireo_result_description changed errno!\n");
        ++failures;
    }
    // 重置errno的值
    errno = EACCES;
    // 调用vireo_result_is_retryable函数
    (void)vireo_result_is_retryable(VIREO_RESULT_CANCELLED);
    // 获取errno的值
    actual_errno = errno;
    // 检查此时actual_errno的值是否与EACCES相等
    if (actual_errno != EACCES) {
        fprintf(stderr, "vireo_result_is_retryable changed errno!\n");
        ++failures;
    }

    return failures;
}

int main(void) {
    int failures = 0;

    // 测试check_known_results函数
    failures += check_known_results();
    failures += check_unknown_results((vireo_result_t)-1);
    failures += check_unknown_results((vireo_result_t)999);

    failures += check_error_preservation();

    // 判断failures是否不等于0，若不等于函数绝对是有报错的
    if (failures != 0) {
        fprintf(stderr, "test_result: %d check failed\n", failures);
        return EXIT_FAILURE;
    }

    puts("test_result: all checks passed");

    return EXIT_SUCCESS;
}

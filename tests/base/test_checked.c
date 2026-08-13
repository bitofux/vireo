/*
 * PROJECT : VIREO
 * FILE    : test_checked.c
 * AUTHOR  : bitofux
 * DATE    : 2026-08-12
 * BRIEF   : 测试 base 下的 vireo_checked
 * -- 验证正常加法、乘法、窄化、对齐和区间检查
 * -- 验证各整数类型的最大边界和溢出边界
 * -- 验证无效参数和失败时输出保持合同
 * -- 验证所有公共函数不会修改 errno
 */
#include <vireo/base/checked.h>

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// 测试预期返回值与实际返回值是否相同
static int expect_result(char const *case_name, vireo_result_t actual, vireo_result_t expected) {
    /* 比较预期值返回码和实际返回码
     *
     * 相同返回 0
     * 不同返回1
     */
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected result %d, got %d\n", case_name, (int)expected, (int)actual);

    return 1;
}

// 测试预期 size_t 类型的实际值和预期值是否相同
static int expect_size_value(char const *case_name, size_t actual, size_t expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected size_t value %zu, got %zu\n", case_name, expected, actual);

    return 1;
}

// 测试预期 uint32_t 类型的实际值和预期值是否相同
static int expect_u32_value(char const *case_name, uint32_t actual, uint32_t expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected uint32_t value %" PRIu32 ", got %" PRIu32 "\n", case_name,
            expected, actual);

    return 1;
}

// 测试预期 uint64_t 类型的实际值和预期值是否相同
static int expect_u64_value(char const *case_name, uint64_t actual, uint64_t expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected uint64_t value %" PRIu64 ", got %" PRIu64 "\n", case_name,
            expected, actual);

    return 1;
}

// 测试 errno 是否被修改
static int expect_errno_value(char const *case_name, int expected) {
    if (errno == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected errno %d, got %d\n", case_name, expected, errno);

    return 1;
}

// 检查 size_t 类型的加法
static int check_size_add(void) {
    int failures = 0;
    size_t out = 0;
    vireo_result_t result;

    /* 0,0*/
    result = vireo_checked_size_add(0, 0, &out);
    // 测试结果值
    failures += expect_result("size_add zero", result, VIREO_OK);
    // 测试 out 值
    failures += expect_size_value("size_add zero value", out, 0);

    /* 17,25 */
    result = vireo_checked_size_add(17, 25, &out);
    // 测试结果值
    failures += expect_result("size_add 17 25", result, VIREO_OK);
    // 测试 out 值
    failures += expect_size_value("size_add 17 25 value", out, 42);

    /* SIZE_MAX,0 */
    result = vireo_checked_size_add(SIZE_MAX, 0, &out);
    // 测试结果值
    failures += expect_result("size_add SIZE_MAX 0", result, VIREO_OK);
    // 测试 out 值
    failures += expect_size_value("size_add SIZE_MAX 0 value", out, SIZE_MAX);

    /* SIZE_MAX-1,1 */
    result = vireo_checked_size_add(SIZE_MAX - 1, 1, &out);
    // 测试结果值
    failures += expect_result("size_add SIZE_MAX - 1 1", result, VIREO_OK);
    failures += expect_size_value("size_add SIZE_MAX - 1 1 value", out, SIZE_MAX);

    /* SIZE_MAX 1 */
    out = 256;
    result = vireo_checked_size_add(SIZE_MAX, 1, &out);
    // 测试结果值
    failures += expect_result("size_add SIZE_MAX 1", result, VIREO_RESULT_OVERFLOW);
    // 测试 out 值
    failures += expect_size_value("size_add SIZE_MAX 1 value", out, 256);

    /* 1 SIZE_MAX */
    out = 526;
    result = vireo_checked_size_add(1, SIZE_MAX, &out);
    // 测试结果值
    failures += expect_result("size_add 1 SIZE_MAX", result, VIREO_RESULT_OVERFLOW);
    // 测试 out 值
    failures += expect_size_value("size_add 1 SIZE_MAX value", out, 526);

    // 测试 *out == NULL
    result = vireo_checked_size_add(1, 2, NULL);
    // 测试结果值
    failures += expect_result("size_add null out", result, VIREO_RESULT_INVALID_ARGUMENT);

    return failures;
}

// 测试 size_t 类型的乘法
static int check_size_mul(void) {
    int failures = 0;
    size_t out = 0;
    vireo_result_t result;

    /* 0 SIZE_MAX */
    result = vireo_checked_size_mul(0, SIZE_MAX, &out);
    // 测试结果值
    failures += expect_result("size_mul 0 SIZE_MAX", result, VIREO_OK);
    // 测试 out 值
    failures += expect_size_value("size_mul 0 SIZE_MAX value", out, 0);

    /* SIZE_MAX 0*/
    result = vireo_checked_size_mul(SIZE_MAX, 0, &out);
    // 测试结果值
    failures += expect_result("size_mul SIZE_MAX 0", result, VIREO_OK);
    // 测试 out 值
    failures += expect_size_value("size_mul SIZE_MAX 0 value", out, 0);

    /* 6 7 */
    result = vireo_checked_size_mul(6, 7, &out);
    failures += expect_result("size_mul 6 7", result, VIREO_OK);
    failures += expect_size_value("size_mul 6 7 value", out, 42);

    /* SIZE_MAX 1 */
    result = vireo_checked_size_mul(SIZE_MAX, 1, &out);
    failures += expect_result("size_mul SIZE_MAX 1", result, VIREO_OK);
    failures += expect_size_value("size_mul SIZE_MAX 1 value", out, SIZE_MAX);

    /* SIZE_MAX 2 */
    out = 123;
    result = vireo_checked_size_mul(SIZE_MAX, 2, &out);
    failures += expect_result("size_mul SIZE_MAX 2", result, VIREO_RESULT_OVERFLOW);
    failures += expect_size_value("size_mul SIZE_MAX 2 value", out, 123);

    /* SIZE_MAX / 2 + 1 2*/
    out = 256;
    result = vireo_checked_size_mul(SIZE_MAX / 2 + 1, 2, &out);
    // 测试结果值
    failures += expect_result("size_mul SIZE_MAX / 2 + 1 2", result, VIREO_RESULT_OVERFLOW);
    failures += expect_size_value("size_mul SIZE_MAX / 2 + 1 2 value", out, 256);

    result = vireo_checked_size_mul(1, 2, NULL);
    failures += expect_result("size_mul 1 2 out", result, VIREO_RESULT_INVALID_ARGUMENT);

    return failures;
}

// 测试 u32 类型的加法
static int check_u32_add(void) {
    int failures = 0;
    uint32_t out = UINT32_C(0);
    vireo_result_t result;

    /* 17 25 */
    result = vireo_checked_u32_add(UINT32_C(17), UINT32_C(25), &out);
    // 测试结果值
    failures += expect_result("u32_add 17 25", result, VIREO_OK);
    // 测试 out 的值是否与预期的值是否相同
    failures += expect_u32_value("u32_add 17 25 value", out, UINT32_C(42));

    /* UINT32_MAX 0 */
    result = vireo_checked_u32_add(UINT32_MAX, UINT32_C(0), &out);
    failures += expect_result("u32_add UINT32_MAX 0", result, VIREO_OK);
    failures += expect_u32_value("u32_add UINT32_MAX 0 value", out, UINT32_MAX);

    /* UINT32_MAX - 1 1 */
    result = vireo_checked_u32_add(UINT32_MAX - UINT32_C(1), UINT32_C(1), &out);
    failures += expect_result("u32_add UINT32_MAX - 1 1", result, VIREO_OK);
    failures += expect_u32_value("u32_add UINT32_MAX - 1 1 value", out, UINT32_MAX);

    /* UINT32_MAX 1 */
    out = UINT32_C(123);
    result = vireo_checked_u32_add(UINT32_MAX, UINT32_C(1), &out);
    failures += expect_result("u32_add UINT32_MAX 1", result, VIREO_RESULT_OVERFLOW);
    failures += expect_u32_value("u32_add UINT32_MAX 1 value", out, UINT32_C(123));

    /* 1 2 NULL*/
    result = vireo_checked_u32_add(UINT32_C(1), UINT32_C(2), NULL);
    failures += expect_result("u32_add 1 2", result, VIREO_RESULT_INVALID_ARGUMENT);

    return failures;
}

// 测试 uint32_t 类型的乘法
static int check_u32_mul(void) {
    int failures = 0;
    uint32_t out = UINT32_C(0);
    vireo_result_t result;

    /* 0 UINT32_MAX */
    result = vireo_checked_u32_mul(UINT32_C(0), UINT32_MAX, &out);
    failures += expect_result("u32_mul 0 UINT32_MAX", result, VIREO_OK);
    failures += expect_u32_value("u32_mul 0 UINT32_MAX value", out, UINT32_C(0));

    /* UINT32_MAX 0 */
    result = vireo_checked_u32_mul(UINT32_MAX, UINT32_C(0), &out);
    failures += expect_result("u32_mul UINT32_MAX 0", result, VIREO_OK);
    failures += expect_u32_value("u32_mul UINT32_MAX 0 value", out, UINT32_C(0));

    /* 6 7 */
    result = vireo_checked_u32_mul(UINT32_C(6), UINT32_C(7), &out);
    failures += expect_result("u32_mul 6 7", result, VIREO_OK);
    failures += expect_u32_value("u32_mul 6 7 value", out, UINT32_C(42));

    /* UINT32_MAX 1 */
    result = vireo_checked_u32_mul(UINT32_MAX, UINT32_C(1), &out);
    failures += expect_result("u32_mul UINT32_MAX 1", result, VIREO_OK);
    failures += expect_u32_value("u32_mul UINT32_MAX 1 value", out, UINT32_MAX);

    /* UINT32_MAX 2 */
    out = UINT32_C(123);
    result = vireo_checked_u32_mul(UINT32_MAX, UINT32_C(2), &out);
    failures += expect_result("u32_mul UINT32_MAX 2", result, VIREO_RESULT_OVERFLOW);
    failures += expect_u32_value("u32_mul UINT32_MAX 2 value", out, UINT32_C(123));

    /* UINT32_MAX / 2 + 1 2 */
    out = UINT32_C(456);
    result = vireo_checked_u32_mul(UINT32_MAX / UINT32_C(2) + UINT32_C(1), UINT32_C(2), &out);
    failures += expect_result("u32_mul UINT32_MAX / 2 + 1 2", result, VIREO_RESULT_OVERFLOW);
    failures += expect_u32_value("u32_mul UINT32_MAX / 2 + 1 2 value", out, UINT32_C(456));

    /* 1 2 NULL */
    result = vireo_checked_u32_mul(UINT32_C(1), UINT32_C(2), NULL);
    failures += expect_result("u32_mul 1 2", result, VIREO_RESULT_INVALID_ARGUMENT);

    return failures;
}

// 测试 uint64_t 类型的加法
static int check_u64_add(void) {
    int failures = 0;
    uint64_t out = UINT64_C(0);
    vireo_result_t result;

    /* 17 25 */
    result = vireo_checked_u64_add(UINT64_C(17), UINT64_C(25), &out);
    // 测试 result 值
    failures += expect_result("u64_add 17 25", result, VIREO_OK);
    failures += expect_u64_value("u64_add 17 25 value", out, UINT64_C(42));

    /* UINT64_MAX 0 */
    result = vireo_checked_u64_add(UINT64_MAX, UINT64_C(0), &out);
    failures += expect_result("u64_add UINT64_MAX 0", result, VIREO_OK);
    failures += expect_u64_value("u64_add UINT64_MAX 0 value", out, UINT64_MAX);

    /* UINT64_MAX - 1 1 */
    result = vireo_checked_u64_add(UINT64_MAX - UINT64_C(1), UINT64_C(1), &out);
    failures += expect_result("u64_add UINT64_MAX - 1 1", result, VIREO_OK);
    failures += expect_u64_value("u64_add UINT64_MAX - 1 1 value", out, UINT64_MAX);

    /* UINT64_MAX 1 */
    out = UINT64_C(123);
    result = vireo_checked_u64_add(UINT64_MAX, 1, &out);
    failures += expect_result("u64_add UINT64_MAX 1", result, VIREO_RESULT_OVERFLOW);
    failures += expect_u64_value("u64_add UINT64_MAX 1 value", out, UINT64_C(123));

    /* 1 2 NULL */
    result = vireo_checked_u64_add(UINT64_C(1), UINT64_C(2), NULL);
    failures += expect_result("u64_add 1 2", result, VIREO_RESULT_INVALID_ARGUMENT);

    return failures;
}

// 测试 uint64_t 类型的乘法
static int check_u64_mul(void) {
    int failures = 0;
    uint64_t out = UINT64_C(0);
    vireo_result_t result;

    /* 0 UINT64_MAX */
    result = vireo_checked_u64_mul(UINT64_C(0), UINT64_MAX, &out);
    failures += expect_result("u64_mul 0 UINT64_MAX", result, VIREO_OK);
    failures += expect_u64_value("u64_mul 0 UINT64_MAX value", out, UINT64_C(0));

    /* UINT64_MAX 0 */
    result = vireo_checked_u64_mul(UINT64_MAX, UINT64_C(0), &out);
    failures += expect_result("u64_mul UINT64_MAX 0", result, VIREO_OK);
    failures += expect_u64_value("u64_mul UINT64_MAX 0 value", out, UINT64_C(0));

    /* 6 7 */
    result = vireo_checked_u64_mul(UINT64_C(6), UINT64_C(7), &out);
    failures += expect_result("u64_mul 6 7", result, VIREO_OK);
    failures += expect_u64_value("u64_mul 6 7 value", out, UINT64_C(42));

    /* UINT64_MAX 1 */
    result = vireo_checked_u64_mul(UINT64_MAX, UINT64_C(1), &out);
    failures += expect_result("u64_mul UINT64_MAX 1", result, VIREO_OK);
    failures += expect_u64_value("u64_mul UINT64_MAX 1 value", out, UINT64_MAX);

    /* UINT64_MAX 2 */
    out = UINT64_C(123);
    result = vireo_checked_u64_mul(UINT64_MAX, UINT64_C(2), &out);
    failures += expect_result("u64_mul UINT64_MAX 2", result, VIREO_RESULT_OVERFLOW);
    failures += expect_u64_value("u64_mul UINT64_MAX 2 value", out, UINT64_C(123));

    /* UINT64_MAX / 2 + 1 2 */
    out = UINT64_C(456);
    result = vireo_checked_u64_mul(UINT64_MAX / UINT64_C(2) + UINT64_C(1), UINT64_C(2), &out);
    failures += expect_result("u64_mul UINT64_MAX / 2 + 1 2", result, VIREO_RESULT_OVERFLOW);
    failures += expect_u64_value("u64_mul UINT64_MAX / 2 + 1 2 value", out, UINT64_C(456));

    /* 1 2 NULL */
    result = vireo_checked_u64_mul(UINT64_C(1), UINT64_C(2), NULL);
    failures += expect_result("u64_mul 1 2", result, VIREO_RESULT_INVALID_ARGUMENT);

    return failures;
}

// 测试 uint64_t 到 size_t 的窄化转换
static int check_u64_to_size(void) {
    int failures = 0;
    size_t out = 0;
    vireo_result_t result;

    /* UINT64_C(0) */
    result = vireo_checked_u64_to_size(UINT64_C(0), &out);
    failures += expect_result("u64_to_size 0", result, VIREO_OK);
    failures += expect_size_value("u64_to_size 0 value", out, 0);

#if SIZE_MAX < UINT64_MAX
    /* (uint64_t)(SIZE_MAX) */
    result = vireo_checked_u64_to_size((uint64_t)SIZE_MAX, &out);
    failures += expect_result("u64_to_size SIZE_MAX", result, VIREO_OK);
    failures += expect_size_value("u64_to_size SIZE_MAX value", out, SIZE_MAX);

    /* (uint64_t)SIZE_MAX + 1 */
    out = 123;
    result = vireo_checked_u64_to_size((uint64_t)SIZE_MAX + UINT64_C(1), &out);
    failures += expect_result("u64_to_size SIZE_MAX + 1", result, VIREO_RESULT_RANGE);
    failures += expect_size_value("u64_to_size SIZE_MAX + 1 value", out, 123);
#else
    /* UINT64_MAX */
    result = vireo_checked_u64_to_size(UINT64_MAX, &out);
    failures += expect_result("u64_to_size UINT64_MAX", result, VIREO_OK);
    failures += expect_size_value("u64_to_size UINT64_MAX value", out, (size_t)UINT64_MAX);
#endif
    /* 1 NULL */
    result = vireo_checked_u64_to_size(UINT64_C(1), NULL);
    failures += expect_result("u64_to_size 1", result, VIREO_RESULT_INVALID_ARGUMENT);

    return failures;
}

// 测试 向上对齐
static int check_size_align_up(void) {
    int failures = 0;
    size_t out = 0;
    vireo_result_t result;

    /* 0 向上对齐8的倍数 */
    result = vireo_checked_size_align_up(0, 8, &out);
    failures += expect_result("size_align_up 0 8", result, VIREO_OK);
    failures += expect_size_value("size_align_up 0 8 value", out, 0);

    /* 13 向上对齐8的倍数 */
    result = vireo_checked_size_align_up(13, 8, &out);
    failures += expect_result("size_align_up 13 8", result, VIREO_OK);
    failures += expect_size_value("size_align_up 13 8 value", out, 16);

    /* 16 向上对齐8的倍数 */
    result = vireo_checked_size_align_up(16, 8, &out);
    failures += expect_result("size_align_up 16 8", result, VIREO_OK);
    failures += expect_size_value("size_align_up 16 8 value", out, 16);

    /* 13 向上对齐6的倍数 */
    result = vireo_checked_size_align_up(13, 6, &out);
    failures += expect_result("size_align_up 13 6", result, VIREO_OK);
    failures += expect_size_value("size_align_up 13 6 value", out, 18);

    /* 1 向上对齐SIZE_MAX的倍数 */
    result = vireo_checked_size_align_up(1, SIZE_MAX, &out);
    failures += expect_result("size_align_up 1 SIZE_MAX", result, VIREO_OK);
    failures += expect_size_value("size_align_up 1 SIZE_MAX value", out, SIZE_MAX);

    /* SIZE_MAX 向上对齐2的倍数 */
    out = 123;
    result = vireo_checked_size_align_up(SIZE_MAX, 2, &out);
    failures += expect_result("size_align_up SIZE_MAX 2", result, VIREO_RESULT_OVERFLOW);
    failures += expect_size_value("size_align_up SIZE_MAX 2 value", out, 123);

    /* 10 向上对齐0的倍数 */
    out = 456;
    result = vireo_checked_size_align_up(10, 0, &out);
    failures += expect_result("size_align_up 10 0", result, VIREO_RESULT_INVALID_ARGUMENT);
    failures += expect_size_value("size_align_up 10 0 value", out, 456);

    /* 10 向上对齐8的倍数 */
    result = vireo_checked_size_align_up(10, 8, NULL);
    failures += expect_result("size_align_up 10 8", result, VIREO_RESULT_INVALID_ARGUMENT);

    return failures;
}

// 测试区间范围
static int check_size_range(void) {
    int failures = 0;
    vireo_result_t result;

    /* offset 0 length 0 limit 0*/
    result = vireo_checked_size_range(0, 0, 0);
    failures += expect_result("size_range 0 0 0", result, VIREO_OK);

    /* offset 0 length 10 limit 10 */
    result = vireo_checked_size_range(0, 10, 10);
    failures += expect_result("size_range 0 10 10", result, VIREO_OK);

    /* offset 3 length 4 limit 10 */
    result = vireo_checked_size_range(3, 4, 10);
    failures += expect_result("size_range 3 4 10", result, VIREO_OK);

    /* offset 10 length 0 limit 10 */
    result = vireo_checked_size_range(10, 0, 10);
    failures += expect_result("size_range 10 0 10", result, VIREO_OK);

    /* offset 11 length 0 limit 10 */
    result = vireo_checked_size_range(11, 0, 10);
    failures += expect_result("size_range 11 0 10", result, VIREO_RESULT_RANGE);

    /* offset 9 length 2 limit 10 */
    result = vireo_checked_size_range(9, 2, 10);
    failures += expect_result("size_range 9 2 10", result, VIREO_RESULT_RANGE);

    /* offset SIZE_MAX length 0 limit SIZE_MAX */
    result = vireo_checked_size_range(SIZE_MAX, 0, SIZE_MAX);
    failures += expect_result("size_range SIZE_MAX 0 SIZE_MAX", result, VIREO_OK);

    /* offset SIZE_MAX length 1 limit SIZE_MAX */
    result = vireo_checked_size_range(SIZE_MAX, 1, SIZE_MAX);
    failures += expect_result("size_range SIZE_MAX 1 SIZE_MAX", result, VIREO_RESULT_RANGE);

    /* offset SIZE_MAX - 1 length 2 limit SIZE_MAX*/
    result = vireo_checked_size_range(SIZE_MAX - 1, 2, SIZE_MAX);
    failures += expect_result("size_range SIZE_MAX - 1 2 SIZE_MAX", result, VIREO_RESULT_RANGE);

    return failures;
}

// 测试 errno 是否被修改
static int check_errno_preservation(void) {
    int failures = 0;
    size_t size_out = 0;
    uint32_t u32_out = UINT32_C(0);
    uint64_t u64_out = UINT64_C(0);

    errno = EACCES;
    (void)vireo_checked_size_add(1, 2, &size_out);
    failures += expect_errno_value("size_add success  errno", EACCES);

    errno = EACCES;
    (void)vireo_checked_size_mul(2, 3, &size_out);
    failures += expect_errno_value("size_mul success errno", EACCES);

    errno = EACCES;
    (void)vireo_checked_u32_add(UINT32_C(1), UINT32_C(2), &u32_out);
    failures += expect_errno_value("u32_add success errno", EACCES);

    errno = EACCES;
    (void)vireo_checked_u32_mul(UINT32_C(2), UINT32_C(3), &u32_out);
    failures += expect_errno_value("u32_mul success errno", EACCES);

    errno = EACCES;
    (void)vireo_checked_u64_add(UINT64_C(1), UINT64_C(2), &u64_out);
    failures += expect_errno_value("u64_add success errno", EACCES);

    errno = EACCES;
    (void)vireo_checked_u64_mul(UINT64_C(2), UINT64_C(3), &u64_out);
    failures += expect_errno_value("u64_mul success errno", EACCES);

    errno = EACCES;
    (void)vireo_checked_u64_to_size(UINT64_C(1), &size_out);
    failures += expect_errno_value("u64_to_size success errno", EACCES);

    errno = EACCES;
    (void)vireo_checked_size_align_up(13, 8, &size_out);
    failures += expect_errno_value("align success errno", EACCES);

    errno = EACCES;
    (void)vireo_checked_size_range(3, 4, 10);
    failures += expect_errno_value("range success errno", EACCES);

    errno = EACCES;
    (void)vireo_checked_size_add(SIZE_MAX, 1, &size_out);
    failures += expect_errno_value("size_add overflow errno", EACCES);

    errno = EACCES;
    (void)vireo_checked_size_align_up(10, 0, &size_out);
    failures += expect_errno_value("align invalid argument errno", EACCES);

    errno = EACCES;
    (void)vireo_checked_size_range(SIZE_MAX, 1, SIZE_MAX);
    failures += expect_errno_value("range failures errno", EACCES);

    return failures;
}
int main(void) {
    int failures = 0;

    failures += check_size_add();
    failures += check_size_mul();
    failures += check_u32_add();
    failures += check_u32_mul();
    failures += check_u64_add();
    failures += check_u64_mul();
    failures += check_u64_to_size();
    failures += check_size_align_up();
    failures += check_size_range();
    failures += check_errno_preservation();

    if (failures != 0) {
        fprintf(stderr, "test_checked: %d check(s) failed\n", failures);
        return EXIT_FAILURE;
    }

    fprintf(stdout, "test_checked: all checks passed\n");
    return EXIT_SUCCESS;
}

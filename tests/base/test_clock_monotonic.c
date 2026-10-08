/*
 * PROJECT : VIREO
 * FILE    : test_clock_monotonic.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-08
 * BRIEF   : 此模块负责：
 * -- 验证真实单调采样的时间域、单位和 errno
 * -- 确定验证最大时间、溢出、畸形值和失败输出
 */

#define _POSIX_C_SOURCE 200809L

#include <vireo/base/clock.h>
#include "base/clock_internal.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

_Static_assert(sizeof(vireo_monotonic_ns_t) == sizeof(uint64_t), "nanosecond value width");
_Static_assert(VIREO_CLOCK_STAGE_NONE == 0, "NONE value");
_Static_assert(VIREO_CLOCK_STAGE_READ == 1, "READ value");
_Static_assert(VIREO_CLOCK_STAGE_CONVERT == 2, "CONVERT value");

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

typedef struct sample_fixture {
    struct timespec sample; /**< 确定的原生输出，失败时也故意写入以检验隔离。 */
    int status; /**< 原生返回值，包括用于防御验证的异常返回。 */
    int system_errno; /**< 采集函数故意设置的 errno，外层须恢复入口值。 */
    size_t calls; /**< 本场景调用数，证明拒绝零调用、采集一次无重试。 */
    clockid_t clock_id; /**< 记录实际选择的 clock，不能用另一个域冒充。 */
} sample_fixture_t;

/**
 * @brief 交付确定原生值并记录实际时钟选择和次数
 *
 * @param[in] clock_id
 *     被测算法选择的原生时钟，按值记录。
 * @param[out] sample
 *     非空局部原生输出，故意在失败时同样写入。
 * @param[in,out] context
 *     非空、本场景独占的 fixture 短借用，更新计数与时钟。
 *
 * @return fixture 指定的原生返回值
 *
 * @note
 *     所有权与线程：不保存地址，单测试线程独占 context。
 * @note
 *     errno：故意修改为指定值，验证被测算法恢复入口值。
 */
static int fixture_gettime(clockid_t clock_id, struct timespec *sample, void *context) {
    sample_fixture_t *fixture = context;
    fixture->calls++;
    fixture->clock_id = clock_id;
    *sample = fixture->sample;
    errno = fixture->system_errno;
    return fixture->status;
}

static int parameter_guards(void) {
    sample_fixture_t fixture = {{12, 345}, 0, EAGAIN, 0, CLOCK_REALTIME};
    vireo_clock_ops_t ops = {fixture_gettime, &fixture};
    vireo_clock_error_t error = {VIREO_CLOCK_STAGE_READ, EIO};
    vireo_monotonic_ns_t now = 123;
    errno = EDOM;
    CHECK(vireo_clock_monotonic_now_with_ops(&ops, NULL, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(fixture.calls == 0 && errno == EDOM);
    CHECK(error.stage == VIREO_CLOCK_STAGE_NONE && error.system_errno == 0);
    CHECK(vireo_clock_monotonic_now_with_ops(NULL, &now, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(now == 123 && errno == EDOM && fixture.calls == 0);
    ops.gettime = NULL;
    CHECK(vireo_clock_monotonic_now_with_ops(&ops, &now, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(now == 123 && errno == EDOM);
    CHECK(vireo_clock_monotonic_now(NULL, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(error.stage == VIREO_CLOCK_STAGE_NONE && error.system_errno == 0 && errno == EDOM);
    CHECK(vireo_clock_monotonic_now(NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    return 0;
}

static int normalized_samples(void) {
    /* 明确十进制期望，不调用生产转换来产生测试答案。 */
    struct { time_t seconds; long nanoseconds; uint64_t expected; } const cases[] = {
        {0, 0, UINT64_C(0)},
        {0, 1, UINT64_C(1)},
        {0, 999999999L, UINT64_C(999999999)},
        {1, 0, UINT64_C(1000000000)},
        {12, 345, UINT64_C(12000000345)},
        {123456789, 987654321L, UINT64_C(123456789987654321)},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        sample_fixture_t fixture = {{cases[i].seconds, cases[i].nanoseconds}, 0, EAGAIN, 0,
                                    CLOCK_REALTIME};
        vireo_clock_ops_t const ops = {fixture_gettime, &fixture};
        vireo_clock_error_t error = {VIREO_CLOCK_STAGE_CONVERT, EIO};
        struct { uint64_t before; vireo_monotonic_ns_t now; uint64_t after; } out = {7, 99, 11};
        errno = ERANGE;
        CHECK(vireo_clock_monotonic_now_with_ops(&ops, &out.now, &error) == VIREO_OK);
        CHECK(out.now == cases[i].expected && out.before == 7 && out.after == 11);
        CHECK(error.stage == VIREO_CLOCK_STAGE_NONE && error.system_errno == 0);
        CHECK(fixture.calls == 1 && fixture.clock_id == CLOCK_MONOTONIC && errno == ERANGE);
    }
    return 0;
}

static int maximum_boundaries(void) {
    if (sizeof(time_t) < sizeof(int64_t)) {
        puts("maximum_boundaries: SKIP native time_t cannot represent 18446744073 seconds");
        return 0;
    }
    struct { uint64_t seconds; long nanoseconds; vireo_result_t result; uint64_t expected; }
    const cases[] = {
        {UINT64_C(18446744073), 709551614L, VIREO_OK, UINT64_MAX - 1},
        {UINT64_C(18446744073), 709551615L, VIREO_OK, UINT64_MAX},
        {UINT64_C(18446744073), 709551616L, VIREO_RESULT_OVERFLOW, UINT64_C(77)},
        {UINT64_C(18446744074), 0, VIREO_RESULT_OVERFLOW, UINT64_C(77)},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        sample_fixture_t fixture = {{(time_t)cases[i].seconds, cases[i].nanoseconds}, 0,
                                    EINTR, 0, CLOCK_REALTIME};
        vireo_clock_ops_t const ops = {fixture_gettime, &fixture};
        vireo_clock_error_t error = {VIREO_CLOCK_STAGE_READ, EIO};
        vireo_monotonic_ns_t now = 77;
        errno = EDOM;
        CHECK(vireo_clock_monotonic_now_with_ops(&ops, &now, &error) == cases[i].result);
        CHECK(now == cases[i].expected && errno == EDOM && fixture.calls == 1);
        CHECK(error.stage == (cases[i].result == VIREO_OK ? VIREO_CLOCK_STAGE_NONE
                                                          : VIREO_CLOCK_STAGE_CONVERT));
        CHECK(error.system_errno == 0);
    }
    return 0;
}

static int malformed_samples(void) {
    struct timespec const cases[] = {{-1, 0}, {0, -1}, {0, 1000000000L},
                                    {-1, 1000000000L}, {1, LONG_MAX}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        sample_fixture_t fixture = {cases[i], 0, EAGAIN, 0, CLOCK_REALTIME};
        vireo_clock_ops_t const ops = {fixture_gettime, &fixture};
        vireo_clock_error_t error = {VIREO_CLOCK_STAGE_READ, EIO};
        vireo_monotonic_ns_t now = UINT64_MAX;
        errno = EDOM;
        CHECK(vireo_clock_monotonic_now_with_ops(&ops, &now, &error) == VIREO_RESULT_INTERNAL);
        CHECK(now == UINT64_MAX && errno == EDOM && fixture.calls == 1);
        CHECK(error.stage == VIREO_CLOCK_STAGE_CONVERT && error.system_errno == 0);
    }
    return 0;
}

static int native_failures(void) {
    struct { int status; int cause; vireo_result_t result; int diagnostic; } const cases[] = {
        {-1, EINVAL, VIREO_RESULT_IO, EINVAL},
        {-1, EINTR, VIREO_RESULT_IO, EINTR},
        {-1, EIO, VIREO_RESULT_IO, EIO},
        {1, EAGAIN, VIREO_RESULT_INTERNAL, 0},
        {-2, EINVAL, VIREO_RESULT_INTERNAL, 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        /* 失败时写进局部“有效时间”，不能被外层错误发布。 */
        sample_fixture_t fixture = {{12, 345}, cases[i].status, cases[i].cause, 0,
                                    CLOCK_REALTIME};
        vireo_clock_ops_t const ops = {fixture_gettime, &fixture};
        vireo_clock_error_t error = {VIREO_CLOCK_STAGE_CONVERT, ERANGE};
        vireo_monotonic_ns_t now = 42;
        errno = EDOM;
        CHECK(vireo_clock_monotonic_now_with_ops(&ops, &now, &error) == cases[i].result);
        CHECK(now == 42 && errno == EDOM && fixture.calls == 1);
        CHECK(fixture.clock_id == CLOCK_MONOTONIC);
        CHECK(error.stage == VIREO_CLOCK_STAGE_READ && error.system_errno == cases[i].diagnostic);
    }
    return 0;
}

static int optional_diagnostic_and_recovery(void) {
    sample_fixture_t fixture = {{12, 345}, -1, EINTR, 0, CLOCK_REALTIME};
    vireo_clock_ops_t const ops = {fixture_gettime, &fixture};
    vireo_monotonic_ns_t now = 42;
    errno = ERANGE;
    CHECK(vireo_clock_monotonic_now_with_ops(&ops, &now, NULL) == VIREO_RESULT_IO);
    CHECK(now == 42 && errno == ERANGE && fixture.calls == 1);
    fixture.status = 0;
    CHECK(vireo_clock_monotonic_now_with_ops(&ops, &now, NULL) == VIREO_OK);
    CHECK(now == UINT64_C(12000000345) && errno == ERANGE && fixture.calls == 2);
    CHECK(vireo_clock_monotonic_now_with_ops(&ops, &now, NULL) == VIREO_OK);
    CHECK(now == UINT64_C(12000000345) && fixture.calls == 3 && errno == ERANGE);
    fixture.sample.tv_nsec = -1;
    CHECK(vireo_clock_monotonic_now_with_ops(&ops, &now, NULL) == VIREO_RESULT_INTERNAL);
    CHECK(now == UINT64_C(12000000345) && errno == ERANGE);
    if (sizeof(time_t) >= sizeof(int64_t)) {
        fixture.sample.tv_sec = (time_t)UINT64_C(18446744074);
        fixture.sample.tv_nsec = 0;
        CHECK(vireo_clock_monotonic_now_with_ops(&ops, &now, NULL) == VIREO_RESULT_OVERFLOW);
        CHECK(now == UINT64_C(12000000345) && errno == ERANGE);
    }
    return 0;
}

static int real_clock_samples(void) {
    vireo_monotonic_ns_t previous = 0;
    for (size_t i = 0; i < 128; i++) {
        struct timespec before = {0, 0};
        struct timespec after = {0, 0};
        vireo_clock_error_t error = {VIREO_CLOCK_STAGE_CONVERT, EIO};
        vireo_monotonic_ns_t now = 0;
        CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
        errno = EDOM;
        CHECK(vireo_clock_monotonic_now(&now, &error) == VIREO_OK);
        CHECK(errno == EDOM);
        CHECK(error.stage == VIREO_CLOCK_STAGE_NONE && error.system_errno == 0);
        CHECK(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
        CHECK(before.tv_sec >= 0 && after.tv_sec >= 0);
        CHECK(before.tv_nsec >= 0 && before.tv_nsec < 1000000000L);
        CHECK(after.tv_nsec >= 0 && after.tv_nsec < 1000000000L);
        CHECK((uintmax_t)after.tv_sec < UINT64_MAX / UINT64_C(1000000000));
        /* 直接原生上下样本夹住公共值，同时验证来源与单位，不要求严格增长。 */
        uint64_t const lower = (uint64_t)before.tv_sec * UINT64_C(1000000000)
                               + (uint64_t)before.tv_nsec;
        uint64_t const upper = (uint64_t)after.tv_sec * UINT64_C(1000000000)
                               + (uint64_t)after.tv_nsec;
        CHECK(lower <= now && now <= upper && previous <= now);
        previous = now;
    }
    errno = ERANGE;
    CHECK(vireo_clock_monotonic_now(&previous, NULL) == VIREO_OK);
    CHECK(errno == ERANGE);
    printf("real_clock_samples: 128 bracketed samples; time_t=%zu bytes; no sleep\n", sizeof(time_t));
    return 0;
}

int main(void) {
    int failures = 0;
    failures += parameter_guards();
    failures += normalized_samples();
    failures += maximum_boundaries();
    failures += malformed_samples();
    failures += native_failures();
    failures += optional_diagnostic_and_recovery();
    failures += real_clock_samples();
    printf("test_clock_monotonic: 7 groups, %d failures\n", failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

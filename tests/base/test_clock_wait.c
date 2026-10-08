/*
 * PROJECT : VIREO
 * FILE    : test_clock_wait.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-08
 * BRIEF   : 此模块负责：
 * -- 验证精确单位转换及失败保持
 * -- 验证 deadline 舍入、等待上限与安全窄化
 */

#include <vireo/base/clock.h>

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

/** @brief 独立给定的毫秒输入与纳秒期望，不由生产函数生成答案。 */
typedef struct duration_case {
    uint64_t milliseconds; /**< 非负毫秒长度输入。 */
    vireo_duration_ns_t expected_ns; /**< 手写精确纳秒长度。 */
} duration_case_t;

/** @brief 显式时间点和预算对应的独立等待期望。 */
typedef struct wait_case {
    vireo_monotonic_ns_t now; /**< 同域输入时间点，单位纳秒。 */
    vireo_monotonic_ns_t deadline; /**< 同域绝对期限，单位纳秒。 */
    int cap_ms; /**< 非负相对等待预算，单位毫秒。 */
    int expected_ms; /**< 手写的有限等待毫秒，范围 0..cap_ms。 */
} wait_case_t;

static int parameter_guards(void) {
    errno = EDOM;
    CHECK(vireo_clock_duration_from_ms(1, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    CHECK(vireo_clock_duration_from_ms(UINT64_MAX, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    CHECK(vireo_clock_deadline_wait_ms(0, 1, 1, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_clock_deadline_wait_ms(1, 0, 0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_clock_deadline_wait_ms(0, UINT64_MAX, -1, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    int const caps[] = {-1, -2, INT_MIN};
    for (size_t i = 0; i < sizeof(caps) / sizeof(caps[0]); i++) {
        int out = 77;
        CHECK(vireo_clock_deadline_wait_ms(0, UINT64_MAX, caps[i], &out) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(out == 77 && errno == EDOM);
        /* 已到期也须拒绝非法预算，不能提前成功返回 0。 */
        CHECK(vireo_clock_deadline_wait_ms(UINT64_MAX, 0, caps[i], &out) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(out == 77 && errno == EDOM);
    }
    return 0;
}

static int duration_golden_values(void) {
    duration_case_t const cases[] = {
        {0, 0}, {1, UINT64_C(1000000)}, {3, UINT64_C(3000000)},
        {1000, UINT64_C(1000000000)},
        {UINT64_C(4294967296), UINT64_C(4294967296000000)},
        {UINT64_C(18446744073708), UINT64_C(18446744073708000000)},
        {UINT64_C(18446744073709), UINT64_C(18446744073709000000)},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct { uint64_t before; vireo_duration_ns_t value; uint64_t after; }
            out = {11, 77, 19};
        errno = EILSEQ;
        CHECK(vireo_clock_duration_from_ms(cases[i].milliseconds, &out.value) == VIREO_OK);
        CHECK(out.value == cases[i].expected_ns && out.before == 11 && out.after == 19);
        CHECK(errno == EILSEQ);
    }
    return 0;
}

static int duration_overflow_and_recovery(void) {
    uint64_t const cases[] = {UINT64_C(18446744073710), UINT64_MAX - 1, UINT64_MAX};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        vireo_duration_ns_t out = 77;
        errno = ERANGE;
        CHECK(vireo_clock_duration_from_ms(cases[i], &out) == VIREO_RESULT_OVERFLOW);
        CHECK(out == 77 && errno == ERANGE);
        CHECK(vireo_clock_duration_from_ms(1, &out) == VIREO_OK);
        CHECK(out == UINT64_C(1000000) && errno == ERANGE);
    }
    return 0;
}

static int wait_rounding_values(void) {
    wait_case_t const cases[] = {
        {0, 0, 17, 0}, {12, 13, 17, 1}, {13, 13, 17, 0}, {14, 13, 17, 0},
        {500, 501, 17, 1}, {500, 1000499, 17, 1}, {500, 1000500, 17, 1},
        {500, 1000501, 17, 2}, {500, 2000500, 17, 2}, {500, 2000501, 17, 3},
        {999999, 1000000, 17, 1}, {0, 17000000, 17, 17}, {0, 17000001, 17, 17},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct { int before; int value; int after; } out = {11, -7, 19};
        errno = EDOM;
        CHECK(vireo_clock_deadline_wait_ms(cases[i].now, cases[i].deadline, cases[i].cap_ms,
                                           &out.value) == VIREO_OK);
        CHECK(out.value == cases[i].expected_ms && out.before == 11 && out.after == 19);
        CHECK(out.value >= 0 && out.value <= cases[i].cap_ms && errno == EDOM);
    }
    return 0;
}

static int wait_caps_and_extremes(void) {
    wait_case_t const cases[] = {
        {0, 1, 0, 0}, {0, UINT64_MAX, 0, 0}, {UINT64_MAX, 0, 0, 0},
        {0, 1000001, 1, 1}, {0, 2000001, 2, 2},
        {0, UINT64_MAX, INT_MAX, INT_MAX},
        {1, UINT64_MAX, INT_MAX, INT_MAX},
        {UINT64_MAX - 1, UINT64_MAX, INT_MAX, 1},
        {UINT64_MAX, UINT64_MAX, INT_MAX, 0},
        {UINT64_MAX, 0, INT_MAX, 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int out = -7;
        errno = EILSEQ;
        CHECK(vireo_clock_deadline_wait_ms(cases[i].now, cases[i].deadline, cases[i].cap_ms,
                                           &out) == VIREO_OK);
        CHECK(out == cases[i].expected_ms && out >= 0 && errno == EILSEQ);
    }
    bool expired = true;
    CHECK(vireo_clock_deadline_expired(0, 1, &expired) == VIREO_OK && !expired);
    /* cap=0 的等待值为 0；期限查询仍未到期。 */
    return 0;
}

static int int_boundary_values(void) {
    /* 先证明测试自己的边界构造安全，不调用生产转换产生答案。 */
    CHECK((uint64_t)INT_MAX <= UINT64_MAX / UINT64_C(1000000));
    uint64_t const boundary = (uint64_t)INT_MAX * UINT64_C(1000000);
    wait_case_t const cases[] = {
        {0, boundary - UINT64_C(1000000), INT_MAX, INT_MAX - 1},
        {0, boundary - UINT64_C(1000000) + 1, INT_MAX, INT_MAX},
        {0, boundary - 1, INT_MAX, INT_MAX},
        {0, boundary, INT_MAX, INT_MAX},
        {0, boundary + 1, INT_MAX, INT_MAX},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int out = -7;
        errno = ERANGE;
        CHECK(vireo_clock_deadline_wait_ms(cases[i].now, cases[i].deadline, cases[i].cap_ms,
                                           &out) == VIREO_OK);
        CHECK(out == cases[i].expected_ms && errno == ERANGE);
    }
    return 0;
}

static int storage_and_deadline_composition(void) {
    vireo_duration_ns_t duration = 3;
    errno = EDOM;
    CHECK(vireo_clock_duration_from_ms(duration, &duration) == VIREO_OK);
    CHECK(duration == UINT64_C(3000000) && errno == EDOM);
    duration = UINT64_MAX;
    CHECK(vireo_clock_duration_from_ms(duration, &duration) == VIREO_RESULT_OVERFLOW);
    CHECK(duration == UINT64_MAX && errno == EDOM);

    int cap = 100;
    CHECK(vireo_clock_deadline_wait_ms(0, 1000001, cap, &cap) == VIREO_OK);
    CHECK(cap == 2 && errno == EDOM);
    cap = -1;
    CHECK(vireo_clock_deadline_wait_ms(0, 1, cap, &cap) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(cap == -1 && errno == EDOM);

    vireo_monotonic_ns_t deadline = 0;
    CHECK(vireo_clock_duration_from_ms(3, &duration) == VIREO_OK);
    CHECK(vireo_clock_deadline_after(100, duration, &deadline) == VIREO_OK);
    CHECK(deadline == UINT64_C(3000100));
    int wait = -7;
    CHECK(vireo_clock_deadline_wait_ms(200, deadline, 10, &wait) == VIREO_OK && wait == 3);
    CHECK(vireo_clock_deadline_wait_ms(200, deadline, 2, &wait) == VIREO_OK && wait == 2);
    CHECK(vireo_clock_deadline_wait_ms(200, deadline, 0, &wait) == VIREO_OK && wait == 0);
    bool expired = true;
    CHECK(vireo_clock_deadline_expired(200, deadline, &expired) == VIREO_OK && !expired);
    CHECK(vireo_clock_deadline_wait_ms(deadline, deadline, 10, &wait) == VIREO_OK && wait == 0);
    CHECK(vireo_clock_deadline_expired(deadline, deadline, &expired) == VIREO_OK && expired);
    CHECK(errno == EDOM);
    return 0;
}

static int real_clock_composition(void) {
    vireo_monotonic_ns_t now = 0;
    errno = EDOM;
    CHECK(vireo_clock_monotonic_now(&now, NULL) == VIREO_OK);
    vireo_duration_ns_t duration = 77;
    CHECK(vireo_clock_duration_from_ms(0, &duration) == VIREO_OK && duration == 0);
    vireo_monotonic_ns_t deadline = 0;
    CHECK(vireo_clock_deadline_after(now, duration, &deadline) == VIREO_OK);
    int wait = -7;
    CHECK(vireo_clock_deadline_wait_ms(now, deadline, INT_MAX, &wait) == VIREO_OK && wait == 0);
    CHECK(vireo_clock_deadline_wait_ms(now, UINT64_MAX, 0, &wait) == VIREO_OK && wait == 0);
    CHECK(errno == EDOM);
    return 0;
}

int main(void) {
    int failures = 0;
    failures += parameter_guards();
    failures += duration_golden_values();
    failures += duration_overflow_and_recovery();
    failures += wait_rounding_values();
    failures += wait_caps_and_extremes();
    failures += int_boundary_values();
    failures += storage_and_deadline_composition();
    failures += real_clock_composition();
    printf("clock wait: 8 groups, %d failures; int bytes=%zu, INT_MAX=%d\n",
           failures, sizeof(int), INT_MAX);
    return failures == 0 ? 0 : 1;
}

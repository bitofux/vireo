/*
 * PROJECT : VIREO
 * FILE    : test_clock_deadline.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-08
 * BRIEF   : 此模块负责：
 * -- 验证期限数学的独立期望与完整 uint64 边界
 * -- 验证错误优先级、输出保持、errno 及显式采样组合
 */

#include <vireo/base/clock.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

_Static_assert(sizeof(vireo_duration_ns_t) == sizeof(uint64_t), "duration width");
_Static_assert(sizeof(vireo_monotonic_ns_t) == sizeof(uint64_t), "point width");

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

static int parameter_guards(void) {
    errno = EDOM;
    CHECK(vireo_clock_deadline_after(10, 3, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    /* NULL 拒绝优先，不能因数值同时超界而变为 OVERFLOW。 */
    CHECK(vireo_clock_deadline_after(UINT64_MAX, 1, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    CHECK(vireo_clock_deadline_expired(0, UINT64_MAX, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    CHECK(vireo_clock_deadline_expired(UINT64_MAX, 0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    CHECK(vireo_clock_deadline_remaining(0, UINT64_MAX, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    CHECK(vireo_clock_deadline_remaining(UINT64_MAX, 0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    return 0;
}

static int after_golden_values(void) {
    /* 期望值直接给定；不调用 checked 或生产函数生成答案。 */
    struct {
        vireo_monotonic_ns_t now;
        vireo_duration_ns_t delay;
        vireo_monotonic_ns_t expected;
    } const cases[] = {
        {0, 0, 0}, {0, 1, 1}, {1, 0, 1}, {10, 3, 13},
        {UINT64_C(10000000000), UINT64_C(3000000000), UINT64_C(13000000000)},
        {UINT64_C(4294967296), UINT64_C(4294967296), UINT64_C(8589934592)},
        {UINT64_MAX, 0, UINT64_MAX}, {0, UINT64_MAX, UINT64_MAX},
        {UINT64_MAX - 1, 1, UINT64_MAX}, {1, UINT64_MAX - 1, UINT64_MAX},
        {UINT64_MAX - 2, 1, UINT64_MAX - 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct { uint64_t before; vireo_monotonic_ns_t value; uint64_t after; }
            out = {11, 77, 19};
        errno = EILSEQ;
        CHECK(vireo_clock_deadline_after(cases[i].now, cases[i].delay, &out.value) == VIREO_OK);
        CHECK(out.value == cases[i].expected && out.before == 11 && out.after == 19);
        CHECK(errno == EILSEQ);
    }
    return 0;
}

static int after_overflow_and_recovery(void) {
    struct { vireo_monotonic_ns_t now; vireo_duration_ns_t delay; } const cases[] = {
        {UINT64_MAX, 1}, {1, UINT64_MAX}, {UINT64_MAX - 1, 2},
        {UINT64_MAX / 2 + 1, UINT64_MAX / 2 + 1}, {UINT64_MAX, UINT64_MAX},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        vireo_monotonic_ns_t out = 77;
        errno = ERANGE;
        CHECK(vireo_clock_deadline_after(cases[i].now, cases[i].delay, &out) == VIREO_RESULT_OVERFLOW);
        CHECK(out == 77 && errno == ERANGE);
        CHECK(vireo_clock_deadline_after(10, 3, &out) == VIREO_OK);
        CHECK(out == 13 && errno == ERANGE);
    }
    return 0;
}

static int expired_boundaries(void) {
    struct {
        vireo_monotonic_ns_t now;
        vireo_monotonic_ns_t deadline;
        bool expected;
    } const cases[] = {
        {0, 0, true}, {0, 1, false}, {1, 0, true},
        {12, 13, false}, {13, 13, true}, {14, 13, true},
        {0, UINT64_MAX, false}, {UINT64_MAX - 1, UINT64_MAX, false},
        {UINT64_MAX, UINT64_MAX, true}, {UINT64_MAX, 0, true},
        {UINT64_MAX, UINT64_MAX - 1, true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bool expired = !cases[i].expected;
        errno = EDOM;
        CHECK(vireo_clock_deadline_expired(cases[i].now, cases[i].deadline, &expired) == VIREO_OK);
        CHECK(expired == cases[i].expected && errno == EDOM);
    }
    return 0;
}

static int remaining_boundaries(void) {
    struct {
        vireo_monotonic_ns_t now;
        vireo_monotonic_ns_t deadline;
        vireo_duration_ns_t expected;
    } const cases[] = {
        {0, 0, 0}, {0, 1, 1}, {1, 0, 0},
        {12, 13, 1}, {13, 13, 0}, {14, 13, 0},
        {UINT64_C(10000000000), UINT64_C(13000000000), UINT64_C(3000000000)},
        {0, UINT64_MAX, UINT64_MAX}, {1, UINT64_MAX, UINT64_MAX - 1},
        {UINT64_MAX - 1, UINT64_MAX, 1}, {UINT64_MAX, UINT64_MAX, 0},
        {UINT64_MAX, 0, 0}, {UINT64_MAX, UINT64_MAX - 1, 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        vireo_duration_ns_t remaining = 77;
        bool expired = false;
        errno = EILSEQ;
        CHECK(vireo_clock_deadline_remaining(cases[i].now, cases[i].deadline, &remaining) == VIREO_OK);
        CHECK(remaining == cases[i].expected && errno == EILSEQ);
        CHECK(vireo_clock_deadline_expired(cases[i].now, cases[i].deadline, &expired) == VIREO_OK);
        CHECK((remaining == 0) == expired && errno == EILSEQ);
    }
    return 0;
}

static int value_storage_and_composition(void) {
    vireo_monotonic_ns_t point = 10;
    vireo_duration_ns_t delay = 3;
    errno = EDOM;
    CHECK(vireo_clock_deadline_after(point, delay, &point) == VIREO_OK);
    CHECK(point == 13 && errno == EDOM);
    CHECK(vireo_clock_deadline_after(10, delay, &delay) == VIREO_OK);
    CHECK(delay == 13 && errno == EDOM);
    CHECK(vireo_clock_deadline_remaining(point, 20, &point) == VIREO_OK);
    CHECK(point == 7 && errno == EDOM);
    CHECK(vireo_clock_deadline_remaining(4, point, &point) == VIREO_OK);
    CHECK(point == 3 && errno == EDOM);
    point = UINT64_MAX;
    CHECK(vireo_clock_deadline_after(point, 1, &point) == VIREO_RESULT_OVERFLOW);
    CHECK(point == UINT64_MAX && errno == EDOM);

    vireo_monotonic_ns_t deadline = 0;
    CHECK(vireo_clock_deadline_after(10, 3, &deadline) == VIREO_OK);
    /* 显式给未来 now，证明函数按输入查询，未用隐式采样替换它。 */
    vireo_monotonic_ns_t const times[] = {10, 12, 13, 14};
    vireo_duration_ns_t const expected[] = {3, 1, 0, 0};
    for (size_t i = 0; i < sizeof(times) / sizeof(times[0]); i++) {
        bool expired = false;
        vireo_duration_ns_t remaining = 77;
        CHECK(vireo_clock_deadline_expired(times[i], deadline, &expired) == VIREO_OK);
        CHECK(expired == (i >= 2));
        CHECK(vireo_clock_deadline_remaining(times[i], deadline, &remaining) == VIREO_OK);
        CHECK(remaining == expected[i] && errno == EDOM);
    }
    return 0;
}

static int real_clock_composition(void) {
    vireo_monotonic_ns_t now = 0;
    vireo_clock_error_t error = {VIREO_CLOCK_STAGE_READ, EIO};
    errno = EDOM;
    CHECK(vireo_clock_monotonic_now(&now, &error) == VIREO_OK);
    CHECK(error.stage == VIREO_CLOCK_STAGE_NONE && error.system_errno == 0 && errno == EDOM);
    vireo_monotonic_ns_t deadline = 0;
    vireo_duration_ns_t remaining = 77;
    bool expired = false;
    CHECK(vireo_clock_deadline_after(now, 0, &deadline) == VIREO_OK);
    CHECK(deadline == now);
    CHECK(vireo_clock_deadline_expired(now, deadline, &expired) == VIREO_OK && expired);
    CHECK(vireo_clock_deadline_remaining(now, deadline, &remaining) == VIREO_OK && remaining == 0);
    CHECK(vireo_clock_deadline_after(now, UINT64_MAX - now, &deadline) == VIREO_OK);
    CHECK(deadline == UINT64_MAX);
    CHECK(vireo_clock_deadline_expired(UINT64_MAX, deadline, &expired) == VIREO_OK && expired);
    CHECK(vireo_clock_deadline_remaining(UINT64_MAX, deadline, &remaining) == VIREO_OK && remaining == 0);
    CHECK(errno == EDOM);
    return 0;
}

int main(void) {
    int failures = 0;
    failures += parameter_guards();
    failures += after_golden_values();
    failures += after_overflow_and_recovery();
    failures += expired_boundaries();
    failures += remaining_boundaries();
    failures += value_storage_and_composition();
    failures += real_clock_composition();
    printf("clock deadline: 7 groups, %d failures\n", failures);
    return failures == 0 ? 0 : 1;
}

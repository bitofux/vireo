/*
 * PROJECT : VIREO
 * FILE    : clock_wait.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-08
 * BRIEF   : 此模块负责：
 * -- 精确受检转换毫秒长度
 * -- 根据显式 deadline 计算受限相对等待值
 */

#include <vireo/base/clock.h>
#include <vireo/base/checked.h>

#include <stddef.h>

/* 长度换算比例，非实际时钟分辨率或时间轮 tick 参数。 */
#define NANOSECONDS_PER_MILLISECOND UINT64_C(1000000)

vireo_result_t vireo_clock_duration_from_ms(uint64_t milliseconds,
                                           vireo_duration_ns_t *out_duration) {
    return vireo_checked_u64_mul(milliseconds, NANOSECONDS_PER_MILLISECOND, out_duration);
}

vireo_result_t vireo_clock_deadline_wait_ms(vireo_monotonic_ns_t now,
                                           vireo_monotonic_ns_t deadline,
                                           int max_wait_ms, int *out_wait_ms) {
    if (out_wait_ms == NULL || max_wait_ms < 0) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    vireo_duration_ns_t remaining = 0;
    vireo_result_t const result = vireo_clock_deadline_remaining(now, deadline, &remaining);
    if (result != VIREO_OK) {
        return result;
    }

    /* 不先加 999999；商最大为 18446744073709，再加至多 1 仍可表示。 */
    uint64_t const whole_ms = remaining / NANOSECONDS_PER_MILLISECOND;
    uint64_t const rounded_ms = whole_ms +
        (remaining % NANOSECONDS_PER_MILLISECOND != 0 ? UINT64_C(1) : UINT64_C(0));

    /* cap 已非负；仅当 rounded_ms <= cap <= INT_MAX 才求值窄化分支。 */
    int const wait_ms = rounded_ms > (uint64_t)max_wait_ms ? max_wait_ms : (int)rounded_ms;
    *out_wait_ms = wait_ms;
    return VIREO_OK;
}

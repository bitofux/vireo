/*
 * PROJECT : VIREO
 * FILE    : clock_deadline.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-08
 * BRIEF   : 此模块负责：
 * -- 受检构造同域绝对 deadline
 * -- 根据显式时间点判断到期及计算剩余纳秒
 */

#include <vireo/base/clock.h>
#include <vireo/base/checked.h>

#include <stddef.h>

vireo_result_t vireo_clock_deadline_after(vireo_monotonic_ns_t now,
                                         vireo_duration_ns_t delay,
                                         vireo_monotonic_ns_t *out_deadline) {
    /* 已封板加法先拒绝 NULL，再证明可表示，失败保持输出和 errno。 */
    return vireo_checked_u64_add(now, delay, out_deadline);
}

vireo_result_t vireo_clock_deadline_expired(vireo_monotonic_ns_t now,
                                           vireo_monotonic_ns_t deadline,
                                           bool *out_expired) {
    if (out_expired == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    *out_expired = now >= deadline;
    return VIREO_OK;
}

vireo_result_t vireo_clock_deadline_remaining(vireo_monotonic_ns_t now,
                                             vireo_monotonic_ns_t deadline,
                                             vireo_duration_ns_t *out_remaining) {
    if (out_remaining == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    /* 只有 deadline > now 才执行减法；到期返回 0 是成功值，不是失败截限。 */
    *out_remaining = now < deadline ? deadline - now : UINT64_C(0);
    return VIREO_OK;
}

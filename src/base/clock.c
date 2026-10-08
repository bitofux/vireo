/*
 * PROJECT : VIREO
 * FILE    : clock.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-08
 * BRIEF   : 此模块负责：
 * -- 单次原生时钟读取与局部受检转换
 * -- 在失败时保持时间输出并保存独立诊断
 */

#define _POSIX_C_SOURCE 200809L

#include <vireo/base/clock.h>
#include <vireo/base/checked.h>

#include "clock_internal.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/**
 * @brief 将本模块的采集调用桥接到 POSIX clock_gettime
 *
 * @param[in] clock_id
 *     本模块传入的 CLOCK_MONOTONIC，不持有资源。
 * @param[out] sample
 *     非空局部 timespec；仅本次调用借用。
 * @param[in] context
 *     可空且不使用，不保存。
 *
 * @retval 0
 *     sample 已由原生 API 完整写入。
 * @retval -1
 *     原生失败，errno 保留原始原因。
 *
 * @note
 *     线程安全：使用 POSIX 线程安全读取，不访问项目共享状态。
 * @note
 *     errno：本桥接不恢复 errno，由外层立即捕获并在返回前恢复入口值。
 */
static int native_gettime(clockid_t clock_id, struct timespec *sample, void *context) {
    (void)context;
    return clock_gettime(clock_id, sample);
}

vireo_result_t vireo_clock_monotonic_now_with_ops(vireo_clock_ops_t const *ops,
                                                 vireo_monotonic_ns_t *out_now,
                                                 vireo_clock_error_t *error) {
    int const entry_errno = errno;
    vireo_clock_error_t diagnostic = {VIREO_CLOCK_STAGE_NONE, 0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    struct timespec sample = {0, 0};
    uint64_t seconds_ns = 0;
    uint64_t now_ns = 0;

    if (ops == NULL || ops->gettime == NULL || out_now == NULL) {
        goto done;
    }

    int const status = ops->gettime(CLOCK_MONOTONIC, &sample, ops->context);
    if (status == -1) {
        diagnostic.stage = VIREO_CLOCK_STAGE_READ;
        diagnostic.system_errno = errno;
        result = VIREO_RESULT_IO;
        goto done;
    }
    if (status != 0) {
        diagnostic.stage = VIREO_CLOCK_STAGE_READ;
        result = VIREO_RESULT_INTERNAL;
        goto done;
    }

    diagnostic.stage = VIREO_CLOCK_STAGE_CONVERT;
    if (sample.tv_sec < 0 || sample.tv_nsec < 0 || sample.tv_nsec >= 1000000000L) {
        result = VIREO_RESULT_INTERNAL;
        goto done;
    }

    /* 非负之后才转无符号；uintmax_t 在 Linux 覆盖 time_t 的整数值域。 */
    if ((uintmax_t)sample.tv_sec > UINT64_MAX) {
        result = VIREO_RESULT_OVERFLOW;
        goto done;
    }
    result = vireo_checked_u64_mul((uint64_t)sample.tv_sec, UINT64_C(1000000000),
                                   &seconds_ns);
    if (result != VIREO_OK) {
        goto done;
    }
    result = vireo_checked_u64_add(seconds_ns, (uint64_t)sample.tv_nsec, &now_ns);
    if (result != VIREO_OK) {
        goto done;
    }

    /* 不把中间乘积交给 caller，成功之后才发布完整时间点。 */
    *out_now = now_ns;
    diagnostic.stage = VIREO_CLOCK_STAGE_NONE;

done:
    if (error != NULL) {
        *error = diagnostic;
    }
    errno = entry_errno;
    return result;
}

vireo_result_t vireo_clock_monotonic_now(vireo_monotonic_ns_t *out_now,
                                        vireo_clock_error_t *error) {
    vireo_clock_ops_t const ops = {native_gettime, NULL};
    return vireo_clock_monotonic_now_with_ops(&ops, out_now, error);
}

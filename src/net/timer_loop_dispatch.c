/*
 * PROJECT : VIREO
 * FILE    : timer_loop_dispatch.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 通过公开轮值合同执行有界同步交付
 * -- 在不可逆的单项领取之后保留部分进度与失败通知
 */
#include "timer_loop_dispatch_internal.h"
#include <errno.h>

/**
 * @brief 将观测依赖接到公开轮入口
 *
 * @param[in] wheel
 *     本层已校验非空的存活短借轮。
 * @param[out] out_progress
 *     本层独立栈快照，失败保持。
 * @param[in] context
 *     native 不使用，值为 NULL。
 *
 * @return
 *     公开观测结果原样返回。
 *
 * @note
 *     不保存地址或执行额外动作，沿公开 errno 保持。
 */
static vireo_result_t inspect_native(vireo_timer_wheel_t const *wheel,
                                     vireo_timer_wheel_progress_t *out_progress,
                                     void *context)
{
    (void)context;
    return vireo_timer_wheel_progress_inspect(wheel, out_progress);
}

/**
 * @brief 将单项领取依赖接到公开轮入口
 *
 * @param[in,out] wheel
 *     本层已校验非空的存活短借轮。
 * @param[out] out_expired
 *     本层独立栈事件，成功注销后写值，失败保持。
 * @param[in] context
 *     native 不使用，值为 NULL。
 *
 * @return
 *     公开领取结果原样返回。
 *
 * @note
 *     不保存地址、不重试，沿公开 errno 保持。
 */
static vireo_result_t take_native(vireo_timer_wheel_t *wheel,
                                  vireo_timer_wheel_expired_t *out_expired,
                                  void *context)
{
    (void)context;
    return vireo_timer_wheel_take_expired(wheel, out_expired);
}

vireo_result_t vireo_timer_loop_dispatch_runtime(
    vireo_timer_wheel_t *wheel, size_t max_events,
    vireo_timer_loop_deliver_fn deliver, void *context,
    vireo_timer_loop_dispatch_report_t *out_report,
    vireo_timer_loop_dispatch_runtime_t const *runtime)
{
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (wheel == NULL || deliver == NULL || out_report == NULL || max_events == 0 ||
        runtime == NULL || runtime->inspect == NULL || runtime->take == NULL) {
        goto done;
    }
    if (max_events > VIREO_TIMER_LOOP_DISPATCH_MAX_EVENTS) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }

    /* 条数已有硬限，两个计数不可能溢出；处理期报告不能隐藏成功注销。 */
    vireo_timer_loop_dispatch_report_t report = {0};
    while (report.consumed_count < max_events) {
        vireo_timer_wheel_progress_t progress;
        report.stage = VIREO_TIMER_LOOP_DISPATCH_STAGE_OBSERVE;
        result = runtime->inspect(wheel, &progress, runtime->context);
        if (result != VIREO_OK) {
            goto publish;
        }
        if (progress.ready_count == 0) {
            break;
        }
        vireo_timer_wheel_expired_t expired;
        report.stage = VIREO_TIMER_LOOP_DISPATCH_STAGE_TAKE;
        result = runtime->take(wheel, &expired, runtime->context);
        if (result != VIREO_OK) {
            goto publish;
        }
        ++report.consumed_count;
        report.stage = VIREO_TIMER_LOOP_DISPATCH_STAGE_DELIVER;
        result = deliver(&expired, context);
        if (result != VIREO_OK) {
            report.has_failed_delivery = true;
            report.failed_delivery = expired;
            goto publish;
        }
        ++report.delivered_count;
    }
    report.stage = VIREO_TIMER_LOOP_DISPATCH_STAGE_NONE;
    result = VIREO_OK;
publish:
    *out_report = report;
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_timer_loop_dispatch(vireo_timer_wheel_t *wheel,
                                        size_t max_events,
                                        vireo_timer_loop_deliver_fn deliver,
                                        void *context,
                                        vireo_timer_loop_dispatch_report_t *out_report)
{
    static vireo_timer_loop_dispatch_runtime_t const native = {
        .inspect = inspect_native, .take = take_native, .context = NULL
    };
    return vireo_timer_loop_dispatch_runtime(wheel, max_events, deliver, context,
                                             out_report, &native);
}

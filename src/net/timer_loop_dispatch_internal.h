/*
 * PROJECT : VIREO
 * FILE    : timer_loop_dispatch_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 本层观测和领取依赖的有限故障测试缝
 */
#ifndef VIREO_NET_TIMER_LOOP_DISPATCH_INTERNAL_H
#define VIREO_NET_TIMER_LOOP_DISPATCH_INTERNAL_H

#include <vireo/net/timer_loop_dispatch.h>

/** 仅本层同步短借的调用表，不拥有轮或公开内部布局。 */
typedef struct vireo_timer_loop_dispatch_runtime {
    vireo_result_t (*inspect)(vireo_timer_wheel_t const *wheel,
                              vireo_timer_wheel_progress_t *out_progress, void *context);
    /**< 沿公开观测合同，失败不写进度、不改轮。 */
    vireo_result_t (*take)(vireo_timer_wheel_t *wheel,
                           vireo_timer_wheel_expired_t *out_expired, void *context);
    /**< 沿公开领取合同，成功注销；失败保持当前项及输出。 */
    void *context; /**< 调用表的短借上下文，与 caller 交付上下文独立。 */
} vireo_timer_loop_dispatch_runtime_t;

/**
 * @brief 仅本层控制观测与领取错误边界
 *
 * @param[in] runtime
 *     非空、两个函数非空且全程稳定，短借至返回，必须沿 public 原合同。
 *
 * @note
 *     其他参数沿 public；非法调用表与基本参数拒绝同样保持整个报告。
 *     本层测试缝不包含其他模块私有头，不授权下游依赖。
 */
vireo_result_t vireo_timer_loop_dispatch_runtime(
    vireo_timer_wheel_t *wheel, size_t max_events,
    vireo_timer_loop_deliver_fn deliver, void *context,
    vireo_timer_loop_dispatch_report_t *out_report,
    vireo_timer_loop_dispatch_runtime_t const *runtime);

#endif /* VIREO_NET_TIMER_LOOP_DISPATCH_INTERNAL_H */

/*
 * PROJECT : VIREO
 * FILE    : timer_loop_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 本层采样及网络调用的有限故障测试缝
 */
#ifndef VIREO_NET_TIMER_LOOP_INTERNAL_H
#define VIREO_NET_TIMER_LOOP_INTERNAL_H

#include <vireo/net/timer_loop_run.h>

/** 仅本层同步短借；生产使用公开 native 适配，不拥有资源或公开为调用者合同。 */
typedef struct vireo_timer_loop_runtime {
    vireo_result_t (*monotonic_now)(vireo_monotonic_ns_t *out_now,
                                   vireo_clock_error_t *out_error, void *context);
    /**< 返回原 clock 合同，成功填值和诊断；失败保值，不保存地址。 */
    vireo_result_t (*run_loop)(vireo_event_loop_t *loop, int timeout_ms,
                              vireo_event_loop_run_info_t *out_info,
                              vireo_event_loop_error_t *out_error, void *context);
    /**< 返回原 loop 合同，调用一次且同步返回，不保存借用。 */
    void *context; /**< 两适配器的短借上下文；native 为 NULL，不拥有业务 payload。 */
} vireo_timer_loop_runtime_t;

/**
 * @brief 仅本层测试依赖调用顺序与失败边界
 *
 * @param[in] runtime
 *     非空、两个函数非空且全程稳定，只借至返回，依赖输出沿公开原合同。
 *
 * @note
 *     其他参数/生命周期/主输出/诊断合同沿 public；异常 runtime 基本拒绝，诊断 NONE。
 * @note
 *     不暴露其他模块 private；入口最终恢复 errno，即使测试适配器改变 errno。
 */
vireo_result_t vireo_timer_loop_run_once_runtime(
    vireo_event_loop_t *loop, vireo_timer_wheel_t *wheel,
    vireo_timer_loop_run_options_t const *options,
    vireo_timer_loop_run_report_t *out_report,
    vireo_timer_loop_diagnostic_t *out_diagnostic,
    vireo_timer_loop_runtime_t const *runtime);

#endif /* VIREO_NET_TIMER_LOOP_INTERNAL_H */

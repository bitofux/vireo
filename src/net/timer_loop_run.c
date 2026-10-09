/*
 * PROJECT : VIREO
 * FILE    : timer_loop_run.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 保留单轮失败阶段、主输出及已完成网络动作的边界
 */
#include "timer_loop_internal.h"
#include <vireo/timer/wheel_shutdown.h>
#include <errno.h>

/** @brief 严格一次公开单调采样，不保存地址、回退或重试。 */
static vireo_result_t monotonic_native(vireo_monotonic_ns_t *out_now,
                                       vireo_clock_error_t *out_error, void *context)
{
    (void)context;
    return vireo_clock_monotonic_now(out_now, out_error);
}

/** @brief 严格一次公开网络一轮，失败原样、已成功动作不回滚。 */
static vireo_result_t loop_native(vireo_event_loop_t *loop, int timeout_ms,
                                  vireo_event_loop_run_info_t *out_info,
                                  vireo_event_loop_error_t *out_error, void *context)
{
    (void)context;
    return vireo_event_loop_run_once(loop, timeout_ms, out_info, out_error);
}

vireo_result_t vireo_timer_loop_run_once_runtime(
    vireo_event_loop_t *loop, vireo_timer_wheel_t *wheel,
    vireo_timer_loop_run_options_t const *options,
    vireo_timer_loop_run_report_t *out_report,
    vireo_timer_loop_diagnostic_t *out_diagnostic,
    vireo_timer_loop_runtime_t const *runtime)
{
    int const saved_errno = errno;
    vireo_timer_loop_diagnostic_t diagnostic = {0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (loop == NULL || wheel == NULL || options == NULL || out_report == NULL ||
        runtime == NULL || runtime->monotonic_now == NULL || runtime->run_loop == NULL) {
        goto done;
    }
    if (options->max_wait_ms < 0 || options->advance_budget.max_ticks == 0 ||
        options->advance_budget.max_nodes == 0) {
        goto done;
    }
    if (options->advance_budget.max_ticks > VIREO_TIMER_WHEEL_ADVANCE_MAX_BUDGET ||
        options->advance_budget.max_nodes > VIREO_TIMER_WHEEL_ADVANCE_MAX_BUDGET) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }

    diagnostic.stage = VIREO_TIMER_LOOP_STAGE_CHECK_WHEEL;
    vireo_timer_wheel_registry_info_t registry;
    result = vireo_timer_wheel_registry_inspect(wheel, &registry);
    if (result != VIREO_OK) {
        goto done;
    }
    if (!registry.prepared) {
        result = VIREO_RESULT_NOT_FOUND;
        goto done;
    }
    vireo_timer_wheel_shutdown_info_t shutdown;
    result = vireo_timer_wheel_shutdown_inspect(wheel, &shutdown);
    if (result != VIREO_OK) {
        goto done;
    }
    if (shutdown.stopping) {
        result = VIREO_RESULT_CANCELLED;
        goto done;
    }

    /* 只有末端成功才发布；晚失败保留诊断，而非回滚已完成的网络动作。 */
    vireo_timer_loop_run_report_t report;
    diagnostic.stage = VIREO_TIMER_LOOP_STAGE_CLOCK_BEFORE;
    result = runtime->monotonic_now(&report.before_now_ns, &diagnostic.clock_error,
                                    runtime->context);
    if (result != VIREO_OK) {
        goto done;
    }
    diagnostic.stage = VIREO_TIMER_LOOP_STAGE_PLAN_WAIT;
    result = vireo_timer_loop_plan_wait(wheel, report.before_now_ns, options->max_wait_ms,
                                        &report.wait_plan);
    if (result != VIREO_OK) {
        goto done;
    }
    diagnostic.stage = VIREO_TIMER_LOOP_STAGE_RUN_LOOP;
    result = runtime->run_loop(loop, report.wait_plan.timeout_ms, &report.loop,
                              &diagnostic.loop_error, runtime->context);
    if (result != VIREO_OK) {
        goto done;
    }
    diagnostic.loop_completed = true;
    diagnostic.stage = VIREO_TIMER_LOOP_STAGE_CLOCK_AFTER;
    result = runtime->monotonic_now(&report.after_now_ns, &diagnostic.clock_error,
                                    runtime->context);
    if (result != VIREO_OK) {
        goto done;
    }
    diagnostic.stage = VIREO_TIMER_LOOP_STAGE_ADVANCE;
    result = vireo_timer_wheel_advance(wheel, report.after_now_ns, options->advance_budget,
                                      &report.advance);
    if (result != VIREO_OK) {
        goto done;
    }
    *out_report = report;
    diagnostic.stage = VIREO_TIMER_LOOP_STAGE_NONE;
done:
    if (out_diagnostic != NULL) {
        *out_diagnostic = diagnostic;
    }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_timer_loop_run_once(vireo_event_loop_t *loop,
                                       vireo_timer_wheel_t *wheel,
                                       vireo_timer_loop_run_options_t const *options,
                                       vireo_timer_loop_run_report_t *out_report,
                                       vireo_timer_loop_diagnostic_t *out_diagnostic)
{
    static vireo_timer_loop_runtime_t const native = {
        .monotonic_now = monotonic_native, .run_loop = loop_native, .context = NULL
    };
    return vireo_timer_loop_run_once_runtime(loop, wheel, options, out_report,
                                             out_diagnostic, &native);
}

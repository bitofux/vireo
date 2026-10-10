/*
 * PROJECT : VIREO
 * FILE    : client_deadline_serve.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 公开双采样、等待规划、有限服务及有界推进
 * -- 只依赖已采用公开合同，保持资源、输出与 errno 的既有边界
 */
#include <errno.h>
#include <vireo/timer/wheel_shutdown.h>
#include "client_deadline_serve_internal.h"

/**
 * @brief
 *     只做一次公开原生 CLOCK_MONOTONIC 采样。
 *
 * @param[out] now
 *     本层提供的非空独立纳秒输出；失败沿 clock 合同保持。
 * @param[out] error
 *     本层提供的非空独立 clock 诊断，每路径发布。
 * @param[in,out] context
 *     生产传 NULL；适配忽略且不保存。
 *
 * @return
 *     公开 clock 原分类，不修正、回退或重试。
 *
 * @note
 *     地址只借到返回；errno 沿公开合同，由编排外层最终恢复。
 */
static vireo_result_t sample_native(vireo_monotonic_ns_t *now, vireo_clock_error_t *error,
                                    void *context) {
    (void)context;
    return vireo_clock_monotonic_now(now, error);
}

vireo_result_t vireo_client_deadline_serve_once_runtime(
    vireo_tcp_server_t *server, vireo_timer_wheel_t *wheel,
    vireo_tcp_server_serve_options_t const *options,
    vireo_timer_wheel_advance_budget_t advance_budget, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_turn_result_t *out_turns, size_t turn_capacity,
    vireo_connection_pool_lease_t *out_clients, size_t client_capacity,
    vireo_client_deadline_serve_report_t *out_report,
    vireo_client_deadline_serve_runtime_t const *runtime) {
    int const saved_errno = errno;
    vireo_client_deadline_serve_report_t report = {0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (server == NULL || wheel == NULL || options == NULL || wire_workspace == NULL ||
        handler == NULL || out_turns == NULL || out_clients == NULL || out_report == NULL ||
        runtime == NULL || runtime->monotonic_now == NULL) {
        goto done;
    }
    vireo_tcp_server_serve_options_t service_options = *options;
    if (service_options.timeout_ms < 0 || advance_budget.max_ticks == 0 ||
        advance_budget.max_nodes == 0) {
        goto done;
    }
    if (advance_budget.max_ticks > VIREO_TIMER_WHEEL_ADVANCE_MAX_BUDGET ||
        advance_budget.max_nodes > VIREO_TIMER_WHEEL_ADVANCE_MAX_BUDGET) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }

    report.stage = VIREO_CLIENT_DEADLINE_SERVE_CHECK_WHEEL;
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

    report.stage = VIREO_CLIENT_DEADLINE_SERVE_CLOCK_BEFORE;
    result = runtime->monotonic_now(&report.before_now_ns, &report.clock_error, runtime->context);
    if (result != VIREO_OK) {
        goto done;
    }
    report.stage = VIREO_CLIENT_DEADLINE_SERVE_PLAN_WAIT;
    result = vireo_timer_loop_plan_wait(wheel, report.before_now_ns, service_options.timeout_ms,
                                        &report.wait_plan);
    if (result != VIREO_OK) {
        goto done;
    }
    service_options.timeout_ms = report.wait_plan.timeout_ms;
    report.stage = VIREO_CLIENT_DEADLINE_SERVE_SERVICE;
    report.serve_called = true;
    /* 原依赖直接写局部报告，晚失败真实前缀不会因编排失败丢失。 */
    result = vireo_tcp_server_serve_once(
        server, &service_options, wire_workspace, workspace_capacity, handler, context, out_turns,
        turn_capacity, out_clients, client_capacity, &report.serve_info, &report.serve_error);
    if (result != VIREO_OK) {
        goto done;
    }
    report.serve_completed = true;
    report.stage = VIREO_CLIENT_DEADLINE_SERVE_CLOCK_AFTER;
    result = runtime->monotonic_now(&report.after_now_ns, &report.clock_error, runtime->context);
    if (result != VIREO_OK) {
        goto done;
    }
    report.stage = VIREO_CLIENT_DEADLINE_SERVE_ADVANCE;
    result = vireo_timer_wheel_advance(wheel, report.after_now_ns, advance_budget, &report.advance);
    if (result == VIREO_OK) {
        report.stage = VIREO_CLIENT_DEADLINE_SERVE_NONE;
    }
done:
    if (out_report != NULL) {
        *out_report = report;
    }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_client_deadline_serve_once(
    vireo_tcp_server_t *server, vireo_timer_wheel_t *wheel,
    vireo_tcp_server_serve_options_t const *options,
    vireo_timer_wheel_advance_budget_t advance_budget, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_turn_result_t *out_turns, size_t turn_capacity,
    vireo_connection_pool_lease_t *out_clients, size_t client_capacity,
    vireo_client_deadline_serve_report_t *out_report) {
    static vireo_client_deadline_serve_runtime_t const native = {.monotonic_now = sample_native,
                                                                 .context = NULL};
    return vireo_client_deadline_serve_once_runtime(
        server, wheel, options, advance_budget, wire_workspace, workspace_capacity, handler,
        context, out_turns, turn_capacity, out_clients, client_capacity, out_report, &native);
}

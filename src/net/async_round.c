/*
 * PROJECT : VIREO
 * FILE    : async_round.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 冻结批次、真实逐项报告和失败后缀交还
 */
#include "async_round_internal.h"
#include <errno.h>

/** 公开机械poll，不借出loop或处理业务。 */
static vireo_result_t poll_ready(void *ctx, vireo_tcp_server_t *s, int timeout, size_t max,
    vireo_tcp_server_ready_client_t *ready, size_t capacity, vireo_tcp_server_poll_report_t *r) {
    (void)ctx; return vireo_tcp_server_poll_ready_once(s, timeout, max, ready, capacity, r);
}
/** 公开单项driver，不在轮次重复提交或补业务。 */
static vireo_result_t drive(void *ctx, vireo_tcp_server_t *s, vireo_connection_pool_lease_t c,
    vireo_inflight_store_t *store, vireo_thread_pool_t *pool, vireo_async_client_drive_options_t const *o,
    vireo_async_client_drive_budget_t const *b, vireo_task_cancel_t *cancel,
    vireo_async_request_pending_t *pending, vireo_task_t **owner, vireo_async_client_drive_report_t *r) {
    (void)ctx; return vireo_async_client_drive_once(s, c, store, pool, o, b, cancel, pending, owner, r);
}
/** 公开一次缓存排尾，成功才计已重新排入。 */
static vireo_result_t schedule(void *ctx, vireo_tcp_server_t *s, vireo_connection_pool_lease_t c,
    vireo_tcp_server_client_error_t *e) {
    (void)ctx; return vireo_tcp_server_schedule_client(s, c, e);
}
static vireo_async_round_ops_t const default_ops = {poll_ready, drive, schedule};

/** 完整边界表验证；不做资源操作。 */
static bool valid_ops(vireo_async_round_ops_t const *o) {
    return o != NULL && o->poll != NULL && o->drive != NULL && o->schedule != NULL;
}
/** 发布真实局部进度，OK归NONE，恢复入口errno。 */
static vireo_result_t finish(vireo_result_t result, vireo_async_round_report_t value,
    vireo_async_round_report_t *out, int saved) {
    if (result == VIREO_OK) value.stage = VIREO_ASYNC_ROUND_NONE;
    if (out != NULL) *out = value;
    errno = saved; return result;
}

vireo_result_t vireo_async_round_with_ops(vireo_tcp_server_t *server, vireo_inflight_store_t *store,
    vireo_thread_pool_t *pool, int timeout, size_t max, vireo_async_round_configure_fn configure, void *context,
    vireo_tcp_server_ready_client_t *ready, size_t ready_capacity, vireo_async_round_turn_t *turns,
    size_t turn_capacity, vireo_task_t **owner, vireo_async_round_report_t *out,
    vireo_async_round_ops_t const *ops, void *ops_context) {
    int const saved = errno; vireo_async_round_report_t value = {0};
    if (server == NULL || store == NULL || pool == NULL || configure == NULL || ready == NULL || turns == NULL ||
        owner == NULL || out == NULL || timeout < 0 || max == 0 || ready_capacity == 0 || turn_capacity == 0 ||
        !valid_ops(ops) || *owner != NULL) return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
    if (max > (size_t)65535 || ready_capacity > (size_t)65535 || turn_capacity > (size_t)65535)
        return finish(VIREO_RESULT_RANGE, value, out, saved);
    value.effective_max_clients = max;
    if (ready_capacity < value.effective_max_clients) value.effective_max_clients = ready_capacity;
    if (turn_capacity < value.effective_max_clients) value.effective_max_clients = turn_capacity;
    value.stage = VIREO_ASYNC_ROUND_POLL; value.poll_called = true;
    vireo_result_t result = ops->poll(ops_context, server, timeout, value.effective_max_clients,
        ready, ready_capacity, &value.poll_report);
    value.poll_result = result;
    if (result != VIREO_OK) return finish(result, value, out, saved);
    for (size_t i = 0; i < value.poll_report.selected_count; ++i) {
        vireo_async_round_turn_t turn = {0}; vireo_async_round_config_t config = {0};
        turn.client = ready[i]; turn.configure_called = true;
        value.stage = VIREO_ASYNC_ROUND_CONFIGURE;
        result = configure(context, turn.client, &config); turn.configure_result = result;
        ++value.turn_count; value.unprocessed_begin = value.turn_count;
        if (result == VIREO_OK) {
            value.stage = VIREO_ASYNC_ROUND_DRIVE; turn.drive_called = true; ++value.drive_calls;
            result = ops->drive(ops_context, server, turn.client.client, store, pool, &config.options,
                &config.budget, config.cancel, config.pending, owner, &turn.drive_report);
            turn.drive_result = result;
            if (result == VIREO_OK && turn.drive_report.needs_reschedule) {
                value.stage = VIREO_ASYNC_ROUND_SCHEDULE; turn.schedule_called = true;
                result = ops->schedule(ops_context, server, turn.client.client, &turn.schedule_error);
                turn.schedule_result = result;
                if (result == VIREO_OK) ++value.requeued_count;
            }
        }
        turns[i] = turn;
        if (result != VIREO_OK) return finish(result, value, out, saved);
    }
    return finish(VIREO_OK, value, out, saved);
}

vireo_result_t vireo_async_round_once(vireo_tcp_server_t *server, vireo_inflight_store_t *store,
    vireo_thread_pool_t *pool, int timeout, size_t max, vireo_async_round_configure_fn configure, void *context,
    vireo_tcp_server_ready_client_t *ready, size_t ready_capacity, vireo_async_round_turn_t *turns,
    size_t turn_capacity, vireo_task_t **owner, vireo_async_round_report_t *report) {
    return vireo_async_round_with_ops(server, store, pool, timeout, max, configure, context,
        ready, ready_capacity, turns, turn_capacity, owner, report, &default_ops, NULL);
}

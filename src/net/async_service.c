/*
 * PROJECT : VIREO
 * FILE    : async_service.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 固定有界单轮、完整前缀与主次错误
 */
#include "async_service_internal.h"
#include <vireo/base/checked.h>
#include <errno.h>

/** 以下薄适配只调用对应公开入口，不访问任何外模块布局。 */
static vireo_result_t pressure(void *ctx, vireo_tcp_server_t *s, vireo_connection_options_t const *o,
    vireo_async_admission_pressure_report_t *r) {
    (void)ctx; return vireo_async_admission_pressure_refresh(s, o, r);
}
static vireo_result_t poll_ready(void *ctx, vireo_tcp_server_t *s, int timeout, size_t max,
    vireo_tcp_server_ready_client_t *ready, size_t capacity, vireo_tcp_server_listener_poll_report_t *r) {
    (void)ctx; return vireo_tcp_server_poll_with_listener_once(s, timeout, max, ready, capacity, r);
}
static vireo_result_t dispatch(void *ctx, vireo_tcp_server_t *s, vireo_event_loop_handle_t h,
    vireo_notifier_t *n, vireo_inflight_store_t *store, vireo_completion_queue_t *q, size_t max,
    size_t frame, size_t batch, uint8_t *scratch, size_t capacity, vireo_completion_response_resolve_fn resolve,
    void *context, vireo_completion_t **owner, vireo_completion_response_dispatch_report_t *r) {
    (void)ctx; return vireo_completion_response_dispatch_ready(s, h, n, store, q, max, frame, batch,
        scratch, capacity, resolve, context, owner, r);
}
static vireo_result_t drive(void *ctx, vireo_tcp_server_t *s, vireo_connection_pool_lease_t c,
    vireo_inflight_store_t *store, vireo_thread_pool_t *pool, vireo_async_client_drive_options_t const *o,
    vireo_async_client_drive_budget_t const *b, vireo_task_cancel_t *cancel,
    vireo_async_request_pending_t *pending, vireo_task_t **owner, vireo_async_client_drive_report_t *r) {
    (void)ctx; return vireo_async_client_drive_once(s, c, store, pool, o, b, cancel, pending, owner, r);
}
static vireo_result_t schedule(void *ctx, vireo_tcp_server_t *s, vireo_connection_pool_lease_t c,
    vireo_tcp_server_client_error_t *e) {
    (void)ctx; return vireo_tcp_server_schedule_client(s, c, e);
}
static vireo_result_t admit(void *ctx, vireo_tcp_server_t *s, vireo_connection_options_t const *c,
    vireo_connection_flow_options_t const *f, vireo_tcp_server_admit_budget_t const *b,
    vireo_connection_pool_lease_t *clients, size_t capacity, vireo_async_admission_turn_t *turns,
    size_t turn_capacity, vireo_async_admission_report_t *r) {
    (void)ctx; return vireo_async_admission_once(s, c, f, b, clients, capacity, turns, turn_capacity, r);
}
static vireo_async_service_ops_t const default_ops = {pressure, poll_ready, dispatch, drive, schedule, admit};

/** 只验证本层完整表，未触碰资源。 */
static bool valid_ops(vireo_async_service_ops_t const *o) {
    return o != NULL && o->pressure != NULL && o->poll != NULL && o->dispatch != NULL &&
        o->drive != NULL && o->schedule != NULL && o->admit != NULL;
}
/** 只比较逻辑字段，不读padding；0不是有效租约。 */
static bool empty_lease(vireo_connection_pool_lease_t c) {
    return c.pool_id == 0 && c.slot_index == 0 && c.generation == 0;
}
/** 两个正size_t的较小值，预算不会相加或乘大。 */
static size_t minimum(size_t a, size_t b) { return a < b ? a : b; }

/** 公开数值合同的纯值前置检查，不包含资源当前性或其他核心私有验证器。 */
static vireo_result_t validate_values(vireo_async_service_options_t const *o,
    vireo_async_service_workspace_t const *w) {
    vireo_connection_options_t const c = o->connection;
    vireo_connection_flow_options_t const f = o->flow;
    size_t pair = 0;
    vireo_result_t const result = vireo_checked_size_add(c.read_capacity, c.write_capacity, &pair);
    if (result != VIREO_OK) return result;
    if (c.read_capacity == 0 || c.write_capacity == 0 || c.max_buffer_bytes == 0 ||
        c.read_capacity > VIREO_BUFFER_MAX_CAPACITY || c.write_capacity > VIREO_BUFFER_MAX_CAPACITY ||
        c.max_buffer_bytes > VIREO_CONNECTION_MAX_BUFFER_BYTES || pair > c.max_buffer_bytes)
        return VIREO_RESULT_RANGE;
    if (f.max_frame_bytes < (size_t)VIREO_PROTOCOL_HEADER_SIZE ||
        f.max_frame_bytes > (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE + (size_t)VIREO_PROTOCOL_HEADER_SIZE ||
        f.max_frame_bytes > c.read_capacity || f.read_low < f.max_frame_bytes - 1 ||
        f.read_low >= f.read_high || f.read_high > c.read_capacity ||
        f.write_low >= f.write_high || f.write_high > c.write_capacity)
        return VIREO_RESULT_RANGE;
    if (o->max_completion_items > VIREO_INFLIGHT_COMPLETION_DRAIN_MAX_ITEMS ||
        o->max_response_frame_bytes < (size_t)VIREO_PROTOCOL_HEADER_SIZE ||
        o->max_response_frame_bytes > VIREO_COMPLETION_RESPONSE_MAX_FRAME_BYTES ||
        o->max_response_batch_bytes > VIREO_COMPLETION_RESPONSE_DISPATCH_MAX_BATCH_BYTES ||
        o->max_response_batch_bytes < o->max_response_frame_bytes ||
        w->response_capacity < o->max_response_frame_bytes) return VIREO_RESULT_RANGE;
    return VIREO_OK;
}
/** 完整发布真实局部报告，成功归NONE；不操作owner或清理资源。 */
static vireo_result_t finish(vireo_result_t result, vireo_async_service_report_t value,
    vireo_async_service_report_t *out, int saved) {
    if (result == VIREO_OK) value.stage = VIREO_ASYNC_SERVICE_NONE;
    if (out != NULL) *out = value;
    errno = saved; return result;
}

vireo_result_t vireo_async_service_with_ops(vireo_tcp_server_t *server, vireo_inflight_store_t *store,
    vireo_thread_pool_t *pool, vireo_notifier_t *notifier, vireo_completion_queue_t *queue,
    vireo_event_loop_handle_t expected, vireo_async_service_options_t const *options,
    vireo_async_service_workspace_t const *workspace, vireo_async_round_configure_fn configure,
    void *configure_context, vireo_completion_response_resolve_fn resolve, void *resolve_context,
    vireo_task_t **task_owner, vireo_completion_t **completion_owner, vireo_async_service_report_t *out,
    vireo_async_service_ops_t const *ops, void *ops_context) {
    int const saved = errno;
    vireo_async_service_report_t value = {0};
    if (server == NULL || store == NULL || pool == NULL || notifier == NULL || queue == NULL ||
        options == NULL || workspace == NULL || configure == NULL || resolve == NULL || task_owner == NULL ||
        completion_owner == NULL || out == NULL || !valid_ops(ops))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
    vireo_async_service_options_t const o = *options;
    vireo_async_service_workspace_t const w = *workspace;
    if (*task_owner != NULL || *completion_owner != NULL || o.timeout_ms < 0 || o.max_clients == 0 ||
        o.admit.max_accepts == 0 || o.admit.max_accept_syscalls == 0 || o.max_completion_items == 0 ||
        o.max_response_batch_bytes == 0 || w.ready == NULL || w.turns == NULL || w.clients == NULL ||
        w.admission_turns == NULL || w.response_bytes == NULL || w.ready_capacity == 0 || w.turn_capacity == 0 ||
        w.client_capacity == 0 || w.admission_turn_capacity == 0)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
    if (o.max_clients > VIREO_TCP_SERVER_MAX_CONNECTIONS || o.admit.max_accepts > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        w.ready_capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS || w.turn_capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        w.client_capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS || w.admission_turn_capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS)
        return finish(VIREO_RESULT_RANGE, value, out, saved);
    size_t const new_max = minimum(o.admit.max_accepts, minimum(w.client_capacity, w.admission_turn_capacity));
    for (size_t i = 0; i < new_max; ++i)
        if (!empty_lease(w.clients[i])) return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
    value.stage = VIREO_ASYNC_SERVICE_VALIDATE;
    vireo_result_t result = validate_values(&o, &w);
    if (result != VIREO_OK) return finish(result, value, out, saved);
    if (expected.loop_id == 0 && expected.token == 0) return finish(VIREO_RESULT_NOT_FOUND, value, out, saved);
    if (expected.loop_id == 0 || expected.token == 0) return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
    value.clients.effective_max_clients = minimum(o.max_clients, minimum(w.ready_capacity, w.turn_capacity));
    value.stage = VIREO_ASYNC_SERVICE_PRE_PRESSURE; value.pre_pressure_called = true;
    result = ops->pressure(ops_context, server, &o.connection, &value.pre_pressure_report);
    if (result != VIREO_OK) return finish(result, value, out, saved);
    value.stage = VIREO_ASYNC_SERVICE_POLL; value.poll_called = true;
    value.clients.poll_called = true; value.clients.stage = VIREO_ASYNC_ROUND_POLL;
    result = ops->poll(ops_context, server, o.timeout_ms, value.clients.effective_max_clients,
        w.ready, w.ready_capacity, &value.poll_report);
    value.clients.poll_result = result; value.clients.poll_report = value.poll_report.poll;
    if (result != VIREO_OK) goto post;
    value.clients.stage = VIREO_ASYNC_ROUND_NONE;
    if (value.poll_report.poll.stopped) { result = VIREO_RESULT_CANCELLED; goto post; }
    value.stage = VIREO_ASYNC_SERVICE_LISTENER_EVENT;
    uint32_t const events = value.poll_report.listener_events;
    if ((events & (VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP)) != 0) { result = VIREO_RESULT_IO; goto post; }
    if ((events & ~(uint32_t)(VIREO_EPOLL_EVENT_READ | VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP)) != 0) {
        result = VIREO_RESULT_INTERNAL; goto post;
    }
    value.stage = VIREO_ASYNC_SERVICE_DISPATCH; value.dispatch_called = true;
    result = ops->dispatch(ops_context, server, expected, notifier, store, queue, o.max_completion_items,
        o.max_response_frame_bytes, o.max_response_batch_bytes, w.response_bytes, w.response_capacity,
        resolve, resolve_context, completion_owner, &value.dispatch_report);
    if (result != VIREO_OK) goto post;
    value.stage = VIREO_ASYNC_SERVICE_CLIENTS;
    for (size_t i = 0; i < value.poll_report.poll.selected_count; ++i) {
        vireo_async_round_turn_t turn = {0}; vireo_async_round_config_t config = {0};
        turn.client = w.ready[i]; turn.configure_called = true;
        value.clients.stage = VIREO_ASYNC_ROUND_CONFIGURE;
        result = configure(configure_context, turn.client, &config); turn.configure_result = result;
        ++value.clients.turn_count; value.clients.unprocessed_begin = value.clients.turn_count;
        if (result == VIREO_OK) {
            value.clients.stage = VIREO_ASYNC_ROUND_DRIVE; turn.drive_called = true; ++value.clients.drive_calls;
            result = ops->drive(ops_context, server, turn.client.client, store, pool, &config.options,
                &config.budget, config.cancel, config.pending, task_owner, &turn.drive_report);
            turn.drive_result = result;
            if (result == VIREO_OK && turn.drive_report.needs_reschedule) {
                value.clients.stage = VIREO_ASYNC_ROUND_SCHEDULE; turn.schedule_called = true;
                result = ops->schedule(ops_context, server, turn.client.client, &turn.schedule_error);
                turn.schedule_result = result;
                if (result == VIREO_OK) ++value.clients.requeued_count;
            }
        }
        w.turns[i] = turn;
        if (result != VIREO_OK) goto post;
    }
    value.clients.stage = VIREO_ASYNC_ROUND_NONE;
    if ((events & VIREO_EPOLL_EVENT_READ) != 0) {
        value.stage = VIREO_ASYNC_SERVICE_ADMIT; value.admission_called = true;
        result = ops->admit(ops_context, server, &o.connection, &o.flow, &o.admit,
            w.clients, w.client_capacity, w.admission_turns, w.admission_turn_capacity, &value.admission_report);
    }
post:
    value.post_pressure_called = true;
    value.post_pressure_result = ops->pressure(ops_context, server, &o.connection, &value.post_pressure_report);
    if (result == VIREO_OK && value.post_pressure_result != VIREO_OK) {
        value.stage = VIREO_ASYNC_SERVICE_POST_PRESSURE; result = value.post_pressure_result;
    }
    return finish(result, value, out, saved);
}

vireo_result_t vireo_async_service_once(vireo_tcp_server_t *server, vireo_inflight_store_t *store,
    vireo_thread_pool_t *pool, vireo_notifier_t *notifier, vireo_completion_queue_t *queue,
    vireo_event_loop_handle_t expected, vireo_async_service_options_t const *options,
    vireo_async_service_workspace_t const *workspace, vireo_async_round_configure_fn configure,
    void *configure_context, vireo_completion_response_resolve_fn resolve, void *resolve_context,
    vireo_task_t **task_owner, vireo_completion_t **completion_owner, vireo_async_service_report_t *report) {
    return vireo_async_service_with_ops(server, store, pool, notifier, queue, expected, options, workspace,
        configure, configure_context, resolve, resolve_context, task_owner, completion_owner, report, &default_ops, NULL);
}

/*
 * PROJECT : VIREO
 * FILE    : async_client_drive.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 仅公开边界组合、单首帧移交和错误后的独立末同步
 */
#include "async_client_drive_internal.h"
#include <errno.h>

/** 原公开只读server观察，context不持有资源。 */
static vireo_result_t server_inspect(void *ctx, vireo_tcp_server_t const *s, vireo_tcp_server_info_t *i) {
    (void)ctx; return vireo_tcp_server_inspect(s, i);
}
/** 原公开客户观察，完整租约核验由server负责。 */
static vireo_result_t client_inspect(void *ctx, vireo_tcp_server_t const *s, vireo_connection_pool_lease_t c,
    vireo_tcp_server_client_info_t *i) {
    (void)ctx; return vireo_tcp_server_client_inspect(s, c, i);
}
/** 原公开一次flow同步，不在此层重试。 */
static vireo_result_t refresh(void *ctx, vireo_tcp_server_t *s, vireo_connection_pool_lease_t c,
    vireo_tcp_server_client_error_t *e) {
    (void)ctx; return vireo_tcp_server_client_flow_refresh(s, c, e);
}
/** 原公开接收预算，不访问connection owner。 */
static vireo_result_t receive(void *ctx, vireo_tcp_server_t *s, vireo_connection_pool_lease_t c,
    vireo_connection_receive_budget_t const *b, vireo_connection_receive_info_t *i, vireo_tcp_server_client_error_t *e) {
    (void)ctx; return vireo_tcp_server_client_receive(s, c, b, i, e);
}
/** 原公开首帧短借；此层只保存header值。 */
static vireo_result_t frames(void *ctx, vireo_tcp_server_t const *s, vireo_connection_pool_lease_t c,
    vireo_connection_frame_options_t const *o, vireo_connection_frame_budget_t const *b,
    vireo_connection_frame_view_t *v, size_t n, vireo_connection_frame_info_t *i, vireo_tcp_server_client_error_t *e) {
    (void)ctx; return vireo_tcp_server_client_frames_peek(s, c, o, b, v, n, i, e);
}
/** 原031唯一提交/消费，不绕过pending和真实转移判断。 */
static vireo_result_t head(void *ctx, vireo_tcp_server_t *s, vireo_connection_pool_lease_t c,
    vireo_inflight_store_t *store, vireo_thread_pool_t *pool, size_t cap, size_t allocation, size_t limit,
    uint32_t operation, uint64_t deadline, vireo_task_cancel_t *cancel, vireo_async_request_pending_t *pending,
    vireo_task_t **owner, vireo_async_request_head_report_t *report) {
    (void)ctx; return vireo_async_request_submit_read_head(s, c, store, pool, cap, allocation,
        limit, operation, deadline, cancel, pending, owner, report);
}
/** 原公开发送旧FIFO，不等待本次worker。 */
static vireo_result_t send_bytes(void *ctx, vireo_tcp_server_t *s, vireo_connection_pool_lease_t c,
    vireo_connection_send_budget_t const *b, vireo_connection_send_info_t *i, vireo_tcp_server_client_error_t *e) {
    (void)ctx; return vireo_tcp_server_client_send(s, c, b, i, e);
}
static vireo_async_client_drive_ops_t const default_ops = {
    server_inspect, client_inspect, refresh, receive, frames, head, send_bytes
};

/** 完整稳定七边界表，缺项不执行任何资源操作。 */
static bool valid_ops(vireo_async_client_drive_ops_t const *o) {
    return o != NULL && o->server_inspect != NULL && o->client_inspect != NULL && o->refresh != NULL &&
        o->receive != NULL && o->frames != NULL && o->head != NULL && o->send != NULL;
}
/** 只用公开metadata合同检验caller gate，不核验活跃性或消费源。 */
static vireo_result_t pending_shape(vireo_async_request_pending_t const *p, bool *empty) {
    vireo_task_metadata_t const m = p->metadata;
    *empty = p->frame_bytes == 0 && m.route.client_owner_id == 0 && m.route.client_slot_index == 0 &&
        m.route.client_generation == 0 && m.route.request_sequence == 0 && m.request_instance_id == 0 &&
        m.operation == 0 && m.deadline_ns == 0;
    if (*empty) return VIREO_OK;
    if (p->frame_bytes < (size_t)VIREO_PROTOCOL_HEADER_SIZE || p->frame_bytes > VIREO_ASYNC_REQUEST_MAX_FRAME_BYTES)
        return VIREO_RESULT_INVALID_ARGUMENT;
    vireo_task_metadata_t checked;
    return vireo_task_metadata_make(m.route, m.request_instance_id, m.operation, m.deadline_ns, &checked);
}
/** 一致发布完整局部报告、恢复入口errno，不销毁/重放或退款。 */
static vireo_result_t finish(vireo_result_t result, vireo_async_client_drive_report_t value,
    vireo_async_client_drive_report_t *report, int saved) {
    if (result == VIREO_OK) value.stage = VIREO_ASYNC_CLIENT_DRIVE_NONE;
    if (report != NULL) *report = value;
    errno = saved; return result;
}

vireo_result_t vireo_async_client_drive_with_ops(vireo_tcp_server_t *server, vireo_connection_pool_lease_t client,
    vireo_inflight_store_t *store, vireo_thread_pool_t *pool, vireo_async_client_drive_options_t const *options,
    vireo_async_client_drive_budget_t const *budget, vireo_task_cancel_t *cancel, vireo_async_request_pending_t *pending,
    vireo_task_t **owner, vireo_async_client_drive_report_t *report, vireo_async_client_drive_ops_t const *ops, void *context) {
    int const saved = errno; vireo_async_client_drive_report_t value = {0};
    if (server == NULL || store == NULL || pool == NULL || options == NULL || budget == NULL ||
        pending == NULL || owner == NULL || report == NULL || !valid_ops(ops) || *owner != NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, value, report, saved);
    vireo_async_client_drive_options_t const o = *options;
    vireo_async_client_drive_budget_t const b = *budget;
    if (o.task_allocation_budget == 0 || o.max_client_requests == 0 || o.operation == 0 ||
        b.receive.max_bytes == 0 || b.receive.max_syscalls == 0 || b.send.max_bytes == 0 || b.send.max_syscalls == 0)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, value, report, saved);
    if (o.max_frame_bytes < (size_t)VIREO_PROTOCOL_HEADER_SIZE || o.max_frame_bytes > VIREO_ASYNC_REQUEST_MAX_FRAME_BYTES ||
        o.task_allocation_budget > (size_t)67108864)
        return finish(VIREO_RESULT_RANGE, value, report, saved);
    value.stage = VIREO_ASYNC_CLIENT_DRIVE_CHECK_PENDING;
    bool empty = false; vireo_result_t result = pending_shape(pending, &empty);
    if (result != VIREO_OK) return finish(result, value, report, saved);
    if (!empty) { value.pending_retained = true; return finish(VIREO_RESULT_BUSY, value, report, saved); }
    value.stage = VIREO_ASYNC_CLIENT_DRIVE_CHECK_SERVER;
    vireo_tcp_server_info_t root = {0}; result = ops->server_inspect(context, server, &root);
    if (result != VIREO_OK) return finish(result, value, report, saved);
    if (root.processing_active || root.driving_active || root.scheduling_active || root.serving_active ||
        root.shutdown_active || root.closing_active) return finish(VIREO_RESULT_BUSY, value, report, saved);
    if (root.stop_requested) return finish(VIREO_RESULT_CANCELLED, value, report, saved);
    value.stage = VIREO_ASYNC_CLIENT_DRIVE_CHECK_CLIENT;
    vireo_tcp_server_client_info_t current = {0};
    result = ops->client_inspect(context, server, client, &current);
    if (result != VIREO_OK) return finish(result, value, report, saved);
    if (current.connection_info.close_state != VIREO_CONNECTION_CLOSE_OPEN)
        return finish(VIREO_RESULT_BUSY, value, report, saved);
    if (!current.connection_info.loop_attached || !current.connection_info.flow_enabled)
        return finish(VIREO_RESULT_NOT_FOUND, value, report, saved);
    if (o.max_frame_bytes > current.connection_info.read_buffer.capacity ||
        o.max_frame_bytes > current.connection_info.flow_options.max_frame_bytes)
        return finish(VIREO_RESULT_RANGE, value, report, saved);
    value.stage = VIREO_ASYNC_CLIENT_DRIVE_PRE_REFRESH; value.pre_refresh_called = true;
    result = ops->refresh(context, server, client, &value.client_error);
    if (result != VIREO_OK) return finish(result, value, report, saved);
    value.stage = VIREO_ASYNC_CLIENT_DRIVE_CHECK_CLIENT;
    result = ops->client_inspect(context, server, client, &current);
    if (result != VIREO_OK) goto final_refresh;
    if (!current.connection_info.read_eof && !current.connection_info.read_pressure && !current.connection_info.write_pressure) {
        value.stage = VIREO_ASYNC_CLIENT_DRIVE_RECEIVE; value.receive_called = true;
        result = ops->receive(context, server, client, &b.receive, &value.receive, &value.client_error);
        if (result != VIREO_OK) goto final_refresh;
    }
    value.stage = VIREO_ASYNC_CLIENT_DRIVE_PEEK_FRAME; value.frame_peek_called = true;
    vireo_connection_frame_options_t const fo = {VIREO_CONNECTION_FRAME_REQUEST, o.max_frame_bytes};
    vireo_connection_frame_budget_t const fb = {1, o.max_frame_bytes};
    vireo_connection_frame_view_t view = {0};
    result = ops->frames(context, server, client, &fo, &fb, &view, 1, &value.frame_info, &value.client_error);
    if (result != VIREO_OK) goto final_refresh;
    if (value.frame_info.frame_count != 0) {
        if (value.frame_info.frame_count != 1 || view.wire_size < (size_t)VIREO_PROTOCOL_HEADER_SIZE ||
            view.wire_size > o.max_frame_bytes) { result = VIREO_RESULT_INTERNAL; goto final_refresh; }
        value.request_header = view.header; value.request_header_available = true;
        /* 只保存header数值，到此结束本层view/body使用，031自行借用后consume。 */
        value.stage = VIREO_ASYNC_CLIENT_DRIVE_SUBMIT; value.head_called = true;
        result = ops->head(context, server, client, store, pool, o.max_frame_bytes, o.task_allocation_budget,
            o.max_client_requests, o.operation, o.deadline_ns, cancel, pending, owner, &value.head_report);
        value.pending_retained = value.head_report.pending_retained;
        if (result != VIREO_OK) goto final_refresh;
    }
    value.stage = VIREO_ASYNC_CLIENT_DRIVE_SEND; value.send_called = true;
    result = ops->send(context, server, client, &b.send, &value.send, &value.client_error);
final_refresh:
    value.final_refresh_called = true;
    value.final_refresh_result = ops->refresh(context, server, client, &value.final_refresh_error);
    if (result == VIREO_OK && value.final_refresh_result != VIREO_OK) {
        result = value.final_refresh_result; value.stage = VIREO_ASYNC_CLIENT_DRIVE_FINAL_REFRESH;
        value.client_error = value.final_refresh_error;
    }
    if (result == VIREO_OK) {
        value.stage = VIREO_ASYNC_CLIENT_DRIVE_FINAL_INSPECT; value.final_inspect_called = true;
        result = ops->client_inspect(context, server, client, &current);
        if (result == VIREO_OK) value.needs_reschedule = value.head_called && value.head_report.submit_report.task_transferred &&
            value.head_report.consume_called && value.head_report.consume_result == VIREO_OK &&
            current.connection_info.read_buffer.readable_size != 0;
    }
    return finish(result, value, report, saved);
}

vireo_result_t vireo_async_client_drive_once(vireo_tcp_server_t *server, vireo_connection_pool_lease_t client,
    vireo_inflight_store_t *store, vireo_thread_pool_t *pool, vireo_async_client_drive_options_t const *options,
    vireo_async_client_drive_budget_t const *budget, vireo_task_cancel_t *cancel, vireo_async_request_pending_t *pending,
    vireo_task_t **remaining_task, vireo_async_client_drive_report_t *report) {
    return vireo_async_client_drive_with_ops(server, client, store, pool, options, budget, cancel,
        pending, remaining_task, report, &default_ops, NULL);
}

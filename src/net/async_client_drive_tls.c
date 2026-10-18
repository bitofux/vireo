/* TLS异步单客户组合；仅调用公开依赖。 */
#include "async_client_drive_tls_internal.h"
#include <errno.h>

static vireo_result_t io_inspect(void *c, vireo_tls_connection_t const *t, vireo_tls_io_info_t *i, vireo_tls_connection_error_t *e) {
    (void)c; return vireo_tls_connection_io_inspect(t,i,e);
}
static vireo_result_t flow(void *c, vireo_tls_connection_t *t, vireo_tls_io_flow_t *i, vireo_tls_connection_error_t *e) {
    (void)c; return vireo_tls_connection_flow_refresh(t,i,e);
}
static vireo_result_t receive(void *c, vireo_tls_connection_t *t, vireo_tls_io_budget_t const *b, vireo_tls_io_progress_t *i, vireo_tls_connection_error_t *e) {
    (void)c; return vireo_tls_connection_receive(t,b,i,e);
}
static vireo_result_t send_bytes(void *c, vireo_tls_connection_t *t, vireo_tls_io_budget_t const *b, vireo_tls_io_progress_t *i, vireo_tls_connection_error_t *e) {
    (void)c; return vireo_tls_connection_send(t,b,i,e);
}
static vireo_result_t sync_flow(void *c, vireo_tcp_server_t *s, vireo_connection_pool_lease_t l,
    vireo_tcp_server_tls_flow_info_t *i, vireo_tcp_server_tls_application_error_t *e) {
    (void)c; return vireo_tcp_server_client_tls_flow_refresh(s,l,i,e);
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
static vireo_async_client_drive_tls_ops_t const default_ops = {
    io_inspect, flow, receive, send_bytes, frames, head, sync_flow
};
static bool valid_ops(vireo_async_client_drive_tls_ops_t const *o) {
    return o && o->io_inspect && o->flow && o->receive && o->send && o->frames && o->head && o->sync;
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
static vireo_result_t finish(vireo_result_t result, vireo_async_client_drive_tls_report_t value,
    vireo_async_client_drive_tls_report_t *report, int saved) {
    if (result == VIREO_OK) value.stage = VIREO_ASYNC_CLIENT_DRIVE_TLS_NONE;
    if (report != NULL) *report = value;
    errno = saved; return result;
}

/** 原native前拒绝可能保持输出；非法哨兵不对外传播，合法报告必须满足原预算。 */
static vireo_result_t io_report(vireo_tls_io_progress_t *p, vireo_tls_io_budget_t const *b,
    bool *reported, vireo_result_t result) {
    if (p->stop_reason == (vireo_tls_io_stop_t)-1) {
        *p = (vireo_tls_io_progress_t){0};
        return result == VIREO_OK ? VIREO_RESULT_INTERNAL : result;
    }
    *reported = true;
    if (p->stop_reason < VIREO_TLS_IO_STOP_WOULD_BLOCK || p->stop_reason > VIREO_TLS_IO_STOP_FLOW_PAUSED ||
        p->wait < VIREO_TLS_IO_WAIT_NONE || p->wait > VIREO_TLS_IO_WAIT_WRITE ||
        p->bytes > b->max_bytes || p->native_calls > b->max_native_calls) {
        *p = (vireo_tls_io_progress_t){0}; *reported = false; return VIREO_RESULT_INTERNAL;
    }
    return result;
}
static size_t minimum_budget(size_t capacity) {
    return capacity < VIREO_TLS_IO_SCRATCH_BYTES ? capacity : VIREO_TLS_IO_SCRATCH_BYTES;
}

vireo_result_t vireo_async_client_drive_tls_with_ops(vireo_tcp_server_t *server, vireo_connection_pool_lease_t client,
    vireo_inflight_store_t *store, vireo_thread_pool_t *pool, vireo_async_client_drive_options_t const *options,
    vireo_async_client_drive_tls_budget_t const *budget, vireo_task_cancel_t *cancel, vireo_async_request_pending_t *pending,
    vireo_task_t **owner, vireo_async_client_drive_tls_report_t *report,
    vireo_async_client_drive_tls_ops_t const *ops, void *context) {
    int const saved = errno; vireo_async_client_drive_tls_report_t value = {0};
    if (!server || !store || !pool || !options || !budget || !pending || !owner || !report ||
        !valid_ops(ops) || *owner != NULL) return finish(VIREO_RESULT_INVALID_ARGUMENT,value,report,saved);
    vireo_async_client_drive_options_t const o = *options;
    vireo_async_client_drive_tls_budget_t const b = *budget;
    if (!o.task_allocation_budget || !o.max_client_requests || !o.operation || !b.receive.max_bytes ||
        !b.receive.max_native_calls || !b.send.max_bytes || !b.send.max_native_calls)
        return finish(VIREO_RESULT_INVALID_ARGUMENT,value,report,saved);
    if (o.max_frame_bytes < (size_t)VIREO_PROTOCOL_HEADER_SIZE || o.max_frame_bytes > VIREO_ASYNC_REQUEST_MAX_FRAME_BYTES ||
        o.task_allocation_budget > (size_t)67108864) return finish(VIREO_RESULT_RANGE,value,report,saved);
    value.stage = VIREO_ASYNC_CLIENT_DRIVE_TLS_CHECK_PENDING;
    bool empty = false; vireo_result_t result = pending_shape(pending,&empty);
    if (result != VIREO_OK) return finish(result,value,report,saved);
    if (!empty) { value.pending_retained = true; return finish(VIREO_RESULT_BUSY,value,report,saved); }
    value.stage = VIREO_ASYNC_CLIENT_DRIVE_TLS_CHECK_SERVER;
    vireo_tcp_server_info_t root = {0}; result = vireo_tcp_server_inspect(server,&root);
    if (result != VIREO_OK) return finish(result,value,report,saved);
    if (root.processing_active || root.driving_active || root.scheduling_active || root.serving_active ||
        root.shutdown_active || root.closing_active) return finish(VIREO_RESULT_BUSY,value,report,saved);
    if (root.stop_requested) return finish(VIREO_RESULT_CANCELLED,value,report,saved);
    value.stage = VIREO_ASYNC_CLIENT_DRIVE_TLS_CHECK_CLIENT;
    vireo_tcp_server_client_info_t current = {0}; result = vireo_tcp_server_client_inspect(server,client,&current);
    if (result != VIREO_OK) return finish(result,value,report,saved);
    if (current.connection_info.transport != VIREO_CONNECTION_TRANSPORT_TLS)
        return finish(VIREO_RESULT_BUSY,value,report,saved);
    if (!current.connection_info.loop_attached) return finish(VIREO_RESULT_NOT_FOUND,value,report,saved);
    vireo_tls_connection_t *tls = NULL;
    result = vireo_tcp_server_client_tls_borrow(server,client,&tls,&value.lookup_error);
    if (result != VIREO_OK) return finish(result,value,report,saved);
    vireo_tls_connection_info_t connection = {0};
    result = vireo_tls_connection_inspect(tls,&connection,&value.tls_error);
    if (result != VIREO_OK) return finish(result,value,report,saved);
    vireo_tls_io_info_t io = {0}; result = ops->io_inspect(context,tls,&io,&value.tls_error);
    if (result != VIREO_OK) return finish(result,value,report,saved);
    vireo_tls_close_info_t close = {0}; result = vireo_tls_connection_close_inspect(tls,&close,&value.tls_error);
    if (result != VIREO_OK) return finish(result,value,report,saved);
    if (connection.handshake_state != VIREO_TLS_HANDSHAKE_ESTABLISHED || close.state != VIREO_TLS_CLOSE_NONE ||
        (io.state != VIREO_TLS_IO_OPEN && io.state != VIREO_TLS_IO_FAILED))
        return finish(VIREO_RESULT_BUSY,value,report,saved);
    value.stage = VIREO_ASYNC_CLIENT_DRIVE_TLS_CHECK_BUDGET;
    if (o.max_frame_bytes > io.options.read_capacity || o.max_frame_bytes > io.options.max_read_unit_bytes ||
        b.receive.max_bytes < minimum_budget(io.options.read_capacity) || b.send.max_bytes < minimum_budget(io.options.write_capacity) ||
        b.receive.max_bytes < io.read_retry_bytes || b.send.max_bytes < io.write_retry_bytes)
        return finish(VIREO_RESULT_RANGE,value,report,saved);
    value.stage = VIREO_ASYNC_CLIENT_DRIVE_TLS_PRE_REFRESH; value.pre_refresh_called = true;
    result = ops->sync(context,server,client,&value.pre_flow,&value.pre_error);
    if (result != VIREO_OK) return finish(result,value,report,saved);
    vireo_tls_io_flow_t active = value.pre_flow.flow;
    if (io.state == VIREO_TLS_IO_FAILED) goto receive_failed;
    if (active.priority_retry == VIREO_TLS_IO_OPERATION_WRITE) {
        value.stage = VIREO_ASYNC_CLIENT_DRIVE_TLS_SEND; value.send_called = true;
        value.send.stop_reason = (vireo_tls_io_stop_t)-1;
        result = ops->send(context,tls,&b.send,&value.send,&value.tls_error);
        result = io_report(&value.send,&b.send,&value.send_reported,result);
        if (result != VIREO_OK) goto final_refresh;
        value.stage = VIREO_ASYNC_CLIENT_DRIVE_TLS_FLOW;
        result = ops->flow(context,tls,&active,&value.tls_error);
        if (result != VIREO_OK) goto final_refresh;
    }
    if (active.application_read_enabled || active.priority_retry == VIREO_TLS_IO_OPERATION_READ) {
receive_failed:
        value.stage = VIREO_ASYNC_CLIENT_DRIVE_TLS_RECEIVE; value.receive_called = true;
        value.receive.stop_reason = (vireo_tls_io_stop_t)-1;
        result = ops->receive(context,tls,&b.receive,&value.receive,&value.tls_error);
        result = io_report(&value.receive,&b.receive,&value.receive_reported,result);
        if (result == VIREO_OK && io.state == VIREO_TLS_IO_FAILED) result = VIREO_RESULT_INTERNAL;
        if (result != VIREO_OK) goto final_refresh;
    }
    value.stage = VIREO_ASYNC_CLIENT_DRIVE_TLS_PEEK_FRAME; value.frame_peek_called = true;
    vireo_connection_frame_options_t const fo = {VIREO_CONNECTION_FRAME_REQUEST,o.max_frame_bytes};
    vireo_connection_frame_budget_t const fb = {1,o.max_frame_bytes};
    vireo_connection_frame_view_t view = {0};
    result = ops->frames(context,server,client,&fo,&fb,&view,1,&value.frame_info,&value.client_error);
    if (result != VIREO_OK) goto final_refresh;
    if (value.frame_info.frame_count != 0) {
        if (value.frame_info.frame_count != 1 || view.wire_size < (size_t)VIREO_PROTOCOL_HEADER_SIZE || view.wire_size > o.max_frame_bytes) {
            result = VIREO_RESULT_INTERNAL; goto final_refresh;
        }
        value.request_header = view.header; value.request_header_available = true;
        /* 本层到此结束view使用；原031重新借用并按真实transfer消费。 */
        value.stage = VIREO_ASYNC_CLIENT_DRIVE_TLS_SUBMIT; value.head_called = true;
        result = ops->head(context,server,client,store,pool,o.max_frame_bytes,o.task_allocation_budget,
            o.max_client_requests,o.operation,o.deadline_ns,cancel,pending,owner,&value.head_report);
        value.pending_retained = value.head_report.pending_retained;
        if (result != VIREO_OK) goto final_refresh;
    }
    if (!value.send_called) {
        value.stage = VIREO_ASYNC_CLIENT_DRIVE_TLS_FLOW;
        result = ops->flow(context,tls,&active,&value.tls_error);
        if (result != VIREO_OK) goto final_refresh;
        if ((active.want_write || active.priority_retry == VIREO_TLS_IO_OPERATION_WRITE) &&
            active.priority_retry != VIREO_TLS_IO_OPERATION_READ) {
            value.stage = VIREO_ASYNC_CLIENT_DRIVE_TLS_SEND; value.send_called = true;
            value.send.stop_reason = (vireo_tls_io_stop_t)-1;
            result = ops->send(context,tls,&b.send,&value.send,&value.tls_error);
            result = io_report(&value.send,&b.send,&value.send_reported,result);
        }
    }
final_refresh:
    value.final_refresh_called = true;
    value.final_refresh_result = ops->sync(context,server,client,&value.final_flow,&value.final_error);
    if (result == VIREO_OK && value.final_refresh_result != VIREO_OK) {
        result = value.final_refresh_result; value.stage = VIREO_ASYNC_CLIENT_DRIVE_TLS_FINAL_REFRESH;
    }
    if (result == VIREO_OK) {
        value.stage = VIREO_ASYNC_CLIENT_DRIVE_TLS_FINAL_INSPECT; value.final_inspect_called = true;
        result = ops->io_inspect(context,tls,&io,&value.tls_error);
        if (result == VIREO_OK) value.needs_reschedule = value.head_called && value.head_report.submit_report.task_transferred &&
            value.head_report.consume_called && value.head_report.consume_result == VIREO_OK && io.read_size != 0;
    }
    return finish(result,value,report,saved);
}

vireo_result_t vireo_async_client_drive_tls_once(vireo_tcp_server_t *server, vireo_connection_pool_lease_t client,
    vireo_inflight_store_t *store, vireo_thread_pool_t *pool, vireo_async_client_drive_options_t const *options,
    vireo_async_client_drive_tls_budget_t const *budget, vireo_task_cancel_t *cancel, vireo_async_request_pending_t *pending,
    vireo_task_t **remaining_task, vireo_async_client_drive_tls_report_t *report) {
    return vireo_async_client_drive_tls_with_ops(server,client,store,pool,options,budget,cancel,pending,remaining_task,
        report,&default_ops,NULL);
}

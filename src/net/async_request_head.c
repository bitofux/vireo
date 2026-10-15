/*
 * PROJECT : VIREO
 * FILE    : async_request_head.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 真移交后提交pending，消费失败只恢复消费
 */
#include "async_request_head_internal.h"
#include <errno.h>

static vireo_result_t frames_public(void *context, vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, vireo_connection_frame_options_t const *options,
    vireo_connection_frame_budget_t const *budget, vireo_connection_frame_view_t *view,
    size_t capacity, vireo_connection_frame_info_t *info, vireo_tcp_server_client_error_t *error) {
    (void)context; return vireo_tcp_server_client_frames_peek(server, client, options, budget, view, capacity, info, error);
}
static vireo_result_t read_public(void *context, vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, uint8_t const **data, size_t *size, vireo_tcp_server_client_error_t *error) {
    (void)context; return vireo_tcp_server_client_read_peek(server, client, data, size, error);
}
static vireo_result_t submit_public(void *context, vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    uint8_t const *data, size_t size, size_t cap, size_t allocation, size_t limit,
    uint32_t operation, uint64_t deadline, vireo_task_cancel_t *cancel, vireo_task_t **owner,
    vireo_async_request_report_t *report) {
    (void)context; return vireo_async_request_copy_try_submit(server, client, store, pool,
        data, size, cap, allocation, limit, operation, deadline, cancel, owner, report);
}
static vireo_result_t consume_public(void *context, vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, size_t size, vireo_tcp_server_client_error_t *error) {
    (void)context; return vireo_tcp_server_client_read_consume(server, client, size, error);
}
static vireo_async_request_head_ops_t const default_ops = {frames_public, read_public, submit_public, consume_public};

/** 纯逻辑形态，不用padding比较、不发号/查客户/查在途或保活。 */
static vireo_result_t pending_shape(vireo_async_request_pending_t const *pending, bool *empty) {
    vireo_task_metadata_t const m = pending->metadata;
    if (pending->frame_bytes == 0 && m.route.client_owner_id == 0 && m.route.client_slot_index == 0 &&
        m.route.client_generation == 0 && m.route.request_sequence == 0 && m.request_instance_id == 0 &&
        m.operation == 0 && m.deadline_ns == 0) { *empty = true; return VIREO_OK; }
    if (pending->frame_bytes < (size_t)VIREO_PROTOCOL_HEADER_SIZE ||
        pending->frame_bytes > VIREO_ASYNC_REQUEST_MAX_FRAME_BYTES) return VIREO_RESULT_INVALID_ARGUMENT;
    vireo_task_metadata_t checked;
    vireo_result_t const result = vireo_task_metadata_make(m.route, m.request_instance_id, m.operation, m.deadline_ns, &checked);
    if (result != VIREO_OK) return result;
    *empty = false; return VIREO_OK;
}
/** 私有依赖表须完整，恢复也不保存或改变表。 */
static bool valid_ops(vireo_async_request_head_ops_t const *ops) {
    return ops != NULL && ops->frames != NULL && ops->read != NULL && ops->submit != NULL && ops->consume != NULL;
}

/**
 * @brief
 *     发布全部真实局部报告并恢复errno，不清理任务/回滚读区。
 *
 * @param[in] result
 *     主返回原值。
 * @param[in] stage
 *     本层主错位置。
 * @param[in] value
 *     所有已发生前缀。
 * @param[out] report
 *     可写报告，NULL基本拒绝无处发布。
 * @param[in] saved_errno
 *     入口int原值。
 *
 * @return
 *     原result。
 */
static vireo_result_t finish(vireo_result_t result, vireo_async_request_head_stage_t stage,
    vireo_async_request_head_report_t value, vireo_async_request_head_report_t *report, int saved_errno) {
    value.stage = stage; if (report != NULL) *report = value;
    errno = saved_errno; return result;
}

/**
 * @brief
 *     只按有效pending原租约消费一次，成功清空，错误保原值与消费诊断。
 *
 * @param[in,out] server
 *     原资源根短借。
 * @param[in,out] pending
 *     已校验非空且源稳定的caller唯一记录。
 * @param[in,out] value
 *     独立栈报告，本次原消费前快照和结果。
 * @param[in] ops
 *     完整稳定公开依赖表。
 * @param[in,out] context
 *     可空隔离短借上下文。
 *
 * @return
 *     consume原结果，不查登记或重新提交。
 */
static vireo_result_t consume_pending(vireo_tcp_server_t *server, vireo_async_request_pending_t *pending,
    vireo_async_request_head_report_t *value, vireo_async_request_head_ops_t const *ops, void *context) {
    value->pending_snapshot = *pending; value->frame_bytes = pending->frame_bytes;
    vireo_task_route_t const route = pending->metadata.route;
    vireo_connection_pool_lease_t const client = {route.client_owner_id, route.client_slot_index, route.client_generation};
    value->consume_called = true;
    value->consume_result = ops->consume(context, server, client, pending->frame_bytes, &value->consume_error);
    if (value->consume_result == VIREO_OK) *pending = (vireo_async_request_pending_t){0};
    value->pending_retained = value->consume_result != VIREO_OK;
    return value->consume_result;
}

vireo_result_t vireo_async_request_head_with_ops(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    size_t cap, size_t allocation, size_t limit, uint32_t operation, uint64_t deadline,
    vireo_task_cancel_t *cancel, vireo_async_request_pending_t *pending, vireo_task_t **owner,
    vireo_async_request_head_report_t *report, vireo_async_request_head_ops_t const *ops, void *context) {
    int const saved_errno = errno; vireo_async_request_head_report_t value = {0};
    if (server == NULL || store == NULL || pool == NULL || pending == NULL || owner == NULL || report == NULL ||
        allocation == 0 || limit == 0 || operation == 0 || !valid_ops(ops) || *owner != NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_ASYNC_REQUEST_HEAD_NONE, value, report, saved_errno);
    if (cap < (size_t)VIREO_PROTOCOL_HEADER_SIZE || cap > VIREO_ASYNC_REQUEST_MAX_FRAME_BYTES)
        return finish(VIREO_RESULT_RANGE, VIREO_ASYNC_REQUEST_HEAD_NONE, value, report, saved_errno);
    bool empty = false; vireo_result_t result = pending_shape(pending, &empty);
    if (result != VIREO_OK)
        return finish(result, VIREO_ASYNC_REQUEST_HEAD_CHECK_PENDING, value, report, saved_errno);
    if (!empty) {
        value.pending_retained = true; value.pending_snapshot = *pending;
        return finish(VIREO_RESULT_BUSY, VIREO_ASYNC_REQUEST_HEAD_CHECK_PENDING, value, report, saved_errno);
    }
    vireo_connection_frame_options_t const options = {VIREO_CONNECTION_FRAME_REQUEST, cap};
    vireo_connection_frame_budget_t const budget = {1, cap};
    vireo_connection_frame_view_t view = {0}; value.frame_peek_called = true;
    result = ops->frames(context, server, client, &options, &budget, &view, 1, &value.frame_info, &value.frame_error);
    if (result != VIREO_OK)
        return finish(result, VIREO_ASYNC_REQUEST_HEAD_PEEK_FRAME, value, report, saved_errno);
    if (value.frame_info.frame_count == 0)
        return finish(VIREO_OK, VIREO_ASYNC_REQUEST_HEAD_NONE, value, report, saved_errno);
    value.frame_found = true; value.frame_bytes = view.wire_size;
    if (value.frame_info.frame_count != 1 || view.wire_size < (size_t)VIREO_PROTOCOL_HEADER_SIZE || view.wire_size > cap)
        return finish(VIREO_RESULT_INTERNAL, VIREO_ASYNC_REQUEST_HEAD_PEEK_FRAME, value, report, saved_errno);
    uint8_t const *data = NULL; size_t size = 0; value.read_peek_called = true;
    result = ops->read(context, server, client, &data, &size, &value.frame_error);
    if (result != VIREO_OK)
        return finish(result, VIREO_ASYNC_REQUEST_HEAD_PEEK_BYTES, value, report, saved_errno);
    if (data == NULL || size < view.wire_size)
        return finish(VIREO_RESULT_INTERNAL, VIREO_ASYNC_REQUEST_HEAD_PEEK_BYTES, value, report, saved_errno);
    value.submit_called = true;
    value.submit_result = ops->submit(context, server, client, store, pool, data, view.wire_size,
        cap, allocation, limit, operation, deadline, cancel, owner, &value.submit_report);
    /* body/raw借用到此结束；以下只读数值元数据/长度，不触碰source地址。 */
    if (!value.submit_report.task_transferred)
        return finish(value.submit_result, value.submit_result == VIREO_OK ? VIREO_ASYNC_REQUEST_HEAD_NONE :
            VIREO_ASYNC_REQUEST_HEAD_SUBMIT, value, report, saved_errno);
    *pending = (vireo_async_request_pending_t){value.submit_report.metadata, value.frame_bytes};
    value.pending_committed = true;
    result = consume_pending(server, pending, &value, ops, context);
    if (value.submit_result != VIREO_OK)
        return finish(value.submit_result, VIREO_ASYNC_REQUEST_HEAD_SUBMIT, value, report, saved_errno);
    return finish(result, result == VIREO_OK ? VIREO_ASYNC_REQUEST_HEAD_NONE : VIREO_ASYNC_REQUEST_HEAD_CONSUME,
        value, report, saved_errno);
}

vireo_result_t vireo_async_request_resume_with_ops(vireo_tcp_server_t *server,
    vireo_async_request_pending_t *pending, vireo_async_request_head_report_t *report,
    vireo_async_request_head_ops_t const *ops, void *context) {
    int const saved_errno = errno; vireo_async_request_head_report_t value = {0};
    if (server == NULL || pending == NULL || report == NULL || !valid_ops(ops))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_ASYNC_REQUEST_HEAD_NONE, value, report, saved_errno);
    bool empty = false; vireo_result_t result = pending_shape(pending, &empty);
    if (result != VIREO_OK || empty)
        return finish(result == VIREO_OK ? VIREO_RESULT_NOT_FOUND : result,
            VIREO_ASYNC_REQUEST_HEAD_CHECK_PENDING, value, report, saved_errno);
    result = consume_pending(server, pending, &value, ops, context);
    return finish(result, result == VIREO_OK ? VIREO_ASYNC_REQUEST_HEAD_NONE : VIREO_ASYNC_REQUEST_HEAD_CONSUME,
        value, report, saved_errno);
}

vireo_result_t vireo_async_request_submit_read_head(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    size_t cap, size_t allocation, size_t limit, uint32_t operation, uint64_t deadline,
    vireo_task_cancel_t *cancel, vireo_async_request_pending_t *pending, vireo_task_t **owner,
    vireo_async_request_head_report_t *report) {
    return vireo_async_request_head_with_ops(server, client, store, pool, cap, allocation, limit,
        operation, deadline, cancel, pending, owner, report, &default_ops, NULL);
}
vireo_result_t vireo_async_request_resume_consume(vireo_tcp_server_t *server,
    vireo_async_request_pending_t *pending, vireo_async_request_head_report_t *report) {
    return vireo_async_request_resume_with_ops(server, pending, report, &default_ops, NULL);
}

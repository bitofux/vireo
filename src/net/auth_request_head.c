/*
 * PROJECT : VIREO
 * FILE    : auth_request_head.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-20
 * BRIEF   : 认证处理结果先落凭据，原帧消费独立恢复
 */
#include "auth_request_head_internal.h"
#include <errno.h>

static vireo_result_t frames_public(void *context, vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, vireo_connection_frame_options_t const *options,
    vireo_connection_frame_budget_t const *budget, vireo_connection_frame_view_t *view,
    size_t capacity, vireo_connection_frame_info_t *info, vireo_tcp_server_client_error_t *error) {
    (void)context;
    return vireo_tcp_server_client_frames_peek(server, client, options, budget, view, capacity, info, error);
}
static vireo_result_t read_public(void *context, vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, uint8_t const **data, size_t *size,
    vireo_tcp_server_client_error_t *error) {
    (void)context;
    return vireo_tcp_server_client_read_peek(server, client, data, size, error);
}
static vireo_result_t submit_public(void *context, vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    vireo_auth_login_admission_t *admission, vireo_monotonic_ns_t now, vireo_auth_sessions_t *sessions, uint64_t utc, uint8_t const *wire,
    size_t size, vireo_auth_request_submit_options_t const *options, vireo_task_cancel_t *cancel,
    vireo_task_t **task, vireo_auth_request_submit_report_t *report) {
    (void)context;
    return vireo_auth_request_copy_try_submit(server, client, store, pool, admission, now, sessions, utc,
        wire, size, options, cancel, task, report);
}
static vireo_result_t consume_public(void *context, vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, size_t size, vireo_tcp_server_client_error_t *error) {
    (void)context;
    return vireo_tcp_server_client_read_consume(server, client, size, error);
}
static vireo_auth_request_head_ops_t const default_ops = {
    frames_public, read_public, submit_public, consume_public
};

/* 只检查本层标识/状态/长度的形态；嵌套报告由041-11产生，caller不得伪造或改写。 */
static bool receipt_valid(vireo_auth_request_head_receipt_t const *receipt) {
    if (receipt->state == VIREO_AUTH_REQUEST_HEAD_EMPTY)
        return receipt->client.pool_id == 0 && receipt->client.slot_index == 0 &&
            receipt->client.generation == 0 && receipt->frame_bytes == 0 &&
            receipt->command == 0 && receipt->sequence == 0 && receipt->submit_result == VIREO_OK;
    return (receipt->state == VIREO_AUTH_REQUEST_HEAD_NEEDS_CONSUME ||
        receipt->state == VIREO_AUTH_REQUEST_HEAD_CONSUMED) && receipt->client.pool_id != 0 &&
        receipt->client.generation != 0 && receipt->sequence != 0 &&
        receipt->frame_bytes >= (size_t)VIREO_PROTOCOL_HEADER_SIZE &&
        receipt->frame_bytes <= VIREO_AUTH_REQUEST_FRAME_MAX;
}
static bool ops_valid(vireo_auth_request_head_ops_t const *ops) {
    return ops != NULL && ops->frames != NULL && ops->read != NULL &&
        ops->submit != NULL && ops->consume != NULL;
}

/**
 * @brief 发布真实报告并恢复入口errno
 * @param[in] result 原主返回值。
 * @param[in] stage 本次主错位置。
 * @param[in] value 栈报告值，无owner或秘密。
 * @param[out] report 可NULL，非空时覆盖。
 * @param[in] saved_errno 入口errno。
 * @return 原result。
 */
static vireo_result_t finish(vireo_result_t result, vireo_auth_request_head_stage_t stage,
    vireo_auth_request_head_report_t value, vireo_auth_request_head_report_t *report, int saved_errno) {
    value.stage = stage;
    if (report != NULL) *report = value;
    errno = saved_errno;
    return result;
}

/**
 * @brief 按已保存原租约消费一次，成功只改变状态，保留历史结果
 * @param[in,out] server 原存活根短借。
 * @param[in,out] receipt 已校验NEEDS_CONSUME且源稳定的唯一凭据。
 * @param[in,out] report 独立栈报告。
 * @param[in] ops 完整短借依赖表。
 * @param[in,out] context 可NULL测试上下文，不保存。
 * @return 原consume返回值，不查登记、不处理task或退款。
 */
static vireo_result_t consume_receipt(vireo_tcp_server_t *server,
    vireo_auth_request_head_receipt_t *receipt, vireo_auth_request_head_report_t *report,
    vireo_auth_request_head_ops_t const *ops, void *context) {
    report->consume_called = true;
    report->consume_result = ops->consume(context, server, receipt->client,
        receipt->frame_bytes, &report->consume_error);
    if (report->consume_result == VIREO_OK) receipt->state = VIREO_AUTH_REQUEST_HEAD_CONSUMED;
    report->receipt = *receipt;
    return report->consume_result;
}

vireo_result_t vireo_auth_request_head_with(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    vireo_auth_login_admission_t *admission, vireo_monotonic_ns_t now, vireo_auth_sessions_t *sessions, uint64_t utc,
    vireo_auth_request_submit_options_t const *options, vireo_task_cancel_t *cancel,
    vireo_auth_request_head_receipt_t *receipt, vireo_task_t **remaining_task,
    vireo_auth_request_head_report_t *report, vireo_auth_request_head_ops_t const *ops, void *context) {
    int const saved_errno = errno;
    vireo_auth_request_head_report_t value = {0};
    if (server == NULL || store == NULL || pool == NULL || admission == NULL || sessions == NULL || options == NULL ||
        receipt == NULL || remaining_task == NULL || report == NULL || !ops_valid(ops) || *remaining_task != NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_AUTH_REQUEST_HEAD_NONE, value, report, saved_errno);
    vireo_auth_request_submit_options_t const o = *options;
    if (o.task_allocation_budget == 0 || o.max_client_requests == 0 || o.register_operation == 0 ||
        o.login_operation == 0 || !o.logout_operation || !o.resume_operation ||
        o.register_operation==o.login_operation || o.register_operation==o.logout_operation ||
        o.register_operation==o.resume_operation || o.login_operation==o.logout_operation ||
        o.login_operation==o.resume_operation || o.logout_operation==o.resume_operation)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_AUTH_REQUEST_HEAD_NONE, value, report, saved_errno);
    if (o.task_allocation_budget > VIREO_TASK_MAX_ALLOCATION_BYTES)
        return finish(VIREO_RESULT_RANGE, VIREO_AUTH_REQUEST_HEAD_NONE, value, report, saved_errno);
    if (!receipt_valid(receipt))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_AUTH_REQUEST_HEAD_CHECK_RECEIPT, value, report, saved_errno);
    value.receipt = *receipt;
    if (receipt->state != VIREO_AUTH_REQUEST_HEAD_EMPTY)
        return finish(VIREO_RESULT_BUSY, VIREO_AUTH_REQUEST_HEAD_CHECK_RECEIPT, value, report, saved_errno);
    vireo_connection_frame_options_t const frame_options = {
        VIREO_CONNECTION_FRAME_REQUEST, VIREO_AUTH_REQUEST_FRAME_MAX
    };
    vireo_connection_frame_budget_t const budget = {1, VIREO_AUTH_REQUEST_FRAME_MAX};
    vireo_connection_frame_view_t view = {0};
    value.frame_peek_called = true;
    vireo_result_t result = ops->frames(context, server, client, &frame_options, &budget,
        &view, 1, &value.frame_info, &value.frame_error);
    if (result != VIREO_OK)
        return finish(result, VIREO_AUTH_REQUEST_HEAD_PEEK_FRAME, value, report, saved_errno);
    if (value.frame_info.frame_count == 0)
        return finish(VIREO_OK, VIREO_AUTH_REQUEST_HEAD_NONE, value, report, saved_errno);
    if (value.frame_info.frame_count != 1 || view.wire_size < (size_t)VIREO_PROTOCOL_HEADER_SIZE ||
        view.wire_size > VIREO_AUTH_REQUEST_FRAME_MAX || view.header.sequence == 0)
        return finish(VIREO_RESULT_INTERNAL, VIREO_AUTH_REQUEST_HEAD_PEEK_FRAME, value, report, saved_errno);
    uint8_t const *wire = NULL;
    size_t bytes = 0;
    value.read_peek_called = true;
    result = ops->read(context, server, client, &wire, &bytes, &value.frame_error);
    if (result != VIREO_OK)
        return finish(result, VIREO_AUTH_REQUEST_HEAD_PEEK_BYTES, value, report, saved_errno);
    if (wire == NULL || bytes < view.wire_size)
        return finish(VIREO_RESULT_INTERNAL, VIREO_AUTH_REQUEST_HEAD_PEEK_BYTES, value, report, saved_errno);
    vireo_auth_request_head_receipt_t next = {
        .state = VIREO_AUTH_REQUEST_HEAD_NEEDS_CONSUME, .client = client,
        .frame_bytes = view.wire_size, .command = view.header.command, .sequence = view.header.sequence
    };
    value.submit_called = true;
    next.submit_result = ops->submit(context, server, client, store, pool, admission, now, sessions, utc,
        wire, next.frame_bytes, &o, cancel, remaining_task, &next.submit_report);
    /* 不再读取view.body或wire；不论是否已扣费/移交，都先保存拒绝或交接的完整事实。 */
    *receipt = next;
    value.receipt_committed = true;
    result = consume_receipt(server, receipt, &value, ops, context);
    if (next.submit_result != VIREO_OK)
        return finish(next.submit_result, VIREO_AUTH_REQUEST_HEAD_SUBMIT, value, report, saved_errno);
    return finish(result, result == VIREO_OK ? VIREO_AUTH_REQUEST_HEAD_NONE : VIREO_AUTH_REQUEST_HEAD_CONSUME,
        value, report, saved_errno);
}

vireo_result_t vireo_auth_request_head_resume_with(vireo_tcp_server_t *server,
    vireo_auth_request_head_receipt_t *receipt, vireo_auth_request_head_report_t *report,
    vireo_auth_request_head_ops_t const *ops, void *context) {
    int const saved_errno = errno;
    vireo_auth_request_head_report_t value = {0};
    if (server == NULL || receipt == NULL || report == NULL || !ops_valid(ops))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_AUTH_REQUEST_HEAD_NONE, value, report, saved_errno);
    if (!receipt_valid(receipt))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_AUTH_REQUEST_HEAD_CHECK_RECEIPT, value, report, saved_errno);
    value.receipt = *receipt;
    if (receipt->state != VIREO_AUTH_REQUEST_HEAD_NEEDS_CONSUME)
        return finish(VIREO_RESULT_NOT_FOUND, VIREO_AUTH_REQUEST_HEAD_CHECK_RECEIPT, value, report, saved_errno);
    vireo_result_t const result = consume_receipt(server, receipt, &value, ops, context);
    return finish(result, result == VIREO_OK ? VIREO_AUTH_REQUEST_HEAD_NONE : VIREO_AUTH_REQUEST_HEAD_CONSUME,
        value, report, saved_errno);
}

vireo_result_t vireo_auth_request_submit_read_head(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    vireo_auth_login_admission_t *admission, vireo_monotonic_ns_t now, vireo_auth_sessions_t *sessions, uint64_t utc,
    vireo_auth_request_submit_options_t const *options, vireo_task_cancel_t *cancel,
    vireo_auth_request_head_receipt_t *receipt, vireo_task_t **remaining_task,
    vireo_auth_request_head_report_t *report) {
    return vireo_auth_request_head_with(server, client, store, pool, admission, now, sessions, utc, options, cancel,
        receipt, remaining_task, report, &default_ops, NULL);
}
vireo_result_t vireo_auth_request_head_resume_consume(vireo_tcp_server_t *server,
    vireo_auth_request_head_receipt_t *receipt, vireo_auth_request_head_report_t *report) {
    return vireo_auth_request_head_resume_with(server, receipt, report, &default_ops, NULL);
}
vireo_result_t vireo_auth_request_head_acknowledge(vireo_auth_request_head_receipt_t *receipt) {
    if (receipt == NULL || !receipt_valid(receipt)) return VIREO_RESULT_INVALID_ARGUMENT;
    if (receipt->state == VIREO_AUTH_REQUEST_HEAD_EMPTY) return VIREO_RESULT_NOT_FOUND;
    if (receipt->state == VIREO_AUTH_REQUEST_HEAD_NEEDS_CONSUME) return VIREO_RESULT_BUSY;
    *receipt = (vireo_auth_request_head_receipt_t){0};
    return VIREO_OK;
}

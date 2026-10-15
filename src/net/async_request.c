/*
 * PROJECT : VIREO
 * FILE    : async_request.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 验证单帧后复制独立输入，以原提交报告判断拥有权
 */
#include "async_request_internal.h"
#include <vireo/base/checked.h>
#include <errno.h>

/** 原桥接发行，不退号或改准入策略。 */
static vireo_result_t metadata_public(void *context, vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, uint32_t sequence, uint32_t operation,
    uint64_t deadline, vireo_task_metadata_t *out, vireo_inflight_stage_t *stage) {
    (void)context;
    return vireo_inflight_metadata_make_next(server, client, sequence, operation, deadline, out, stage);
}
/** 可选取消只决定原公开构造入口，不创建新取消对象。 */
static vireo_result_t copy_public(void *context, vireo_task_metadata_t metadata,
    void const *data, size_t size, size_t budget, vireo_task_cancel_t *cancel, vireo_task_t **out) {
    (void)context;
    return cancel == NULL ? vireo_task_create_copy(metadata, data, size, budget, out) :
        vireo_task_create_copy_with_cancel(metadata, data, size, budget, cancel, out);
}
/** 原登记/提交/撤销原样返回，不补第二次撤销。 */
static vireo_result_t submit_public(void *context, vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_thread_pool_t *pool, size_t limit,
    vireo_task_t **owner, vireo_inflight_submit_report_t *report) {
    (void)context;
    return vireo_inflight_store_try_submit(store, server, pool, limit, owner, report);
}
static vireo_async_request_ops_t const default_ops = {metadata_public, copy_public, submit_public};

/**
 * @brief
 *     发布局部真实前缀并恢复 errno，不清理 task 或改变网络借用。
 *
 * @param[in] result
 *     主结果原值。
 * @param[in] stage
 *     本层主错位置。
 * @param[in] value
 *     全部真实局部进度。
 * @param[out] report
 *     可写报告，NULL 拒绝无处发布。
 * @param[in] saved_errno
 *     入口 int 原值。
 *
 * @return
 *     result 原值。
 */
static vireo_result_t finish(vireo_result_t result, vireo_async_request_stage_t stage,
    vireo_async_request_report_t value, vireo_async_request_report_t *report, int saved_errno) {
    value.stage = stage;
    if (report != NULL) *report = value;
    errno = saved_errno; return result;
}

vireo_result_t vireo_async_request_with_ops(vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    uint8_t const *data, size_t size, size_t max_frame_bytes, size_t task_allocation_budget,
    size_t max_client_requests, uint32_t operation, uint64_t deadline_ns,
    vireo_task_cancel_t *cancel, vireo_task_t **remaining_task, vireo_async_request_report_t *report,
    vireo_async_request_ops_t const *ops, void *ops_context) {
    int const saved_errno = errno;
    vireo_async_request_report_t value = {0};
    if (server == NULL || store == NULL || pool == NULL || data == NULL || remaining_task == NULL ||
        report == NULL || operation == 0 || task_allocation_budget == 0 || max_client_requests == 0 ||
        ops == NULL || ops->metadata == NULL || ops->copy == NULL || ops->submit == NULL || *remaining_task != NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_ASYNC_REQUEST_NONE, value, report, saved_errno);
    if (max_frame_bytes < (size_t)VIREO_PROTOCOL_HEADER_SIZE || max_frame_bytes > VIREO_ASYNC_REQUEST_MAX_FRAME_BYTES ||
        size < (size_t)VIREO_PROTOCOL_HEADER_SIZE || size > max_frame_bytes)
        return finish(VIREO_RESULT_RANGE, VIREO_ASYNC_REQUEST_NONE, value, report, saved_errno);
    vireo_protocol_header_t header;
    vireo_result_t result = vireo_protocol_header_decode(data, size, &header, &value.codec_issue);
    if (result == VIREO_OK) result = vireo_protocol_request_header_validate(&header, &value.codec_issue);
    if (result != VIREO_OK)
        return finish(result, VIREO_ASYNC_REQUEST_CHECK_FRAME, value, report, saved_errno);
    result = vireo_checked_size_add((size_t)VIREO_PROTOCOL_HEADER_SIZE, (size_t)header.body_len, &value.frame_bytes);
    if (result != VIREO_OK)
        return finish(result, VIREO_ASYNC_REQUEST_CHECK_FRAME, value, report, saved_errno);
    if (value.frame_bytes != size) {
        value.codec_issue = VIREO_PROTOCOL_CODEC_ISSUE_BODY_LENGTH_MISMATCH;
        return finish(VIREO_RESULT_PROTOCOL, VIREO_ASYNC_REQUEST_CHECK_FRAME, value, report, saved_errno);
    }
    result = vireo_protocol_frame_crc32c_verify(data, (size_t)VIREO_PROTOCOL_HEADER_SIZE,
        data + VIREO_PROTOCOL_HEADER_SIZE, (size_t)header.body_len, &value.codec_issue);
    if (result != VIREO_OK)
        return finish(result, VIREO_ASYNC_REQUEST_CHECK_FRAME, value, report, saved_errno);
    value.input_validated = true;
    result = ops->metadata(ops_context, server, client, header.sequence, operation, deadline_ns,
        &value.metadata, &value.inflight_stage);
    if (result != VIREO_OK)
        return finish(result, VIREO_ASYNC_REQUEST_MAKE_METADATA, value, report, saved_errno);
    value.metadata_created = true;
    result = ops->copy(ops_context, value.metadata, data, size, task_allocation_budget, cancel, remaining_task);
    if (result != VIREO_OK)
        return finish(result, VIREO_ASYNC_REQUEST_CREATE_TASK, value, report, saved_errno);
    value.task_created = true;
    value.submit_called = true;
    result = ops->submit(ops_context, store, server, pool, max_client_requests, remaining_task, &value.submit_report);
    value.task_transferred = value.submit_report.pool_report.queue_report.transferred;
    value.task_retained = *remaining_task != NULL;
    return finish(result, result == VIREO_OK ? VIREO_ASYNC_REQUEST_NONE : VIREO_ASYNC_REQUEST_SUBMIT,
        value, report, saved_errno);
}

vireo_result_t vireo_async_request_copy_try_submit(vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    uint8_t const *data, size_t size, size_t max_frame_bytes, size_t task_allocation_budget,
    size_t max_client_requests, uint32_t operation, uint64_t deadline_ns, vireo_task_cancel_t *cancel,
    vireo_task_t **remaining_task, vireo_async_request_report_t *report) {
    return vireo_async_request_with_ops(server, client, store, pool, data, size, max_frame_bytes,
        task_allocation_budget, max_client_requests, operation, deadline_ns, cancel, remaining_task,
        report, &default_ops, NULL);
}

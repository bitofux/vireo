/*
 * PROJECT : VIREO
 * FILE    : completion_response_dispatch.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 消费前计算保守额度，回调保真实响应前缀
 */
#include "completion_response_dispatch_internal.h"
#include <vireo/base/checked.h>
#include <errno.h>

static vireo_result_t inspect_public(void *context, vireo_tcp_server_t const *server,
    vireo_tcp_server_info_t *info) {
    (void)context; return vireo_tcp_server_inspect(server, info);
}
static vireo_result_t dispatch_public(void *ops_context, vireo_tcp_server_t *server,
    vireo_event_loop_handle_t handle, vireo_notifier_t *notifier, vireo_inflight_store_t *store,
    vireo_completion_queue_t *queue, size_t max_items, vireo_inflight_completion_deliver_fn deliver,
    void *context, vireo_completion_t **remaining, vireo_notifier_server_dispatch_report_t *report) {
    (void)ops_context;
    return vireo_notifier_server_dispatch_ready(server, handle, notifier, store, queue,
        max_items, deliver, context, remaining, report);
}
static vireo_result_t response_public(void *context, vireo_tcp_server_t *server,
    vireo_completion_t const *completion, vireo_inflight_completion_match_t match,
    vireo_completion_response_descriptor_t descriptor, size_t max_frame_bytes,
    uint8_t *workspace, size_t workspace_size, vireo_completion_response_report_t *report) {
    (void)context;
    return vireo_completion_response_enqueue(server, completion, match, descriptor,
        max_frame_bytes, workspace, workspace_size, report);
}
/** 常量表，无可变全局接线状态。 */
static vireo_completion_response_dispatch_ops_t const default_ops = {
    inspect_public, dispatch_public, response_public};

/** 每次外部调用独立栈上下文，不保存到资源或后续回调。 */
typedef struct response_delivery {
    vireo_tcp_server_t *server; /**< 只借，原 server 生命周期由 caller 保证。 */
    size_t max_frame_bytes; /**< 本批每帧正字节上限，已通过公共范围校验。 */
    uint8_t *workspace; /**< 只借可写 scratch，依次复用。 */
    size_t workspace_size; /**< 真实 scratch 字节容量，至少帧上限。 */
    vireo_completion_response_resolve_fn resolve; /**< 非空同步描述函数，不保存结果指针。 */
    void *context; /**< 可空 caller 上下文短借。 */
    vireo_completion_response_dispatch_report_t *report; /**< 独立局部报告借用，逐项累计。 */
    vireo_completion_response_dispatch_ops_t const *ops; /**< 稳定完整表短借。 */
    void *ops_context; /**< 可空隔离上下文短借。 */
    vireo_completion_response_dispatch_stage_t callback_stage; /**< 回调首错阶段，初 NONE。 */
} response_delivery_t;

/**
 * @brief
 *     原消费已结束登记；描述一次、响应一次，保留已确认入队及末次诊断。
 *
 * @param[in,out] context
 *     本批独立栈上下文，只借到外入口返回。
 * @param[in] completion
 *     原交付的只读短借结果。
 * @param[in] match
 *     原未篡改匹配快照。
 *
 * @return
 *     描述或响应的原返回，错误即停原批次，不回滚已发生动作。
 */
static vireo_result_t deliver_response(void *context, vireo_completion_t const *completion,
    vireo_inflight_completion_match_t match) {
    response_delivery_t *d = context;
    vireo_completion_response_dispatch_report_t *p = d->report;
    ++p->resolve_calls;
    p->last_response_called = false;
    p->last_response_result = VIREO_OK;
    p->last_response_report = (vireo_completion_response_report_t){0};
    vireo_completion_response_descriptor_t descriptor = {0};
    p->last_resolve_result = d->resolve(d->context, completion, match, &descriptor);
    if (p->last_resolve_result != VIREO_OK) {
        d->callback_stage = VIREO_COMPLETION_RESPONSE_DISPATCH_RESOLVE_DESCRIPTOR;
        return p->last_resolve_result;
    }
    ++p->response_calls;
    p->last_response_called = true;
    p->last_response_result = d->ops->response(d->ops_context, d->server, completion, match,
        descriptor, d->max_frame_bytes, d->workspace, d->workspace_size, &p->last_response_report);
    if (p->last_response_report.enqueued) {
        /* 公开合同每帧 <= cap，调用数 <= safe：受检 reserved <= 64 MiB 已限定全部累加。 */
        ++p->enqueued_responses;
        p->enqueued_bytes += p->last_response_report.frame_bytes;
    }
    if (p->last_response_result != VIREO_OK)
        d->callback_stage = VIREO_COMPLETION_RESPONSE_DISPATCH_ENQUEUE_RESPONSE;
    return p->last_response_result;
}

/**
 * @brief
 *     发布完整局部报告并恢复入口 errno，不清理结果或回滚资源。
 *
 * @param[in] result
 *     主返回原值。
 * @param[in] stage
 *     本层主错位置。
 * @param[in] value
 *     全部真实前缀的局部值。
 * @param[out] report
 *     可写报告；NULL 基本错误无处发布。
 * @param[in] saved_errno
 *     入口 int 原值。
 *
 * @return
 *     原 result。
 */
static vireo_result_t finish(vireo_result_t result, vireo_completion_response_dispatch_stage_t stage,
    vireo_completion_response_dispatch_report_t value,
    vireo_completion_response_dispatch_report_t *report, int saved_errno) {
    value.stage = stage;
    if (report != NULL) *report = value;
    errno = saved_errno; return result;
}

vireo_result_t vireo_completion_response_dispatch_with_ops(vireo_tcp_server_t *server,
    vireo_event_loop_handle_t expected_handle, vireo_notifier_t *notifier,
    vireo_inflight_store_t *store, vireo_completion_queue_t *queue, size_t max_items,
    size_t max_frame_bytes, size_t max_batch_bytes, uint8_t *workspace, size_t workspace_size,
    vireo_completion_response_resolve_fn resolve, void *context, vireo_completion_t **remaining,
    vireo_completion_response_dispatch_report_t *report,
    vireo_completion_response_dispatch_ops_t const *ops, void *ops_context) {
    int const saved_errno = errno;
    vireo_completion_response_dispatch_report_t value = {0};
    if (server == NULL || notifier == NULL || store == NULL || queue == NULL || workspace == NULL ||
        resolve == NULL || remaining == NULL || report == NULL || max_items == 0 || max_batch_bytes == 0 ||
        ops == NULL || ops->inspect == NULL || ops->dispatch == NULL || ops->response == NULL || *remaining != NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_COMPLETION_RESPONSE_DISPATCH_NONE,
            value, report, saved_errno);
    if (max_items > VIREO_INFLIGHT_COMPLETION_DRAIN_MAX_ITEMS ||
        max_frame_bytes < VIREO_PROTOCOL_HEADER_SIZE || max_frame_bytes > VIREO_COMPLETION_RESPONSE_MAX_FRAME_BYTES ||
        max_batch_bytes > VIREO_COMPLETION_RESPONSE_DISPATCH_MAX_BATCH_BYTES ||
        max_batch_bytes < max_frame_bytes || workspace_size < max_frame_bytes)
        return finish(VIREO_RESULT_RANGE, VIREO_COMPLETION_RESPONSE_DISPATCH_NONE, value, report, saved_errno);
    if (expected_handle.loop_id == 0 && expected_handle.token == 0)
        return finish(VIREO_RESULT_NOT_FOUND, VIREO_COMPLETION_RESPONSE_DISPATCH_NONE, value, report, saved_errno);
    if (expected_handle.loop_id == 0 || expected_handle.token == 0)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_COMPLETION_RESPONSE_DISPATCH_NONE, value, report, saved_errno);
    size_t const byte_items = max_batch_bytes / max_frame_bytes;
    value.effective_max_items = max_items < byte_items ? max_items : byte_items;
    vireo_result_t result = vireo_checked_size_mul(value.effective_max_items, max_frame_bytes,
        &value.reserved_frame_bytes);
    if (result != VIREO_OK)
        return finish(result, VIREO_COMPLETION_RESPONSE_DISPATCH_NONE, value, report, saved_errno);
    vireo_tcp_server_info_t info;
    result = ops->inspect(ops_context, server, &info);
    if (result != VIREO_OK || info.stop_requested)
        return finish(result == VIREO_OK ? VIREO_RESULT_CANCELLED : result,
            VIREO_COMPLETION_RESPONSE_DISPATCH_CHECK_SERVER, value, report, saved_errno);
    response_delivery_t delivery = {server, max_frame_bytes, workspace, workspace_size, resolve,
        context, &value, ops, ops_context, VIREO_COMPLETION_RESPONSE_DISPATCH_NONE};
    value.dispatch_called = true;
    result = ops->dispatch(ops_context, server, expected_handle, notifier, store, queue,
        value.effective_max_items, deliver_response, &delivery, remaining, &value.dispatch_report);
    vireo_completion_response_dispatch_stage_t stage = VIREO_COMPLETION_RESPONSE_DISPATCH_NONE;
    if (result != VIREO_OK) stage = delivery.callback_stage != VIREO_COMPLETION_RESPONSE_DISPATCH_NONE ?
        delivery.callback_stage : VIREO_COMPLETION_RESPONSE_DISPATCH_DISPATCH_READY;
    return finish(result, stage, value, report, saved_errno);
}

vireo_result_t vireo_completion_response_dispatch_ready(vireo_tcp_server_t *server,
    vireo_event_loop_handle_t expected_handle, vireo_notifier_t *notifier,
    vireo_inflight_store_t *store, vireo_completion_queue_t *queue, size_t max_items,
    size_t max_frame_bytes, size_t max_batch_bytes, uint8_t *workspace, size_t workspace_size,
    vireo_completion_response_resolve_fn resolve, void *context, vireo_completion_t **remaining,
    vireo_completion_response_dispatch_report_t *report) {
    return vireo_completion_response_dispatch_with_ops(server, expected_handle, notifier, store, queue,
        max_items, max_frame_bytes, max_batch_bytes, workspace, workspace_size, resolve, context,
        remaining, report, &default_ops, NULL);
}

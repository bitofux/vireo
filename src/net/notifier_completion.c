/*
 * PROJECT : VIREO
 * FILE    : notifier_completion.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 提示不当条数，保真实排空前缀与主次错误
 */
#include "notifier_completion_internal.h"
#include <errno.h>

/** 一次公开消费，context 不保存。 */
static vireo_result_t consume_public(void *context, vireo_notifier_t *notifier,
    uint64_t *count, vireo_notifier_error_t *error) {
    (void)context;
    return vireo_notifier_consume(notifier, count, error);
}

/** 一批公开有界排空，不替换 callback 或改变 remaining 责任。 */
static vireo_result_t drain_public(void *ops_context, vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_completion_queue_t *queue, size_t max_items,
    vireo_inflight_completion_deliver_fn deliver, void *context,
    vireo_completion_t **remaining, vireo_inflight_completion_drain_report_t *report) {
    (void)ops_context;
    return vireo_inflight_store_drain_completions(store, server, queue, max_items,
        deliver, context, remaining, report);
}

/** 一次公开通知，不重试、回收或重新入队。 */
static vireo_result_t notify_public(void *context, vireo_notifier_t *notifier,
    vireo_notifier_notify_outcome_t *outcome, vireo_notifier_error_t *error) {
    (void)context;
    return vireo_notifier_notify(notifier, outcome, error);
}

/** 只读调用表，运行没有本层可变共享状态。 */
static vireo_notifier_completion_ops_t const default_ops = {
    consume_public, drain_public, notify_public};

/**
 * @brief
 *     发布真实进度、恢复 errno 并返回主错，不执行失败后资源清理。
 *
 * @param[in] result
 *     本次主返回类别。
 * @param[in] stage
 *     对应主错误位置，成功或基本拒绝 NONE。
 * @param[in] value
 *     本次局部进度，不覆盖原 drain_result 或补提示原结果。
 * @param[out] report
 *     独立可写输出；NULL 拒绝路径无法发布。
 * @param[in] saved_errno
 *     入口 int 原值。
 *
 * @return
 *     原 result。
 */
static vireo_result_t finish(vireo_result_t result, vireo_notifier_completion_stage_t stage,
    vireo_notifier_completion_report_t value, vireo_notifier_completion_report_t *report,
    int saved_errno) {
    value.stage = stage;
    if (report != NULL) *report = value;
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_notifier_completion_with_ops(vireo_notifier_t *notifier,
    vireo_inflight_store_t *store, vireo_tcp_server_t const *server,
    vireo_completion_queue_t *queue, size_t max_items,
    vireo_inflight_completion_deliver_fn deliver, void *context,
    vireo_completion_t **remaining, vireo_notifier_completion_report_t *report,
    vireo_notifier_completion_ops_t const *ops, void *ops_context) {
    int const saved_errno = errno;
    vireo_notifier_completion_report_t value = {0};
    if (notifier == NULL || store == NULL || server == NULL || queue == NULL ||
        deliver == NULL || remaining == NULL || report == NULL || max_items == 0 ||
        ops == NULL || ops->consume == NULL || ops->drain == NULL || ops->notify == NULL ||
        *remaining != NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_NOTIFIER_COMPLETION_NONE,
            value, report, saved_errno);
    if (max_items > VIREO_INFLIGHT_COMPLETION_DRAIN_MAX_ITEMS)
        return finish(VIREO_RESULT_RANGE, VIREO_NOTIFIER_COMPLETION_NONE,
            value, report, saved_errno);
    value.consume_called = true;
    vireo_result_t result = ops->consume(ops_context, notifier, &value.notification_count,
        &value.consume_error);
    if (result != VIREO_OK)
        return finish(result, VIREO_NOTIFIER_COMPLETION_CONSUME_HINT, value, report, saved_errno);

    value.drain_called = true;
    value.drain_result = ops->drain(ops_context, store, server, queue, max_items,
        deliver, context, remaining, &value.drain_report);
    /* BUDGET 没有探空；只对领取阶段未转移 BUSY 补提示，不重放交付失败项。 */
    value.renotify_needed = (value.drain_result == VIREO_OK &&
        value.drain_report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_BUDGET) ||
        (value.drain_result == VIREO_RESULT_BUSY &&
        value.drain_report.stage == VIREO_INFLIGHT_COMPLETION_DRAIN_POP &&
        !value.drain_report.queue_report.transferred);
    if (value.renotify_needed) {
        value.renotify_called = true;
        value.renotify_result = ops->notify(ops_context, notifier, &value.renotify_outcome,
            &value.renotify_error);
    }
    if (value.drain_result != VIREO_OK)
        return finish(value.drain_result, VIREO_NOTIFIER_COMPLETION_DRAIN, value, report, saved_errno);
    if (value.renotify_called && value.renotify_result != VIREO_OK)
        return finish(value.renotify_result, VIREO_NOTIFIER_COMPLETION_RENOTIFY, value, report, saved_errno);
    return finish(VIREO_OK, VIREO_NOTIFIER_COMPLETION_NONE, value, report, saved_errno);
}

vireo_result_t vireo_notifier_completion_consume_and_drain(vireo_notifier_t *notifier,
    vireo_inflight_store_t *store, vireo_tcp_server_t const *server,
    vireo_completion_queue_t *queue, size_t max_items,
    vireo_inflight_completion_deliver_fn deliver, void *context,
    vireo_completion_t **remaining, vireo_notifier_completion_report_t *report) {
    return vireo_notifier_completion_with_ops(notifier, store, server, queue, max_items,
        deliver, context, remaining, report, &default_ops, NULL);
}

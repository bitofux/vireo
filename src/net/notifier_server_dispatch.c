/*
 * PROJECT : VIREO
 * FILE    : notifier_server_dispatch.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 显式安全点的就绪身份核对与原有界消费接线
 */
#include "notifier_server_dispatch_internal.h"
#include <errno.h>

/** 一次公开取出，不保存 context。 */
static vireo_result_t take_public(void *context, vireo_tcp_server_t *server,
    vireo_tcp_server_auxiliary_event_t *event, vireo_tcp_server_auxiliary_error_t *error) {
    (void)context;
    return vireo_tcp_server_auxiliary_read_take_ready(server, event, error);
}

/** 一次公开消费链，原条数/回调/真实 owner 责任不变。 */
static vireo_result_t dispatch_public(void *ops_context, vireo_notifier_t *notifier,
    vireo_inflight_store_t *store, vireo_tcp_server_t const *server,
    vireo_completion_queue_t *queue, size_t max_items,
    vireo_inflight_completion_deliver_fn deliver, void *context,
    vireo_completion_t **remaining, vireo_notifier_completion_report_t *report) {
    (void)ops_context;
    return vireo_notifier_completion_consume_and_drain(notifier, store, server, queue,
        max_items, deliver, context, remaining, report);
}

/** 无本层可变共享调用表。 */
static vireo_notifier_server_dispatch_ops_t const default_ops = {take_public, dispatch_public};

/**
 * @brief
 *     发布局部真实报告并恢复入口 errno，不回滚标记或清理残留。
 *
 * @param[in] result
 *     原主返回类别。
 * @param[in] stage
 *     本层主错位置，成功及基本拒绝 NONE。
 * @param[in] value
 *     原事件及消费前缀的局部副本。
 * @param[out] report
 *     可写报告，NULL 拒绝路径无处发布。
 * @param[in] saved_errno
 *     入口 errno 的 int 原值。
 *
 * @return
 *     result 原值。
 */
static vireo_result_t finish(vireo_result_t result, vireo_notifier_server_dispatch_stage_t stage,
    vireo_notifier_server_dispatch_report_t value,
    vireo_notifier_server_dispatch_report_t *report, int saved_errno) {
    value.stage = stage;
    if (report != NULL) *report = value;
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_notifier_server_dispatch_with_ops(vireo_tcp_server_t *server,
    vireo_event_loop_handle_t expected_handle, vireo_notifier_t *notifier,
    vireo_inflight_store_t *store, vireo_completion_queue_t *queue, size_t max_items,
    vireo_inflight_completion_deliver_fn deliver, void *context,
    vireo_completion_t **remaining, vireo_notifier_server_dispatch_report_t *report,
    vireo_notifier_server_dispatch_ops_t const *ops, void *ops_context) {
    int const saved_errno = errno;
    vireo_notifier_server_dispatch_report_t value = {0};
    if (server == NULL || notifier == NULL || store == NULL || queue == NULL ||
        deliver == NULL || remaining == NULL || report == NULL || max_items == 0 ||
        ops == NULL || ops->take == NULL || ops->dispatch == NULL || *remaining != NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_NOTIFIER_SERVER_DISPATCH_NONE,
            value, report, saved_errno);
    if (max_items > VIREO_INFLIGHT_COMPLETION_DRAIN_MAX_ITEMS)
        return finish(VIREO_RESULT_RANGE, VIREO_NOTIFIER_SERVER_DISPATCH_NONE,
            value, report, saved_errno);
    if (expected_handle.loop_id == 0 && expected_handle.token == 0)
        return finish(VIREO_RESULT_NOT_FOUND, VIREO_NOTIFIER_SERVER_DISPATCH_NONE,
            value, report, saved_errno);
    if (expected_handle.loop_id == 0 || expected_handle.token == 0)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_NOTIFIER_SERVER_DISPATCH_NONE,
            value, report, saved_errno);

    value.ready_called = true;
    vireo_result_t result = ops->take(ops_context, server, &value.ready_event, &value.ready_error);
    if (result == VIREO_RESULT_NOT_FOUND)
        return finish(VIREO_OK, VIREO_NOTIFIER_SERVER_DISPATCH_NONE, value, report, saved_errno);
    if (result != VIREO_OK)
        return finish(result, VIREO_NOTIFIER_SERVER_DISPATCH_TAKE_READY, value, report, saved_errno);
    value.ready_taken = true;
    if (value.ready_event.handle.loop_id != expected_handle.loop_id ||
        value.ready_event.handle.token != expected_handle.token)
        return finish(VIREO_RESULT_NOT_FOUND, VIREO_NOTIFIER_SERVER_DISPATCH_CHECK_READY,
            value, report, saved_errno);
    uint32_t const known = VIREO_EPOLL_EVENT_READ | VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP;
    if (value.ready_event.events == 0 || (value.ready_event.events & ~known) != 0)
        return finish(VIREO_RESULT_INTERNAL, VIREO_NOTIFIER_SERVER_DISPATCH_CHECK_READY,
            value, report, saved_errno);
    if ((value.ready_event.events & (VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP)) != 0)
        return finish(VIREO_RESULT_IO, VIREO_NOTIFIER_SERVER_DISPATCH_CHECK_READY,
            value, report, saved_errno);

    value.dispatch_called = true;
    value.dispatch_result = ops->dispatch(ops_context, notifier, store, server, queue,
        max_items, deliver, context, remaining, &value.dispatch_report);
    return finish(value.dispatch_result, value.dispatch_result == VIREO_OK ?
        VIREO_NOTIFIER_SERVER_DISPATCH_NONE : VIREO_NOTIFIER_SERVER_DISPATCH_DISPATCH,
        value, report, saved_errno);
}

vireo_result_t vireo_notifier_server_dispatch_ready(vireo_tcp_server_t *server,
    vireo_event_loop_handle_t expected_handle, vireo_notifier_t *notifier,
    vireo_inflight_store_t *store, vireo_completion_queue_t *queue, size_t max_items,
    vireo_inflight_completion_deliver_fn deliver, void *context,
    vireo_completion_t **remaining, vireo_notifier_server_dispatch_report_t *report) {
    return vireo_notifier_server_dispatch_with_ops(server, expected_handle, notifier, store,
        queue, max_items, deliver, context, remaining, report, &default_ops, NULL);
}

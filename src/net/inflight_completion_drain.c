/*
 * PROJECT : VIREO
 * FILE    : inflight_completion_drain.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 每次 try 领取与单项消费配对，首错保 owner 和真实前缀
 */
#include "inflight_completion_drain_internal.h"
#include <errno.h>

/** 默认依赖只转发公开合同，不保存上下文或参数，不改变真实资源责任。 */
static vireo_result_t pop_public(void *ops_context, vireo_completion_queue_t *queue,
    vireo_completion_t **owner, vireo_completion_queue_transfer_report_t *report) {
    (void)ops_context;
    return vireo_completion_queue_try_pop(queue, owner, report);
}

/** 默认依赖只转发单项消费，报告和 owner 原样交还，不增加失败清理。 */
static vireo_result_t consume_public(void *ops_context, vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_completion_t **owner,
    vireo_inflight_completion_deliver_fn deliver, void *context,
    vireo_inflight_completion_consume_report_t *report) {
    (void)ops_context;
    return vireo_inflight_store_consume_completion(store, server, owner, deliver, context, report);
}

/**
 * @brief
 *     发布完整真实进度并恢复入口 errno，无失败后的资源清理。
 *
 * @param[in] result
 *     本路径原返回类别。
 * @param[in] stage
 *     主错误位置，成功/基本拒绝为 NONE。
 * @param[in] stop
 *     已发生的停止原因。
 * @param[in] value
 *     本次独立局部报告。
 * @param[out] report
 *     可写输出；NULL 基本拒绝路径不能发布。
 * @param[in] saved_errno
 *     入口 int 原值。
 *
 * @return
 *     原 result。
 */
static vireo_result_t finish(vireo_result_t result, vireo_inflight_completion_drain_stage_t stage,
    vireo_inflight_completion_drain_stop_t stop, vireo_inflight_completion_drain_report_t value,
    vireo_inflight_completion_drain_report_t *report, int saved_errno) {
    value.stage = stage;
    value.stop_reason = stop;
    if (report != NULL) *report = value;
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_inflight_completion_drain_with_ops(vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_completion_queue_t *queue, size_t max_items,
    vireo_inflight_completion_deliver_fn deliver, void *context,
    vireo_completion_t **remaining, vireo_inflight_completion_drain_report_t *report,
    vireo_inflight_completion_drain_ops_t const *ops, void *ops_context) {
    int const saved_errno = errno;
    vireo_inflight_completion_drain_report_t value = {0};
    if (store == NULL || server == NULL || queue == NULL || deliver == NULL ||
        remaining == NULL || report == NULL || max_items == 0 || ops == NULL ||
        ops->pop == NULL || ops->consume == NULL || *remaining != NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_COMPLETION_DRAIN_NONE,
            VIREO_INFLIGHT_COMPLETION_DRAIN_NOT_STARTED, value, report, saved_errno);
    if (max_items > VIREO_INFLIGHT_COMPLETION_DRAIN_MAX_ITEMS)
        return finish(VIREO_RESULT_RANGE, VIREO_INFLIGHT_COMPLETION_DRAIN_NONE,
            VIREO_INFLIGHT_COMPLETION_DRAIN_NOT_STARTED, value, report, saved_errno);

    /* 单批预算限制所有增量，五计数最多 65536；新领取前清掉前一项的嵌套诊断。 */
    for (size_t i = 0; i < max_items; ++i) {
        value.last_item_consume_called = false;
        value.queue_report = (vireo_completion_queue_transfer_report_t){0};
        value.consume_report = (vireo_inflight_completion_consume_report_t){0};
        ++value.pop_calls;
        vireo_result_t result = ops->pop(ops_context, queue, remaining, &value.queue_report);
        if (value.queue_report.transferred) ++value.received;
        if (result != VIREO_OK) {
            if (result == VIREO_RESULT_NOT_FOUND && !value.queue_report.transferred)
                return finish(VIREO_OK, VIREO_INFLIGHT_COMPLETION_DRAIN_NONE,
                    VIREO_INFLIGHT_COMPLETION_DRAIN_EMPTY, value, report, saved_errno);
            return finish(result, VIREO_INFLIGHT_COMPLETION_DRAIN_POP,
                VIREO_INFLIGHT_COMPLETION_DRAIN_ERROR, value, report, saved_errno);
        }
        value.last_item_consume_called = true;
        result = ops->consume(ops_context, store, server, remaining, deliver, context,
            &value.consume_report);
        if (value.consume_report.delivery_called && value.consume_report.delivery_result == VIREO_OK)
            ++value.delivered;
        if (result != VIREO_OK)
            return finish(result, VIREO_INFLIGHT_COMPLETION_DRAIN_CONSUME,
                VIREO_INFLIGHT_COMPLETION_DRAIN_ERROR, value, report, saved_errno);
        ++value.finished;
        if (value.consume_report.disposition == VIREO_INFLIGHT_COMPLETION_CLIENT_GONE ||
            value.consume_report.disposition == VIREO_INFLIGHT_COMPLETION_REQUEST_GONE)
            ++value.late_cleaned;
    }
    return finish(VIREO_OK, VIREO_INFLIGHT_COMPLETION_DRAIN_NONE,
        VIREO_INFLIGHT_COMPLETION_DRAIN_BUDGET, value, report, saved_errno);
}

vireo_result_t vireo_inflight_store_drain_completions(vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_completion_queue_t *queue, size_t max_items,
    vireo_inflight_completion_deliver_fn deliver, void *context,
    vireo_completion_t **remaining, vireo_inflight_completion_drain_report_t *report) {
    static vireo_inflight_completion_drain_ops_t const ops = {pop_public, consume_public};
    return vireo_inflight_completion_drain_with_ops(store, server, queue, max_items,
        deliver, context, remaining, report, &ops, NULL);
}

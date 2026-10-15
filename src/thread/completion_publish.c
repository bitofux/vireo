/*
 * PROJECT : VIREO
 * FILE    : completion_publish.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 公开依赖构造、真实交接后通知及主次失败组合
 */
#include "completion_publish_internal.h"
#include <errno.h>

static vireo_completion_publish_ops_t const default_ops = {
    vireo_task_inspect, vireo_completion_metadata_make, vireo_completion_create_copy,
    vireo_completion_queue_wait_push, vireo_notifier_notify
};

/**
 * @brief
 *     发布已发生的本调用进度，再恢复入口errno。
 *
 * @param[out] report
 *     可空独立报告地址，基本NULL拒绝也从此出口返回。
 * @param[in] candidate
 *     本次按值进度，不拥有资源。
 * @param[in] result
 *     原主结果，不从errno重新分类。
 * @param[in] saved_errno
 *     本次入口errno值。
 *
 * @return
 *     原result，不重试或改变对象义务。
 */
static vireo_result_t finish(vireo_completion_publish_report_t *report,
    vireo_completion_publish_report_t candidate, vireo_result_t result, int saved_errno) {
    if (report != NULL) { *report = candidate; }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_completion_publish_with_ops(vireo_task_t const *task,
    vireo_result_t result, vireo_status_t suggested_status, void const *data,
    size_t payload_size, size_t allocation_budget, vireo_completion_queue_t *queue,
    vireo_notifier_t *notifier, vireo_completion_t **remaining,
    vireo_completion_publish_report_t *report, vireo_completion_publish_ops_t const *ops) {
    int const saved_errno = errno;
    vireo_completion_publish_report_t progress = {0};
    if (task == NULL || queue == NULL || notifier == NULL || remaining == NULL ||
        report == NULL || allocation_budget == 0 || (payload_size != 0 && data == NULL) ||
        (remaining != NULL && *remaining != NULL) || ops == NULL ||
        ops->inspect == NULL || ops->make_metadata == NULL || ops->create_copy == NULL ||
        ops->wait_push == NULL || ops->notify == NULL) {
        return finish(report, progress, VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    vireo_task_info_t info;
    progress.stage = VIREO_COMPLETION_PUBLISH_INSPECT_TASK;
    vireo_result_t error = ops->inspect(task, &info);
    if (error != VIREO_OK) { return finish(report, progress, error, saved_errno); }
    progress.task_inspected = true;
    progress.request_metadata = info.metadata;
    vireo_completion_metadata_t metadata;
    progress.stage = VIREO_COMPLETION_PUBLISH_MAKE_METADATA;
    error = ops->make_metadata(info.metadata, result, suggested_status, &metadata);
    if (error != VIREO_OK) { return finish(report, progress, error, saved_errno); }
    vireo_completion_t *owner = NULL;
    progress.stage = VIREO_COMPLETION_PUBLISH_CREATE_COMPLETION;
    error = ops->create_copy(metadata, data, payload_size, allocation_budget, &owner);
    if (error != VIREO_OK) { return finish(report, progress, error, saved_errno); }
    progress.completion_created = true;
    progress.stage = VIREO_COMPLETION_PUBLISH_PUSH_QUEUE;
    progress.push_called = true;
    progress.push_result = ops->wait_push(queue, &owner, &progress.queue_report);
    progress.completion_transferred = progress.queue_report.transferred;
    if (!progress.completion_transferred) {
        *remaining = owner;
        progress.completion_retained = true;
        return finish(report, progress, progress.push_result, saved_errno);
    }
    /* 所有权已经离开，consumer可并发销毁；此后仅访问数值报告和notifier。 */
    progress.notify_called = true;
    progress.notify_result = ops->notify(notifier, &progress.notify_outcome,
                                        &progress.notify_error);
    if (progress.push_result != VIREO_OK) {
        return finish(report, progress, progress.push_result, saved_errno);
    }
    if (progress.notify_result != VIREO_OK) {
        progress.stage = VIREO_COMPLETION_PUBLISH_NOTIFY;
        return finish(report, progress, progress.notify_result, saved_errno);
    }
    progress.stage = VIREO_COMPLETION_PUBLISH_NONE;
    return finish(report, progress, VIREO_OK, saved_errno);
}

vireo_result_t vireo_completion_copy_wait_publish(vireo_task_t const *task,
    vireo_result_t result, vireo_status_t suggested_status, void const *data,
    size_t payload_size, size_t allocation_budget, vireo_completion_queue_t *queue,
    vireo_notifier_t *notifier, vireo_completion_t **remaining,
    vireo_completion_publish_report_t *report) {
    return vireo_completion_publish_with_ops(task, result, suggested_status, data,
        payload_size, allocation_budget, queue, notifier, remaining, report, &default_ops);
}

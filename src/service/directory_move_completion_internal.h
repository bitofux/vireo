/*
 * PROJECT : VIREO
 * FILE    : directory_move_completion_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-25
 * BRIEF   : 目录移动内部桥接与原线程所有权。
 */
#ifndef VIREO_SERVICE_DIRECTORY_MOVE_COMPLETION_INTERNAL_H
#define VIREO_SERVICE_DIRECTORY_MOVE_COMPLETION_INTERNAL_H
#include <vireo/service/directory_move_completion.h>
/** 同公开publisher签名/所有权，不保存输入借用。 */
typedef vireo_result_t (*vireo_directory_move_publish_fn)(const vireo_task_t *, vireo_result_t,
                                                          vireo_status_t, const void *, size_t,
                                                          size_t, vireo_completion_queue_t *,
                                                          vireo_notifier_t *, vireo_completion_t **,
                                                          vireo_completion_publish_report_t *);
/** 同公开publish，额外必需同步publisher，仅本层故障注入。 */
vireo_result_t vireo_directory_move_completion_publish_with(
    const vireo_task_t *task, uint32_t op, const vireo_directory_move_task_result_t *result,
    size_t budget, vireo_completion_queue_t *queue, vireo_notifier_t *notifier,
    vireo_completion_t **remaining, vireo_directory_move_completion_publish_report_t *report,
    vireo_directory_move_publish_fn publish);
#endif

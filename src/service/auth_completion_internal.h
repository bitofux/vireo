/* PROJECT : VIREO
 * FILE : auth_completion_internal.h
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 仅本模块旧公开发布边界注入，不使用thread私有合同。
 */
#ifndef VIREO_SERVICE_AUTH_COMPLETION_INTERNAL_H
#define VIREO_SERVICE_AUTH_COMPLETION_INTERNAL_H
#include <vireo/service/auth_completion.h>
/** 同原公开publisher的同步函数签名，不能保存输入借用或伪造交接事实。 */
typedef vireo_result_t (*vireo_auth_publish_fn)(vireo_task_t const *, vireo_result_t,
    vireo_status_t, void const *, size_t, size_t, vireo_completion_queue_t *,
    vireo_notifier_t *, vireo_completion_t **, vireo_completion_publish_report_t *);
/** 同公共publish，额外必需公开依赖函数，只供本模块注入。 */
vireo_result_t vireo_auth_completion_publish_with(vireo_task_t const *task,
    vireo_auth_task_result_t const *result, size_t allocation_budget,
    vireo_completion_queue_t *queue, vireo_notifier_t *notifier,
    vireo_completion_t **remaining, vireo_auth_completion_publish_report_t *report,
    vireo_auth_publish_fn publish);
#endif

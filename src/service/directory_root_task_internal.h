/*
 * PROJECT : VIREO
 * FILE    : directory_root_task_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-22
 * BRIEF   : 根查询内部桥接与原线程所有权。
 */
#ifndef VIREO_SERVICE_DIRECTORY_ROOT_TASK_INTERNAL_H
#define VIREO_SERVICE_DIRECTORY_ROOT_TASK_INTERNAL_H
#include <vireo/service/directory_root_task.h>
/** 只借调用期context，回调遵守公开service合同，不保存输入地址。 */
typedef struct vireo_directory_root_task_ops {
    void *context; /**< 同步短借，不在execute返回后保存。 */
    vireo_result_t (*root)(void *, vireo_mysql_node_repository_t *,
                           const vireo_mysql_node_actor_t *, uint32_t,
                           vireo_directory_root_result_t *,
                           vireo_mysql_node_error_t *); /**< 原公开根服务语义。 */
} vireo_directory_root_task_ops_t;
/** 同公开execute，额外必需完整同步操作表；基本地址拒绝保持out。 */
vireo_result_t vireo_directory_root_task_execute_with(
    const vireo_task_t *task, const vireo_directory_root_task_options_t *options,
    vireo_mysql_node_repository_t *repository, uint64_t now_ns,
    vireo_directory_root_task_result_t *out, const vireo_directory_root_task_ops_t *ops);
#endif

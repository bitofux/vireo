/* PROJECT: VIREO; DATE: 2026-10-22; BRIEF: 本层同步service依赖接点。 */
#ifndef VIREO_SERVICE_DIRECTORY_STAT_TASK_INTERNAL_H
#define VIREO_SERVICE_DIRECTORY_STAT_TASK_INTERNAL_H
#include <vireo/service/directory_stat_task.h>
/** 只借调用期context，回调遵守公开service合同，不保存输入地址。 */
typedef struct vireo_directory_stat_task_ops {
    void *context;
    vireo_result_t (*stat)(void *, vireo_mysql_node_repository_t *, const vireo_mysql_node_actor_t *,
        uint64_t, uint32_t, vireo_directory_stat_result_t *, vireo_mysql_node_error_t *);
} vireo_directory_stat_task_ops_t;
/** 同公开execute，额外必需完整同步操作表；基本地址拒绝保持out。 */
vireo_result_t vireo_directory_stat_task_execute_with(const vireo_task_t *task,
    const vireo_directory_stat_task_options_t *options, vireo_mysql_node_repository_t *repository,
    uint64_t now_ns, vireo_directory_stat_task_result_t *out, const vireo_directory_stat_task_ops_t *ops);
#endif

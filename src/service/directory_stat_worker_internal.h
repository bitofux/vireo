/* PROJECT: VIREO; DATE: 2026-10-22; BRIEF: 本层公开依赖操作表，原owner语义。 */
#ifndef VIREO_SERVICE_DIRECTORY_STAT_WORKER_INTERNAL_H
#define VIREO_SERVICE_DIRECTORY_STAT_WORKER_INTERNAL_H
#include <vireo/service/directory_stat_worker.h>
/** 表按值复制，context长期借至destroy；不使用其他组件私有布局。 */
typedef struct vireo_directory_stat_worker_ops {
    void *context;
    void *(*allocate)(void *, size_t);
    void (*release)(void *, void *);
    vireo_result_t (*attach)(void *, vireo_mysql_runtime_t *, vireo_mysql_thread_t **, vireo_mysql_error_t *);
    vireo_result_t (*repository_create)(void *, vireo_mysql_thread_t *, vireo_mysql_pool_t *, vireo_mysql_node_repository_t **, vireo_mysql_node_error_t *);
    vireo_result_t (*clock)(void *, uint64_t *, vireo_clock_error_t *);
    vireo_result_t (*execute)(void *, const vireo_task_t *, const vireo_directory_stat_task_options_t *, vireo_mysql_node_repository_t *, uint64_t, vireo_directory_stat_task_result_t *);
    vireo_result_t (*repository_destroy)(void *, vireo_mysql_node_repository_t **, vireo_mysql_node_error_t *);
    vireo_result_t (*detach)(void *, vireo_mysql_thread_t **);
    vireo_result_t (*publish)(void *, const vireo_task_t *, uint32_t, const vireo_directory_stat_task_result_t *, size_t, vireo_completion_queue_t *, vireo_notifier_t *, vireo_completion_t **, vireo_directory_stat_completion_publish_report_t *);
    vireo_result_t (*completion_destroy)(void *, vireo_completion_t **);
} vireo_directory_stat_worker_ops_t;
/** 同公开create，额外完整同步操作表；所有权/线程/errno规则相同。 */
vireo_result_t vireo_directory_stat_worker_create_with(const vireo_directory_stat_worker_resources_t *,
    const vireo_directory_stat_worker_options_t *, vireo_directory_stat_worker_t **,
    const vireo_directory_stat_worker_ops_t *);
#endif

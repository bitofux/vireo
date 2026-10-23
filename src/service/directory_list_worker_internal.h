/* PROJECT : VIREO; FILE : directory_list_worker_internal.h; AUTHOR : bitofux;
 * DATE : 2026-10-23; BRIEF : LIST worker独占依赖与故障接点。 */
#ifndef VIREO_SERVICE_DIRECTORY_LIST_WORKER_INTERNAL_H
#define VIREO_SERVICE_DIRECTORY_LIST_WORKER_INTERNAL_H
#include <vireo/service/directory_list_worker.h>
/** @brief 表按值复制，context借至owner销毁，回调遵循对应公开owner合同。 */
typedef struct vireo_directory_list_worker_ops {
    void *context;
    void *(*allocate)(void *, size_t);
    void (*release)(void *, void *);
    vireo_result_t (*attach)(void *, vireo_mysql_runtime_t *, vireo_mysql_thread_t **,
                             vireo_mysql_error_t *);
    vireo_result_t (*repository_create)(void *, vireo_mysql_thread_t *, vireo_mysql_pool_t *,
                                        vireo_mysql_node_repository_t **,
                                        vireo_mysql_node_error_t *);
    vireo_result_t (*clock)(void *, uint64_t *, vireo_clock_error_t *);
    vireo_result_t (*execute)(void *, const vireo_task_t *,
                              const vireo_directory_list_task_options_t *,
                              vireo_mysql_node_repository_t *, const vireo_page_token_key_t *,
                              uint64_t, vireo_directory_list_task_result_t *);
    vireo_result_t (*repository_destroy)(void *, vireo_mysql_node_repository_t **,
                                         vireo_mysql_node_error_t *);
    vireo_result_t (*detach)(void *, vireo_mysql_thread_t **);
    vireo_result_t (*publish)(void *, const vireo_task_t *, uint32_t,
                              const vireo_directory_list_task_result_t *, size_t,
                              vireo_completion_queue_t *, vireo_notifier_t *, vireo_completion_t **,
                              vireo_directory_list_completion_publish_report_t *);
    vireo_result_t (*completion_destroy)(void *, vireo_completion_t **);
} vireo_directory_list_worker_ops_t;
vireo_result_t vireo_directory_list_worker_create_with(
    const vireo_directory_list_worker_resources_t *, const vireo_directory_list_worker_options_t *,
    vireo_directory_list_worker_t **, const vireo_directory_list_worker_ops_t *);
#endif

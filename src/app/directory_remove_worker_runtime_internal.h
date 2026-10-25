#ifndef VIREO_APP_DIRECTORY_REMOVE_WORKER_RUNTIME_INTERNAL_H
#define VIREO_APP_DIRECTORY_REMOVE_WORKER_RUNTIME_INTERNAL_H
#include "directory_remove_worker_runtime.h"
typedef struct vireo_directory_remove_worker_runtime_ops {
    void *context;
    vireo_result_t (*create)(void *,const vireo_directory_remove_worker_resources_t *,
        const vireo_directory_remove_worker_options_t *,vireo_directory_remove_worker_t **);
    vireo_result_t (*run)(void *,vireo_directory_remove_worker_t *,const vireo_task_t *,
        vireo_directory_remove_worker_report_t *);
    vireo_result_t (*destroy)(void *,vireo_directory_remove_worker_t **,
        vireo_directory_remove_worker_cleanup_report_t *);
    vireo_result_t (*previous_execute)(void *,vireo_directory_move_worker_runtime_t *,const vireo_task_t *);
} vireo_directory_remove_worker_runtime_ops_t;
vireo_result_t vireo_directory_remove_worker_runtime_execute_with(
    vireo_directory_remove_worker_runtime_t *,const vireo_task_t *,
    const vireo_directory_remove_worker_runtime_ops_t *);
#endif

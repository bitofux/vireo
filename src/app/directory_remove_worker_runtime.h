#ifndef VIREO_APP_DIRECTORY_REMOVE_WORKER_RUNTIME_H
#define VIREO_APP_DIRECTORY_REMOVE_WORKER_RUNTIME_H
#include "directory_move_worker_runtime.h"
#include <vireo/service/directory_remove_worker.h>
typedef enum vireo_directory_remove_worker_fault {
    VIREO_DIRECTORY_REMOVE_WORKER_FAULT_CREATE=1u,
    VIREO_DIRECTORY_REMOVE_WORKER_FAULT_TASK=2u,
    VIREO_DIRECTORY_REMOVE_WORKER_FAULT_CLEANUP=4u,
    VIREO_DIRECTORY_REMOVE_WORKER_FAULT_PUBLISH=8u,
    VIREO_DIRECTORY_REMOVE_WORKER_FAULT_RESIDUAL=16u,
    VIREO_DIRECTORY_REMOVE_WORKER_FAULT_DISPATCH=32u
} vireo_directory_remove_worker_fault_t;
typedef struct vireo_directory_remove_worker_faults { unsigned auth,stat,root,list,mkdir,move,remove; } vireo_directory_remove_worker_faults_t;
typedef struct vireo_directory_remove_worker_runtime {
    vireo_directory_move_worker_runtime_t *previous;
    vireo_directory_remove_worker_resources_t resources;
    vireo_directory_remove_worker_options_t options;
    size_t destroy_attempts;
    atomic_uint faults;
} vireo_directory_remove_worker_runtime_t;
vireo_result_t vireo_directory_remove_worker_runtime_init(vireo_directory_remove_worker_runtime_t *,vireo_directory_move_worker_runtime_t *,const vireo_directory_remove_worker_resources_t *,const vireo_directory_remove_worker_options_t *,size_t);
vireo_result_t vireo_directory_remove_worker_runtime_inspect_faults(const vireo_directory_remove_worker_runtime_t *,vireo_directory_remove_worker_faults_t *);
vireo_result_t vireo_directory_remove_worker_runtime_execute(void *,const vireo_task_t *);
#endif

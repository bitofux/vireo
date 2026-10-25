/* PROJECT : VIREO; FILE : directory_remove_internal.h; BRIEF : service依赖seam。 */
#ifndef VIREO_SERVICE_DIRECTORY_REMOVE_INTERNAL_H
#define VIREO_SERVICE_DIRECTORY_REMOVE_INTERNAL_H
#include <vireo/service/directory_remove.h>
typedef struct vireo_directory_remove_runtime {
    void *context;
    vireo_result_t (*remove_once)(void *, vireo_mysql_node_repository_t *,
        const vireo_mysql_node_actor_t *, const vireo_mysql_node_remove_once_input_t *, uint32_t,
        vireo_mysql_node_remove_once_report_t *, vireo_mysql_node_error_t *);
} vireo_directory_remove_runtime_t;
vireo_result_t vireo_directory_service_remove_with_runtime(vireo_mysql_node_repository_t *,
    const vireo_mysql_node_actor_t *, const vireo_mysql_node_remove_once_input_t *, uint32_t,
    vireo_directory_remove_result_t *, vireo_mysql_node_error_t *, const vireo_directory_remove_runtime_t *);
#endif

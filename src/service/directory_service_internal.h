/* PROJECT : VIREO; FILE : directory_service_internal.h; AUTHOR : bitofux;
 * DATE : 2026-10-22; BRIEF : 单次调用的STAT测试依赖，不替换全局状态。 */
#ifndef VIREO_SERVICE_DIRECTORY_SERVICE_INTERNAL_H
#define VIREO_SERVICE_DIRECTORY_SERVICE_INTERNAL_H
#include <vireo/service/directory_service.h>

/** @brief 调用期短借的同步依赖；回调遵循公开repo stat合同，不保存借用地址。 */
typedef struct vireo_directory_service_runtime {
    void *context; /**< caller拥有，借至返回，原生入口为NULL。 */
    vireo_result_t (*stat)(void *, vireo_mysql_node_repository_t *,
        const vireo_mysql_node_actor_t *, uint64_t, uint32_t,
        vireo_mysql_node_value_t *, vireo_mysql_node_report_t *, vireo_mysql_node_error_t *);
        /**< 同公开repo stat；error在本接点始终非NULL。 */
} vireo_directory_service_runtime_t;

/**
 * @brief STAT的本组件私有依赖接点，其余参数、输出、线程与errno合同同公开入口。
 * @param[in,out] repository 同公开stat。
 * @param[in] actor 同公开stat。
 * @param[in] node_id 同公开stat。
 * @param[in] timeout_ms 同公开stat。
 * @param[out] result 同公开stat。
 * @param[out] error 同公开stat，可NULL。
 * @param[in] runtime 必需完整同步依赖，短借至返回，不保存或接管。
 * @return 同公开stat；runtime或回调NULL时INVALID_ARGUMENT且保持输出。
 */
vireo_result_t vireo_directory_service_stat_with_runtime(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, uint64_t node_id, uint32_t timeout_ms,
    vireo_directory_stat_result_t *result, vireo_mysql_node_error_t *error,
    const vireo_directory_service_runtime_t *runtime);
#endif

/* PROJECT : VIREO; FILE : directory_root_internal.h; AUTHOR : bitofux;
 * DATE : 2026-10-22; BRIEF : 调用期同步根查询依赖，不替换全局状态。 */
#ifndef VIREO_SERVICE_DIRECTORY_ROOT_INTERNAL_H
#define VIREO_SERVICE_DIRECTORY_ROOT_INTERNAL_H
#include <vireo/service/directory_root.h>

/** @brief 短借至返回；回调遵守公开get_root合同，不保存借用地址。 */
typedef struct vireo_directory_root_runtime {
    void *context; /**< caller拥有；原生入口为NULL，无所有权交接。 */
    vireo_result_t (*get_root)(void *, vireo_mysql_node_repository_t *,
        const vireo_mysql_node_actor_t *, uint32_t, vireo_mysql_node_value_t *,
        vireo_mysql_node_report_t *, vireo_mysql_node_error_t *);
        /**< 同公开repo get_root；本接点始终提供非NULL诊断。 */
} vireo_directory_root_runtime_t;

/**
 * @brief 私有同步依赖接点；业务/输出/线程/errno合同同公开根查询服务。
 * @param[in,out] repository 同公开root，短借且不接管。
 * @param[in] actor 同公开root，调用期稳定可信值。
 * @param[in] timeout_ms 同公开root，只限制池等待。
 * @param[out] result 同公开root，独立输出。
 * @param[out] error 同公开root，可NULL。
 * @param[in] runtime 必需完整同步依赖，短借至返回，不保存。
 * @return 同公开root；runtime或回调NULL时INVALID_ARGUMENT并保持输出。
 */
vireo_result_t vireo_directory_service_root_with_runtime(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, uint32_t timeout_ms,
    vireo_directory_root_result_t *result, vireo_mysql_node_error_t *error,
    const vireo_directory_root_runtime_t *runtime);
#endif

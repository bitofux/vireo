/* PROJECT : VIREO; FILE : directory_move_internal.h; AUTHOR : bitofux;
 * DATE : 2026-10-24; BRIEF : 单次同步服务依赖。 */
#ifndef VIREO_SERVICE_DIRECTORY_MOVE_INTERNAL_H
#define VIREO_SERVICE_DIRECTORY_MOVE_INTERNAL_H
#include <vireo/service/directory_move.h>

/** @brief 调用期稳定依赖，回调遵守对应公开接口且不保存地址。 */
typedef struct vireo_directory_move_runtime {
    void *context; /**< caller拥有，原生NULL，无所有权转移。 */
    vireo_result_t (*name_validate)(void *, const unsigned char *, size_t,
        vireo_directory_name_issue_t *);
    /**< 同公开name_validate，不把分配故障伪装成名字拒绝。 */
    vireo_result_t (*move_once)(void *, vireo_mysql_node_repository_t *,
        const vireo_mysql_node_actor_t *, const vireo_mysql_node_move_once_input_t *, uint32_t,
        vireo_mysql_node_move_once_report_t *, vireo_mysql_node_error_t *);
    /**< 同02公开入口，本层始终提供非NULL诊断，最多调用一次。 */
} vireo_directory_move_runtime_t;

/**
 * @brief 本组件私有同步入口，其余合同同公开move服务
 * @param[in,out] repository 必需当前worker的存活repo，短借。
 * @param[in] actor 必需可信持久身份，短借。
 * @param[in] input 必需稳定原载荷和独立可信执行事件，短借。
 * @param[in] timeout_ms 池等待0..60000毫秒。
 * @param[out] result 必需独立输出，同公开服务。
 * @param[out] error 可NULL，数值诊断，同公开服务。
 * @param[in] runtime 必需完整回调，短借至返回，不保存。
 * @return 同公开服务；runtime/回调缺失时INVALID_ARGUMENT并保持输出。
 */
vireo_result_t vireo_directory_service_move_with_runtime(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_move_once_input_t *input,
    uint32_t timeout_ms, vireo_directory_move_result_t *result, vireo_mysql_node_error_t *error,
    const vireo_directory_move_runtime_t *runtime);
#endif

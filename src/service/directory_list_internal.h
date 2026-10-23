/* PROJECT : VIREO; AUTHOR : bitofux; DATE : 2026-10-22;
 * BRIEF : 调用期同步接点，无全局时钟/SQL/crypto替换。 */
#ifndef VIREO_SERVICE_DIRECTORY_LIST_INTERNAL_H
#define VIREO_SERVICE_DIRECTORY_LIST_INTERNAL_H
#include <time.h>
#include <vireo/service/directory_list.h>

/** @brief runtime和context只借至调用返回；回调不保存指针，遵守对应公开合同。 */
typedef struct vireo_directory_list_runtime {
    void *context;
    int (*utc)(void *, struct timespec *);
    vireo_result_t (*verify)(void *, const vireo_page_token_key_t *,
                             const vireo_page_token_context_t *, const vireo_page_token_t *,
                             uint64_t, vireo_page_token_claims_t *);
    vireo_result_t (*sign)(void *, const vireo_page_token_key_t *,
                           const vireo_page_token_claims_t *, uint64_t, vireo_page_token_t *);
    vireo_result_t (*list)(void *, vireo_mysql_node_repository_t *,
                           const vireo_mysql_node_actor_t *, const vireo_mysql_node_list_query_t *,
                           uint32_t, vireo_mysql_node_page_t *, vireo_mysql_node_report_t *,
                           vireo_mysql_node_error_t *);
} vireo_directory_list_runtime_t;

/** @brief 私有同步注入；合同同公开入口；runtime不完整时保持输出并INVALID_ARGUMENT。 */
vireo_result_t vireo_directory_service_list_with_runtime(
    vireo_mysql_node_repository_t *repository, const vireo_page_token_key_t *key,
    const vireo_mysql_node_actor_t *actor, const vireo_directory_list_query_t *query,
    uint32_t timeout_ms, vireo_directory_list_result_t *result, vireo_directory_list_error_t *error,
    const vireo_directory_list_runtime_t *runtime);
#endif

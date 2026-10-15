/* 仅本核心实现/测试使用，不依赖其他模块私有布局。 */
#ifndef VIREO_NET_ASYNC_COMPLETION_RECOVERY_INTERNAL_H
#define VIREO_NET_ASYNC_COMPLETION_RECOVERY_INTERNAL_H
#include <vireo/net/async_completion_recovery.h>

/** 三公开边界短借表，替身须遵守原失败保持/消费合同。 */
typedef struct vireo_async_completion_recovery_ops {
    vireo_result_t (*inspect)(void *, vireo_completion_t const *, vireo_completion_info_t *); /**< 只读原对象。 */
    vireo_result_t (*refresh)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_tcp_server_client_error_t *); /**< 一次原flow刷新。 */
    vireo_result_t (*destroy)(void *, vireo_completion_t **); /**< 原配对释放。 */
} vireo_async_completion_recovery_ops_t;

vireo_result_t vireo_async_completion_recovery_with_ops(vireo_tcp_server_t *server,
    vireo_completion_metadata_t expected, vireo_completion_t **owner,
    vireo_async_completion_recovery_step_t from, vireo_async_completion_recovery_report_t *report,
    vireo_async_completion_recovery_ops_t const *ops, void *context);
#endif

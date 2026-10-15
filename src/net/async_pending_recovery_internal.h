/* 本层公开三边界seam，不包含任何外模块private。 */
#ifndef VIREO_NET_ASYNC_PENDING_RECOVERY_INTERNAL_H
#define VIREO_NET_ASYNC_PENDING_RECOVERY_INTERNAL_H
#include <vireo/net/async_pending_recovery.h>

/** 完整稳定只读表/context仅本次短借，替身须遵守原消费/保持/诊断合同。 */
typedef struct vireo_async_pending_recovery_ops {
    vireo_result_t (*consume)(void *, vireo_tcp_server_t *, vireo_async_request_pending_t *,
        vireo_async_request_head_report_t *); /**< 一次公开resume，OK清记录，错误保记录。 */
    vireo_result_t (*refresh)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_tcp_server_client_error_t *); /**< 一次公开flow，原MOD进度与诊断。 */
    vireo_result_t (*schedule)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_tcp_server_client_error_t *); /**< 一次公开去重FIFO，不重提task。 */
} vireo_async_pending_recovery_ops_t;

/**
 * @brief
 *     公共同一实现，只隔离本层三个公开依赖；缺表/函数INVALID。
 *
 * @param[in,out] server
 *     原资源根短借。
 * @param[in] client
 *     原完整数值身份。
 * @param[in,out] pending
 *     原唯一记录，后段起点须空。
 * @param[in] resume_from
 *     原三个可输入起点。
 * @param[out] report
 *     必需完整真实前缀报告。
 * @param[in] ops
 *     完整稳定表，不保存地址或认证历史。
 * @param[in,out] context
 *     可空独立短借，不保存。
 *
 * @return
 *     沿公共合同，每可写路径报告/保持errno，无重试或清理。
 */
vireo_result_t vireo_async_pending_recovery_with_ops(vireo_tcp_server_t *,
    vireo_connection_pool_lease_t, vireo_async_request_pending_t *, vireo_async_pending_recovery_step_t,
    vireo_async_pending_recovery_report_t *, vireo_async_pending_recovery_ops_t const *, void *);
#endif /* VIREO_NET_ASYNC_PENDING_RECOVERY_INTERNAL_H */

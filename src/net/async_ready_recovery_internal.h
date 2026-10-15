/* 本层唯一公开schedule边界，不包含外模块private。 */
#ifndef VIREO_NET_ASYNC_READY_RECOVERY_INTERNAL_H
#define VIREO_NET_ASYNC_READY_RECOVERY_INTERNAL_H
#include <vireo/net/async_ready_recovery.h>

/** 稳定只读表和context仅本次短借，替身遵守原调度/诊断合同。 */
typedef struct vireo_async_ready_recovery_ops {
    vireo_result_t (*schedule)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_tcp_server_client_error_t *); /**< 每选中项最多一次公开schedule，不重试。 */
} vireo_async_ready_recovery_ops_t;

/**
 * @brief
 *     与公共入口同一实现，仅替换本层公开schedule供故障隔离。
 *
 * @param[in,out] server
 *     沿公共入口资源根短借。
 * @param[in] ready
 *     原稳定只读有效前缀，count0可NULL。
 * @param[in] ready_count
 *     原有效元素数0..65535。
 * @param[in] begin_index
 *     原显式起点0..count。
 * @param[in] max_clients
 *     原正调用预算≤65535。
 * @param[out] report
 *     必需完整真实进度报告。
 * @param[in] ops
 *     必需完整稳定单边界表，不保存。
 * @param[in,out] context
 *     可空独立短借故障上下文，不保存。
 *
 * @return
 *     沿公共合同；缺表/函数INVALID，每可写路径发布报告并保持errno。
 */
vireo_result_t vireo_async_ready_recovery_with_ops(vireo_tcp_server_t *,
    vireo_tcp_server_ready_client_t const *, size_t, size_t, size_t,
    vireo_async_ready_recovery_report_t *, vireo_async_ready_recovery_ops_t const *, void *);
#endif /* VIREO_NET_ASYNC_READY_RECOVERY_INTERNAL_H */

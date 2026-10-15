/* 本层公开接线边界，禁止包含别模块private。 */
#ifndef VIREO_NET_ASYNC_REQUEST_HEAD_INTERNAL_H
#define VIREO_NET_ASYNC_REQUEST_HEAD_INTERNAL_H
#include <vireo/net/async_request_head.h>

/** 稳定完整表/context只借至返回，替身遵守原预算/输出/拥有合同。 */
typedef struct vireo_async_request_head_ops {
    vireo_result_t (*frames)(void *, vireo_tcp_server_t const *, vireo_connection_pool_lease_t,
        vireo_connection_frame_options_t const *, vireo_connection_frame_budget_t const *,
        vireo_connection_frame_view_t *, size_t, vireo_connection_frame_info_t *, vireo_tcp_server_client_error_t *);
        /**< 一次公开首帧校验，不消费。 */
    vireo_result_t (*read)(void *, vireo_tcp_server_t const *, vireo_connection_pool_lease_t,
        uint8_t const **, size_t *, vireo_tcp_server_client_error_t *);
        /**< 一次公开连续原读区短借。 */
    vireo_result_t (*submit)(void *, vireo_tcp_server_t const *, vireo_connection_pool_lease_t,
        vireo_inflight_store_t *, vireo_thread_pool_t *, uint8_t const *, size_t, size_t, size_t,
        size_t, uint32_t, uint64_t, vireo_task_cancel_t *, vireo_task_t **, vireo_async_request_report_t *);
        /**< 一次公开031-01，原转移/残留报告保留。 */
    vireo_result_t (*consume)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        size_t, vireo_tcp_server_client_error_t *);
        /**< 一次公开consume，错误保持读区，成功消费明确字节。 */
} vireo_async_request_head_ops_t;

/**
 * @brief
 *     同一实现仅替换四个公开边界，前十三参数沿public；表必须完整，不保存。
 *
 * @param[in] ops
 *     必需稳定完整表。
 * @param[in,out] ops_context
 *     可空独立短借隔离上下文。
 *
 * @return
 *     沿public，缺表/任一函数INVALID；每路径报告/errno保持。
 */
vireo_result_t vireo_async_request_head_with_ops(vireo_tcp_server_t *, vireo_connection_pool_lease_t,
    vireo_inflight_store_t *, vireo_thread_pool_t *, size_t, size_t, size_t, uint32_t, uint64_t,
    vireo_task_cancel_t *, vireo_async_request_pending_t *, vireo_task_t **,
    vireo_async_request_head_report_t *, vireo_async_request_head_ops_t const *, void *);

/**
 * @brief
 *     同一恢复实现，仅隔离完整公开依赖表；前三参数沿public。
 *
 * @param[in] ops
 *     必需稳定完整表，只实际调用consume。
 * @param[in,out] ops_context
 *     可空独立短借隔离上下文。
 *
 * @return
 *     沿public，缺表/任一函数INVALID；不提交、每路径报告/errno保持。
 */
vireo_result_t vireo_async_request_resume_with_ops(vireo_tcp_server_t *,
    vireo_async_request_pending_t *, vireo_async_request_head_report_t *,
    vireo_async_request_head_ops_t const *, void *);
#endif /* VIREO_NET_ASYNC_REQUEST_HEAD_INTERNAL_H */

/* 仅本组合的公开依赖替身；不访问任何外模块私有布局。 */
#ifndef VIREO_NET_ASYNC_CLIENT_DRIVE_TLS_INTERNAL_H
#define VIREO_NET_ASYNC_CLIENT_DRIVE_TLS_INTERNAL_H
#include <vireo/net/async_client_drive_tls.h>

/** 七边界完整稳定只读表；context同步短借，替身遵守真实提交/报告合同。 */
typedef struct vireo_async_client_drive_tls_ops {
    vireo_result_t (*io_inspect)(void *, vireo_tls_connection_t const *, vireo_tls_io_info_t *,
        vireo_tls_connection_error_t *); /**< 只读IO观察，不制造native进度。 */
    vireo_result_t (*flow)(void *, vireo_tls_connection_t *, vireo_tls_io_flow_t *,
        vireo_tls_connection_error_t *); /**< 原TLS纯flow刷新，不同步epoll。 */
    vireo_result_t (*receive)(void *, vireo_tls_connection_t *, vireo_tls_io_budget_t const *,
        vireo_tls_io_progress_t *, vireo_tls_connection_error_t *); /**< 一次有界receive；前置失败可保持报告。 */
    vireo_result_t (*send)(void *, vireo_tls_connection_t *, vireo_tls_io_budget_t const *,
        vireo_tls_io_progress_t *, vireo_tls_connection_error_t *); /**< 一次有界send，不补预算。 */
    vireo_result_t (*frames)(void *, vireo_tcp_server_t const *, vireo_connection_pool_lease_t,
        vireo_connection_frame_options_t const *, vireo_connection_frame_budget_t const *,
        vireo_connection_frame_view_t *, size_t, vireo_connection_frame_info_t *,
        vireo_tcp_server_client_error_t *); /**< 原REQUEST短借，不消费。 */
    vireo_result_t (*head)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_inflight_store_t *, vireo_thread_pool_t *, size_t, size_t, size_t, uint32_t, uint64_t,
        vireo_task_cancel_t *, vireo_async_request_pending_t *, vireo_task_t **,
        vireo_async_request_head_report_t *); /**< 原唯一移交/消费，禁止伪造task transfer。 */
    vireo_result_t (*sync)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_tcp_server_tls_flow_info_t *, vireo_tcp_server_tls_application_error_t *);
        /**< 原公开完整TLS flow/实际关注/有限恢复续排。 */
} vireo_async_client_drive_tls_ops_t;

/** 与公开入口同一核心；只替换本层七边界，不保存ops/context，缺项INVALID。 */
vireo_result_t vireo_async_client_drive_tls_with_ops(vireo_tcp_server_t *, vireo_connection_pool_lease_t,
    vireo_inflight_store_t *, vireo_thread_pool_t *, vireo_async_client_drive_options_t const *,
    vireo_async_client_drive_tls_budget_t const *, vireo_task_cancel_t *, vireo_async_request_pending_t *,
    vireo_task_t **, vireo_async_client_drive_tls_report_t *, vireo_async_client_drive_tls_ops_t const *, void *);
#endif /* VIREO_NET_ASYNC_CLIENT_DRIVE_TLS_INTERNAL_H */

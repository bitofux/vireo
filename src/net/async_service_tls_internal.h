/* 本层独立公开边界seam，不含其他模块private。 */
#ifndef VIREO_NET_ASYNC_SERVICE_TLS_INTERNAL_H
#define VIREO_NET_ASYNC_SERVICE_TLS_INTERNAL_H
#include <vireo/net/async_service_tls.h>
/** 六边界稳定只读表，替身遵守原容量/真实前缀/owner合同，context只借至返回。 */
typedef struct vireo_async_service_tls_ops {
    vireo_result_t (*inspect)(void *,vireo_tcp_server_t const *,vireo_tcp_server_info_t *); /**< 入口/接入前stop观察。 */
    vireo_result_t (*pressure)(void *,vireo_tcp_server_t *,vireo_tcp_server_tls_admission_info_t *,
        vireo_tcp_server_listener_error_t *); /**< pre/post各最多一次。 */
    vireo_result_t (*poll)(void *,vireo_tcp_server_t *,int,size_t,vireo_tcp_server_ready_client_t *,size_t,
        vireo_tcp_server_tls_poll_report_t *,vireo_tcp_server_tls_error_t *); /**< 一次期限poll。 */
    vireo_result_t (*dispatch)(void *,vireo_tcp_server_t *,vireo_event_loop_handle_t,vireo_notifier_t *,
        vireo_inflight_store_t *,vireo_completion_queue_t *,size_t,size_t,size_t,uint8_t *,size_t,
        vireo_completion_response_resolve_fn,void *,vireo_completion_t **,
        vireo_completion_response_dispatch_tls_report_t *); /**< 一次TLS分发。 */
    vireo_result_t (*clients)(void *,vireo_tcp_server_t *,vireo_inflight_store_t *,vireo_thread_pool_t *,size_t,
        vireo_async_round_tls_configure_fn,void *,vireo_tcp_server_ready_client_t const *,size_t,
        vireo_async_round_tls_turn_t *,size_t,vireo_task_t **,vireo_async_round_tls_report_t *); /**< 不再poll的同批次处理。 */
    vireo_result_t (*admit)(void *,vireo_tcp_server_t *,vireo_tcp_server_admit_budget_t const *,
        vireo_connection_pool_lease_t *,size_t,vireo_tcp_server_tls_admit_info_t *,
        vireo_tcp_server_tls_error_t *); /**< 一次有界TLS接入，含错误发布前缀。 */
} vireo_async_service_tls_ops_t;
/** 与公开入口同实现，额外只借完整ops/context；缺项INVALID，报告/errno沿公开合同。 */
vireo_result_t vireo_async_service_tls_with_ops(vireo_tcp_server_t *,vireo_inflight_store_t *,vireo_thread_pool_t *,
    vireo_notifier_t *,vireo_completion_queue_t *,vireo_event_loop_handle_t,vireo_async_service_tls_options_t const *,
    vireo_async_service_tls_workspace_t const *,vireo_async_round_tls_configure_fn,void *,
    vireo_completion_response_resolve_fn,void *,vireo_task_t **,vireo_completion_t **,
    vireo_async_service_tls_report_t *,vireo_async_service_tls_ops_t const *,void *);
#endif /* VIREO_NET_ASYNC_SERVICE_TLS_INTERNAL_H */

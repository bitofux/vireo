/* 仅本轮公开依赖边界，不包含外模块private。 */
#ifndef VIREO_NET_ASYNC_ROUND_TLS_INTERNAL_H
#define VIREO_NET_ASYNC_ROUND_TLS_INTERNAL_H
#include <vireo/net/async_round_tls.h>

/** 五边界稳定完整表/context只同步短借，替身不伪造真实移交或改变外模块布局。 */
typedef struct vireo_async_round_tls_ops {
    vireo_result_t (*poll)(void *, vireo_tcp_server_t *, int, size_t,
        vireo_tcp_server_ready_client_t *, size_t, vireo_tcp_server_tls_poll_report_t *, vireo_tcp_server_tls_error_t *);
        /**< 一次原期限感知poll，错误仍保selected真实前缀。 */
    vireo_result_t (*handshake)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_tcp_server_tls_handshake_info_t *, vireo_tcp_server_tls_error_t *);
        /**< 一次公开握手，真实建立后只交接下轮。 */
    vireo_result_t (*close)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t, size_t,
        vireo_tcp_server_tls_close_step_info_t *, vireo_tcp_server_tls_close_error_t *);
        /**< 一次公开关闭step，不能自动消费尾部或归还。 */
    vireo_result_t (*drive)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_inflight_store_t *, vireo_thread_pool_t *, vireo_async_client_drive_options_t const *,
        vireo_async_client_drive_tls_budget_t const *, vireo_task_cancel_t *, vireo_async_request_pending_t *,
        vireo_task_t **, vireo_async_client_drive_tls_report_t *);
        /**< 原034-16单客户驱动，真实移交/消费/残留报告保持。 */
    vireo_result_t (*schedule)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_tcp_server_client_error_t *); /**< 原公开一次排尾，去重不等新插入。 */
} vireo_async_round_tls_ops_t;

/** 同一公开核心的本层五边界seam，缺项INVALID；ops/context不保存，其余合同沿public。 */
vireo_result_t vireo_async_round_tls_with_ops(vireo_tcp_server_t *, vireo_inflight_store_t *, vireo_thread_pool_t *,
    vireo_async_round_tls_options_t const *, vireo_async_round_tls_configure_fn, void *,
    vireo_tcp_server_ready_client_t *, size_t, vireo_async_round_tls_turn_t *, size_t, vireo_task_t **,
    vireo_async_round_tls_report_t *, vireo_async_round_tls_ops_t const *, void *);
#endif /* VIREO_NET_ASYNC_ROUND_TLS_INTERNAL_H */

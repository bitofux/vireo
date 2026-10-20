#ifndef VIREO_NET_AUTH_REQUEST_SUBMIT_INTERNAL_H
#define VIREO_NET_AUTH_REQUEST_SUBMIT_INTERNAL_H
#include <vireo/net/auth_request_submit.h>

/* 仅本组件自测隔离依赖；默认全部使用公开API，不是可注入生产政策。 */
typedef struct vireo_auth_request_submit_ops {
    vireo_result_t (*ready)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_tcp_server_tls_error_t *, vireo_tls_connection_error_t *);
    vireo_result_t (*peer)(void *, vireo_tcp_server_t const *, vireo_connection_pool_lease_t,
        vireo_connection_peer_t *, vireo_tcp_server_client_error_t *);
    vireo_result_t (*submit)(void *, vireo_tcp_server_t const *, vireo_connection_pool_lease_t,
        vireo_inflight_store_t *, vireo_thread_pool_t *, uint8_t const *, size_t, size_t, size_t,
        size_t, uint32_t, uint64_t, vireo_task_cancel_t *, vireo_task_t **, vireo_async_request_report_t *);
} vireo_auth_request_submit_ops_t;

vireo_result_t vireo_auth_request_submit_with(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    vireo_auth_login_admission_t *admission, vireo_monotonic_ns_t now, vireo_auth_sessions_t *sessions, uint64_t utc,
    uint8_t const *wire, size_t wire_size, vireo_auth_request_submit_options_t const *options,
    vireo_task_cancel_t *cancel, vireo_task_t **remaining_task,
    vireo_auth_request_submit_report_t *report, vireo_auth_request_submit_ops_t const *ops,
    void *context);
#endif

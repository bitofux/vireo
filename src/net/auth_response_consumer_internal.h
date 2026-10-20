/* 仅本组件公开依赖的同步注入边界，不接其他组件私有头。 */
#ifndef VIREO_NET_AUTH_RESPONSE_CONSUMER_INTERNAL_H
#define VIREO_NET_AUTH_RESPONSE_CONSUMER_INTERNAL_H
#include <vireo/net/auth_response_consumer.h>
typedef struct vireo_auth_response_consumer_ops {
    vireo_result_t (*enqueue)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        unsigned char const *, size_t, vireo_tcp_server_client_error_t *);
    vireo_result_t (*refresh)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_tcp_server_tls_flow_info_t *, vireo_tcp_server_tls_application_error_t *);
} vireo_auth_response_consumer_ops_t;
vireo_result_t vireo_auth_response_consumer_with(vireo_tcp_server_t *server,
    vireo_inflight_store_t *store, vireo_auth_sessions_t *sessions, vireo_completion_t **owner,
    vireo_auth_response_consumer_options_t const *options, uint64_t now_utc_ms,
    vireo_auth_response_consumer_receipt_t *receipt, vireo_auth_response_consumer_report_t *report,
    vireo_auth_response_consumer_ops_t const *ops, void *context);
#endif

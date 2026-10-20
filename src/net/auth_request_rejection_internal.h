/* 本模块own故障接点；仅包装公开完整入队及TLS关注刷新。 */
#ifndef VIREO_NET_AUTH_REQUEST_REJECTION_INTERNAL_H
#define VIREO_NET_AUTH_REQUEST_REJECTION_INTERNAL_H
#include <vireo/net/auth_request_rejection.h>
typedef struct vireo_auth_request_rejection_ops {
    vireo_result_t (*enqueue)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        uint8_t const *, size_t, vireo_tcp_server_client_error_t *);
    vireo_result_t (*refresh)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_tcp_server_tls_flow_info_t *, vireo_tcp_server_tls_application_error_t *);
} vireo_auth_request_rejection_ops_t;
vireo_result_t vireo_auth_request_rejection_with(vireo_tcp_server_t *server,
    vireo_auth_request_head_receipt_t const *head, vireo_auth_request_rejection_receipt_t *receipt,
    vireo_auth_request_rejection_report_t *report, vireo_auth_request_rejection_ops_t const *ops,
    void *context);
vireo_result_t vireo_auth_request_rejection_classify(vireo_auth_request_head_receipt_t const *head,
    vireo_status_t *status);
#endif

/*
 * PROJECT : VIREO
 * FILE    : auth_request_head_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-20
 * BRIEF   : 本组件自测的窄依赖隔离，不作为生产注入入口
 */
#ifndef VIREO_NET_AUTH_REQUEST_HEAD_INTERNAL_H
#define VIREO_NET_AUTH_REQUEST_HEAD_INTERNAL_H
#include <vireo/net/auth_request_head.h>

typedef struct vireo_auth_request_head_ops {
    vireo_result_t (*frames)(void *, vireo_tcp_server_t const *, vireo_connection_pool_lease_t,
        vireo_connection_frame_options_t const *, vireo_connection_frame_budget_t const *,
        vireo_connection_frame_view_t *, size_t, vireo_connection_frame_info_t *,
        vireo_tcp_server_client_error_t *);
    vireo_result_t (*read)(void *, vireo_tcp_server_t const *, vireo_connection_pool_lease_t,
        uint8_t const **, size_t *, vireo_tcp_server_client_error_t *);
    vireo_result_t (*submit)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_inflight_store_t *, vireo_thread_pool_t *, vireo_auth_login_admission_t *,
        vireo_monotonic_ns_t, vireo_auth_sessions_t *, uint64_t, uint8_t const *, size_t, vireo_auth_request_submit_options_t const *,
        vireo_task_cancel_t *, vireo_task_t **, vireo_auth_request_submit_report_t *);
    vireo_result_t (*consume)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        size_t, vireo_tcp_server_client_error_t *);
} vireo_auth_request_head_ops_t;

vireo_result_t vireo_auth_request_head_with(vireo_tcp_server_t *, vireo_connection_pool_lease_t,
    vireo_inflight_store_t *, vireo_thread_pool_t *, vireo_auth_login_admission_t *,
    vireo_monotonic_ns_t, vireo_auth_sessions_t *, uint64_t, vireo_auth_request_submit_options_t const *, vireo_task_cancel_t *,
    vireo_auth_request_head_receipt_t *, vireo_task_t **, vireo_auth_request_head_report_t *,
    vireo_auth_request_head_ops_t const *, void *);
vireo_result_t vireo_auth_request_head_resume_with(vireo_tcp_server_t *,
    vireo_auth_request_head_receipt_t *, vireo_auth_request_head_report_t *,
    vireo_auth_request_head_ops_t const *, void *);
#endif

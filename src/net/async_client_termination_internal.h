/*
 * PROJECT : VIREO
 * FILE    : async_client_termination_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 仅本接线层短借的公开依赖模型，无外模块私有布局
 */
#ifndef VIREO_NET_ASYNC_CLIENT_TERMINATION_INTERNAL_H
#define VIREO_NET_ASYNC_CLIENT_TERMINATION_INTERNAL_H
#include <vireo/net/async_client_termination.h>

/** 四个公开依赖边界，替身须保原消费/部分进度合同，无全局故障开关。 */
typedef struct vireo_async_client_termination_ops {
    vireo_result_t (*inspect)(void *, vireo_inflight_store_t const *,
        vireo_inflight_store_info_t *); /**< 只读表容量，无内部槽借用。 */
    vireo_result_t (*close)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_connection_close_mode_t, vireo_connection_close_reason_t,
        vireo_tcp_server_client_error_t *); /**< 一次公开关闭意图。 */
    vireo_result_t (*release)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t *,
        vireo_tcp_server_client_error_t *); /**< 原归还，消费型失败须真实清零租约。 */
    vireo_result_t (*cleanup)(void *, vireo_inflight_store_t *, vireo_connection_pool_lease_t,
        size_t, size_t, vireo_inflight_client_cleanup_report_t *); /**< 一次有预算历史清退。 */
} vireo_async_client_termination_ops_t;

vireo_result_t vireo_async_client_termination_with_ops(vireo_tcp_server_t *server,
    vireo_inflight_store_t *store, vireo_connection_pool_lease_t client,
    vireo_connection_close_reason_t reason, vireo_async_client_termination_step_t from,
    size_t begin_index, size_t max_slots, vireo_async_client_termination_report_t *report,
    vireo_async_client_termination_ops_t const *ops, void *context);
#endif

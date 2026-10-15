/* 本层公开边界seam；不引入任何外模块private。 */
#ifndef VIREO_NET_ASYNC_SERVICE_INTERNAL_H
#define VIREO_NET_ASYNC_SERVICE_INTERNAL_H
#include <vireo/net/async_service.h>

/** 稳定只读六边界；替身同样遵守公开预算/转移/报告，context仅短借。 */
typedef struct vireo_async_service_ops {
    vireo_result_t (*pressure)(void *, vireo_tcp_server_t *, vireo_connection_options_t const *,
        vireo_async_admission_pressure_report_t *); /**< pre/post各最多一次，原开关真实进度。 */
    vireo_result_t (*poll)(void *, vireo_tcp_server_t *, int, size_t,
        vireo_tcp_server_ready_client_t *, size_t, vireo_tcp_server_listener_poll_report_t *);
        /**< 一次公开同次poll，完整已取前缀不能丢。 */
    vireo_result_t (*dispatch)(void *, vireo_tcp_server_t *, vireo_event_loop_handle_t, vireo_notifier_t *,
        vireo_inflight_store_t *, vireo_completion_queue_t *, size_t, size_t, size_t, uint8_t *, size_t,
        vireo_completion_response_resolve_fn, void *, vireo_completion_t **,
        vireo_completion_response_dispatch_report_t *); /**< 一次030原完成分发，无第二次。 */
    vireo_result_t (*drive)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_inflight_store_t *, vireo_thread_pool_t *, vireo_async_client_drive_options_t const *,
        vireo_async_client_drive_budget_t const *, vireo_task_cancel_t *, vireo_async_request_pending_t *,
        vireo_task_t **, vireo_async_client_drive_report_t *); /**< 每冻结客户最多一次单帧driver。 */
    vireo_result_t (*schedule)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_tcp_server_client_error_t *); /**< 仅成功有缓存时一次排尾。 */
    vireo_result_t (*admit)(void *, vireo_tcp_server_t *, vireo_connection_options_t const *,
        vireo_connection_flow_options_t const *, vireo_tcp_server_admit_budget_t const *,
        vireo_connection_pool_lease_t *, size_t, vireo_async_admission_turn_t *, size_t,
        vireo_async_admission_report_t *); /**< 一次03304，全部新租约与准备前缀原样。 */
} vireo_async_service_ops_t;

/**
 * @brief
 *     与公共入口同一实现，仅替换本层六公开边界；缺表或任一函数INVALID_ARGUMENT。
 *
 * @param[in,out] server
 *     沿公共入口短借网络根。
 * @param[in,out] store
 *     沿公共入口短借在途表。
 * @param[in,out] pool
 *     沿公共入口串行管理池。
 * @param[in,out] notifier
 *     沿公共入口提示资源。
 * @param[in,out] queue
 *     沿公共入口单consumer队列。
 * @param[in] expected_handle
 *     原完整辅助登记身份。
 * @param[in] options
 *     原八字段显式值。
 * @param[in,out] workspace
 *     原十字段caller工作区描述。
 * @param[in] configure
 *     原配置回调。
 * @param[in,out] configure_context
 *     可空配置context。
 * @param[in] resolve
 *     原描述回调。
 * @param[in,out] resolve_context
 *     可空描述context。
 * @param[out] remaining_task
 *     入口NULL的task owner。
 * @param[out] remaining_completion
 *     入口NULL的completion owner。
 * @param[out] report
 *     必需完整真实进度报告。
 * @param[in] ops
 *     完整稳定只读表，不保存。
 * @param[in,out] ops_context
 *     可空独立短借替身context，不保存。
 *
 * @return
 *     沿公共合同，每可写路径报告并保持errno。
 */
vireo_result_t vireo_async_service_with_ops(vireo_tcp_server_t *, vireo_inflight_store_t *,
    vireo_thread_pool_t *, vireo_notifier_t *, vireo_completion_queue_t *, vireo_event_loop_handle_t,
    vireo_async_service_options_t const *, vireo_async_service_workspace_t const *,
    vireo_async_round_configure_fn, void *, vireo_completion_response_resolve_fn, void *,
    vireo_task_t **, vireo_completion_t **, vireo_async_service_report_t *, vireo_async_service_ops_t const *, void *);
#endif /* VIREO_NET_ASYNC_SERVICE_INTERNAL_H */

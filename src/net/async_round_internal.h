/* 仅本层公开依赖边界；测试不包含其他模块private头。 */
#ifndef VIREO_NET_ASYNC_ROUND_INTERNAL_H
#define VIREO_NET_ASYNC_ROUND_INTERNAL_H
#include <vireo/net/async_round.h>

/** 稳定完整表/context只本次短借，不保存，不改变其他组件布局。 */
typedef struct vireo_async_round_ops {
    vireo_result_t (*poll)(void *, vireo_tcp_server_t *, int, size_t,
        vireo_tcp_server_ready_client_t *, size_t, vireo_tcp_server_poll_report_t *);
        /**< 原机械poll，必须保真实selected前缀/上限/队列义务。 */
    vireo_result_t (*drive)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_inflight_store_t *, vireo_thread_pool_t *, vireo_async_client_drive_options_t const *,
        vireo_async_client_drive_budget_t const *, vireo_task_cancel_t *, vireo_async_request_pending_t *,
        vireo_task_t **, vireo_async_client_drive_report_t *);
        /**< 原单客户驱动，真实移交/消费/残留不可伪造。 */
    vireo_result_t (*schedule)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_tcp_server_client_error_t *);
        /**< 一次公开排尾；错误后原待办义务沿公开合同。 */
} vireo_async_round_ops_t;

/**
 * @brief
 *     公共同实现的本层三边界seam，完整表/context本次短借，缺项INVALID。
 *
 * @param[in] ops
 *     必需稳定完整表；替身遵守原公开上限/输出/真实进度合同。
 * @param[in,out] ops_context
 *     可空本层独立短借，和caller配置context分离，不保存。
 *
 * @return
 *     其他参数/报告/errno沿公开入口，不修改旧private或共享故障全局。
 */
vireo_result_t vireo_async_round_with_ops(vireo_tcp_server_t *, vireo_inflight_store_t *,
    vireo_thread_pool_t *, int, size_t, vireo_async_round_configure_fn, void *,
    vireo_tcp_server_ready_client_t *, size_t, vireo_async_round_turn_t *, size_t,
    vireo_task_t **, vireo_async_round_report_t *, vireo_async_round_ops_t const *, void *);
#endif /* VIREO_NET_ASYNC_ROUND_INTERNAL_H */

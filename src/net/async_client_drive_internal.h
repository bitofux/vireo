/* 仅本接线层测试的公开依赖边界，不包含其他核心私有头。 */
#ifndef VIREO_NET_ASYNC_CLIENT_DRIVE_INTERNAL_H
#define VIREO_NET_ASYNC_CLIENT_DRIVE_INTERNAL_H
#include <vireo/net/async_client_drive.h>

/** 完整表及context仅短借至本次返回，不保存，不授予布局/资源指针；替身遵守原合同。 */
typedef struct vireo_async_client_drive_ops {
    vireo_result_t (*server_inspect)(void *, vireo_tcp_server_t const *, vireo_tcp_server_info_t *);
        /**< 公开只读阶段/停止观察，不变更server。 */
    vireo_result_t (*client_inspect)(void *, vireo_tcp_server_t const *, vireo_connection_pool_lease_t,
        vireo_tcp_server_client_info_t *);
        /**< 公开只读客户/压力/缓存观察，错误保持输出。 */
    vireo_result_t (*refresh)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_tcp_server_client_error_t *);
        /**< 一次公开flow刷新，不改读区或业务字节。 */
    vireo_result_t (*receive)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_connection_receive_budget_t const *, vireo_connection_receive_info_t *,
        vireo_tcp_server_client_error_t *);
        /**< 原有界接收，失败可有原报告的实际字节进度。 */
    vireo_result_t (*frames)(void *, vireo_tcp_server_t const *, vireo_connection_pool_lease_t,
        vireo_connection_frame_options_t const *, vireo_connection_frame_budget_t const *,
        vireo_connection_frame_view_t *, size_t, vireo_connection_frame_info_t *, vireo_tcp_server_client_error_t *);
        /**< 原首帧校验/短借view，不消费，header复制后结束view使用。 */
    vireo_result_t (*head)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_inflight_store_t *, vireo_thread_pool_t *, size_t, size_t, size_t, uint32_t, uint64_t,
        vireo_task_cancel_t *, vireo_async_request_pending_t *, vireo_task_t **, vireo_async_request_head_report_t *);
        /**< 原031提交/消费入口，真实转移及剩余owner/pending规则保持。 */
    vireo_result_t (*send)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_connection_send_budget_t const *, vireo_connection_send_info_t *, vireo_tcp_server_client_error_t *);
        /**< 原有界发送，不自动入队或回写业务。 */
} vireo_async_client_drive_ops_t;

/**
 * @brief
 *     与公开驱动同实现，只替换本层七个公开边界，缺项INVALID，不持久保存表。
 *
 * @param[in] ops
 *     必需完整稳定表；不读外模块私有头或候选布局，不伪造移交/消费成功。
 * @param[in,out] context
 *     可空独立短借上下文；真实故障和模型必须分别说明。
 *
 * @return
 *     其他沿公开参数/阶段/真实输出合同，报告每路径发布、errno保持。
 */
vireo_result_t vireo_async_client_drive_with_ops(vireo_tcp_server_t *, vireo_connection_pool_lease_t,
    vireo_inflight_store_t *, vireo_thread_pool_t *, vireo_async_client_drive_options_t const *,
    vireo_async_client_drive_budget_t const *, vireo_task_cancel_t *, vireo_async_request_pending_t *,
    vireo_task_t **, vireo_async_client_drive_report_t *, vireo_async_client_drive_ops_t const *, void *);
#endif /* VIREO_NET_ASYNC_CLIENT_DRIVE_INTERNAL_H */

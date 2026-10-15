/* 本接线层仅公开依赖 seam，不包含外模块 private。 */
#ifndef VIREO_NET_ASYNC_REQUEST_INTERNAL_H
#define VIREO_NET_ASYNC_REQUEST_INTERNAL_H
#include <vireo/net/async_request.h>

/** 稳定完整表/context 只借至返回；替身遵守公开输出、拥有及转移合同。 */
typedef struct vireo_async_request_ops {
    vireo_result_t (*metadata)(void *, vireo_tcp_server_t const *, vireo_connection_pool_lease_t,
        uint32_t, uint32_t, uint64_t, vireo_task_metadata_t *, vireo_inflight_stage_t *);
        /**< 一次公开客户桥接与发行。 */
    vireo_result_t (*copy)(void *, vireo_task_metadata_t, void const *, size_t, size_t,
        vireo_task_cancel_t *, vireo_task_t **);
        /**< 一次公开普通或带取消 task 复制，失败不发布半对象。 */
    vireo_result_t (*submit)(void *, vireo_inflight_store_t *, vireo_tcp_server_t const *,
        vireo_thread_pool_t *, size_t, vireo_task_t **, vireo_inflight_submit_report_t *);
        /**< 一次公开限额登记与提交，原真实转移/撤销报告保持。 */
} vireo_async_request_ops_t;

/**
 * @brief
 *     同一组合实现，只隔离本层公开依赖；前十四参数沿公共入口。
 *
 * @param[in] server
 *     沿公共入口客户资源根短借。
 * @param[in] client
 *     原完整客户租约。
 * @param[in,out] store
 *     原在途表短借。
 * @param[in,out] pool
 *     原池短借，管理 caller 串行。
 * @param[in] data
 *     原稳定连续单帧。
 * @param[in] size
 *     真实可读字节数。
 * @param[in] max_frame_bytes
 *     原显式整帧上限。
 * @param[in] task_allocation_budget
 *     原 task 申请预算。
 * @param[in] max_client_requests
 *     原正客户请求限额。
 * @param[in] operation
 *     原显式非零操作标签。
 * @param[in] deadline_ns
 *     原同域绝对纳秒值。
 * @param[in] cancel
 *     原可空强引用保护的取消对象。
 * @param[out] remaining_task
 *     原入口 NULL 的独占 owner。
 * @param[out] report
 *     原独立真实前缀。
 * @param[in] ops
 *     必需稳定完整三函数表，不保存。
 * @param[in,out] ops_context
 *     可空独立短借上下文，不保存。
 *
 * @return
 *     沿公共入口；缺表/任一函数 INVALID_ARGUMENT，每路径报告并保持 errno。
 */
vireo_result_t vireo_async_request_with_ops(vireo_tcp_server_t const *,
    vireo_connection_pool_lease_t, vireo_inflight_store_t *, vireo_thread_pool_t *,
    uint8_t const *, size_t, size_t, size_t, size_t, uint32_t, uint64_t,
    vireo_task_cancel_t *, vireo_task_t **, vireo_async_request_report_t *,
    vireo_async_request_ops_t const *, void *);
#endif /* VIREO_NET_ASYNC_REQUEST_INTERNAL_H */

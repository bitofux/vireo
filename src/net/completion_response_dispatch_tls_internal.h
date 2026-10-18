/* 本接线层公开依赖 seam，禁止引入其他模块 private。 */
#ifndef VIREO_NET_COMPLETION_RESPONSE_DISPATCH_TLS_INTERNAL_H
#define VIREO_NET_COMPLETION_RESPONSE_DISPATCH_TLS_INTERNAL_H
#include <vireo/net/completion_response_dispatch_tls.h>

/** 稳定只读表/context 只借至返回；替身遵守公开预算/转移/报告合同。 */
typedef struct vireo_completion_response_dispatch_tls_ops {
    vireo_result_t (*inspect)(void *, vireo_tcp_server_t const *, vireo_tcp_server_info_t *, vireo_tcp_server_tls_error_t *);
        /**< 一次公开停止观测，不发布同步屏障。 */
    vireo_result_t (*dispatch)(void *, vireo_tcp_server_t *, vireo_event_loop_handle_t,
        vireo_notifier_t *, vireo_inflight_store_t *, vireo_completion_queue_t *, size_t,
        vireo_inflight_completion_deliver_fn, void *, vireo_completion_t **,
        vireo_notifier_server_dispatch_report_t *);
        /**< 一次原安全点分发，不新增消费/续提示。 */
    vireo_result_t (*response)(void *, vireo_tcp_server_t *, vireo_completion_t const *,
        vireo_inflight_completion_match_t, vireo_completion_response_descriptor_t, size_t,
        uint8_t *, size_t, vireo_completion_response_tls_report_t *);
        /**< 一次原响应助手，已入队后失败也发布 enqueued/字节。 */
} vireo_completion_response_dispatch_tls_ops_t;

/**
 * @brief
 *     同一实现，仅替换本层三公开依赖供故障隔离；其余参数沿公共入口。
 *
 * @param[in,out] server
 *     沿公共入口短借 server。
 * @param[in] expected_handle
 *     原完整辅助登记身份。
 * @param[in,out] notifier
 *     沿公共入口短借提示资源。
 * @param[in,out] store
 *     沿公共入口短借登记表。
 * @param[in,out] queue
 *     沿公共入口单 consumer 队列。
 * @param[in] max_items
 *     沿公共入口正条数上限。
 * @param[in] max_frame_bytes
 *     沿公共入口单帧字节上限。
 * @param[in] max_batch_bytes
 *     沿公共入口正批次字节额度。
 * @param[in,out] workspace
 *     沿公共入口可写 scratch。
 * @param[in] workspace_size
 *     真实可写字节容量。
 * @param[in] resolve
 *     沿公共入口描述函数及短借限制。
 * @param[in,out] context
 *     可空 caller 短借上下文。
 * @param[out] remaining
 *     必需独占入口 NULL 的 owner 地址。
 * @param[out] report
 *     必需独立真实前缀报告。
 * @param[in] ops
 *     必需完整三函数稳定表，不保存。
 * @param[in,out] ops_context
 *     可空独立短借测试上下文，不保存。
 *
 * @return
 *     沿公共入口；缺表/任一函数 INVALID_ARGUMENT，每路径报告并保持 errno。
 */
vireo_result_t vireo_completion_response_dispatch_tls_with_ops(vireo_tcp_server_t *,
    vireo_event_loop_handle_t, vireo_notifier_t *, vireo_inflight_store_t *,
    vireo_completion_queue_t *, size_t, size_t, size_t, uint8_t *, size_t,
    vireo_completion_response_resolve_fn, void *, vireo_completion_t **,
    vireo_completion_response_dispatch_tls_report_t *,
    vireo_completion_response_dispatch_tls_ops_t const *, void *);
#endif /* VIREO_NET_COMPLETION_RESPONSE_DISPATCH_TLS_INTERNAL_H */

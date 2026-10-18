/* 本层测试 seam，不含 server/connection/codec 等外模块私有头。 */
#ifndef VIREO_NET_COMPLETION_RESPONSE_INTERNAL_H
#define VIREO_NET_COMPLETION_RESPONSE_INTERNAL_H
#include <vireo/net/completion_response_tls.h>

/** 两个公开写入边界，只短借稳定表/context，替身遵守原提交及诊断合同。 */
typedef struct vireo_completion_response_ops {
    vireo_result_t (*enqueue)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        uint8_t const *, size_t, vireo_tcp_server_client_error_t *);
        /**< 完整复制，不发送；普通拒绝保持队列。 */
    vireo_result_t (*refresh)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_tcp_server_client_error_t *);
        /**< 原流控刷新，不回滚先前字节。 */
} vireo_completion_response_ops_t;

/**
 * @brief
 *     同一实现，只替换本层两个公开写边界供隔离故障测试。
 *
 * @param[in,out] server
 *     沿公共入口短借。
 * @param[in] completion
 *     沿公共入口只读短借。
 * @param[in] match
 *     原匹配快照。
 * @param[in] descriptor
 *     显式原响应描述。
 * @param[in] max_frame_bytes
 *     沿公共入口字节预算。
 * @param[in,out] workspace
 *     沿公共入口独立 scratch。
 * @param[in] workspace_size
 *     真实可写容量。
 * @param[out] report
 *     必需独立真实进度。
 * @param[in] ops
 *     必需完整只读表，两个函数非空，不保存。
 * @param[in,out] ops_context
 *     可空独立短借上下文，只借至返回。
 *
 * @return
 *     沿公共入口；缺表/函数 INVALID，不调用依赖，errno 保持。
 */
vireo_result_t vireo_completion_response_with_ops(vireo_tcp_server_t *,
    vireo_completion_t const *, vireo_inflight_completion_match_t,
    vireo_completion_response_descriptor_t, size_t, uint8_t *, size_t,
    vireo_completion_response_report_t *, vireo_completion_response_ops_t const *, void *);
/** 本层TLS两个提交边界；表/context只短借，替身遵守原公开合同。 */
typedef struct vireo_completion_response_tls_ops {
    vireo_result_t (*enqueue)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        uint8_t const *, size_t, vireo_tcp_server_client_error_t *);
        /**< 整帧明文复制，不做native读写。 */
    vireo_result_t (*refresh)(void *, vireo_tcp_server_t *, vireo_connection_pool_lease_t,
        vireo_tcp_server_tls_flow_info_t *, vireo_tcp_server_tls_application_error_t *);
        /**< 原TLS关注及续调度，主次失败各自保留。 */
} vireo_completion_response_tls_ops_t;

/**
 * @brief TLS入口同核，只替换本层两个公开提交边界
 *
 * @param[in,out] server
 *     公共TLS入口同生命周期根。
 * @param[in] completion
 *     公共入口同只读短借结果。
 * @param[in] match
 *     原匹配快照。
 * @param[in] descriptor
 *     wire响应描述。
 * @param[in] max_frame_bytes
 *     单帧预算。
 * @param[in,out] workspace
 *     独立scratch。
 * @param[in] workspace_size
 *     scratch容量。
 * @param[out] report
 *     必需独立真实进度。
 * @param[in] ops
 *     必需完整表，不保存。
 * @param[in,out] ops_context
 *     可空独立context，只借至返回。
 *
 * @return
 *     沿公共入口；缺表/函数INVALID，typed覆盖可写报告，errno保持。
 */
vireo_result_t vireo_completion_response_tls_with_ops(vireo_tcp_server_t *server,
    vireo_completion_t const *completion, vireo_inflight_completion_match_t match,
    vireo_completion_response_descriptor_t descriptor, size_t max_frame_bytes,
    uint8_t *workspace, size_t workspace_size, vireo_completion_response_tls_report_t *report,
    vireo_completion_response_tls_ops_t const *ops, void *ops_context);
#endif /* VIREO_NET_COMPLETION_RESPONSE_INTERNAL_H */

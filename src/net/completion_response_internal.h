/* 本层测试 seam，不含 server/connection/codec 等外模块私有头。 */
#ifndef VIREO_NET_COMPLETION_RESPONSE_INTERNAL_H
#define VIREO_NET_COMPLETION_RESPONSE_INTERNAL_H
#include <vireo/net/completion_response.h>

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
#endif /* VIREO_NET_COMPLETION_RESPONSE_INTERNAL_H */

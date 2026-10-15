/*
 * PROJECT : VIREO
 * FILE    : inflight_completion_drain_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 仅本接线层的隔离依赖调用 seam，不包含外模块私有布局
 */
#ifndef VIREO_NET_INFLIGHT_COMPLETION_DRAIN_INTERNAL_H
#define VIREO_NET_INFLIGHT_COMPLETION_DRAIN_INTERNAL_H
#include <vireo/net/inflight_completion_drain.h>

/** 同步短借的依赖替身；每入口必须遵守对应公开报告/所有权合同，不长期保存参数。 */
typedef struct vireo_inflight_completion_drain_ops {
    vireo_result_t (*pop)(void *ops_context, vireo_completion_queue_t *queue,
        vireo_completion_t **owner, vireo_completion_queue_transfer_report_t *report);
        /**< 一次公开领取，context 可空；报告必须说明真实转移。 */
    vireo_result_t (*consume)(void *ops_context, vireo_inflight_store_t *store,
        vireo_tcp_server_t const *server, vireo_completion_t **owner,
        vireo_inflight_completion_deliver_fn deliver, void *context,
        vireo_inflight_completion_consume_report_t *report);
        /**< 一次单项消费，context 可空；保留真实报告和失败前缀。 */
} vireo_inflight_completion_drain_ops_t;

/**
 * @brief
 *     与公共入口相同的有界编排，只替换两项依赖调用，供本层隔离故障验证。
 *
 * @param[in,out] store
 *     公开入口要求的存活短借表。
 * @param[in] server
 *     公开入口要求的存活短借客户资源根。
 * @param[in,out] queue
 *     公开入口要求的存活短借队列。
 * @param[in] max_items
 *     正条预算，最多 65536。
 * @param[in] deliver
 *     必需符合公开合同的回调。
 * @param[in,out] context
 *     可空短借交付上下文。
 * @param[out] remaining
 *     必需入口 NULL 的独占输出 owner，失败保真实义务。
 * @param[out] report
 *     必需独立报告，每可写路径发布。
 * @param[in] ops
 *     必需稳定可读的两个非空依赖函数，不保存，只借至返回。
 * @param[in,out] ops_context
 *     可空短借 seam 上下文，独立于资源/owner/report，不保存。
 *
 * @return
 *     沿公共入口；ops 或任一函数 NULL 为 INVALID_ARGUMENT，不调用依赖。
 *
 * @note
 *     Reactor-only，所有路径保持 errno；替身报告须遵守原公开进度合同。
 *     故障模拟不是实际内核同步失败证据，不读外模块 private 或冻结其布局。
 */
vireo_result_t vireo_inflight_completion_drain_with_ops(vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_completion_queue_t *queue, size_t max_items,
    vireo_inflight_completion_deliver_fn deliver, void *context,
    vireo_completion_t **remaining, vireo_inflight_completion_drain_report_t *report,
    vireo_inflight_completion_drain_ops_t const *ops, void *ops_context);
#endif /* VIREO_NET_INFLIGHT_COMPLETION_DRAIN_INTERNAL_H */

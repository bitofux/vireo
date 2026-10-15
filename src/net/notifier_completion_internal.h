/*
 * PROJECT : VIREO
 * FILE    : notifier_completion_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 本协调层隔离公开调用 seam，无外模块 private
 */
#ifndef VIREO_NET_NOTIFIER_COMPLETION_INTERNAL_H
#define VIREO_NET_NOTIFIER_COMPLETION_INTERNAL_H
#include <vireo/net/notifier_completion.h>

/** 只短借稳定函数表，替身遵守原公开诊断、转移和失败进度合同。 */
typedef struct vireo_notifier_completion_ops {
    vireo_result_t (*consume)(void *ops_context, vireo_notifier_t *notifier,
        uint64_t *count, vireo_notifier_error_t *error); /**< 一次原提示消费，不领队列。 */
    vireo_result_t (*drain)(void *ops_context, vireo_inflight_store_t *store,
        vireo_tcp_server_t const *server, vireo_completion_queue_t *queue, size_t max_items,
        vireo_inflight_completion_deliver_fn deliver, void *context,
        vireo_completion_t **remaining, vireo_inflight_completion_drain_report_t *report);
        /**< 一批原有界排空，不掩盖真实残留 owner 和消费前缀。 */
    vireo_result_t (*notify)(void *ops_context, vireo_notifier_t *notifier,
        vireo_notifier_notify_outcome_t *outcome, vireo_notifier_error_t *error);
        /**< 一次补提示，失败不回滚原排空。 */
} vireo_notifier_completion_ops_t;

/**
 * @brief
 *     同一组合实现，仅替换本层三个公开依赖调用用于隔离故障验证。
 *
 * @param[in,out] notifier
 *     沿公共入口的短借 notifier。
 * @param[in,out] store
 *     沿公共入口的短借在途表。
 * @param[in] server
 *     沿公共入口的短借客户资源根。
 * @param[in,out] queue
 *     沿公共入口的单 consumer 队列。
 * @param[in] max_items
 *     沿公共入口的显式条数预算。
 * @param[in] deliver
 *     必需符合原有界回调合同。
 * @param[in,out] context
 *     可空短借交付上下文。
 * @param[out] remaining
 *     必需入口 NULL 的独立 owner。
 * @param[out] report
 *     必需独立可写进度报告。
 * @param[in] ops
 *     必需稳定可读表，三函数均非空，只借至返回。
 * @param[in,out] ops_context
 *     可空隔离上下文，与输出/资源独立，只借至返回。
 *
 * @return
 *     沿公共入口，缺失 ops 或任一函数 INVALID_ARGUMENT，不调用依赖。
 *
 * @note
 *     全路径保持 errno；只有本核心 private，模型不是原内核/同步损坏实证。
 */
vireo_result_t vireo_notifier_completion_with_ops(vireo_notifier_t *notifier,
    vireo_inflight_store_t *store, vireo_tcp_server_t const *server,
    vireo_completion_queue_t *queue, size_t max_items,
    vireo_inflight_completion_deliver_fn deliver, void *context,
    vireo_completion_t **remaining, vireo_notifier_completion_report_t *report,
    vireo_notifier_completion_ops_t const *ops, void *ops_context);
#endif /* VIREO_NET_NOTIFIER_COMPLETION_INTERNAL_H */

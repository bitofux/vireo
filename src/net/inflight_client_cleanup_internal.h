/* PROJECT : VIREO
 * FILE    : inflight_client_cleanup_internal.h
 * BRIEF   : 仅028清退实现和测试的公开取消边界模型
 */
#ifndef VIREO_NET_INFLIGHT_CLIENT_CLEANUP_INTERNAL_H
#define VIREO_NET_INFLIGHT_CLIENT_CLEANUP_INTERNAL_H
#include <vireo/net/inflight_client_cleanup.h>

/** 短借操作表，不保存进表；失败须保持该次引用义务，不重入store。 */
typedef struct vireo_inflight_client_cleanup_ops {
    void *context; /**< 可空上下文，只借至返回，不交给worker。 */
    vireo_result_t (*request)(void *context, vireo_task_cancel_t *cancel); /**< 一次公开请求，失败模型不改标志。 */
    vireo_result_t (*release)(void *context, vireo_task_cancel_t **owner); /**< OK真实归还并清owner，失败保持。 */
} vireo_inflight_client_cleanup_ops_t;

/**
 * @brief
 *     本核心测试用取消边界替身，其他合同沿公开入口。
 *
 * @param[in,out] store
 *     存活Reactor表，仅本核心实现可访问布局。
 * @param[in] client
 *     原完整历史客户。
 * @param[in] begin_index
 *     同公开游标范围。
 * @param[in] max_slots
 *     同公开正扫描预算。
 * @param[out] report
 *     独立完整进度输出。
 * @param[in] ops
 *     完整稳定操作表，仅短借；NULL或缺函数为基本INVALID。
 *
 * @return
 *     原分类及真实进度，全部路径保持errno。
 */
vireo_result_t vireo_inflight_client_cleanup_with_ops(vireo_inflight_store_t *store,
    vireo_connection_pool_lease_t client, size_t begin_index, size_t max_slots,
    vireo_inflight_client_cleanup_report_t *report, vireo_inflight_client_cleanup_ops_t const *ops);
#endif

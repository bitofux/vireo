/* 本核心私有公开依赖seam；下游不得包含。 */
#ifndef VIREO_NET_ASYNC_TASK_RECOVERY_INTERNAL_H
#define VIREO_NET_ASYNC_TASK_RECOVERY_INTERNAL_H
#include <vireo/net/async_task_recovery.h>

/** 只借公开值，不读其他模块布局；替身须遵守原失败保持/消费合同。 */
typedef struct vireo_async_task_recovery_ops {
    vireo_result_t (*inspect)(void *, vireo_task_t const *, vireo_task_info_t *); /**< 只读实际task。 */
    vireo_result_t (*get)(void *, vireo_inflight_store_t const *, vireo_task_metadata_t,
        vireo_task_metadata_t *, vireo_inflight_stage_t *); /**< 只读原登记。 */
    vireo_result_t (*take)(void *, vireo_inflight_store_t *, vireo_task_metadata_t,
        vireo_task_metadata_t *, vireo_inflight_stage_t *); /**< 成功才结束登记。 */
    vireo_result_t (*destroy)(void *, vireo_task_t **); /**< 原唯一task配对释放。 */
} vireo_async_task_recovery_ops_t;

vireo_result_t vireo_async_task_recovery_with_ops(vireo_inflight_store_t *store,
    vireo_task_metadata_t expected, vireo_task_t **task_owner,
    vireo_async_task_recovery_step_t from, vireo_async_task_recovery_report_t *report,
    vireo_async_task_recovery_ops_t const *ops, void *context);
#endif

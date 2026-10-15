/*
 * PROJECT : VIREO
 * FILE    : completion_publish_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 本回投层的公开依赖隔离表，无外模块私有布局
 */
#ifndef VIREO_THREAD_COMPLETION_PUBLISH_INTERNAL_H
#define VIREO_THREAD_COMPLETION_PUBLISH_INTERNAL_H
#include <vireo/thread/completion_publish.h>

/** 五个公开边界，只短借稳定函数表；替身须遵守原输出/转移合同。 */
typedef struct vireo_completion_publish_ops {
    vireo_result_t (*inspect)(vireo_task_t const *, vireo_task_info_t *);
        /**< 只读原task的按值快照。 */
    vireo_result_t (*make_metadata)(vireo_task_metadata_t, vireo_result_t,
        vireo_status_t, vireo_completion_metadata_t *);
        /**< 完整验证并构造原请求及显式结果值。 */
    vireo_result_t (*create_copy)(vireo_completion_metadata_t, void const *,
        size_t, size_t, vireo_completion_t **);
        /**< 成功才发布唯一对象，失败不发布半对象。 */
    vireo_result_t (*wait_push)(vireo_completion_queue_t *, vireo_completion_t **,
        vireo_completion_queue_transfer_report_t *);
        /**< 保留原返回与真实交接，未转移保源。 */
    vireo_result_t (*notify)(vireo_notifier_t *, vireo_notifier_notify_outcome_t *,
        vireo_notifier_error_t *);
        /**< 一次提示，原系统诊断保持。 */
} vireo_completion_publish_ops_t;

/**
 * @brief
 *     公共入口的同一实现，仅用本层函数表隔离失败核验。
 *
 * @param[in] task
 *     沿公共入口的const短借。
 * @param[in] result
 *     沿公共入口的工作内部结果。
 * @param[in] suggested_status
 *     沿公共入口的显式协议建议。
 * @param[in] data
 *     沿公共入口的稳定响应字节。
 * @param[in] payload_size
 *     沿公共入口的字节长度。
 * @param[in] allocation_budget
 *     沿公共入口的正申请预算。
 * @param[in,out] queue
 *     沿公共入口的短借队列。
 * @param[in,out] notifier
 *     沿公共入口的短借通知对象。
 * @param[out] remaining
 *     沿公共入口的入口空唯一owner。
 * @param[out] report
 *     沿公共入口的必需独立报告。
 * @param[in] ops
 *     必需稳定表，五函数非空，仅借至返回，不保存。
 *
 * @return
 *     沿公共合同，缺表/函数INVALID_ARGUMENT，不调用依赖。
 *
 * @note
 *     全路径保持errno；模型只证明本层组合，不冒原OS或损坏同步实证。
 */
vireo_result_t vireo_completion_publish_with_ops(vireo_task_t const *task,
    vireo_result_t result, vireo_status_t suggested_status, void const *data,
    size_t payload_size, size_t allocation_budget, vireo_completion_queue_t *queue,
    vireo_notifier_t *notifier, vireo_completion_t **remaining,
    vireo_completion_publish_report_t *report, vireo_completion_publish_ops_t const *ops);
#endif /* VIREO_THREAD_COMPLETION_PUBLISH_INTERNAL_H */

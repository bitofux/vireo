/*
 * PROJECT : VIREO
 * FILE    : async_task_recovery.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 未移交task的显式放弃及残留登记撤销
 */
#ifndef VIREO_NET_ASYNC_TASK_RECOVERY_H
#define VIREO_NET_ASYNC_TASK_RECOVERY_H

#include <vireo/net/inflight_store.h>

/** 仅TAKE_RECORD/DESTROY_TASK可输入，NONE/DONE仅报告。 */
typedef enum vireo_async_task_recovery_step {
    VIREO_ASYNC_TASK_STEP_NONE = 0,
    VIREO_ASYNC_TASK_STEP_TAKE_RECORD = 1,
    VIREO_ASYNC_TASK_STEP_DESTROY_TASK = 2,
    VIREO_ASYNC_TASK_STEP_DONE = 3
} vireo_async_task_recovery_step_t;

/** 本层错误来源，不改变既有inflight阶段。 */
typedef enum vireo_async_task_recovery_stage {
    VIREO_ASYNC_TASK_RECOVERY_NONE = 0,
    VIREO_ASYNC_TASK_RECOVERY_CHECK_METADATA = 1,
    VIREO_ASYNC_TASK_RECOVERY_INSPECT_TASK = 2,
    VIREO_ASYNC_TASK_RECOVERY_MATCH_TASK = 3,
    VIREO_ASYNC_TASK_RECOVERY_CHECK_RECORD = 4,
    VIREO_ASYNC_TASK_RECOVERY_MATCH_RECORD = 5,
    VIREO_ASYNC_TASK_RECOVERY_TAKE_RECORD = 6,
    VIREO_ASYNC_TASK_RECOVERY_DESTROY_TASK = 7
} vireo_async_task_recovery_stage_t;

/** 本次事实副本，无owner或保活；未调用结果逻辑零不表示成功。 */
typedef struct vireo_async_task_recovery_report {
    vireo_async_task_recovery_stage_t stage; /**< 主错来源，成功/基本拒绝NONE。 */
    vireo_async_task_recovery_step_t next_step; /**< task完整匹配后为未成功动作，成功DONE。 */
    vireo_task_metadata_t metadata; /**< 仅task_inspected时为实际task快照，非expected冒充。 */
    bool task_inspected; /**< 本次inspect已成功，即使随后匹配失败仍true。 */
    bool record_checked; /**< 本次get成功且全部元数据字段已匹配。 */
    bool take_called; /**< 本次是否实际调用一次公开take。 */
    vireo_result_t take_result; /**< take_called时原返回。 */
    bool record_consumed; /**< 仅本次take成功，不累计历史退款。 */
    vireo_inflight_stage_t inflight_stage; /**< 实际get或take的原诊断。 */
    bool destroy_called; /**< 本次是否实际调用一次公开task_destroy。 */
    vireo_result_t destroy_result; /**< destroy_called时原返回。 */
    bool task_consumed; /**< destroy调用后原owner是否实际清空。 */
} vireo_async_task_recovery_report_t;

/**
 * @brief
 *     核对未移交task，按显式起点撤销残留登记，再释放唯一task。
 *
 * @param[in,out] store
 *     必需存活表，全部访问Reactor串行；DESTROY_TASK不访问表内容。
 * @param[in] expected
 *     caller从原真实报告保存的完整元数据，含operation及有限纳秒deadline。
 * @param[in,out] task_owner
 *     必需独占非空的原未移交task，先结束全部操作/借用；销毁成功清NULL。
 * @param[in] resume_from
 *     TAKE_RECORD或DESTROY_TASK；后者须已确认从未登记/退款已完成。
 * @param[out] report
 *     必需独立可写值，每可写路径完整发布，不拥有或保活资源。
 *
 * @retval VIREO_OK
 *     经过动作均成功，stage NONE/next DONE；task owner为NULL。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL、非法起点、无效expected，或task/登记完整快照不匹配。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空task owner，或TAKE_RECORD未找到原登记；不自动视为退款成功。
 *
 * @return
 *     其他公开依赖错误原样返回，首错停止后段，不重试。
 *
 * @note
 *     顺序：基本/空owner/expected公开形态→inspect/完整匹配→可选get/完整匹配/take→destroy。
 *     route+instance为原表键；本层额外核对operation/deadline，不比较padding。
 *     task匹配前next NONE；之后next停未成功动作，不保证该错误可重试。
 * @note
 *     caller保证真正未转移及唯一owner、真实起点来源，不能由旧裸指针重造owner。
 *     DESTROY_TASK不认证历史或检查登记缺失；必须先明确已无退款义务。
 *     take成功不放回；后段出错仍保退款事实，不重提task或消费原网络输入。
 * @note
 *     释放表和task各自的cancel引用，不自动request；caller独立引用仍有效。
 *     不核验客户当前性，历史客户归还/停止后仍可清登记，不触server/fd。
 *     合法task的既有destroy正常仅OK；无自然销毁失败或同步损坏恢复承诺。
 * @note
 *     原run外Reactor串行安全窗口，全调用禁POSIX取消，get/take间无其他改表。
 *     地址存活对齐互不重叠，也不重叠资源/errno；全部受控路径保持入口errno。
 *     各动作最多一次，无新申请/持久状态/回调，get/take各有界O(capacity)，不保证硬实时。
 *     业务重试、错误响应、完成对象残留、取消及全停机由caller另行处理。
 */
vireo_result_t vireo_async_request_discard_remaining(vireo_inflight_store_t *store,
    vireo_task_metadata_t expected, vireo_task_t **task_owner,
    vireo_async_task_recovery_step_t resume_from, vireo_async_task_recovery_report_t *report);

#endif /* VIREO_NET_ASYNC_TASK_RECOVERY_H */

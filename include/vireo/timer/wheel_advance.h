/*
 * PROJECT : VIREO
 * FILE    : wheel_advance.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 显式双预算推进与到期发现
 * -- 观测进度并单项领取数值通知
 */
#ifndef VIREO_TIMER_WHEEL_ADVANCE_H
#define VIREO_TIMER_WHEEL_ADVANCE_H

#include <vireo/timer/wheel_registry.h>

/** 两项独立工作预算硬限，不是默认预算或性能最优结论。 */
#define VIREO_TIMER_WHEEL_ADVANCE_MAX_BUDGET ((size_t)65536)

/** 调用者显式工作上限，两个字段必须为正。 */
typedef struct vireo_timer_wheel_advance_budget {
    size_t max_ticks; /**< 本次最多新开启的桶访问数；续接在途桶不再次收费。 */
    size_t max_nodes; /**< 本次最多检查的节点数，未来圈节点也收费。 */
} vireo_timer_wheel_advance_budget_t;

/** 独立进度快照，无内部借用或保活。 */
typedef struct vireo_timer_wheel_progress {
    vireo_monotonic_ns_t latest_now_ns; /**< 最近成功推进的 now，初始为 origin。 */
    vireo_timer_wheel_tick_t target_tick; /**< latest_now 向下量化的目标刻度。 */
    vireo_timer_wheel_tick_t completed_tick; /**< 已完整检查至此刻度，初始为 0。 */
    bool processing; /**< 正在检查 completed_tick+1；其 pending 环可暂时为空。 */
    size_t ready_count; /**< 已发现但未领取/取消/撤销的项数，仍占活跃容量。 */
    bool caught_up; /**< 当前无在途桶且 completed==target；不表示通知已处理。 */
} vireo_timer_wheel_progress_t;

/** 一次成功推进的工作量与最终进度，不是运行时耗时。 */
typedef struct vireo_timer_wheel_advance_report {
    vireo_timer_wheel_progress_t progress; /**< 返回时的数值进度。 */
    size_t ticks_started; /**< 本次新开启桶数，不超过 max_ticks。 */
    size_t nodes_examined; /**< 本次检查节点数，不超过 max_nodes。 */
} vireo_timer_wheel_advance_report_t;

/** 单项已注销通知；仅历史值，不含回调、业务资源或有效控制权。 */
typedef struct vireo_timer_wheel_expired {
    vireo_timer_handle_t handle; /**< 注销前的原身份；返回时其全部副本已失效。 */
    vireo_timer_wheel_timer_info_t timer; /**< 原 deadline、due_tick 和数学桶位置。 */
} vireo_timer_wheel_expired_t;

/**
 * @brief 在双预算内推进并发现到期项，不执行业务动作
 *
 * @param[in,out] wheel
 *     非空、存活、已 prepare 的轮，所属 Reactor 独占。
 * @param[in] now_ns
 *     同域单调纳秒，不早于 origin 和前次成功 advance；等值可继续推进。
 * @param[in] budget
 *     两个正上限，均不得超过硬限；按值传入，无默认。
 * @param[out] out_report
 *     非空、对齐可写且独立的报告，短借至返回。
 *
 * @retval VIREO_OK
 *     发布工作量和进度；预算耗尽也成功，可能尚未追上目标。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL，或任一预算为 0。
 * @retval VIREO_RESULT_RANGE
 *     预算超过硬限，或 now 早于 origin/前次成功 advance。
 * @retval VIREO_RESULT_NOT_FOUND
 *     此轮未 prepare。
 * @retval VIREO_RESULT_CANCELLED
 *     已 begin 停止；参数/预算/准备之后、时间检查之前拒绝。
 *
 * @note
 *     目标为 floor 刻度，按当前访问刻度判断 due_tick，不提前处理未来圈节点。
 * @note
 *     节点从桶快照逐项检查，未检查项可跨调用续接；工作量 O(max_ticks+max_nodes)。
 * @note
 *     发现仍保留活跃身份，可 get/cancel/rearm；不承诺发现或领取顺序，不采样时钟。
 * @note
 *     失败保持整个输出和轮状态，所有路径保持 errno；不分配、I/O 或回调。
 * @note
 *     输出不在轮自有资源内、不与其重叠、不指 errno；同轮所有访问 Reactor-only。
 */
vireo_result_t vireo_timer_wheel_advance(vireo_timer_wheel_t *wheel,
                                        vireo_monotonic_ns_t now_ns,
                                        vireo_timer_wheel_advance_budget_t budget,
                                        vireo_timer_wheel_advance_report_t *out_report);

/**
 * @brief 只观测推进进度，不读取时钟或推进状态
 *
 * @param[in] wheel
 *     非空、存活、已 prepare 的轮，所属 Reactor 独占。
 * @param[out] out_progress
 *     非空、对齐可写且独立的数值快照，短借至返回。
 *
 * @retval VIREO_OK
 *     写六个逻辑字段，不承诺 padding。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL。
 * @retval VIREO_RESULT_NOT_FOUND
 *     此轮未 prepare。
 *
 * @note
 *     失败保持整个输出、所有路径保持 errno；快照不保活轮、不分配。
 * @note
 *     输出不在轮资源内、不与其重叠、不指 errno；同轮所有访问 Reactor-only。
 */
vireo_result_t vireo_timer_wheel_progress_inspect(vireo_timer_wheel_t const *wheel,
                                                 vireo_timer_wheel_progress_t *out_progress);

/**
 * @brief 领取一个已发现项，成功时归还其活跃身份
 *
 * @param[in,out] wheel
 *     非空、存活、已 prepare 的轮，所属 Reactor 独占。
 * @param[out] out_expired
 *     非空、对齐可写且独立的数值事件，短借至返回；入口值任意。
 *
 * @retval VIREO_OK
 *     注销一个项并发布原身份和期限快照，原身份的所有副本已 NOT_FOUND。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL；另沿公开 owner 归还的身份错误。
 * @retval VIREO_RESULT_NOT_FOUND
 *     未 prepare 或没有已发现项；另沿公开 owner 的失活错误。
 * @retval VIREO_RESULT_RANGE
 *     公开 owner 归还拒绝越界身份；合法内部登记不会到此边界。
 *
 * @note
 *     先摘链再 public release，归还失败恢复精确链位、计数及全部输出/状态。
 * @note
 *     返回 handle 是历史记录，不清 caller 的旧副本数值，也不再授权 get/cancel/rearm。
 * @note
 *     业务关闭/取消/清理由 caller 负责；没有业务借用、回调、排序或自动重试。
 * @note
 *     全路径保持 errno，不分配；输出不在轮资源内、不重叠、不指 errno。
 * @note
 *     同轮所有访问 Reactor-only；快照不保活轮。
 */
vireo_result_t vireo_timer_wheel_take_expired(vireo_timer_wheel_t *wheel,
                                             vireo_timer_wheel_expired_t *out_expired);

#endif /* VIREO_TIMER_WHEEL_ADVANCE_H */

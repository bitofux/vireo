/*
 * PROJECT : VIREO
 * FILE    : timer_loop_run.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 用两次单调采样组合一次网络循环及有界轮推进
 * -- 分离成功报告、失败阶段及已完成网络动作
 */
#ifndef VIREO_NET_TIMER_LOOP_RUN_H
#define VIREO_NET_TIMER_LOOP_RUN_H

#include <vireo/net/timer_loop.h>
#include <vireo/net/event_loop.h>
#include <vireo/timer/wheel_advance.h>

/** 显式单轮选项，无默认值；整个调用期间短借且稳定。 */
typedef struct vireo_timer_loop_run_options {
    int max_wait_ms; /**< 非负 int 毫秒等待上限，不含回调或推进耗时。 */
    vireo_timer_wheel_advance_budget_t advance_budget; /**< 两项正工作预算，各不超过 65536。 */
} vireo_timer_loop_run_options_t;

/** 只有完整成功才发布的独立值，不保活 loop、wheel 或登记。 */
typedef struct vireo_timer_loop_run_report {
    vireo_monotonic_ns_t before_now_ns; /**< 第一次 CLOCK_MONOTONIC 采样，供等待规划。 */
    vireo_timer_loop_wait_plan_t wait_plan; /**< 实际交给网络一轮的等待计划，不是业务期限。 */
    vireo_event_loop_run_info_t loop; /**< 公开网络一轮的成功计数；停止入口也可为四零。 */
    vireo_monotonic_ns_t after_now_ns; /**< 网络一轮返回后采样，供预算推进。 */
    vireo_timer_wheel_advance_report_t advance; /**< 本次推进工作量及进度，不消费 ready。 */
} vireo_timer_loop_run_report_t;

/** 组合检测失败的位置，不是 wire 状态或重试策略。 */
typedef enum vireo_timer_loop_stage {
    VIREO_TIMER_LOOP_STAGE_NONE = 0, /**< 完整成功或基本参数/预算拒绝。 */
    VIREO_TIMER_LOOP_STAGE_CHECK_WHEEL = 1, /**< 轮准备/停止的公开预检。 */
    VIREO_TIMER_LOOP_STAGE_CLOCK_BEFORE = 2, /**< 第一次单调采样。 */
    VIREO_TIMER_LOOP_STAGE_PLAN_WAIT = 3, /**< 显式时间的只读等待规划。 */
    VIREO_TIMER_LOOP_STAGE_RUN_LOOP = 4, /**< 一次公开网络循环。 */
    VIREO_TIMER_LOOP_STAGE_CLOCK_AFTER = 5, /**< 网络成功后的单调采样。 */
    VIREO_TIMER_LOOP_STAGE_ADVANCE = 6, /**< 第二采样后的有界轮推进。 */
} vireo_timer_loop_stage_t;

/** 所有路径覆盖的独立诊断；主报告保持不表示已经完成的动作回滚。 */
typedef struct vireo_timer_loop_diagnostic {
    vireo_timer_loop_stage_t stage; /**< 失败阶段；成功及基本拒绝为 NONE。 */
    vireo_clock_error_t clock_error; /**< clock 原诊断，未采样或成功时 NONE/0。 */
    vireo_event_loop_error_t loop_error; /**< loop 原诊断，未运行或成功时各层 NONE/0。 */
    bool loop_completed; /**< 仅表示 loop 入口返回 OK，不保证实际等待或分发。 */
} vireo_timer_loop_diagnostic_t;

/**
 * @brief 双采样夹住网络一轮，再按显式双预算推进轮
 *
 * @param[in,out] loop
 *     非空、存活的公开 loop，所属 Reactor 独占；只借至整个调用返回。
 * @param[in,out] wheel
 *     非空、存活、已 prepare 的轮，同一 Reactor 独占，不转移所有权。
 * @param[in] options
 *     非空、对齐可读且全程稳定的显式选项，cap 非负、两预算为正且不超硬限。
 * @param[out] out_report
 *     非空、存活、对齐独立可写的完整成功报告，失败整个对象保持。
 * @param[out] out_diagnostic
 *     可空、否则全程独立可写，覆盖全部逻辑字段，不保活资源。
 *
 * @retval VIREO_OK
 *     两次采样、规划、loop 一轮和一次推进完整成功；预算不足仍可成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、负 cap 或任一零预算，未采样或运行。
 * @retval VIREO_RESULT_RANGE
 *     预算超硬限，或规划/推进发现时间倒退；依赖结果原样返回。
 * @retval VIREO_RESULT_NOT_FOUND
 *     预检轮未 prepare，未采样或运行。
 * @retval VIREO_RESULT_CANCELLED
 *     预检轮已停止，或网络期间停止轮后推进被拒绝。
 * @retval VIREO_RESULT_BUSY
 *     loop 已在运行；原错误透传，不重试。
 * @retval VIREO_RESULT_IO
 *     任一次 clock 或 loop 失败；原诊断透传，包括 loop EINTR，不重试。
 * @retval VIREO_RESULT_OVERFLOW
 *     clock 转换或等待规划受检时间不可表示，不截限或回绕。
 * @retval VIREO_RESULT_INTERNAL
 *     clock 或 loop 原合同检测到异常；原诊断透传。
 *
 * @note
 *     顺序：基本参数/预算→公开轮准备/停止预检→采样→规划→loop 一次→采样→advance 一次。
 * @note
 *     无自动重试、运行期申请、内部资源借用、到期领取、timer callback 或业务清理。
 * @note
 *     网络成功后的晚失败不回滚已完成网络动作；loop_completed 此时为 true，不能当事务重放。
 * @note
 *     loop 已停止沿旧入口成功四零，此后仍采样推进轮；不自动联动停止或销毁两个对象。
 * @note
 *     成功诊断 stage=NONE、原错误各层 NONE/0、loop_completed=true；成功不承诺 padding。
 * @note
 *     主报告/选项/诊断与对象资源互不重叠、非 errno 存储，地址只借至返回，不保存。
 * @note
 *     同轮 Reactor-only，禁止并发或递归本组合入口；网络回调可以合法修改轮，
 *     但须有界非阻塞，不得销毁借用对象或改写、释放选项与输出。loop 原回调借用合同保持。
 * @note
 *     轮积压时规划 0，仍检查一次网络再有界推进；不保证硬实时、调度公平或期限业务已处理。
 * @note
 *     所有路径保持入口 errno；诊断可空不改变处理，caller 安排下一轮、通知消费或收尾。
 */
vireo_result_t vireo_timer_loop_run_once(vireo_event_loop_t *loop,
                                       vireo_timer_wheel_t *wheel,
                                       vireo_timer_loop_run_options_t const *options,
                                       vireo_timer_loop_run_report_t *out_report,
                                       vireo_timer_loop_diagnostic_t *out_diagnostic);

#endif /* VIREO_NET_TIMER_LOOP_RUN_H */

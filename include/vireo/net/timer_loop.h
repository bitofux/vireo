/*
 * PROJECT : VIREO
 * FILE    : timer_loop.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 从显式单调时间及只读时间轮快照规划等待
 * -- 区分轮待处理工作、等待上限与下一刻度边界
 */
#ifndef VIREO_NET_TIMER_LOOP_H
#define VIREO_NET_TIMER_LOOP_H

#include <stdbool.h>
#include <vireo/timer/wheel.h>

/** 独立等待值快照，不保活轮、不预留未来状态，不作为 wire ABI。 */
typedef struct vireo_timer_loop_wait_plan {
    int timeout_ms; /**< 非负等待毫秒，不超过 caller 上限，永不为 -1。 */
    bool timer_work_pending; /**< 新时间尚未追上、桶处理中或仍有 ready 通知。 */
    bool has_tick_deadline; /**< 已追上且有活跃登记，给出下一刻度边界。 */
    vireo_monotonic_ns_t tick_deadline_ns; /**< 同域有限 ns 边界；无边界时逻辑值为 0。 */
} vireo_timer_loop_wait_plan_t;

/**
 * @brief 只读规划下一次等待，不采样、推进或消费时间轮
 *
 * @param[in] wheel
 *     非空、存活且已 prepare 的轮，所属 Reactor 独占，只短借至返回。
 * @param[in] now_ns
 *     caller 显式同域单调 ns，不早于 origin 或前次成功 advance 的 now。
 * @param[in] max_wait_ms
 *     显式非负 int 毫秒上限，最多 INT_MAX；0 表示不等待。
 * @param[out] out_plan
 *     非空、存活、对齐可写的独立快照，不重叠、不在轮资源内、不指 errno。
 *
 * @retval VIREO_OK
 *     待处理时返回 0/true/false/0；已追上空轮返回上限/false/false/0。
 *     已追上非空轮给下一 tick 边界，剩余 ns 向上舍入 ms 再限额。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL 或上限为负；优先于准备、停止和时间检查。
 * @retval VIREO_RESULT_NOT_FOUND
 *     此轮未 prepare。
 * @retval VIREO_RESULT_CANCELLED
 *     轮已永久停止；准备检查之后、时间检查之前拒绝。
 * @retval VIREO_RESULT_RANGE
 *     now 早于 origin 或前次成功 advance 的 now。
 * @retval VIREO_RESULT_OVERFLOW
 *     受检下一累计刻度或其纳秒边界不可表示，不能回绕或截限。
 *
 * @note
 *     失败整个输出和轮保持，依赖错误原样返回；所有路径保持入口 errno。
 * @note
 *     待处理包含显式新 now 的进度债，不能仅依据旧 caught_up；processing 即使 pending 空也有效。
 * @note
 *     无 tick 边界时逻辑值 0，不承诺 padding；0 和 UINT64_MAX 仍是正常有限时间值。
 * @note
 *     cap 为 0 不代表到期；已追上非空轮仍提供边界且 pending=false。
 * @note
 *     下一 tick 策略无需最近期限遍历；长期项周期唤醒，空轮等待上限会留下日后追赶工作。
 * @note
 *     O(1)，同轮 Reactor-only，无分配、I/O、回调、业务指针保存或内部资源借用。
 * @note
 *     caller 在时间或轮变化后重新规划；实际采样、运行、通知消费及业务收尾由 caller 另行负责。
 */
vireo_result_t vireo_timer_loop_plan_wait(vireo_timer_wheel_t const *wheel,
                                        vireo_monotonic_ns_t now_ns, int max_wait_ms,
                                        vireo_timer_loop_wait_plan_t *out_plan);

#endif /* VIREO_NET_TIMER_LOOP_H */

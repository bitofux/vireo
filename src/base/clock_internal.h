/*
 * PROJECT : VIREO
 * FILE    : clock_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-08
 * BRIEF   : 此模块负责：
 * -- 提供 clock 自身实现和测试使用的窄采集入口
 * -- 不向其他模块授予原生时钟或私有操作表合同
 */

#ifndef VIREO_BASE_CLOCK_INTERNAL_H
#define VIREO_BASE_CLOCK_INTERNAL_H

#include <time.h>

#include <vireo/base/clock.h>

/**
 * @brief 本次调用期间借用的采集操作表，无全局可变替换
 *
 * gettime 应遵守 clock_gettime 的 0/-1 与 errno 约定；异常返回亦被防御检查。
 * 成功时完整写入 sample，失败时局部 sample 可改变，不保存任何指针。
 */
typedef struct vireo_clock_ops {
    int (*gettime)(clockid_t clock_id, struct timespec *sample, void *context);
    /**< 必需采集函数，收到固定 CLOCK_MONOTONIC，单次调用，无所有权转移。 */
    void *context;
    /**< 可空短期借用上下文；须有效至返回，共享测试上下文由调用者同步。 */
} vireo_clock_ops_t;

/**
 * @brief 使用本模块的借用操作表执行公共采集算法
 *
 * @param[in] ops
 *     非空且 gettime 非空的稳定操作表；仅调用期间借用。
 * @param[out] out_now
 *     非空独立可写时间地址；只有完整成功才写入，调用者持有。
 * @param[out] error
 *     可空独立可写诊断；与输入、输出、上下文及 errno 存储不重叠。
 *
 * @retval VIREO_OK
 *     输出完整纳秒时间点，诊断 NONE/0。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     ops、gettime 或 out_now 为空；零次采集，诊断 NONE/0。
 * @retval VIREO_RESULT_IO
 *     采集返回 -1，报告 READ/原始 errno。
 * @retval VIREO_RESULT_OVERFLOW
 *     受检纳秒结果无法表示，报告 CONVERT/0。
 * @retval VIREO_RESULT_INTERNAL
 *     原生约定或时间形态异常，报告对应阶段/0。
 *
 * @note
 *     输出保持：失败保持时间输出，诊断可覆盖；地址只借用到返回。
 * @note
 *     errno：所有路径恢复入口 errno；采集上下文不得破坏 errno 存储。
 * @note
 *     线程安全：无内部共享状态；注入函数及上下文须自行满足并发约束。
 * @note
 *     范围边界：只供 clock 自身实现/测试使用，不是下游公共 backend。
 */
vireo_result_t vireo_clock_monotonic_now_with_ops(vireo_clock_ops_t const *ops,
                                                 vireo_monotonic_ns_t *out_now,
                                                 vireo_clock_error_t *error);

#endif /* VIREO_BASE_CLOCK_INTERNAL_H */

/*
 * PROJECT : VIREO
 * FILE    : clock.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-08
 * BRIEF   : 此模块负责：
 * -- 采集固定 CLOCK_MONOTONIC 时间点
 * -- 定义纳秒时间值和独立失败诊断
 * -- 对显式时间点执行受检 deadline 数学
 * -- 精确转换毫秒长度并计算有上限的等待毫秒
 */

#ifndef VIREO_BASE_CLOCK_H
#define VIREO_BASE_CLOCK_H

#include <stdbool.h>
#include <stdint.h>

#include <vireo/base/result.h>

/**
 * @brief 同一单调时间域内的纳秒时间点
 *
 * uint64_t 的全部值均有效，0 和 UINT64_MAX 不表示空值或无限期限。
 * 这是单位别名，不提供 C 类型系统的强隔离；不能当作 UTC、wire 或持久时间戳。
 * 不承诺跨系统重启或不同时间 namespace 可比，也不承诺实际纳秒分辨率。
 */
typedef uint64_t vireo_monotonic_ns_t;

/** @brief 本次采集或转换的诊断阶段；不是协议状态或重试指令。 */
typedef enum vireo_clock_stage {
    VIREO_CLOCK_STAGE_NONE = 0, /**< 成功或参数拒绝，没有采集/转换失败。 */
    VIREO_CLOCK_STAGE_READ = 1, /**< 固定时钟读取失败或原生返回约定异常。 */
    VIREO_CLOCK_STAGE_CONVERT = 2, /**< 原生时间形态异常或纳秒结果不可表示。 */
} vireo_clock_stage_t;

/** @brief 调用者持有的按值诊断，不保存资源或借用指针。 */
typedef struct vireo_clock_error {
    vireo_clock_stage_t stage; /**< 本次调用的失败位置，成功/参数拒绝为 NONE。 */
    int system_errno; /**< 原生读取返回 -1 时的 errno；其他情况为 0。 */
} vireo_clock_error_t;

/**
 * @brief 单次采集 CLOCK_MONOTONIC 并受检转换为纳秒时间点
 *
 * 此时钟不受墙钟不连续跳变影响，但受系统渐进校准影响，不累计系统挂起时间。
 * 同一时间域内的顺序采样不会后退，允许相邻结果相等。
 * 原生秒须非负，亚秒须在 0..999999999；不对异常值进行归一化或截断。
 *
 * @param[out] out_now
 *     非空、有效且可写的时间值地址；调用者保留所有权，单位纳秒。
 * @param[out] error
 *     可空的独立可写诊断地址；调用者保留所有权，非空时覆盖两个成员。
 *
 * @retval VIREO_OK
 *     原生采集及受检转换成功，*out_now 已完整写入，诊断为 NONE/0。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     out_now 为 NULL，不读取系统时钟，诊断为 NONE/0。
 * @retval VIREO_RESULT_IO
 *     clock_gettime 返回 -1，诊断为 READ 和立即保存的原始 errno。
 * @retval VIREO_RESULT_OVERFLOW
 *     秒到纳秒的转换或最终相加不可由 uint64_t 表示，诊断为 CONVERT/0。
 * @retval VIREO_RESULT_INTERNAL
 *     原生返回约定异常（READ/0）或成功返回的时间形态异常（CONVERT/0）。
 *
 * @note
 *     输出保持：任何失败均保持 *out_now；诊断可改变，NULL 诊断不改变处理。
 * @note
 *     所有权与生命周期：只在调用期间借用地址，不保存指针，无对象创建或销毁。
 * @note
 *     地址约束：输出与诊断须存活、正确对齐、可写且互不重叠，不得指向 errno 存储。
 * @note
 *     线程安全：thread-safe；并发调用须使用独立输出，共享地址由调用者同步。
 * @note
 *     errno：保存并恢复入口 errno，原生失败原因由 error.system_errno 报告。
 * @note
 *     运行边界：只读取一次，无重试、备用时钟或缓存修正，无用户态动态分配。
 * @note
 *     范围边界：不等待、不构造 deadline、不驱动 timer 或网络关闭；无硬实时延迟保证。
 */
vireo_result_t vireo_clock_monotonic_now(vireo_monotonic_ns_t *out_now,
                                        vireo_clock_error_t *error);

/**
 * @brief 非负纳秒时间长度
 *
 * uint64_t 的全部值均有效，0 表示零长度，UINT64_MAX 表示有限长度。
 * 与时间点含义不同；这是单位别名，不提供 C 类型系统的强隔离。
 */
typedef uint64_t vireo_duration_ns_t;

/**
 * @brief 从显式单调时间点与非负长度受检构造绝对 deadline
 *
 * deadline 与 now 属于同一单调时间域，只有数学和可表示时才发布。
 * delay 为 0 时 deadline 等于 now，按到期合同立即到期；不读取系统时钟。
 *
 * @param[in] now
 *     调用者提供的单调纳秒时间点，全部 uint64_t 值有效。
 * @param[in] delay
 *     纳秒时间长度，全部 uint64_t 值有效，无无限期限哨兵。
 * @param[out] out_deadline
 *     非空、有效、正确对齐且可写的时间点地址；调用者保留所有权。
 *
 * @retval VIREO_OK
 *     *out_deadline 写入准确的 now + delay，包括恰为 UINT64_MAX 的结果。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     out_deadline 为 NULL；参数拒绝优先于数值溢出检查。
 * @retval VIREO_RESULT_OVERFLOW
 *     数学和大于 UINT64_MAX；不回绕、不截限或转换为无限期限。
 *
 * @note
 *     输出保持：任何失败均保持 *out_deadline；只有完整成功才写入。
 * @note
 *     地址与生命周期：仅借用到返回，不保存；可与输入值原存储相同，不得指向 errno 存储。
 * @note
 *     线程安全：thread-safe；独立输出可并发，共享输出由调用者同步。
 * @note
 *     errno：不读取、不保存且不修改 errno；无系统采集或采集错误诊断。
 * @note
 *     时间域：调用者负责来源与采样新鲜度；函数不能识别墙钟、跨重启或 namespace 混用。
 */
vireo_result_t vireo_clock_deadline_after(vireo_monotonic_ns_t now,
                                         vireo_duration_ns_t delay,
                                         vireo_monotonic_ns_t *out_deadline);

/**
 * @brief 判断显式时间点是否已达到同域的绝对 deadline
 *
 * 使用 now >= deadline，包括相等边界；已经到期是成功查询结果，不返回 TIMEOUT。
 *
 * @param[in] now
 *     调用者提供的单调纳秒时间点，全部 uint64_t 值有效。
 * @param[in] deadline
 *     同一单调时间域的纳秒 deadline；0 与 UINT64_MAX 都是正常有限时间点。
 * @param[out] out_expired
 *     非空、有效、正确对齐且可写的 bool 地址；调用者保留所有权。
 *
 * @retval VIREO_OK
 *     *out_expired 写入 now >= deadline 的结果。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     out_expired 为 NULL。
 *
 * @note
 *     输出与生命周期：失败保持输出，只借用到返回，不保存地址，不得指向 errno 存储。
 * @note
 *     线程安全：thread-safe；共享输出由调用者同步，无内部可变状态。
 * @note
 *     errno：不读取、不保存且不修改 errno；不读取时钟或使用采集错误诊断。
 * @note
 *     范围边界：仅比较数值，调用者负责同域与采样新鲜度；不关闭、取消或延长期限。
 */
vireo_result_t vireo_clock_deadline_expired(vireo_monotonic_ns_t now,
                                           vireo_monotonic_ns_t deadline,
                                           bool *out_expired);

/**
 * @brief 计算显式时间点距离同域绝对 deadline 的非负剩余长度
 *
 * now < deadline 时返回准确差值，否则成功返回 0；先比较再减法，不产生无符号下溢。
 *
 * @param[in] now
 *     调用者提供的单调纳秒时间点，全部 uint64_t 值有效。
 * @param[in] deadline
 *     同一单调时间域的纳秒 deadline，无无限或未设置哨兵。
 * @param[out] out_remaining
 *     非空、有效、正确对齐且可写的纳秒长度地址；调用者保留所有权。
 *
 * @retval VIREO_OK
 *     输出准确的正剩余长度，或已到期时的 0；不返回 TIMEOUT。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     out_remaining 为 NULL。
 *
 * @note
 *     输出与生命周期：失败保持输出，只借用到返回；可与输入值原存储相同，不得指向 errno 存储。
 * @note
 *     线程安全：thread-safe；共享输出由调用者同步，无内部可变状态。
 * @note
 *     errno：不读取、不保存且不修改 errno；不读取时钟或使用采集错误诊断。
 * @note
 *     范围边界：只返回纳秒长度，不换算等待毫秒或 timer tick，不延长期限或执行到期动作。
 */
vireo_result_t vireo_clock_deadline_remaining(vireo_monotonic_ns_t now,
                                             vireo_monotonic_ns_t deadline,
                                             vireo_duration_ns_t *out_remaining);

/**
 * @brief 把非负毫秒长度精确受检转换为纳秒长度
 *
 * 只有 milliseconds * 1000000 的数学结果可由 uint64_t 表示才发布，不截断或饱和。
 *
 * @param[in] milliseconds
 *     非负毫秒长度，全部 uint64_t 输入可传；0 表示零长度，无无限哨兵。
 * @param[out] out_duration
 *     非空、有效、正确对齐且可写的纳秒长度地址；调用者保留所有权。
 *
 * @retval VIREO_OK
 *     输出准确的纳秒长度。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     out_duration 为 NULL；参数拒绝优先于溢出检查。
 * @retval VIREO_RESULT_OVERFLOW
 *     毫秒转换的数学结果大于 UINT64_MAX。
 *
 * @note
 *     输出与生命周期：失败保持输出，地址短借至返回，不保存；可写回输入原存储。
 * @note
 *     地址约束：输出不得指向 errno 存储；调用者须保证存活、对齐且可写。
 * @note
 *     线程安全：thread-safe；共享输出由调用者同步，无内部可变状态。
 * @note
 *     errno：不读取、不保存且不修改 errno，无采集或采集错误诊断。
 * @note
 *     范围边界：只转换长度，不采样、构造期限或等待；原网络接口的 -1 不属于此无符号输入合同。
 */
vireo_result_t vireo_clock_duration_from_ms(uint64_t milliseconds,
                                           vireo_duration_ns_t *out_duration);

/**
 * @brief 将同域 deadline 的剩余长度转换为有调用者上限的相对等待毫秒
 *
 * 已到期时为 0；未到期时取剩余纳秒向上舍入的毫秒与 max_wait_ms 的较小者。
 * 这是等待预算，不改变纳秒 deadline；不读取系统时钟或执行实际等待。
 *
 * @param[in] now
 *     调用者提供的单调纳秒时间点，全部 uint64_t 值有效。
 * @param[in] deadline
 *     同一单调时间域的纳秒 deadline，0 与 UINT64_MAX 均为有限时间点。
 * @param[in] max_wait_ms
 *     非负 int 毫秒上限，0 表示本轮不等待；负值（含 -1）均非法。
 * @param[out] out_wait_ms
 *     非空、有效、正确对齐且可写的 int 地址；调用者保留所有权。
 *
 * @retval VIREO_OK
 *     输出 0..max_wait_ms 的有限等待毫秒；永不产生 -1，不返回 TIMEOUT。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     out_wait_ms 为 NULL 或 max_wait_ms 为负；即使已到期也先拒绝非法参数。
 *
 * @note
 *     输出与生命周期：失败保持输出，只借用到返回，不保存；可写回 max_wait_ms 原存储。
 * @note
 *     地址约束：输出不得指向 errno 存储；调用者须保证存活、对齐且可写。
 * @note
 *     线程安全：thread-safe；共享输出由调用者同步，无内部可变状态。
 * @note
 *     errno：不读取、不保存且不修改 errno；无采集、IO 或采集诊断。
 * @note
 *     舍入影响：向上舍入的请求可比剩余期限多不足 1 ms；返回后须重新采样并检查到期。
 * @note
 *     上限语义：max_wait_ms 为 0 时未到期也可输出 0，不能仅凭等待值判定到期。
 * @note
 *     时间域与范围：调用者负责同域和采样新鲜度；无硬实时调度保证或自动到期动作。
 */
vireo_result_t vireo_clock_deadline_wait_ms(vireo_monotonic_ns_t now,
                                           vireo_monotonic_ns_t deadline,
                                           int max_wait_ms, int *out_wait_ms);

#endif /* VIREO_BASE_CLOCK_H */

/*
 * PROJECT : VIREO
 * FILE    : wheel_time.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 定义显式时间轮几何和累计刻度
 * -- 受检映射时间点、刻度和数学桶位置
 * -- 区分数值映射与实际定时器调度
 */
#ifndef VIREO_TIMER_WHEEL_TIME_H
#define VIREO_TIMER_WHEEL_TIME_H

#include <vireo/base/clock.h>

/** 累计刻度数量，不是纳秒；0..UINT64_MAX 均有效，不回绕或安排哨兵。 */
typedef uint64_t vireo_timer_wheel_tick_t;

/**
 * @brief 不拥有资源的时间轮几何值，布局不作为 wire ABI
 *
 * origin_ns 与输入时间须来自同一 boot/namespace/CLOCK_MONOTONIC 域。
 * tick_ns 和 bucket_count 必须非零；不分配桶或保证未来刻度可还原。
 * 全部函数只做数学，不读时钟、登记定时器、推进游标或执行回调。
 */
typedef struct vireo_timer_wheel_geometry {
    vireo_monotonic_ns_t origin_ns; /**< 累计刻度 0 的单调纳秒时间点，0..MAX。 */
    vireo_duration_ns_t tick_ns; /**< 一个刻度的正纳秒长度，1..MAX，无默认值。 */
    uint64_t bucket_count; /**< 正数学桶数，非实际数组容量或身份登记槽数。 */
} vireo_timer_wheel_geometry_t;

/**
 * @brief 构造合法几何值，不创建实际时间轮
 *
 * @param[in] origin_ns
 *     同域单调起点，0..UINT64_MAX 均为有限有效时间。
 * @param[in] tick_ns
 *     正纳秒刻度长度，不使用特殊哨兵或默认值。
 * @param[in] bucket_count
 *     正 uint64 数学桶数，UINT64_MAX 也可表达；不承诺能够分配数组。
 * @param[out] out_geometry
 *     caller 持有的非空、存活、对齐可写地址，不指向 errno 存储。
 *
 * @retval VIREO_OK
 *     完整写入三个逻辑字段，不承诺 padding 或未来正刻度可还原。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     输出为 NULL、tick_ns 或 bucket_count 为 0。
 *
 * @note
 *     失败保持整个输出对象；只借地址至返回，不保存，按值输入可来自原字段。
 * @note
 *     独立输出 thread-safe；共享输出由 caller 同步。所有路径不读、不改 errno。
 */
vireo_result_t vireo_timer_wheel_geometry_make(vireo_monotonic_ns_t origin_ns,
                                              vireo_duration_ns_t tick_ns,
                                              uint64_t bucket_count,
                                              vireo_timer_wheel_geometry_t *out_geometry);

/**
 * @brief 向下计算截至显式当前时间已经完整过去的累计刻度
 *
 * @param[in] geometry
 *     按值合法几何，两个正参数均非零。
 * @param[in] now_ns
 *     同域单调时间点，必须不小于 origin_ns，等号返回刻度 0。
 * @param[out] out_tick
 *     caller 持有的非空、存活、对齐可写刻度地址，不指向 errno。
 *
 * @retval VIREO_OK
 *     输出 floor((now_ns - origin_ns) / tick_ns)，不修改实际时间游标。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     输出为 NULL 或几何形态非法，优先于时间范围检查。
 * @retval VIREO_RESULT_RANGE
 *     now_ns 小于起点；不回绕相减或静默夹到 0。
 *
 * @note
 *     失败保持输出；按值输入可按正确类型写回原存储，地址只借至返回。
 * @note
 *     caller 负责同域和采样新鲜度；独立输出 thread-safe，所有路径不读、不改 errno。
 */
vireo_result_t vireo_timer_wheel_elapsed_tick(vireo_timer_wheel_geometry_t geometry,
                                             vireo_monotonic_ns_t now_ns,
                                             vireo_timer_wheel_tick_t *out_tick);

/**
 * @brief 将 deadline 向上映射到可表示的轮边界刻度
 *
 * @param[in] geometry
 *     按值合法几何，caller 保证与 deadline 同域。
 * @param[in] deadline_ns
 *     有限纳秒期限；不大于 origin_ns 时映射为刻度 0。
 * @param[out] out_tick
 *     caller 持有的非空、存活、对齐可写刻度地址，不指向 errno。
 *
 * @retval VIREO_OK
 *     输出 0 或 ceil((deadline_ns - origin_ns) / tick_ns)，对应边界可表示。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     输出为 NULL 或几何形态非法。
 * @retval VIREO_RESULT_OVERFLOW
 *     origin_ns + 刻度 * tick_ns 不可表示；即使刻度自身可表示也拒绝。
 *
 * @note
 *     失败保持输出；商余数求 ceil，不先加 tick_ns - 1。无回绕、截限或无限哨兵。
 * @note
 *     deadline 大于起点时，边界不提前且只晚不足一个 tick；实际调度可更晚。
 * @note
 *     不处理相对真实游标已经过期的登记策略，不执行到期动作。
 * @note
 *     地址只短借，可按正确类型写回按值输入；独立输出 thread-safe，不读、不改 errno。
 */
vireo_result_t vireo_timer_wheel_deadline_tick(vireo_timer_wheel_geometry_t geometry,
                                              vireo_monotonic_ns_t deadline_ns,
                                              vireo_timer_wheel_tick_t *out_tick);

/**
 * @brief 将累计刻度受检还原为绝对单调时间点
 *
 * @param[in] geometry
 *     按值合法几何，两个正参数均非零。
 * @param[in] tick
 *     累计刻度，0..UINT64_MAX；0 对应 origin_ns。
 * @param[out] out_time_ns
 *     caller 持有的非空、存活、对齐可写时间地址，不指向 errno。
 *
 * @retval VIREO_OK
 *     完整输出 origin_ns + tick * tick_ns。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     输出为 NULL 或几何形态非法，优先于溢出检查。
 * @retval VIREO_RESULT_OVERFLOW
 *     乘积或最终和不可表示，不回绕或饱和。
 *
 * @note
 *     失败保持输出；地址只借至返回，可按正确类型写回按值输入。
 * @note
 *     无时钟采样或等待；独立输出 thread-safe，所有路径不读、不改 errno。
 */
vireo_result_t vireo_timer_wheel_tick_time(vireo_timer_wheel_geometry_t geometry,
                                          vireo_timer_wheel_tick_t tick,
                                          vireo_monotonic_ns_t *out_time_ns);

/**
 * @brief 根据累计刻度取模定位数学时间桶，不索引数组
 *
 * @param[in] geometry
 *     按值合法几何，bucket_count 为正 uint64 数学桶数。
 * @param[in] tick
 *     累计刻度，0..UINT64_MAX，不要求对应纳秒边界可以还原。
 * @param[out] out_bucket_index
 *     caller 持有的非空、存活、对齐可写 uint64 地址，不指向 errno。
 *
 * @retval VIREO_OK
 *     输出 tick % bucket_count，范围 0..bucket_count - 1。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     输出为 NULL 或几何形态非法。
 *
 * @note
 *     同桶可能属于不同圈；此索引不是 handle 的身份登记槽，不授予数组访问权。
 * @note
 *     失败保持输出；地址只短借，可按正确类型写回按值输入，不保存指针。
 * @note
 *     独立输出 thread-safe；所有路径不读、不改 errno，不修改任何游标或定时器。
 */
vireo_result_t vireo_timer_wheel_bucket_index(vireo_timer_wheel_geometry_t geometry,
                                             vireo_timer_wheel_tick_t tick,
                                             uint64_t *out_bucket_index);

#endif /* VIREO_TIMER_WHEEL_TIME_H */

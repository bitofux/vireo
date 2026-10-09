/*
 * PROJECT : VIREO
 * FILE    : wheel.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 创建显式预算内的固定空时间桶
 * -- 提供不借内部指针的数值观测
 * -- 拒绝非空桶销毁并成对释放空轮资源
 */
#ifndef VIREO_TIMER_WHEEL_H
#define VIREO_TIMER_WHEEL_H

#include <stddef.h>
#include <vireo/timer/wheel_time.h>

/** 实际桶数组硬限，不是定时器数量、身份槽容量或默认桶数。 */
#define VIREO_TIMER_WHEEL_MAX_BUCKETS UINT64_C(65536)
/** 控制块与桶数组申请总量预算硬限；不包含 allocator 开销或 RSS。 */
#define VIREO_TIMER_WHEEL_MAX_MEMORY ((size_t)67108864)

/** 唯一拥有型 opaque 轮；全部同轮访问 Reactor-only，布局不公开。 */
typedef struct vireo_timer_wheel vireo_timer_wheel_t;

/** 显式创建值，无默认参数；不作为 wire ABI。 */
typedef struct vireo_timer_wheel_options {
    vireo_timer_wheel_geometry_t geometry; /**< 沿用单调 ns 几何；实际桶数另受资源限制。 */
    size_t max_memory_bytes; /**< 正请求字节预算，不超过 MAX_MEMORY。 */
} vireo_timer_wheel_options_t;

/** 不保活轮、不持有内部借用的数值快照。 */
typedef struct vireo_timer_wheel_info {
    vireo_timer_wheel_geometry_t geometry; /**< 创建时保存的几何，不是已推进游标。 */
    size_t allocation_bytes; /**< 控制块与完整固定桶数组的实际请求总字节。 */
    size_t max_memory_bytes; /**< 创建时显式预算，非 RSS 或全局多轮预算。 */
} vireo_timer_wheel_info_t;

/**
 * @brief 完整初始化固定 dummy 桶后发布空轮
 *
 * @param[in] options
 *     非空、存活、对齐可读选项；tick 和桶数均正，预算正，无默认。
 * @param[in,out] out_wheel
 *     非空、存活、对齐可写的唯一拥有者地址，入口值必须为 NULL。
 *
 * @retval VIREO_OK
 *     发布完整空轮，每桶内嵌双向循环 dummy 自环；不发放 timer handle。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、入口轮非空、零 tick、零桶数或零预算。
 * @retval VIREO_RESULT_RANGE
 *     桶数不能由 size_t 表示，硬限超出或总申请量超过预算。
 * @retval VIREO_RESULT_OVERFLOW
 *     桶数组乘法或总量加法不可表示；算术检查先于硬限和预算。
 * @retval VIREO_RESULT_NO_MEMORY
 *     两次申请中任一次失败，已申请资源逆序释放。
 *
 * @note
 *     options 与输出独立、不重叠、不指向 errno；只短借至返回，不保存地址。
 * @note
 *     失败保持整个输出，所有路径恢复入口 errno，无短进度或自动重试。
 * @note
 *     本入口只创建控制块和桶数组；预算不含 allocator 开销、业务或独立 prepare 的登记资源。
 * @note
 *     不采样时钟、登记或执行定时器；合法几何不保证下一正刻度可还原。
 * @note
 *     同轮所有访问 Reactor-only，无锁；初始化 O(桶数)，申请无硬实时保证。
 */
vireo_result_t vireo_timer_wheel_create(vireo_timer_wheel_options_t const *options,
                                       vireo_timer_wheel_t **out_wheel);

/**
 * @brief 读取三个逻辑字段的数值快照
 *
 * @param[in] wheel
 *     非空、存活的本层轮，由所属 Reactor 访问。
 * @param[out] out_info
 *     非空、存活、对齐可写地址；不在轮自有资源内，不与轮重叠、不指向 errno。
 *
 * @retval VIREO_OK
 *     完整写快照，不承诺 padding、返回内部指针或保活轮。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     任一必需地址为 NULL，保持整个输出对象。
 *
 * @note
 *     地址只短借至返回；不检查定时器活跃性或采样、推进时间。
 * @note
 *     O(1)，同轮 Reactor-only；所有路径不读、不改 errno。
 */
vireo_result_t vireo_timer_wheel_inspect(vireo_timer_wheel_t const *wheel,
                                        vireo_timer_wheel_info_t *out_info);

/**
 * @brief 仅在所有节点环及身份登记为空时释放轮，并清空唯一拥有者
 *
 * @param[in,out] wheel
 *     非空、存活、对齐可读写的唯一拥有者地址；不在轮自有资源内、不指向 errno。
 *
 * @retval VIREO_OK
 *     入口 *wheel 为 NULL 时空操作成功；否则释放桶数组与控制块，清 NULL。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     拥有者地址为 NULL。
 * @retval VIREO_RESULT_BUSY
 *     任一普通桶/pending/ready 非空或仍有身份登记，保持全部输出与资源。
 *
 * @note
 *     caller 先停止同轮操作和裸别名使用；成功后所有旧裸别名失效，不提供引用计数。
 * @note
 *     全桶扫描 O(桶数)，不遍历业务节点，不执行回调或强制清理业务资源。
 * @note
 *     已 prepare 时同时释放空身份 owner 和节点表；空 pending 的推进状态不阻止销毁。
 * @note
 *     同轮 Reactor-only；只短借拥有者地址，失败保持输出，所有路径恢复入口 errno。
 */
vireo_result_t vireo_timer_wheel_destroy(vireo_timer_wheel_t **wheel);

#endif /* VIREO_TIMER_WHEEL_H */

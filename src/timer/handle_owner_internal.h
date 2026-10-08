/*
 * PROJECT : VIREO
 * FILE    : handle_owner_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-08
 * BRIEF   : 此模块负责：
 * -- 定义本模块真实登记布局
 * -- 提供本模块隔离分配与身份计数测试入口
 */
#ifndef VIREO_TIMER_HANDLE_OWNER_INTERNAL_H
#define VIREO_TIMER_HANDLE_OWNER_INTERNAL_H

#include <stdatomic.h>
#include <vireo/timer/handle_owner.h>

/** 成对分配策略；只用于本模块，context 必须存活至 owner 销毁。 */
typedef struct vireo_timer_handle_owner_allocator {
    void *(*allocate)(size_t bytes, void *context); /**< 成功返回至少 bytes 字节、适合本层对象对齐的独占可写内存；NULL 为失败。 */
    void (*deallocate)(void *memory, void *context); /**< 消费对应成功申请，不报告失败。 */
    void *context; /**< 借用测试状态；生产默认 NULL，不拥有。 */
} vireo_timer_handle_owner_allocator_t;

/** 空闲槽索引链与活跃身份分离；本模块独占，不返回给使用者。 */
typedef struct vireo_timer_handle_owner_slot {
    uint64_t generation; /**< 活跃时当前非零代次；空闲时不授予身份。 */
    size_t next_free; /**< 空闲时下一槽，SIZE_MAX 为链尾，活跃时不读取。 */
    bool active; /**< 当前是否有尚未归还的身份。 */
} vireo_timer_handle_owner_slot_t;

struct vireo_timer_handle_owner {
    vireo_timer_handle_owner_slot_t *slots; /**< 拥有固定登记表，最终由同 allocator 释放。 */
    size_t capacity; /**< 正固定槽数量。 */
    size_t free_head; /**< 空闲链头，SIZE_MAX 表示无空闲槽。 */
    size_t active_count; /**< 当前活跃数，始终不大于 capacity。 */
    size_t allocation_bytes; /**< 控制块与表的受检申请总字节。 */
    size_t max_memory_bytes; /**< 创建时显式预算。 */
    uint64_t owner_id; /**< 非零管理身份，生存期内不变。 */
    uint64_t last_generation; /**< 最后成功发序，0 表示从未发放，MAX 停发。 */
    vireo_timer_handle_owner_allocator_t allocator; /**< 按值保存成对释放策略，context 仅借用。 */
};

/**
 * @brief 用隔离 allocator 与 ID counter 执行同一构造路径，非公共 API
 *
 * @param[in] options
 *     遵守公共 create 的选项合同。
 * @param[in,out] out_owner
 *     遵守公共 create 的入口空 owner 合同。
 * @param[in] allocator
 *     非 NULL，两个函数均非 NULL；按值保存，context 活到 destroy。
 * @param[in,out] identity_counter
 *     非 NULL、已初始化的独立原子计数器；不得重置生产 counter 或与输出/资源重叠。
 *
 * @retval VIREO_OK
 *     成功发布完整 owner。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     额外策略/计数器参数非法，或公共参数非法。
 * @retval VIREO_RESULT_OVERFLOW
 *     申请量或身份耗尽。
 * @retval VIREO_RESULT_RANGE
 *     硬限或预算不满足。
 * @retval VIREO_RESULT_NO_MEMORY
 *     分配失败并逆序回滚。
 *
 * @note
 *     输出/errno/线程沿公共 create；测试独立域不代表生产真实发放极大次数。
 */
vireo_result_t vireo_timer_handle_owner_create_runtime(
    vireo_timer_handle_owner_options_t const *options, vireo_timer_handle_owner_t **out_owner,
    vireo_timer_handle_owner_allocator_t const *allocator, _Atomic uint64_t *identity_counter);

#endif /* VIREO_TIMER_HANDLE_OWNER_INTERNAL_H */

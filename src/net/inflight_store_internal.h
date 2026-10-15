/*
 * PROJECT : VIREO
 * FILE    : inflight_store_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 仅本核心实现与测试使用的记录槽布局及配对申请 seam
 */
#ifndef VIREO_NET_INFLIGHT_STORE_INTERNAL_H
#define VIREO_NET_INFLIGHT_STORE_INTERNAL_H

#include <vireo/net/inflight_store.h>
#include <vireo/thread/task.h>

/** 本核心显式申请操作表，按值保存；没有全局可变故障开关。 */
typedef struct vireo_inflight_store_allocator {
    void *context; /**< 可空长借上下文，存活到表销毁，不由表释放。 */
    void *(*allocate)(void *context, size_t bytes); /**< 返回正确对齐独占块或 NULL。 */
    void (*deallocate)(void *context, void *allocation); /**< 配对释放原块，不失败或重入。 */
} vireo_inflight_store_allocator_t;

/** 表自有请求槽，可持取消引用；只有 occupied 时才读取 metadata。 */
typedef struct vireo_inflight_store_slot {
    bool occupied; /**< 初始 false，register 提交为 true，take 清为 false。 */
    vireo_task_metadata_t metadata; /**< occupied 时为完整有效值；空槽逻辑全零，不读取。 */
    vireo_task_cancel_t *cancel; /**< 可选自有强引用；空槽必须 NULL，take 仅释放本份。 */
} vireo_inflight_store_slot_t;

/** 一块申请拥有控制信息和固定柔性槽数组，不拥有外部业务资源。 */
struct vireo_inflight_store {
    size_t capacity; /**< 创建后固定的正槽数。 */
    size_t count; /**< 初始 0，等于 occupied 槽数，0..capacity，不是 queue 深度。 */
    size_t allocated_bytes; /**< 受检 sizeof 控制块加完整槽数组的申请字节数。 */
    size_t max_memory_bytes; /**< 创建时正预算，稳定至销毁。 */
    vireo_inflight_store_allocator_t allocator; /**< 自有操作表副本，context 长借。 */
    vireo_inflight_store_slot_t slots[]; /**< 自有固定 capacity 个记录槽，不对外借用。 */
};

/**
 * @brief
 *     本核心测试用配对申请入口，其余合同沿公开 create。
 *
 * @param[in] options
 *     稳定选项，短借至返回。
 * @param[in] allocator
 *     必需完整操作表，成功按值保存；context 借至销毁。
 *     allocate 成功须返回至少 bytes 字节正确对齐独占内存，deallocate 配对消费原块。
 * @param[out] out_store
 *     必需独占空 owner 地址，不重叠输入、资源或 errno。
 *
 * @return
 *     沿公开 create；额外 NULL 操作表或 callback 为 INVALID_ARGUMENT。
 *
 * @note
 *     操作不得改写输入、重入或非局部退出；deallocate 无失败返回。
 *     失败保持输出及资源，全部路径保持 errno；不供其他核心依赖。
 */
vireo_result_t vireo_inflight_store_create_with_allocator(
    vireo_inflight_store_options_t const *options,
    vireo_inflight_store_allocator_t const *allocator, vireo_inflight_store_t **out_store);

#endif /* VIREO_NET_INFLIGHT_STORE_INTERNAL_H */

/*
 * PROJECT : VIREO
 * FILE    : task_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : 仅本核心实现及测试使用的分配 seam 与 opaque 布局
 */

#ifndef VIREO_THREAD_TASK_INTERNAL_H
#define VIREO_THREAD_TASK_INTERNAL_H

#include <vireo/thread/task.h>

/**
 * @brief
 *     单对象配对分配操作，按值保存在 task 内；不是公开可替换分配器。
 *
 * @note
 *     allocate 返回全新、足量、正确对齐的独占内存或 NULL；deallocate 必须释放原块。
 *     两 callback 不得递归访问正在创建/销毁的 task 或破坏调用者输出。
 *     context 只借用，须存活且适当同步直到所有相关 task 销毁。
 */
typedef struct vireo_task_allocator {
    void *context; /**< callback 借用上下文，可 NULL，不由 task 释放。 */
    void *(*allocate)(void *context, size_t bytes); /**< 按字节申请，失败 NULL，可扰动 errno。 */
    void (*deallocate)(void *context, void *allocation); /**< 配对释放完整原块，无失败返回。 */
} vireo_task_allocator_t;

/**
 * @brief
 *     输入及关联创建后只读的唯一对象；共享取消标志可变，字段/sizeof 非公共合同。
 */
struct vireo_task {
    vireo_task_metadata_t metadata; /**< 自有按值元数据副本，不拥有客户。 */
    size_t payload_size; /**< flexible 区中有效字节数，允许零。 */
    size_t allocated_bytes; /**< sizeof 控制块加 payload 的受检申请量。 */
    vireo_task_allocator_t allocator; /**< 自有操作表副本，context 借到销毁。 */
    vireo_task_cancel_t *cancel; /**< 可 NULL；非空恰持一份强引用，移动转移，销毁释放。 */
    unsigned char payload[]; /**< 同一申请中的自有字节副本，只通过 const view 公开。 */
};

/**
 * @brief
 *     本核心用于确定分配失败的窄构造入口，其余语义同公开 create_copy。
 *
 * @param[in] metadata
 *     公开有效按值元数据，允许已到期。
 * @param[in] data
 *     稳定可读输入，非零长度不能 NULL。
 * @param[in] payload_size
 *     输入字节数，允许零。
 * @param[in] allocation_budget
 *     显式正申请量预算，最高64MiB。
 * @param[in] allocator
 *     必需有效操作表，两 callback 非 NULL；表只借到构造返回，context 借到销毁。
 * @param[out] out_task
 *     必需合法空 owner 地址，和对象/输入不重叠，不指 errno。
 *
 * @retval VIREO_OK
 *     完整复制后发布唯一 owner，私有表副本配对销毁。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     基本参数、metadata 或操作表无效，输出保持。
 * @retval VIREO_RESULT_OVERFLOW
 *     申请量不可表示，输出保持，不申请或读取输入字节。
 * @retval VIREO_RESULT_RANGE
 *     预算超限或不足，输出保持，不申请或读取输入字节。
 * @retval VIREO_RESULT_NO_MEMORY
 *     allocate 失败，输出保持。
 *
 * @note
 *     所有路径保持 errno；没有全局 mutable fault，不是下游可依赖布局或 API。
 */
vireo_result_t vireo_task_create_copy_with_allocator(vireo_task_metadata_t metadata,
    void const *data, size_t payload_size, size_t allocation_budget,
    vireo_task_allocator_t const *allocator, vireo_task_t **out_task);

/**
 * @brief
 *     带取消状态的本核心分配 seam，语义同公开 create_copy_with_cancel。
 *
 * @param[in] metadata
 *     有效按值元数据，允许已到期。
 * @param[in] data
 *     稳定可读输入，非零长度不能 NULL。
 * @param[in] payload_size
 *     输入字节数，允许零。
 * @param[in] allocation_budget
 *     显式正 task 申请预算，最高64MiB，不重复计共享 cancel 块。
 * @param[in] cancel
 *     必需、由来源强引用保护至返回的对象，不消费来源。
 * @param[in] allocator
 *     必需有效配对表，只借至返回，context 借至 task 销毁。
 * @param[out] out_task
 *     必需合法空 owner 地址，不与输入、资源或 errno 重叠。
 *
 * @return
 *     公开构造结果；额外拒绝非法表，retain 失败不申请，申请失败回滚引用。
 *
 * @note
 *     所有路径保持 errno，仅本核心实现/测试使用，不供下游依赖。
 */
vireo_result_t vireo_task_create_copy_with_cancel_and_allocator(vireo_task_metadata_t metadata,
    void const *data, size_t payload_size, size_t allocation_budget, vireo_task_cancel_t *cancel,
    vireo_task_allocator_t const *allocator, vireo_task_t **out_task);

#endif /* VIREO_THREAD_TASK_INTERNAL_H */

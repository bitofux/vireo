/*
 * PROJECT : VIREO
 * FILE    : completion_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 仅本核心实现和测试使用的配对分配 seam 与 opaque 布局
 */

#ifndef VIREO_THREAD_COMPLETION_INTERNAL_H
#define VIREO_THREAD_COMPLETION_INTERNAL_H

#include <vireo/thread/completion.h>

/**
 * @brief
 *     单对象配对分配操作，按值保存，不是公共可替换分配器。
 *
 * @note
 *     allocate 返回全新、足量、正确对齐的独占块或 NULL；deallocate 释放原块且无失败返回。
 *     callback 不重入或破坏构造/销毁及输出；context 借到所有相关对象销毁，须适当同步。
 */
typedef struct vireo_completion_allocator {
    void *context; /**< 分配操作借用上下文，可 NULL，不由 completion 释放。 */
    void *(*allocate)(void *context, size_t bytes); /**< 按字节申请，失败 NULL，可改变 errno。 */
    void (*deallocate)(void *context, void *allocation); /**< 配对释放完整原块，可改变 errno。 */
} vireo_completion_allocator_t;

/**
 * @brief
 *     同块自有完成描述和响应字节，创建后只读，布局和 sizeof 非公共合同。
 */
struct vireo_completion {
    vireo_completion_metadata_t metadata; /**< 自有完成描述副本，不保活客户或 task。 */
    size_t payload_size; /**< flexible 区中有效字节数，允许零。 */
    size_t allocated_bytes; /**< sizeof 控制块加 payload 的受检申请量。 */
    vireo_completion_allocator_t allocator; /**< 自有配对操作表副本，其 context 借到销毁。 */
    unsigned char payload[]; /**< 同一申请内的独立字节副本，只通过 const view 短借。 */
};

/**
 * @brief
 *     本核心验证实际申请失败的窄入口，其他合同沿公开 create_copy。
 *
 * @param[in] metadata
 *     有效按值完成描述。
 * @param[in] data
 *     稳定可读输入，非零长度须非 NULL。
 * @param[in] payload_size
 *     要复制的字节数，允许零。
 * @param[in] allocation_budget
 *     显式正申请预算，最高 64MiB。
 * @param[in] allocator
 *     必需有效配对表，两 callback 非 NULL；表借到返回，context 借到销毁。
 * @param[out] out_completion
 *     必需合法空 owner 地址，不与输入、资源或 errno 重叠。
 *
 * @return
 *     公开构造结果；额外非法表为 INVALID_ARGUMENT，失败保持整个输出和资源。
 *
 * @note
 *     所有路径保持 errno；没有全局 mutable fault，不供其他模块依赖。
 */
vireo_result_t vireo_completion_create_copy_with_allocator(vireo_completion_metadata_t metadata,
    void const *data, size_t payload_size, size_t allocation_budget,
    vireo_completion_allocator_t const *allocator, vireo_completion_t **out_completion);

#endif /* VIREO_THREAD_COMPLETION_INTERNAL_H */

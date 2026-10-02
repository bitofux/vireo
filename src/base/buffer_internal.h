/*
 * PROJECT : VIREO
 * FILE    : buffer_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-01
 * BRIEF   : 此模块负责：
 * -- 为本模块实现和测试提供窄的分配失败注入，不是下游公共合同
 */
#ifndef VIREO_BASE_BUFFER_INTERNAL_H
#define VIREO_BASE_BUFFER_INTERNAL_H

#include <vireo/base/buffer.h>

/** 对象内按值复制；生产使用 malloc/free，测试可记录真实分配与回滚。 */
typedef struct vireo_buffer_allocator {
    void *context; /**< 借用到对象销毁；生产为 NULL，测试 fixture 必须仍存活。 */
    void *(*allocate)(void *context, size_t size); /**< 返回独立且适当对齐的 size 字节或 NULL。 */
    void (*deallocate)(void *context, void *memory); /**< 精确释放配对分配，不失败、不重入对象。 */
} vireo_buffer_allocator_t;

/**
 * @brief 使用按值复制的有效操作表执行同一生产创建路径
 * @param[in] capacity 与公共 create 相同的正字节容量。
 * @param[in] allocator 非空，两个 callback 均必需；表仅借用到返回，context
 *     必须在失败清理或成功对象销毁前有效，不修改任何已发布资源。
 * @param[in,out] out_buffer 与公共 create 相同的空拥有者句柄。
 * @retval VIREO_OK 成功发布唯一拥有对象。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 操作表/callback或拥有者句柄非法。
 * @retval VIREO_RESULT_RANGE capacity 不在公共范围。
 * @retval VIREO_RESULT_NO_MEMORY 任一分配返回 NULL，已取得资源逆序释放。
 * @note allocator/context/out_buffer 与被创建对象不重叠；外部同步，保持 errno。
 * @note 操作表不是全局可变 hook，不允许下游 target 包含本头。
 */
vireo_result_t vireo_buffer_create_with_allocator(size_t capacity,
    vireo_buffer_allocator_t const *allocator, vireo_buffer_t **out_buffer);

#endif /* VIREO_BASE_BUFFER_INTERNAL_H */

/*
 * PROJECT : VIREO
 * FILE    : task_cancel_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : 本核心取消状态布局及局部配对分配 seam
 */

#ifndef VIREO_THREAD_TASK_CANCEL_INTERNAL_H
#define VIREO_THREAD_TASK_CANCEL_INTERNAL_H

#include <vireo/thread/task_cancel.h>

#include <stdatomic.h>
#include <stdint.h>

/**
 * @brief
 *     仅本核心实现及测试使用的配对分配表，复制表、借用 context。
 *
 * @note
 *     allocate 返回全新、足量、正确对齐块或 NULL；deallocate 配对释放原块。
 *     context 须存活至最后引用销毁，且与最后释放访问适当同步。
 *     callback 不得递归破坏正在处理的对象/输出；无公开 allocator 合同。
 */
typedef struct vireo_task_cancel_allocator {
    void *context; /**< 借用上下文，允许 NULL，不由取消状态释放。 */
    void *(*allocate)(void *context, size_t bytes); /**< 正字节申请，可扰动 errno。 */
    void (*deallocate)(void *context, void *allocation); /**< 配对释放完整块，无失败返回。 */
} vireo_task_cancel_allocator_t;

/**
 * @brief
 *     只共享标志和寿命，不拥有 task/客户；布局不属于公共 ABI。
 */
struct vireo_task_cancel {
    _Atomic(uint64_t) references; /**< 存活引用数1..MAX，受检增加，最后减到0释放。 */
    atomic_bool requested; /**< 初始化 false；只允许原子写 true，不允许 reset。 */
    vireo_task_cancel_allocator_t allocator; /**< 初始化后只读操作表，context 借至最后释放。 */
};

/**
 * @brief
 *     本核心局部分配 seam，其他合同与公开 create 相同。
 *
 * @param[in] allocation_budget
 *     显式正控制块申请字节预算，最高64MiB。
 * @param[in] allocator
 *     必需有效表，两 callback 非 NULL；表借到返回，context 借到最后销毁。
 * @param[out] out_cancel
 *     必需合法空 owner 地址，只借至返回，不与对象/操作表/errno 重叠。
 *
 * @retval VIREO_OK
 *     初始化全部状态后发布一份强引用。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     基本参数或操作表非法，输出保持。
 * @retval VIREO_RESULT_RANGE
 *     预算超限或不足，不申请，输出保持。
 * @retval VIREO_RESULT_NO_MEMORY
 *     allocate 返回 NULL，无残留申请，输出保持。
 *
 * @note
 *     所有路径保持 errno，无全局可变 fault。测试计数边界仅限独占测试对象，
 *     不在并发活跃对象上注入，不成为公开修改或下游依赖入口。
 */
vireo_result_t vireo_task_cancel_create_with_allocator(size_t allocation_budget,
    vireo_task_cancel_allocator_t const *allocator, vireo_task_cancel_t **out_cancel);

#endif /* VIREO_THREAD_TASK_CANCEL_INTERNAL_H */

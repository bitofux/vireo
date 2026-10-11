/*
 * PROJECT : VIREO
 * FILE    : task_cancel.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : 原子永久取消标志与受检共享引用生命周期
 */

#include "task_cancel_internal.h"

#include <errno.h>
#include <stdlib.h>

/**
 * @brief
 *     申请标准独占控制块，errno 由外层恢复。
 *
 * @param[in] context
 *     标准适配不使用，允许 NULL。
 * @param[in] bytes
 *     已核预算的正控制块请求字节数。
 *
 * @return
 *     全新、正确对齐的足量内存或 NULL。
 */
static void *standard_allocate(void *context, size_t bytes) {
    (void)context;
    return malloc(bytes);
}

/**
 * @brief
 *     配对释放最后引用拥有的标准原块，errno 由外层恢复。
 *
 * @param[in] context
 *     标准适配不使用，允许 NULL。
 * @param[in] allocation
 *     标准分配返回的原块，无其他存活引用或操作。
 *
 * @note
 *     无失败返回，不清理业务资源，不释放 caller 上下文。
 */
static void standard_deallocate(void *context, void *allocation) {
    (void)context;
    free(allocation);
}

vireo_result_t vireo_task_cancel_create_with_allocator(size_t allocation_budget,
    vireo_task_cancel_allocator_t const *allocator, vireo_task_cancel_t **out_cancel) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (out_cancel == NULL || *out_cancel != NULL || allocation_budget == 0 ||
        allocator == NULL || allocator->allocate == NULL || allocator->deallocate == NULL) {
        goto done;
    }
    if (allocation_budget > VIREO_TASK_CANCEL_MAX_ALLOCATION_BYTES ||
        allocation_budget < sizeof(vireo_task_cancel_t)) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }
    vireo_task_cancel_t *cancel = allocator->allocate(allocator->context, sizeof(*cancel));
    if (cancel == NULL) {
        result = VIREO_RESULT_NO_MEMORY;
        goto done;
    }
    atomic_init(&cancel->references, UINT64_C(1));
    atomic_init(&cancel->requested, false);
    cancel->allocator = *allocator;
    *out_cancel = cancel;
    result = VIREO_OK;
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_task_cancel_create(size_t allocation_budget,
                                        vireo_task_cancel_t **out_cancel) {
    vireo_task_cancel_allocator_t const allocator = {
        NULL, standard_allocate, standard_deallocate
    };
    return vireo_task_cancel_create_with_allocator(allocation_budget, &allocator, out_cancel);
}

vireo_result_t vireo_task_cancel_retain(vireo_task_cancel_t *cancel,
                                        vireo_task_cancel_t **out_cancel) {
    if (cancel == NULL || out_cancel == NULL || *out_cancel != NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    int const saved_errno = errno;
    /* 调用者已持一份存活引用；只改变计数，不承担对象或 owner 的发布同步。 */
    uint64_t count = atomic_load_explicit(&cancel->references, memory_order_relaxed);
    for (;;) {
        if (count == UINT64_MAX) {
            errno = saved_errno;
            return VIREO_RESULT_OVERFLOW;
        }
        if (atomic_compare_exchange_weak_explicit(&cancel->references, &count, count + 1,
                                                  memory_order_relaxed, memory_order_relaxed)) {
            *out_cancel = cancel;
            errno = saved_errno;
            return VIREO_OK;
        }
        /* 失败时 count 更新为实际观测数，重新检查上限；不作饥饿或耗时保证。 */
    }
}

vireo_result_t vireo_task_cancel_request(vireo_task_cancel_t *cancel) {
    if (cancel == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    int const saved_errno = errno;
    atomic_store_explicit(&cancel->requested, true, memory_order_release);
    errno = saved_errno;
    return VIREO_OK;
}

vireo_result_t vireo_task_cancel_is_requested(vireo_task_cancel_t *cancel,
                                              bool *out_requested) {
    if (cancel == NULL || out_requested == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    int const saved_errno = errno;
    bool const value = atomic_load_explicit(&cancel->requested, memory_order_acquire);
    *out_requested = value;
    errno = saved_errno;
    return VIREO_OK;
}

vireo_result_t vireo_task_cancel_move(vireo_task_cancel_t **source,
                                      vireo_task_cancel_t **destination) {
    if (source == NULL || destination == NULL || source == destination || *destination != NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (*source == NULL) {
        return VIREO_RESULT_NOT_FOUND;
    }
    *destination = *source;
    *source = NULL;
    return VIREO_OK;
}

vireo_result_t vireo_task_cancel_destroy(vireo_task_cancel_t **owner) {
    if (owner == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    int const saved_errno = errno;
    vireo_task_cancel_t *cancel = *owner;
    if (cancel != NULL) {
        /* release 交出本份寿命；最后 acquire 汇合先前各份 release 后才释放。 */
        uint64_t const previous = atomic_fetch_sub_explicit(&cancel->references, 1,
                                                           memory_order_acq_rel);
        if (previous == 1) {
            vireo_task_cancel_allocator_t const allocator = cancel->allocator;
            allocator.deallocate(allocator.context, cancel);
        }
        /* 非最后持有者不能继续读取 cancel，其他线程此时可能释放最后一份。 */
    }
    *owner = NULL;
    errno = saved_errno;
    return VIREO_OK;
}

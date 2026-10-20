/*
 * PROJECT : VIREO
 * FILE    : task.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : 独立输入、可选取消引用与唯一所有权生命周期
 */

#include "task_internal.h"

#include <vireo/base/checked.h>
#include <vireo/base/secure_clear.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief
 *     标准分配适配，成功块由 task 唯一拥有。
 *
 * @param[in] context
 *     标准适配不使用，允许 NULL。
 * @param[in] bytes
 *     经过受检预算验证的正申请量。
 *
 * @return
 *     正确对齐的新独占块或 NULL，errno 由外层构造恢复。
 */
static void *standard_allocate(void *context, size_t bytes) {
    (void)context;
    return malloc(bytes);
}

/**
 * @brief
 *     配对释放标准申请块，外层销毁恢复 errno。
 *
 * @param[in] context
 *     标准适配不使用，允许 NULL。
 * @param[in] allocation
 *     唯一拥有、无存活借用且由标准分配器返回的原块。
 *
 * @note
 *     不返回错误，不释放 caller 的输入或上下文。
 */
static void standard_deallocate(void *context, void *allocation) {
    (void)context;
    free(allocation);
}

/**
 * @brief
 *     共用构造：校验与预算后 retain，申请失败释放临时引用，完整成功才发布。
 *
 * @param[in] metadata
 *     有效按值元数据，允许已到期。
 * @param[in] data
 *     调用期间稳定可读的输入，非零长度须非 NULL。
 * @param[in] payload_size
 *     输入字节数，允许零。
 * @param[in] allocation_budget
 *     显式正 task 请求量预算，只计控制块与 payload。
 * @param[in] cancel
 *     可 NULL；非空由来源强引用保护至返回，不消费来源。
 * @param[in] allocator
 *     配对分配表借至返回，context 借至 task 销毁。
 * @param[out] out_task
 *     合法独占空 owner 地址，不与输入、资源或 errno 重叠。
 *
 * @return
 *     公开构造结果或依赖原错；失败保持输出及本调用引用义务。
 *
 * @note
 *     不读取取消状态布局；失败回滚的 destroy 使用合法局部 owner，按公开合同 OK。
 *     不冻结其他持有者的合法变化；所有路径保持 errno。
 */
static vireo_result_t create_copy(vireo_task_metadata_t metadata,
    void const *data, size_t payload_size, size_t allocation_budget,
    vireo_task_cancel_t *cancel, vireo_task_allocator_t const *allocator,
    vireo_task_t **out_task) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (out_task == NULL || *out_task != NULL || allocation_budget == 0 ||
        (payload_size != 0 && data == NULL) || allocator == NULL ||
        allocator->allocate == NULL || allocator->deallocate == NULL) {
        goto done;
    }

    /* 显式零样本仅利用公开查询核形态；不采样、不据此拒绝已到期值。 */
    bool ignored_expired = false;
    result = vireo_task_metadata_deadline_expired(metadata, 0, &ignored_expired);
    if (result != VIREO_OK) {
        goto done;
    }

    size_t bytes = 0;
    result = vireo_checked_size_add(sizeof(vireo_task_t), payload_size, &bytes);
    if (result != VIREO_OK) {
        goto done;
    }
    if (allocation_budget > VIREO_TASK_MAX_ALLOCATION_BYTES || bytes > allocation_budget) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }

    vireo_task_cancel_t *held_cancel = NULL;
    if (cancel != NULL) {
        result = vireo_task_cancel_retain(cancel, &held_cancel);
        if (result != VIREO_OK) {
            goto done;
        }
    }
    vireo_task_t *task = allocator->allocate(allocator->context, bytes);
    if (task == NULL) {
        result = vireo_task_cancel_destroy(&held_cancel);
        if (result == VIREO_OK) {
            result = VIREO_RESULT_NO_MEMORY;
        }
        goto done;
    }
    task->metadata = metadata;
    task->payload_size = payload_size;
    task->allocated_bytes = bytes;
    task->allocator = *allocator;
    task->cancel = held_cancel;
    if (payload_size != 0) {
        memcpy(task->payload, data, payload_size);
    }
    *out_task = task;
    result = VIREO_OK;

done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_task_create_copy_with_allocator(vireo_task_metadata_t metadata,
    void const *data, size_t payload_size, size_t allocation_budget,
    vireo_task_allocator_t const *allocator, vireo_task_t **out_task) {
    return create_copy(metadata, data, payload_size, allocation_budget, NULL, allocator, out_task);
}

vireo_result_t vireo_task_create_copy_with_cancel_and_allocator(vireo_task_metadata_t metadata,
    void const *data, size_t payload_size, size_t allocation_budget, vireo_task_cancel_t *cancel,
    vireo_task_allocator_t const *allocator, vireo_task_t **out_task) {
    if (cancel == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    return create_copy(metadata, data, payload_size, allocation_budget, cancel, allocator, out_task);
}

vireo_result_t vireo_task_create_copy(vireo_task_metadata_t metadata, void const *data,
                                      size_t payload_size, size_t allocation_budget,
                                      vireo_task_t **out_task) {
    vireo_task_allocator_t const allocator = {NULL, standard_allocate, standard_deallocate};
    return vireo_task_create_copy_with_allocator(metadata, data, payload_size, allocation_budget,
                                                &allocator, out_task);
}

vireo_result_t vireo_task_create_copy_with_cancel(vireo_task_metadata_t metadata,
    void const *data, size_t payload_size, size_t allocation_budget,
    vireo_task_cancel_t *cancel, vireo_task_t **out_task) {
    vireo_task_allocator_t const allocator = {NULL, standard_allocate, standard_deallocate};
    return vireo_task_create_copy_with_cancel_and_allocator(metadata, data, payload_size,
        allocation_budget, cancel, &allocator, out_task);
}

vireo_result_t vireo_task_is_cancel_requested(vireo_task_t const *task, bool *out_requested) {
    if (task == NULL || out_requested == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (task->cancel == NULL) {
        *out_requested = false;
        return VIREO_OK;
    }
    return vireo_task_cancel_is_requested(task->cancel, out_requested);
}

vireo_result_t vireo_task_retain_cancel(vireo_task_t const *task,
                                       vireo_task_cancel_t **out_cancel) {
    if (task == NULL || out_cancel == NULL || *out_cancel != NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (task->cancel == NULL) {
        return VIREO_RESULT_NOT_FOUND;
    }
    return vireo_task_cancel_retain(task->cancel, out_cancel);
}

vireo_result_t vireo_task_inspect(vireo_task_t const *task, vireo_task_info_t *out_info) {
    if (task == NULL || out_info == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    vireo_task_info_t const value = {task->metadata, task->payload_size, task->allocated_bytes};
    *out_info = value;
    return VIREO_OK;
}

vireo_result_t vireo_task_borrow_payload(vireo_task_t const *task,
                                        vireo_task_payload_view_t *out_view) {
    if (task == NULL || out_view == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    vireo_task_payload_view_t const value = {
        task->payload_size != 0 ? task->payload : NULL, task->payload_size
    };
    *out_view = value;
    return VIREO_OK;
}

vireo_result_t vireo_task_move(vireo_task_t **source, vireo_task_t **destination) {
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

vireo_result_t vireo_task_destroy(vireo_task_t **owner) {
    if (owner == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    int const saved_errno = errno;
    if (*owner != NULL) {
        vireo_result_t const result = vireo_task_cancel_destroy(&(*owner)->cancel);
        if (result != VIREO_OK) {
            errno = saved_errno;
            return result;
        }
        /* 取消引用先释放成功；先保存操作表和长度，擦除后不再读取 task 字段。 */
        vireo_task_allocator_t const allocator = (*owner)->allocator;
        size_t const allocated_bytes = (*owner)->allocated_bytes;
        (void)vireo_secure_clear(*owner, allocated_bytes);
        allocator.deallocate(allocator.context, *owner);
    }
    *owner = NULL;
    errno = saved_errno;
    return VIREO_OK;
}

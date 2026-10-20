/*
 * PROJECT : VIREO
 * FILE    : completion.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 独立完成字节、受检预算与唯一 owner 生命周期
 */

#include "completion_internal.h"

#include <vireo/base/checked.h>
#include <vireo/base/secure_clear.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief
 *     标准分配适配，外层构造保持 errno。
 *
 * @param[in] context
 *     标准适配不使用，允许 NULL。
 * @param[in] bytes
 *     已受检且符合预算的正申请量。
 *
 * @return
 *     新独占、正确对齐的块或 NULL。
 */
static void *standard_allocate(void *context, size_t bytes) {
    (void)context;
    return malloc(bytes);
}

/**
 * @brief
 *     释放标准申请原块，外层销毁保持 errno。
 *
 * @param[in] context
 *     标准适配不使用，允许 NULL。
 * @param[in] allocation
 *     唯一拥有且借用已结束的原块。
 *
 * @note
 *     无失败返回，不释放 caller 输入或上下文。
 */
static void standard_deallocate(void *context, void *allocation) {
    (void)context;
    free(allocation);
}

vireo_result_t vireo_completion_create_copy_with_allocator(vireo_completion_metadata_t metadata,
    void const *data, size_t payload_size, size_t allocation_budget,
    vireo_completion_allocator_t const *allocator, vireo_completion_t **out_completion) {
    if (out_completion == NULL || *out_completion != NULL || allocation_budget == 0 ||
        (payload_size != 0 && data == NULL) || allocator == NULL ||
        allocator->allocate == NULL || allocator->deallocate == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    bool same = false;
    vireo_result_t result = vireo_completion_metadata_same_request(metadata, metadata, &same);
    if (result != VIREO_OK) {
        return result;
    }
    size_t allocated_bytes = 0;
    result = vireo_checked_size_add(sizeof(vireo_completion_t), payload_size, &allocated_bytes);
    if (result != VIREO_OK) {
        return result;
    }
    if (allocation_budget > VIREO_COMPLETION_MAX_ALLOCATION_BYTES ||
        allocated_bytes > allocation_budget) {
        return VIREO_RESULT_RANGE;
    }
    int const saved_errno = errno;
    vireo_completion_allocator_t const operations = *allocator;
    vireo_completion_t *completion = operations.allocate(operations.context, allocated_bytes);
    if (completion == NULL) {
        errno = saved_errno;
        return VIREO_RESULT_NO_MEMORY;
    }
    completion->metadata = metadata;
    completion->payload_size = payload_size;
    completion->allocated_bytes = allocated_bytes;
    completion->allocator = operations;
    if (payload_size != 0) {
        memcpy(completion->payload, data, payload_size);
    }
    *out_completion = completion;
    errno = saved_errno;
    return VIREO_OK;
}

vireo_result_t vireo_completion_create_copy(vireo_completion_metadata_t metadata,
    void const *data, size_t payload_size, size_t allocation_budget,
    vireo_completion_t **out_completion) {
    vireo_completion_allocator_t const allocator = {NULL, standard_allocate, standard_deallocate};
    return vireo_completion_create_copy_with_allocator(metadata, data, payload_size,
        allocation_budget, &allocator, out_completion);
}

vireo_result_t vireo_completion_inspect(vireo_completion_t const *completion,
    vireo_completion_info_t *out_info) {
    if (completion == NULL || out_info == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    vireo_completion_info_t const info = {completion->metadata, completion->payload_size,
        completion->allocated_bytes};
    *out_info = info;
    return VIREO_OK;
}

vireo_result_t vireo_completion_borrow_payload(vireo_completion_t const *completion,
    vireo_completion_payload_view_t *out_view) {
    if (completion == NULL || out_view == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    vireo_completion_payload_view_t const view = {
        completion->payload_size == 0 ? NULL : completion->payload, completion->payload_size};
    *out_view = view;
    return VIREO_OK;
}

vireo_result_t vireo_completion_move(vireo_completion_t **source,
    vireo_completion_t **destination) {
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

vireo_result_t vireo_completion_destroy(vireo_completion_t **owner) {
    if (owner == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (*owner == NULL) {
        return VIREO_OK;
    }
    int const saved_errno = errno;
    vireo_completion_t *completion = *owner;
    vireo_completion_allocator_t const operations = completion->allocator;
    size_t const allocated_bytes = completion->allocated_bytes;
    /* 操作表在块外，整块清理后仅将原地址交给配对释放器。 */
    (void)vireo_secure_clear(completion, allocated_bytes);
    operations.deallocate(operations.context, completion);
    *owner = NULL;
    errno = saved_errno;
    return VIREO_OK;
}

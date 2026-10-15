/*
 * PROJECT : VIREO
 * FILE    : inflight_store.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 固定记录表的受检预分配、快照和仅空表配对释放
 */
#include "inflight_store_internal.h"

#include <vireo/base/checked.h>

#include <errno.h>
#include <stdlib.h>

/**
 * @brief
 *     标准单块申请适配，外层保存 errno。
 *
 * @param[in] context
 *     不使用，可空。
 * @param[in] bytes
 *     已受检并符合预算的正申请字节数。
 *
 * @return
 *     正确对齐独占块或 NULL。
 */
static void *standard_allocate(void *context, size_t bytes) {
    (void)context;
    return malloc(bytes);
}

/**
 * @brief
 *     配对释放原申请块，外层保存 errno。
 *
 * @param[in] context
 *     不使用，可空。
 * @param[in] allocation
 *     全部访问结束的唯一自有原块。
 *
 * @note
 *     无失败返回，不释放 caller 上下文。
 */
static void standard_deallocate(void *context, void *allocation) {
    (void)context;
    free(allocation);
}

vireo_result_t vireo_inflight_store_create_with_allocator(
    vireo_inflight_store_options_t const *options,
    vireo_inflight_store_allocator_t const *allocator, vireo_inflight_store_t **out_store) {
    int const saved_errno = errno;
    if (out_store == NULL || *out_store != NULL || options == NULL ||
        options->capacity == 0 || options->max_memory_bytes == 0 || allocator == NULL ||
        allocator->allocate == NULL || allocator->deallocate == NULL) {
        errno = saved_errno;
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    size_t slot_bytes = 0;
    vireo_result_t result = vireo_checked_size_mul(options->capacity,
        sizeof(vireo_inflight_store_slot_t), &slot_bytes);
    size_t allocated_bytes = 0;
    if (result == VIREO_OK) {
        result = vireo_checked_size_add(sizeof(vireo_inflight_store_t), slot_bytes,
            &allocated_bytes);
    }
    if (result != VIREO_OK) {
        errno = saved_errno;
        return result;
    }
    if (options->capacity > VIREO_INFLIGHT_STORE_MAX_CAPACITY ||
        options->max_memory_bytes > VIREO_INFLIGHT_STORE_MAX_ALLOCATION_BYTES ||
        allocated_bytes > options->max_memory_bytes) {
        errno = saved_errno;
        return VIREO_RESULT_RANGE;
    }
    vireo_inflight_store_allocator_t const ops = *allocator;
    vireo_inflight_store_t *store = ops.allocate(ops.context, allocated_bytes);
    if (store == NULL) {
        errno = saved_errno;
        return VIREO_RESULT_NO_MEMORY;
    }
    store->capacity = options->capacity;
    store->count = 0;
    store->allocated_bytes = allocated_bytes;
    store->max_memory_bytes = options->max_memory_bytes;
    store->allocator = ops;
    for (size_t i = 0; i < store->capacity; ++i) {
        store->slots[i].occupied = false;
        store->slots[i].metadata = (vireo_task_metadata_t){0};
        store->slots[i].cancel = NULL;
    }
    *out_store = store;
    errno = saved_errno;
    return VIREO_OK;
}

vireo_result_t vireo_inflight_store_create(vireo_inflight_store_options_t const *options,
    vireo_inflight_store_t **out_store) {
    vireo_inflight_store_allocator_t const allocator = {
        NULL, standard_allocate, standard_deallocate
    };
    return vireo_inflight_store_create_with_allocator(options, &allocator, out_store);
}

vireo_result_t vireo_inflight_store_inspect(vireo_inflight_store_t const *store,
    vireo_inflight_store_info_t *out_info) {
    if (store == NULL || out_info == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    vireo_inflight_store_info_t const info = {
        store->capacity, store->count, store->allocated_bytes, store->max_memory_bytes
    };
    *out_info = info;
    return VIREO_OK;
}

vireo_result_t vireo_inflight_store_destroy(vireo_inflight_store_t **owner) {
    int const saved_errno = errno;
    if (owner == NULL) {
        errno = saved_errno;
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (*owner != NULL) {
        vireo_inflight_store_t *store = *owner;
        if (store->count != 0) {
            errno = saved_errno;
            return VIREO_RESULT_BUSY;
        }
        vireo_inflight_store_allocator_t const ops = store->allocator;
        ops.deallocate(ops.context, store);
    }
    *owner = NULL;
    errno = saved_errno;
    return VIREO_OK;
}

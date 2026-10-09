/*
 * PROJECT : VIREO
 * FILE    : wheel.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 受检申请固定桶并完整初始化 dummy
 * -- 保存显式几何与数值资源快照
 * -- 拒绝非空销毁、空轮成对释放并保持 errno
 */
#include "wheel_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <vireo/base/checked.h>

/** @brief 默认申请正请求字节，入口统一恢复 errno。 */
static void *allocate_native(size_t bytes, void *context) {
    (void)context;
    return malloc(bytes);
}

/** @brief 成对释放本层申请，无返回错误，入口统一恢复 errno。 */
static void deallocate_native(void *memory, void *context) {
    (void)context;
    free(memory);
}

vireo_result_t vireo_timer_wheel_create_runtime(vireo_timer_wheel_options_t const *options,
                                                vireo_timer_wheel_t **out_wheel,
                                                vireo_timer_wheel_allocator_t const *allocator) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (options == NULL || out_wheel == NULL || allocator == NULL || *out_wheel != NULL ||
        allocator->allocate == NULL || allocator->deallocate == NULL ||
        options->geometry.tick_ns == 0 || options->geometry.bucket_count == 0 ||
        options->max_memory_bytes == 0) {
        goto done;
    }
    size_t count;
    size_t bucket_bytes;
    size_t total_bytes;
    result = vireo_checked_u64_to_size(options->geometry.bucket_count, &count);
    if (result != VIREO_OK) {
        goto done;
    }
    result = vireo_checked_size_mul(count, sizeof(vireo_timer_wheel_link_t), &bucket_bytes);
    if (result != VIREO_OK) {
        goto done;
    }
    result = vireo_checked_size_add(sizeof(vireo_timer_wheel_t), bucket_bytes, &total_bytes);
    if (result != VIREO_OK) {
        goto done;
    }
    if (options->geometry.bucket_count > VIREO_TIMER_WHEEL_MAX_BUCKETS ||
        options->max_memory_bytes > VIREO_TIMER_WHEEL_MAX_MEMORY ||
        total_bytes > options->max_memory_bytes) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }
    vireo_timer_wheel_t *candidate = allocator->allocate(sizeof(*candidate), allocator->context);
    if (candidate == NULL) {
        result = VIREO_RESULT_NO_MEMORY;
        goto done;
    }
    vireo_timer_wheel_link_t *buckets = allocator->allocate(bucket_bytes, allocator->context);
    if (buckets == NULL) {
        allocator->deallocate(candidate, allocator->context);
        result = VIREO_RESULT_NO_MEMORY;
        goto done;
    }
    /* 数量和全部数组字节已受检，头地址固定，不逐桶申请业务资源。 */
    for (size_t i = 0; i < count; i++) {
        buckets[i].prev = &buckets[i];
        buckets[i].next = &buckets[i];
    }
    *candidate = (vireo_timer_wheel_t){
        .geometry = options->geometry,
        .buckets = buckets,
        .bucket_count = count,
        .allocation_bytes = total_bytes,
        .max_memory_bytes = options->max_memory_bytes,
        .allocator = *allocator,
        .latest_now_ns = options->geometry.origin_ns,
    };
    candidate->pending = (vireo_timer_wheel_link_t){&candidate->pending, &candidate->pending};
    candidate->ready = (vireo_timer_wheel_link_t){&candidate->ready, &candidate->ready};
    *out_wheel = candidate;
    result = VIREO_OK;
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_timer_wheel_create(vireo_timer_wheel_options_t const *options,
                                        vireo_timer_wheel_t **out_wheel) {
    vireo_timer_wheel_allocator_t const allocator = {allocate_native, deallocate_native, NULL};
    return vireo_timer_wheel_create_runtime(options, out_wheel, &allocator);
}

vireo_result_t vireo_timer_wheel_inspect(vireo_timer_wheel_t const *wheel,
                                         vireo_timer_wheel_info_t *out_info) {
    if (wheel == NULL || out_info == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    *out_info = (vireo_timer_wheel_info_t){
        .geometry = wheel->geometry,
        .allocation_bytes = wheel->allocation_bytes,
        .max_memory_bytes = wheel->max_memory_bytes,
    };
    return VIREO_OK;
}

vireo_result_t vireo_timer_wheel_destroy(vireo_timer_wheel_t **wheel) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (wheel == NULL) {
        goto done;
    }
    if (*wheel == NULL) {
        result = VIREO_OK;
        goto done;
    }
    vireo_timer_wheel_t *owned = *wheel;
    if (owned->pending.next != &owned->pending || owned->pending.prev != &owned->pending ||
        owned->ready.next != &owned->ready || owned->ready.prev != &owned->ready) {
        result = VIREO_RESULT_BUSY;
        goto done;
    }
    for (size_t i = 0; i < owned->bucket_count; i++) {
        vireo_timer_wheel_link_t const *head = &owned->buckets[i];
        if (head->prev != head || head->next != head) {
            result = VIREO_RESULT_BUSY;
            goto done;
        }
    }
    /* public owner 销毁失败保持自身；在其成功前不释放任何轮资源。 */
    result = vireo_timer_handle_owner_destroy(&owned->owner);
    if (result != VIREO_OK) {
        goto done;
    }
    vireo_timer_wheel_allocator_t const allocator = owned->allocator;
    if (owned->nodes != NULL) {
        allocator.deallocate(owned->nodes, allocator.context);
    }
    allocator.deallocate(owned->buckets, allocator.context);
    allocator.deallocate(owned, allocator.context);
    *wheel = NULL;
    result = VIREO_OK;
done:
    errno = saved_errno;
    return result;
}

/*
 * PROJECT : VIREO
 * FILE    : handle_owner.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-08
 * BRIEF   : 此模块负责：
 * -- 完整发布预算内固定身份登记资源
 * -- 原子发放 owner ID 与 Reactor 内单调代次
 * -- 校验后归还、拒绝旧身份并空表收尾
 */
#include "handle_owner_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <vireo/base/checked.h>

static _Atomic uint64_t last_owner_id = ATOMIC_VAR_INIT(0);

/** @brief 默认申请正字节内存，errno 由构造入口统一恢复。 */
static void *allocate_native(size_t bytes, void *context) {
    (void)context;
    return malloc(bytes);
}

/** @brief 成对释放本层内存，errno 由销毁或回滚入口统一恢复。 */
static void deallocate_native(void *memory, void *context) {
    (void)context;
    free(memory);
}

/**
 * @brief 原子预约一个非零且不回绕的 ID，只同步数值发放
 *
 * @param[in,out] counter
 *     已初始化、独立且存活的原子 counter，不重置。
 * @param[out] out_id
 *     有效独立的局部 uint64_t 输出。
 *
 * @retval VIREO_OK
 *     CAS 成功，发布唯一下一序号。
 * @retval VIREO_RESULT_OVERFLOW
 *     已到 MAX，保持输出与 counter。
 *
 * @note
 *     relaxed 仅保证唯一修改次序，不发布对象；不承诺 lock-free 或有界重试次数。
 * @note
 *     不读取/修改 errno，无内存申请，创建失败不撤回已预约 ID。
 */
static vireo_result_t reserve_identity(_Atomic uint64_t *counter, uint64_t *out_id) {
    uint64_t last = atomic_load_explicit(counter, memory_order_relaxed);
    for (;;) {
        uint64_t next;
        vireo_result_t result = vireo_timer_handle_next_generation(last, &next);
        if (result != VIREO_OK) {
            return result;
        }
        if (atomic_compare_exchange_weak_explicit(counter, &last, next,
                                                  memory_order_relaxed, memory_order_relaxed)) {
            *out_id = next;
            return VIREO_OK;
        }
    }
}

vireo_result_t vireo_timer_handle_owner_create_runtime(
    vireo_timer_handle_owner_options_t const *options, vireo_timer_handle_owner_t **out_owner,
    vireo_timer_handle_owner_allocator_t const *allocator, _Atomic uint64_t *identity_counter) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (options == NULL || out_owner == NULL || allocator == NULL || identity_counter == NULL ||
        *out_owner != NULL || allocator->allocate == NULL || allocator->deallocate == NULL ||
        options->capacity == 0 || options->max_memory_bytes == 0) {
        goto done;
    }
    size_t slot_bytes;
    size_t total_bytes;
    result = vireo_checked_size_mul(options->capacity, sizeof(vireo_timer_handle_owner_slot_t),
                                    &slot_bytes);
    if (result != VIREO_OK) {
        goto done;
    }
    result = vireo_checked_size_add(sizeof(vireo_timer_handle_owner_t), slot_bytes, &total_bytes);
    if (result != VIREO_OK) {
        goto done;
    }
    if (options->capacity > VIREO_TIMER_HANDLE_OWNER_MAX_CAPACITY ||
        options->max_memory_bytes > VIREO_TIMER_HANDLE_OWNER_MAX_MEMORY ||
        total_bytes > options->max_memory_bytes) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }
    uint64_t identity;
    result = reserve_identity(identity_counter, &identity);
    if (result != VIREO_OK) {
        goto done;
    }
    vireo_timer_handle_owner_t *candidate = allocator->allocate(sizeof(*candidate), allocator->context);
    if (candidate == NULL) {
        result = VIREO_RESULT_NO_MEMORY;
        goto done;
    }
    vireo_timer_handle_owner_slot_t *slots = allocator->allocate(slot_bytes, allocator->context);
    if (slots == NULL) {
        allocator->deallocate(candidate, allocator->context);
        result = VIREO_RESULT_NO_MEMORY;
        goto done;
    }
    /* capacity 已受硬限约束；初始化只建立本层元数据，没有业务对象。 */
    for (size_t i = 0; i < options->capacity; i++) {
        slots[i] = (vireo_timer_handle_owner_slot_t){0, i + 1, false};
    }
    slots[options->capacity - 1].next_free = SIZE_MAX;
    *candidate = (vireo_timer_handle_owner_t){
        .slots = slots, .capacity = options->capacity, .free_head = 0, .active_count = 0,
        .allocation_bytes = total_bytes, .max_memory_bytes = options->max_memory_bytes,
        .owner_id = identity, .last_generation = 0, .allocator = *allocator,
    };
    *out_owner = candidate;
    result = VIREO_OK;
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_timer_handle_owner_create(vireo_timer_handle_owner_options_t const *options,
                                               vireo_timer_handle_owner_t **out_owner) {
    vireo_timer_handle_owner_allocator_t const allocator = {allocate_native, deallocate_native, NULL};
    return vireo_timer_handle_owner_create_runtime(options, out_owner, &allocator, &last_owner_id);
}

vireo_result_t vireo_timer_handle_owner_inspect(vireo_timer_handle_owner_t const *owner,
                                                vireo_timer_handle_owner_info_t *out_info) {
    if (owner == NULL || out_info == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    *out_info = (vireo_timer_handle_owner_info_t){
        owner->owner_id, owner->last_generation, owner->capacity, owner->active_count,
        owner->capacity - owner->active_count, owner->allocation_bytes, owner->max_memory_bytes,
    };
    return VIREO_OK;
}

vireo_result_t vireo_timer_handle_owner_acquire(vireo_timer_handle_owner_t *owner,
                                                vireo_timer_handle_t *out_handle) {
    if (owner == NULL || out_handle == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    uint64_t next;
    vireo_result_t result = vireo_timer_handle_next_generation(owner->last_generation, &next);
    if (result != VIREO_OK) {
        return result;
    }
    if (owner->free_head == SIZE_MAX) {
        return VIREO_RESULT_BUSY;
    }
    size_t const index = owner->free_head;
    vireo_timer_handle_owner_slot_t *slot = &owner->slots[index];
    owner->free_head = slot->next_free;
    slot->generation = next;
    slot->active = true;
    owner->active_count++;
    owner->last_generation = next;
    *out_handle = (vireo_timer_handle_t){owner->owner_id, index, next};
    return VIREO_OK;
}

vireo_result_t vireo_timer_handle_owner_validate(vireo_timer_handle_owner_t const *owner,
                                                 vireo_timer_handle_t handle) {
    if (owner == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    bool empty;
    vireo_result_t result = vireo_timer_handle_is_empty(handle, &empty);
    if (result != VIREO_OK) {
        return result;
    }
    if (empty) {
        return VIREO_RESULT_NOT_FOUND;
    }
    if (handle.owner_id != owner->owner_id) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (handle.slot_index >= owner->capacity) {
        return VIREO_RESULT_RANGE;
    }
    vireo_timer_handle_owner_slot_t const *slot = &owner->slots[handle.slot_index];
    if (!slot->active || slot->generation != handle.generation) {
        return VIREO_RESULT_NOT_FOUND;
    }
    return VIREO_OK;
}

vireo_result_t vireo_timer_handle_owner_release(vireo_timer_handle_owner_t *owner,
                                                vireo_timer_handle_t *handle) {
    if (owner == NULL || handle == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    vireo_result_t result = vireo_timer_handle_owner_validate(owner, *handle);
    if (result != VIREO_OK) {
        return result;
    }
    vireo_timer_handle_owner_slot_t *slot = &owner->slots[handle->slot_index];
    slot->active = false;
    slot->next_free = owner->free_head;
    owner->free_head = handle->slot_index;
    owner->active_count--;
    *handle = (vireo_timer_handle_t){0};
    return VIREO_OK;
}

vireo_result_t vireo_timer_handle_owner_destroy(vireo_timer_handle_owner_t **owner) {
    if (owner == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (*owner == NULL) {
        return VIREO_OK;
    }
    if ((*owner)->active_count != 0) {
        return VIREO_RESULT_BUSY;
    }
    int const saved_errno = errno;
    vireo_timer_handle_owner_t *value = *owner;
    /* 释放控制块前复制策略，避免从已释放内存读取 deallocate/context。 */
    vireo_timer_handle_owner_allocator_t const allocator = value->allocator;
    allocator.deallocate(value->slots, allocator.context);
    allocator.deallocate(value, allocator.context);
    *owner = NULL;
    errno = saved_errno;
    return VIREO_OK;
}

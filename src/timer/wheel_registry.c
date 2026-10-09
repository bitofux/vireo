/*
 * PROJECT : VIREO
 * FILE    : wheel_registry.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 准备固定节点并通过公开 owner 管理身份
 * -- 将受检期限链接到 dummy 桶并查询
 * -- 取消失败恢复原位，重排保留身份
 */
#include "wheel_internal.h"

#include <errno.h>
#include <vireo/base/checked.h>

/** @brief 只适配已封板的 public owner 创建，不暴露或读取其布局。 */
static vireo_result_t owner_create_native(vireo_timer_handle_owner_options_t const *options,
                                          vireo_timer_handle_owner_t **out, void *context) {
    (void)context;
    return vireo_timer_handle_owner_create(options, out);
}

/** @brief 只适配 public acquire，不提前用活跃数覆盖耗尽优先级。 */
static vireo_result_t owner_acquire_native(vireo_timer_handle_owner_t *owner,
                                           vireo_timer_handle_t *out, void *context) {
    (void)context;
    return vireo_timer_handle_owner_acquire(owner, out);
}

/** @brief 只适配 public release，失败保持 owner 与局部句柄。 */
static vireo_result_t owner_release_native(vireo_timer_handle_owner_t *owner,
                                           vireo_timer_handle_t *handle, void *context) {
    (void)context;
    return vireo_timer_handle_owner_release(owner, handle);
}

/** @brief 从合法环摘下节点并自环；caller 负责先校验身份和需要的原邻位。 */
static void link_detach(vireo_timer_wheel_link_t *link) {
    link->prev->next = link->next;
    link->next->prev = link->prev;
    link->prev = link;
    link->next = link;
}

/** @brief 恢复独占调用中未变化的精确邻位，无申请或可失败操作。 */
static void link_restore(vireo_timer_wheel_link_t *link, vireo_timer_wheel_link_t *prev,
                          vireo_timer_wheel_link_t *next) {
    link->prev = prev;
    link->next = next;
    prev->next = link;
    next->prev = link;
}

/** @brief 先验证形态/准备/public 身份，再授权本层固定节点索引。 */
static vireo_result_t validate_slot(vireo_timer_wheel_t const *wheel, vireo_timer_handle_t handle) {
    bool empty;
    vireo_result_t result = vireo_timer_handle_is_empty(handle, &empty);
    if (result != VIREO_OK) {
        return result;
    }
    if (wheel->owner == NULL) {
        return VIREO_RESULT_NOT_FOUND;
    }
    result = vireo_timer_handle_owner_validate(wheel->owner, handle);
    if (result != VIREO_OK) {
        return result;
    }
    /* 同容量 public owner 已保证此范围，本层仍在数组索引前显式核对。 */
    if (handle.slot_index >= wheel->timer_capacity) {
        return VIREO_RESULT_RANGE;
    }
    return VIREO_OK;
}

/** @brief 明确未来期限并完成所有时间/桶转换，输出仅是调用者局部暂存。 */
static vireo_result_t deadline_values(vireo_timer_wheel_t const *wheel,
                                      vireo_monotonic_ns_t now_ns,
                                      vireo_monotonic_ns_t deadline_ns,
                                      vireo_timer_wheel_tick_t *out_tick, size_t *out_bucket) {
    if (now_ns < wheel->geometry.origin_ns) {
        return VIREO_RESULT_RANGE;
    }
    if (deadline_ns <= now_ns) {
        return VIREO_RESULT_TIMEOUT;
    }
    vireo_result_t result = vireo_timer_wheel_deadline_tick(wheel->geometry, deadline_ns, out_tick);
    if (result != VIREO_OK) {
        return result;
    }
    uint64_t bucket;
    result = vireo_timer_wheel_bucket_index(wheel->geometry, *out_tick, &bucket);
    if (result != VIREO_OK) {
        return result;
    }
    return vireo_checked_u64_to_size(bucket, out_bucket);
}

vireo_result_t vireo_timer_wheel_prepare_runtime(
    vireo_timer_wheel_t *wheel, vireo_timer_wheel_registry_options_t const *options,
    vireo_timer_wheel_owner_create_fn create_owner, void *context) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (wheel == NULL || options == NULL || create_owner == NULL ||
        options->capacity == 0 || options->max_memory_bytes == 0) {
        goto done;
    }
    if (wheel->owner != NULL) {
        result = VIREO_RESULT_BUSY;
        goto done;
    }
    size_t bytes;
    result = vireo_checked_size_mul(options->capacity, sizeof(vireo_timer_wheel_node_t), &bytes);
    if (result != VIREO_OK) {
        goto done;
    }
    if (options->capacity > VIREO_TIMER_WHEEL_REGISTRY_MAX_CAPACITY ||
        options->max_memory_bytes > VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY ||
        bytes >= options->max_memory_bytes) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }
    vireo_timer_wheel_node_t *nodes = wheel->allocator.allocate(bytes, wheel->allocator.context);
    if (nodes == NULL) {
        result = VIREO_RESULT_NO_MEMORY;
        goto done;
    }
    for (size_t i = 0; i < options->capacity; i++) {
        nodes[i] = (vireo_timer_wheel_node_t){
            .link = {&nodes[i].link, &nodes[i].link}, .handle = {0},
        };
    }
    vireo_timer_handle_owner_options_t const owner_options = {
        options->capacity, options->max_memory_bytes - bytes,
    };
    vireo_timer_handle_owner_t *owner = NULL;
    result = create_owner(&owner_options, &owner, context);
    if (result != VIREO_OK) {
        wheel->allocator.deallocate(nodes, wheel->allocator.context);
        goto done;
    }
    /* 成功 factory 须符合 public 创建的空 owner/容量/剩余预算合同，此后无可失败操作。 */
    wheel->owner = owner;
    wheel->nodes = nodes;
    wheel->timer_capacity = options->capacity;
    wheel->node_bytes = bytes;
    wheel->registry_budget = options->max_memory_bytes;
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_timer_wheel_prepare(vireo_timer_wheel_t *wheel,
                                        vireo_timer_wheel_registry_options_t const *options) {
    return vireo_timer_wheel_prepare_runtime(wheel, options, owner_create_native, NULL);
}

vireo_result_t vireo_timer_wheel_registry_inspect(vireo_timer_wheel_t const *wheel,
                                                 vireo_timer_wheel_registry_info_t *out_info) {
    if (wheel == NULL || out_info == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (wheel->owner == NULL) {
        *out_info = (vireo_timer_wheel_registry_info_t){0};
        return VIREO_OK;
    }
    vireo_timer_handle_owner_info_t info;
    vireo_result_t result = vireo_timer_handle_owner_inspect(wheel->owner, &info);
    if (result != VIREO_OK) {
        return result;
    }
    size_t total;
    result = vireo_checked_size_add(wheel->node_bytes, info.allocation_bytes, &total);
    if (result != VIREO_OK) {
        return result;
    }
    *out_info = (vireo_timer_wheel_registry_info_t){
        .prepared = true, .capacity = wheel->timer_capacity, .active_count = info.active_count,
        .available_count = info.available_count, .allocation_bytes = total,
        .max_memory_bytes = wheel->registry_budget,
    };
    return VIREO_OK;
}

vireo_result_t vireo_timer_wheel_register_runtime(
    vireo_timer_wheel_t *wheel, vireo_monotonic_ns_t now_ns, vireo_monotonic_ns_t deadline_ns,
    vireo_timer_handle_t *out_handle, vireo_timer_wheel_owner_acquire_fn acquire, void *context) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (wheel == NULL || out_handle == NULL || acquire == NULL) {
        goto done;
    }
    bool empty;
    result = vireo_timer_handle_is_empty(*out_handle, &empty);
    if (result != VIREO_OK || !empty) {
        result = VIREO_RESULT_INVALID_ARGUMENT;
        goto done;
    }
    if (wheel->owner == NULL) {
        result = VIREO_RESULT_NOT_FOUND;
        goto done;
    }
    vireo_timer_wheel_tick_t due;
    size_t bucket;
    if (wheel->stopping) {
        result = VIREO_RESULT_CANCELLED;
        goto done;
    }
    result = deadline_values(wheel, now_ns, deadline_ns, &due, &bucket);
    if (result != VIREO_OK) {
        goto done;
    }
    vireo_timer_handle_t handle;
    result = acquire(wheel->owner, &handle, context);
    if (result != VIREO_OK) {
        goto done;
    }
    /* public acquire 保证 slot<同一创建容量，且此槽先前空闲；无 private owner 布局依赖。 */
    vireo_timer_wheel_node_t *node = &wheel->nodes[handle.slot_index];
    node->handle = handle;
    node->deadline_ns = deadline_ns;
    node->due_tick = due;
    node->bucket_index = bucket;
    vireo_timer_wheel_place_node(wheel, node);
    *out_handle = handle;
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_timer_wheel_register(vireo_timer_wheel_t *wheel,
                                         vireo_monotonic_ns_t now_ns,
                                         vireo_monotonic_ns_t deadline_ns,
                                         vireo_timer_handle_t *out_handle) {
    return vireo_timer_wheel_register_runtime(wheel, now_ns, deadline_ns, out_handle,
                                              owner_acquire_native, NULL);
}

vireo_result_t vireo_timer_wheel_get(vireo_timer_wheel_t const *wheel,
                                    vireo_timer_handle_t handle,
                                    vireo_timer_wheel_timer_info_t *out_info) {
    if (wheel == NULL || out_info == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    vireo_result_t result = validate_slot(wheel, handle);
    if (result != VIREO_OK) {
        return result;
    }
    vireo_timer_wheel_node_t const *node = &wheel->nodes[handle.slot_index];
    *out_info = (vireo_timer_wheel_timer_info_t){
        node->deadline_ns, node->due_tick, (uint64_t)node->bucket_index,
    };
    return VIREO_OK;
}

vireo_result_t vireo_timer_wheel_cancel_runtime(
    vireo_timer_wheel_t *wheel, vireo_timer_handle_t *handle,
    vireo_timer_wheel_owner_release_fn release, void *context) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (wheel == NULL || handle == NULL || release == NULL) {
        goto done;
    }
    result = validate_slot(wheel, *handle);
    if (result != VIREO_OK) {
        goto done;
    }
    vireo_timer_wheel_node_t *node = &wheel->nodes[handle->slot_index];
    vireo_timer_wheel_link_t *prev = node->link.prev;
    vireo_timer_wheel_link_t *next = node->link.next;
    link_detach(&node->link);
    vireo_timer_handle_t local = *handle;
    result = release(wheel->owner, &local, context);
    if (result != VIREO_OK) {
        link_restore(&node->link, prev, next);
        goto done;
    }
    if (node->ready) {
        wheel->ready_count--;
        node->ready = false;
    }
    node->handle = (vireo_timer_handle_t){0};
    node->deadline_ns = 0;
    node->due_tick = 0;
    node->bucket_index = 0;
    *handle = (vireo_timer_handle_t){0};
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_timer_wheel_cancel(vireo_timer_wheel_t *wheel,
                                       vireo_timer_handle_t *handle) {
    return vireo_timer_wheel_cancel_runtime(wheel, handle, owner_release_native, NULL);
}

vireo_result_t vireo_timer_wheel_rearm(vireo_timer_wheel_t *wheel,
                                      vireo_timer_handle_t handle,
                                      vireo_monotonic_ns_t now_ns,
                                      vireo_monotonic_ns_t deadline_ns) {
    if (wheel == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    vireo_result_t result = validate_slot(wheel, handle);
    if (result != VIREO_OK) {
        return result;
    }
    if (wheel->stopping) {
        return VIREO_RESULT_CANCELLED;
    }
    vireo_timer_wheel_tick_t due;
    size_t bucket;
    result = deadline_values(wheel, now_ns, deadline_ns, &due, &bucket);
    if (result != VIREO_OK) {
        return result;
    }
    vireo_timer_wheel_node_t *node = &wheel->nodes[handle.slot_index];
    link_detach(&node->link);
    if (node->ready) {
        wheel->ready_count--;
        node->ready = false;
    }
    node->deadline_ns = deadline_ns;
    node->due_tick = due;
    node->bucket_index = bucket;
    vireo_timer_wheel_place_node(wheel, node);
    return VIREO_OK;
}

/*
 * PROJECT : VIREO
 * FILE    : wheel_advance.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 用 pending 桶快照实现有界可续推进
 * -- 保存活跃 ready 并在单项领取成功时注销身份
 */
#include "wheel_internal.h"

#include <errno.h>
#include <stddef.h>

_Static_assert(offsetof(vireo_timer_wheel_node_t, link) == 0, "link must be first member");

/** @brief 将自环节点插入合法 dummy 前，不承诺顺序。 */
static void link_append(vireo_timer_wheel_link_t *head, vireo_timer_wheel_link_t *link) {
    link->prev = head->prev;
    link->next = head;
    head->prev->next = link;
    head->prev = link;
}

/** @brief 将合法成员摘下并自环；不保存跨调用的节点游标。 */
static void link_detach(vireo_timer_wheel_link_t *link) {
    link->prev->next = link->next;
    link->next->prev = link->prev;
    link->prev = link;
    link->next = link;
}

/**
 * @brief 将普通桶整环转为当前未检查快照，O(1)
 *
 * @param[in,out] pending
 *     空自环 dummy；不得与 bucket 相同。
 * @param[in,out] bucket
 *     合法普通桶 dummy，返回后自环。
 *
 * @note
 *     一次独占转移只改边界邻位；后续新登记仍进入普通桶或 ready，不能混入快照。
 */
static void snapshot_bucket(vireo_timer_wheel_link_t *pending, vireo_timer_wheel_link_t *bucket) {
    if (bucket->next == bucket) {
        return;
    }
    pending->next = bucket->next;
    pending->prev = bucket->prev;
    pending->next->prev = pending;
    pending->prev->next = pending;
    bucket->prev = bucket;
    bucket->next = bucket;
}

/** @brief 从合法首成员地址还原所属节点；调用处排除 dummy，C11 首成员规则保证转换。 */
static vireo_timer_wheel_node_t *node_from_link(vireo_timer_wheel_link_t *link) {
    return (vireo_timer_wheel_node_t *)link;
}

/** @brief 仅对合法轮构造进度；latest>=origin、tick>0，由创建/成功推进保证。 */
static vireo_timer_wheel_progress_t progress_value(vireo_timer_wheel_t const *wheel) {
    uint64_t const target = (wheel->latest_now_ns - wheel->geometry.origin_ns) /
                            wheel->geometry.tick_ns;
    return (vireo_timer_wheel_progress_t){
        .latest_now_ns = wheel->latest_now_ns, .target_tick = target,
        .completed_tick = wheel->completed_tick, .processing = wheel->processing,
        .ready_count = wheel->ready_count,
        .caught_up = !wheel->processing && wheel->completed_tick == target,
    };
}

void vireo_timer_wheel_place_node(vireo_timer_wheel_t *wheel, vireo_timer_wheel_node_t *node) {
    /* processing 只可能在 completed<target<=MAX 时开启，故 +1 可表示。 */
    uint64_t const frontier = wheel->processing ? wheel->completed_tick + 1 : wheel->completed_tick;
    node->ready = node->due_tick <= frontier;
    if (node->ready) {
        link_append(&wheel->ready, &node->link);
        wheel->ready_count++;
    } else {
        link_append(&wheel->buckets[node->bucket_index], &node->link);
    }
}

vireo_result_t vireo_timer_wheel_advance(vireo_timer_wheel_t *wheel,
                                        vireo_monotonic_ns_t now_ns,
                                        vireo_timer_wheel_advance_budget_t budget,
                                        vireo_timer_wheel_advance_report_t *out_report) {
    if (wheel == NULL || out_report == NULL || budget.max_ticks == 0 || budget.max_nodes == 0) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (budget.max_ticks > VIREO_TIMER_WHEEL_ADVANCE_MAX_BUDGET ||
        budget.max_nodes > VIREO_TIMER_WHEEL_ADVANCE_MAX_BUDGET) {
        return VIREO_RESULT_RANGE;
    }
    if (wheel->owner == NULL) {
        return VIREO_RESULT_NOT_FOUND;
    }
    if (wheel->stopping) {
        return VIREO_RESULT_CANCELLED;
    }
    if (now_ns < wheel->geometry.origin_ns || now_ns < wheel->latest_now_ns) {
        return VIREO_RESULT_RANGE;
    }
    uint64_t const target = (now_ns - wheel->geometry.origin_ns) / wheel->geometry.tick_ns;
    /* 校验完毕后无可失败依赖调用；预算计数受硬限，所有刻度增量以 completed<target 为前提。 */
    wheel->latest_now_ns = now_ns;
    size_t ticks = 0;
    size_t nodes = 0;
    for (;;) {
        if (wheel->processing && wheel->pending.next == &wheel->pending) {
            wheel->completed_tick++;
            wheel->processing = false;
        }
        if (!wheel->processing) {
            if (wheel->completed_tick == target || ticks == budget.max_ticks) {
                break;
            }
            uint64_t const visiting = wheel->completed_tick + 1;
            size_t const bucket = (size_t)(visiting % wheel->geometry.bucket_count);
            snapshot_bucket(&wheel->pending, &wheel->buckets[bucket]);
            wheel->processing = true;
            ticks++;
        }
        if (wheel->pending.next == &wheel->pending) {
            continue;
        }
        if (nodes == budget.max_nodes) {
            break;
        }
        vireo_timer_wheel_node_t *node = node_from_link(wheel->pending.next);
        link_detach(&node->link);
        vireo_timer_wheel_place_node(wheel, node);
        nodes++;
    }
    *out_report = (vireo_timer_wheel_advance_report_t){progress_value(wheel), ticks, nodes};
    return VIREO_OK;
}

vireo_result_t vireo_timer_wheel_progress_inspect(vireo_timer_wheel_t const *wheel,
                                                 vireo_timer_wheel_progress_t *out_progress) {
    if (wheel == NULL || out_progress == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (wheel->owner == NULL) {
        return VIREO_RESULT_NOT_FOUND;
    }
    *out_progress = progress_value(wheel);
    return VIREO_OK;
}

/** @brief 单项领取只适配 public 归还，错误与身份状态沿已封板合同。 */
static vireo_result_t owner_release_native(vireo_timer_handle_owner_t *owner,
                                           vireo_timer_handle_t *handle, void *context) {
    (void)context;
    return vireo_timer_handle_owner_release(owner, handle);
}

vireo_result_t vireo_timer_wheel_take_expired_runtime(
    vireo_timer_wheel_t *wheel, vireo_timer_wheel_expired_t *out_expired,
    vireo_timer_wheel_owner_release_fn release, void *context) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (wheel == NULL || out_expired == NULL || release == NULL) {
        goto done;
    }
    if (wheel->owner == NULL || wheel->ready.next == &wheel->ready) {
        result = VIREO_RESULT_NOT_FOUND;
        goto done;
    }
    vireo_timer_wheel_node_t const *node = node_from_link(wheel->ready.next);
    vireo_timer_wheel_expired_t const event = {
        .handle = node->handle,
        .timer = {node->deadline_ns, node->due_tick, (uint64_t)node->bucket_index},
    };
    vireo_timer_handle_t local = event.handle;
    result = vireo_timer_wheel_cancel_runtime(wheel, &local, release, context);
    if (result == VIREO_OK) {
        *out_expired = event;
    }
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_timer_wheel_take_expired(vireo_timer_wheel_t *wheel,
                                             vireo_timer_wheel_expired_t *out_expired) {
    return vireo_timer_wheel_take_expired_runtime(wheel, out_expired, owner_release_native, NULL);
}

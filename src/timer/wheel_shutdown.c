/*
 * PROJECT : VIREO
 * FILE    : wheel_shutdown.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 保存不可逆停止状态并观测活跃身份
 * -- 暂存扫描进度，单项归还成功后再提交
 */
#include "wheel_internal.h"

#include <errno.h>

vireo_result_t vireo_timer_wheel_shutdown_begin(vireo_timer_wheel_t *wheel) {
    if (wheel == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (wheel->owner == NULL) {
        return VIREO_RESULT_NOT_FOUND;
    }
    wheel->stopping = true;
    return VIREO_OK;
}

vireo_result_t vireo_timer_wheel_shutdown_inspect(vireo_timer_wheel_t const *wheel,
                                                 vireo_timer_wheel_shutdown_info_t *out_info) {
    if (wheel == NULL || out_info == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (wheel->owner == NULL) {
        return VIREO_RESULT_NOT_FOUND;
    }
    vireo_timer_handle_owner_info_t info;
    vireo_result_t const result = vireo_timer_handle_owner_inspect(wheel->owner, &info);
    if (result != VIREO_OK) {
        return result;
    }
    *out_info = (vireo_timer_wheel_shutdown_info_t){
        wheel->stopping, info.active_count, wheel->stopping && info.active_count == 0,
    };
    return VIREO_OK;
}

/** @brief 只适配 public release，不改变轮链接；失败保持身份和传入局部值。 */
static vireo_result_t owner_release_native(vireo_timer_handle_owner_t *owner,
                                           vireo_timer_handle_t *handle, void *context) {
    (void)context;
    return vireo_timer_handle_owner_release(owner, handle);
}

vireo_result_t vireo_timer_wheel_shutdown_step_runtime(
    vireo_timer_wheel_t *wheel, size_t max_slots, vireo_timer_wheel_shutdown_report_t *out_report,
    vireo_timer_wheel_owner_release_fn release, void *context) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (wheel == NULL || out_report == NULL || release == NULL || max_slots == 0) {
        goto done;
    }
    if (max_slots > VIREO_TIMER_WHEEL_SHUTDOWN_MAX_SLOTS) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }
    if (wheel->owner == NULL) {
        result = VIREO_RESULT_NOT_FOUND;
        goto done;
    }
    if (!wheel->stopping) {
        result = VIREO_RESULT_BUSY;
        goto done;
    }
    vireo_timer_handle_owner_info_t info;
    result = vireo_timer_handle_owner_inspect(wheel->owner, &info);
    if (result != VIREO_OK) {
        goto done;
    }
    vireo_timer_wheel_shutdown_report_t report = {0};
    report.remaining_count = info.active_count;
    size_t cursor = wheel->shutdown_cursor;
    if (info.active_count == 0) {
        /* 停止后不再增加登记，空表无需付空洞扫描成本。 */
        cursor = wheel->timer_capacity;
    } else {
        while (cursor < wheel->timer_capacity && report.scanned_slots < max_slots) {
            vireo_timer_wheel_node_t const *node = &wheel->nodes[cursor];
            /* cursor<capacity<=65536，增量与扫描计数均可表示，不以回绕排序。 */
            cursor++;
            report.scanned_slots++;
            if (node->handle.owner_id == 0) {
                continue;
            }
            vireo_timer_handle_t local = node->handle;
            report.cancelled = (vireo_timer_wheel_shutdown_cancelled_t){
                .handle = local,
                .timer = {node->deadline_ns, node->due_tick, (uint64_t)node->bucket_index},
            };
            result = vireo_timer_wheel_cancel_runtime(wheel, &local, release, context);
            if (result != VIREO_OK) {
                goto done;
            }
            /* 成功只消费这一身份，此后无可失败依赖；停止+单向扫描不变量保证原active>0。 */
            report.remaining_count--;
            report.has_cancelled = true;
            break;
        }
    }
    report.finished = report.remaining_count == 0;
    wheel->shutdown_cursor = cursor;
    *out_report = report;
    result = VIREO_OK;
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_timer_wheel_shutdown_step(vireo_timer_wheel_t *wheel, size_t max_slots,
                                              vireo_timer_wheel_shutdown_report_t *out_report) {
    return vireo_timer_wheel_shutdown_step_runtime(wheel, max_slots, out_report,
                                                   owner_release_native, NULL);
}

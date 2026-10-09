/*
 * PROJECT : VIREO
 * FILE    : timer_loop_wait.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 只依公开轮快照和受检时间运算规划等待
 */
#include <vireo/net/timer_loop.h>
#include <vireo/base/checked.h>
#include <vireo/timer/wheel_advance.h>
#include <vireo/timer/wheel_shutdown.h>

vireo_result_t vireo_timer_loop_plan_wait(vireo_timer_wheel_t const *wheel,
                                        vireo_monotonic_ns_t now_ns, int max_wait_ms,
                                        vireo_timer_loop_wait_plan_t *out_plan)
{
    if (wheel == NULL || out_plan == NULL || max_wait_ms < 0) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    vireo_timer_wheel_registry_info_t registry;
    vireo_result_t result = vireo_timer_wheel_registry_inspect(wheel, &registry);
    if (result != VIREO_OK) {
        return result;
    }
    if (!registry.prepared) {
        return VIREO_RESULT_NOT_FOUND;
    }

    vireo_timer_wheel_shutdown_info_t shutdown;
    result = vireo_timer_wheel_shutdown_inspect(wheel, &shutdown);
    if (result != VIREO_OK) {
        return result;
    }
    if (shutdown.stopping) {
        return VIREO_RESULT_CANCELLED;
    }

    vireo_timer_wheel_info_t info;
    result = vireo_timer_wheel_inspect(wheel, &info);
    if (result != VIREO_OK) {
        return result;
    }
    vireo_timer_wheel_progress_t progress;
    result = vireo_timer_wheel_progress_inspect(wheel, &progress);
    if (result != VIREO_OK) {
        return result;
    }
    if (now_ns < progress.latest_now_ns) {
        return VIREO_RESULT_RANGE;
    }
    vireo_timer_wheel_tick_t elapsed;
    result = vireo_timer_wheel_elapsed_tick(info.geometry, now_ns, &elapsed);
    if (result != VIREO_OK) {
        return result;
    }

    /* 先完成候选，所有依赖成功后才发布；不把 cap=0 当作时间轮工作。 */
    vireo_timer_loop_wait_plan_t plan = {
        .timeout_ms = 0,
        .timer_work_pending = progress.processing || progress.ready_count != 0 ||
                              progress.completed_tick < elapsed,
        .has_tick_deadline = false,
        .tick_deadline_ns = 0
    };
    if (!plan.timer_work_pending) {
        if (registry.active_count == 0) {
            plan.timeout_ms = max_wait_ms;
        } else {
            vireo_timer_wheel_tick_t next_tick;
            result = vireo_checked_u64_add(progress.completed_tick, UINT64_C(1), &next_tick);
            if (result != VIREO_OK) {
                return result;
            }
            result = vireo_timer_wheel_tick_time(info.geometry, next_tick,
                                               &plan.tick_deadline_ns);
            if (result != VIREO_OK) {
                return result;
            }
            result = vireo_clock_deadline_wait_ms(now_ns, plan.tick_deadline_ns,
                                                 max_wait_ms, &plan.timeout_ms);
            if (result != VIREO_OK) {
                return result;
            }
            plan.has_tick_deadline = true;
        }
    }
    *out_plan = plan;
    return VIREO_OK;
}

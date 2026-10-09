/*
 * PROJECT : VIREO
 * FILE    : wheel_time.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 校验数值几何并区分 floor 与 ceil
 * -- 受检计算刻度边界，完整成功后发布输出
 */
#include <vireo/timer/wheel_time.h>

#include <stddef.h>
#include <vireo/base/checked.h>

/** @brief 只核几何的两个正参数，不认证同域或实际数组容量。 */
static bool geometry_valid(vireo_timer_wheel_geometry_t geometry) {
    return geometry.tick_ns != 0 && geometry.bucket_count != 0;
}

/**
 * @brief 用已封板公共 helper 受检还原边界，内部调用者已核几何和输出
 *
 * @param[in] geometry
 *     按值合法几何。
 * @param[in] tick
 *     累计刻度，0..MAX。
 * @param[out] out_time
 *     有效、对齐可写的内部局部输出。
 *
 * @retval VIREO_OK
 *     乘积与最终和可表示，发布准确时间。
 * @retval VIREO_RESULT_OVERFLOW
 *     不可表示，保持输出。
 *
 * @note
 *     无申请/采样，所有路径不读、不改 errno，不含其他模块私有头。
 */
static vireo_result_t tick_boundary(vireo_timer_wheel_geometry_t geometry,
                                    vireo_timer_wheel_tick_t tick,
                                    vireo_monotonic_ns_t *out_time) {
    uint64_t duration;
    vireo_result_t result = vireo_checked_u64_mul(tick, geometry.tick_ns, &duration);
    if (result != VIREO_OK) {
        return result;
    }
    return vireo_clock_deadline_after(geometry.origin_ns, duration, out_time);
}

vireo_result_t vireo_timer_wheel_geometry_make(vireo_monotonic_ns_t origin_ns,
                                              vireo_duration_ns_t tick_ns,
                                              uint64_t bucket_count,
                                              vireo_timer_wheel_geometry_t *out_geometry) {
    if (out_geometry == NULL || tick_ns == 0 || bucket_count == 0) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    *out_geometry = (vireo_timer_wheel_geometry_t){origin_ns, tick_ns, bucket_count};
    return VIREO_OK;
}

vireo_result_t vireo_timer_wheel_elapsed_tick(vireo_timer_wheel_geometry_t geometry,
                                             vireo_monotonic_ns_t now_ns,
                                             vireo_timer_wheel_tick_t *out_tick) {
    if (out_tick == NULL || !geometry_valid(geometry)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (now_ns < geometry.origin_ns) {
        return VIREO_RESULT_RANGE;
    }
    *out_tick = (now_ns - geometry.origin_ns) / geometry.tick_ns;
    return VIREO_OK;
}

vireo_result_t vireo_timer_wheel_deadline_tick(vireo_timer_wheel_geometry_t geometry,
                                              vireo_monotonic_ns_t deadline_ns,
                                              vireo_timer_wheel_tick_t *out_tick) {
    if (out_tick == NULL || !geometry_valid(geometry)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (deadline_ns <= geometry.origin_ns) {
        *out_tick = 0;
        return VIREO_OK;
    }
    uint64_t const delta = deadline_ns - geometry.origin_ns;
    uint64_t tick = delta / geometry.tick_ns;
    if (delta % geometry.tick_ns != 0) {
        vireo_result_t result = vireo_checked_u64_add(tick, 1, &tick);
        if (result != VIREO_OK) {
            return result;
        }
    }
    vireo_monotonic_ns_t boundary;
    vireo_result_t result = tick_boundary(geometry, tick, &boundary);
    if (result != VIREO_OK) {
        return result;
    }
    *out_tick = tick;
    return VIREO_OK;
}

vireo_result_t vireo_timer_wheel_tick_time(vireo_timer_wheel_geometry_t geometry,
                                          vireo_timer_wheel_tick_t tick,
                                          vireo_monotonic_ns_t *out_time_ns) {
    if (out_time_ns == NULL || !geometry_valid(geometry)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    vireo_monotonic_ns_t time;
    vireo_result_t result = tick_boundary(geometry, tick, &time);
    if (result != VIREO_OK) {
        return result;
    }
    *out_time_ns = time;
    return VIREO_OK;
}

vireo_result_t vireo_timer_wheel_bucket_index(vireo_timer_wheel_geometry_t geometry,
                                             vireo_timer_wheel_tick_t tick,
                                             uint64_t *out_bucket_index) {
    if (out_bucket_index == NULL || !geometry_valid(geometry)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    *out_bucket_index = tick % geometry.bucket_count;
    return VIREO_OK;
}

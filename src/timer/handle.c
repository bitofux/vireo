/*
 * PROJECT : VIREO
 * FILE    : handle.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-08
 * BRIEF   : 此模块负责：
 * -- 验证 timer 句柄的数值形态
 * -- 按逻辑字段构造和比较身份
 * -- 复用公开受检加法计算下一代
 */

#include <vireo/timer/handle.h>
#include <vireo/base/checked.h>

/**
 * @brief 区分全零空句柄、正常非空句柄与畸形组合
 *
 * @param[in] handle
 *     已初始化的按值句柄，不持有资源。
 *
 * @retval true
 *     三字段全零，或 owner_id 与 generation 均非零。
 * @retval false
 *     其他零值组合为畸形。
 *
 * @note
 *     边界：不访问槽位，不校验容量、owner 身份来源或活跃状态。
 * @note
 *     errno 与线程：纯数值，无共享可变状态，不读取或修改 errno。
 */
static bool handle_has_valid_shape(vireo_timer_handle_t handle) {
    bool const empty = handle.owner_id == 0 && handle.slot_index == 0 && handle.generation == 0;
    bool const nonempty = handle.owner_id != 0 && handle.generation != 0;
    return empty || nonempty;
}

vireo_result_t vireo_timer_handle_make(uint64_t owner_id, size_t slot_index,
                                       uint64_t generation, vireo_timer_handle_t *out_handle) {
    if (out_handle == NULL || owner_id == 0 || generation == 0) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    vireo_timer_handle_t const value = {owner_id, slot_index, generation};
    *out_handle = value;
    return VIREO_OK;
}

vireo_result_t vireo_timer_handle_is_empty(vireo_timer_handle_t handle, bool *out_empty) {
    if (out_empty == NULL || !handle_has_valid_shape(handle)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    /* 合法形态下，owner 为零只能是三字段全零。 */
    *out_empty = handle.owner_id == 0;
    return VIREO_OK;
}

vireo_result_t vireo_timer_handle_equal(vireo_timer_handle_t left, vireo_timer_handle_t right,
                                        bool *out_equal) {
    if (out_equal == NULL || !handle_has_valid_shape(left) || !handle_has_valid_shape(right)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    *out_equal = left.owner_id == right.owner_id && left.slot_index == right.slot_index &&
                 left.generation == right.generation;
    return VIREO_OK;
}

vireo_result_t vireo_timer_handle_next_generation(uint64_t last_generation,
                                                  uint64_t *out_generation) {
    /* 已封板加法先拒绝 NULL，再验证可表示性；失败保持输出和 errno。 */
    return vireo_checked_u64_add(last_generation, UINT64_C(1), out_generation);
}

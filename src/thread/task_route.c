/*
 * PROJECT : VIREO
 * FILE    : task_route.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : task 路由的纯数值构造与查询
 */

#include <vireo/thread/task.h>

/**
 * @brief
 *     检查逻辑空值或正常非空形态，不访问客户或请求状态。
 *
 * @param[in] route
 *     已初始化的按值路由，无资源所有权。
 *
 * @retval true
 *     四字段全零，或 owner、generation、sequence 均非零。
 * @retval false
 *     其他零值组合畸形。
 *
 * @note
 *     无共享可变状态，不读取或修改 errno，不解释 padding。
 */
static bool route_has_valid_shape(vireo_task_route_t route) {
    bool const empty = route.client_owner_id == 0 && route.client_slot_index == 0 &&
                       route.client_generation == 0 && route.request_sequence == 0;
    bool const nonempty = route.client_owner_id != 0 && route.client_generation != 0 &&
                          route.request_sequence != 0;
    return empty || nonempty;
}

vireo_result_t vireo_task_route_make(uint64_t client_owner_id, size_t client_slot_index,
                                     uint64_t client_generation, uint32_t request_sequence,
                                     vireo_task_route_t *out_route) {
    if (out_route == NULL || client_owner_id == 0 || client_generation == 0 ||
        request_sequence == 0) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    vireo_task_route_t const value = {
        client_owner_id, client_slot_index, client_generation, request_sequence
    };
    *out_route = value;
    return VIREO_OK;
}

vireo_result_t vireo_task_route_is_empty(vireo_task_route_t route, bool *out_empty) {
    if (out_empty == NULL || !route_has_valid_shape(route)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    /* 合法形态下 owner 为零只能是四字段全零。 */
    *out_empty = route.client_owner_id == 0;
    return VIREO_OK;
}

vireo_result_t vireo_task_route_equal(vireo_task_route_t left, vireo_task_route_t right,
                                      bool *out_equal) {
    if (out_equal == NULL || !route_has_valid_shape(left) || !route_has_valid_shape(right)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    *out_equal = left.client_owner_id == right.client_owner_id &&
                 left.client_slot_index == right.client_slot_index &&
                 left.client_generation == right.client_generation &&
                 left.request_sequence == right.request_sequence;
    return VIREO_OK;
}

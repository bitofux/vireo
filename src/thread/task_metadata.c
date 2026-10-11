/*
 * PROJECT : VIREO
 * FILE    : task_metadata.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : task 请求元数据的纯值构造、期限与身份查询
 */

#include <vireo/thread/task.h>

/**
 * @brief
 *     通过本核心已验证的公开 route 查询检查元数据完整形态。
 *
 * @param[in] metadata
 *     已初始化的按值元数据，不拥有客户或请求资源。
 *
 * @retval true
 *     路由正常非空且实例号、操作标签均非零，期限允许所有 uint64_t 值。
 * @retval false
 *     元数据形态无效，包括空路由；不访问任何外部登记表。
 *
 * @note
 *     无私有布局依赖、资源或共享可变状态，不读取或修改 errno。
 */
static bool metadata_has_valid_shape(vireo_task_metadata_t metadata) {
    bool empty = false;
    vireo_result_t const result = vireo_task_route_is_empty(metadata.route, &empty);
    return result == VIREO_OK && !empty && metadata.request_instance_id != 0 &&
           metadata.operation != 0;
}

vireo_result_t vireo_task_metadata_make(vireo_task_route_t route, uint64_t request_instance_id,
                                        uint32_t operation, uint64_t deadline_ns,
                                        vireo_task_metadata_t *out_metadata) {
    if (out_metadata == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    vireo_task_metadata_t const value = {route, request_instance_id, operation, deadline_ns};
    if (!metadata_has_valid_shape(value)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    *out_metadata = value;
    return VIREO_OK;
}

vireo_result_t vireo_task_metadata_deadline_expired(vireo_task_metadata_t metadata,
                                                    uint64_t now_ns, bool *out_expired) {
    if (out_expired == NULL || !metadata_has_valid_shape(metadata)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    /* 与已封板 clock 的显式期限合同一致；纯比较不产生算术溢出。 */
    *out_expired = now_ns >= metadata.deadline_ns;
    return VIREO_OK;
}

vireo_result_t vireo_task_metadata_same_request(vireo_task_metadata_t left,
                                               vireo_task_metadata_t right, bool *out_same) {
    if (out_same == NULL || !metadata_has_valid_shape(left) || !metadata_has_valid_shape(right)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    bool same_route = false;
    vireo_result_t const result = vireo_task_route_equal(left.route, right.route, &same_route);
    if (result != VIREO_OK) {
        return result;
    }

    *out_same = same_route && left.request_instance_id == right.request_instance_id;
    return VIREO_OK;
}

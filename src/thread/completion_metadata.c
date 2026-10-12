/*
 * PROJECT : VIREO
 * FILE    : completion_metadata.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 完成元数据的公开依赖验证、身份与期限查询
 */

#include <vireo/thread/completion.h>

/**
 * @brief
 *     明确接受当前 result 公共注册成员，不以未知枚举名称猜测有效性。
 *
 * @param[in] result
 *     按值内部结果，允许传入未定义值供校验。
 *
 * @retval true
 *     当前公开定义的十三种结果之一。
 * @retval false
 *     未定义结果；未来增加公共分类时需明确扩展此边界。
 *
 * @note
 *     不涉及状态映射、资源或共享可变数据，不修改 errno。
 */
static bool result_is_defined(vireo_result_t result) {
    switch (result) {
        case VIREO_OK:
        case VIREO_RESULT_INVALID_ARGUMENT:
        case VIREO_RESULT_RANGE:
        case VIREO_RESULT_OVERFLOW:
        case VIREO_RESULT_NO_MEMORY:
        case VIREO_RESULT_NOT_FOUND:
        case VIREO_RESULT_BUSY:
        case VIREO_RESULT_TIMEOUT:
        case VIREO_RESULT_CANCELLED:
        case VIREO_RESULT_IO:
        case VIREO_RESULT_PROTOCOL:
        case VIREO_RESULT_DATABASE:
        case VIREO_RESULT_INTERNAL:
            return true;
        default:
            return false;
    }
}

/**
 * @brief
 *     只经已封板的公开查询验证三个逻辑字段，不访问 task 私有布局。
 *
 * @param[in] metadata
 *     已初始化的按值元数据，不拥有或保活外部资源。
 *
 * @retval true
 *     请求形态有效、内部结果已定义且协议状态已注册。
 * @retval false
 *     任一逻辑字段无效；不判断客户当前性或两种结果的业务配对。
 *
 * @note
 *     task 的同请求查询同时验证完整请求形态，避免复制其私有验证规则。
 *     公开依赖查询均为纯值且保持 errno；无采样、分配或同步副作用。
 */
static bool metadata_has_valid_shape(vireo_completion_metadata_t metadata) {
    bool same = false;
    return vireo_task_metadata_same_request(metadata.request, metadata.request, &same) == VIREO_OK &&
           same && result_is_defined(metadata.result) &&
           vireo_status_is_known(metadata.suggested_status);
}

vireo_result_t vireo_completion_metadata_make(vireo_task_metadata_t request,
    vireo_result_t result, vireo_status_t suggested_status,
    vireo_completion_metadata_t *out_metadata) {
    if (out_metadata == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    vireo_completion_metadata_t const value = {request, result, suggested_status};
    if (!metadata_has_valid_shape(value)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    *out_metadata = value;
    return VIREO_OK;
}

vireo_result_t vireo_completion_metadata_same_request(vireo_completion_metadata_t left,
    vireo_completion_metadata_t right, bool *out_same) {
    if (out_same == NULL || !metadata_has_valid_shape(left) || !metadata_has_valid_shape(right)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    return vireo_task_metadata_same_request(left.request, right.request, out_same);
}

vireo_result_t vireo_completion_metadata_deadline_expired(vireo_completion_metadata_t metadata,
    uint64_t now_ns, bool *out_expired) {
    if (out_expired == NULL || !metadata_has_valid_shape(metadata)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    return vireo_task_metadata_deadline_expired(metadata.request, now_ns, out_expired);
}

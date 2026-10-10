/*
 * PROJECT : VIREO
 * FILE    : client_deadline_registration.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 客户核验、未来 timer 登记与显式取消
 * -- 只依赖已采用公开合同，保持资源、输出与 errno 的既有边界
 */
#include <errno.h>
#include <vireo/net/client_deadline.h>

/**
 * @brief
 *     仅校验公开客户租约的数值形态并发布空值判断。
 *
 * @param[in] client
 *     按值租约；不查询所属资源、容量或当前代次。
 * @param[out] out_empty
 *     本层调用者保证非空独立可写 bool；每次写逻辑全零判断。
 *
 * @return
 *     全零或 pool_id／generation 均非零为 true；其余形态为 false。
 *
 * @note
 *     只比较逻辑字段，不比较 padding、不拥有资源、不修改 errno。
 */
static bool client_shape_valid(vireo_connection_pool_lease_t client, bool *out_empty) {
    *out_empty = client.pool_id == 0 && client.slot_index == 0 && client.generation == 0;
    return *out_empty || (client.pool_id != 0 && client.generation != 0);
}

/**
 * @brief
 *     确认 caller 绑定的六个身份字段均为逻辑零。
 *
 * @param[in] binding
 *     按值读取的 caller 记录，不处置其旧资源。
 *
 * @return
 *     全部逻辑字段为零返回 true，否则 false。
 *
 * @note
 *     不比较 padding，不查询活跃性、不修改 errno。
 */
static bool binding_is_empty(vireo_client_deadline_binding_t binding) {
    return binding.client.pool_id == 0 && binding.client.slot_index == 0 &&
           binding.client.generation == 0 && binding.timer.owner_id == 0 &&
           binding.timer.slot_index == 0 && binding.timer.generation == 0;
}

/**
 * @brief
 *     统一发布本次独立诊断并恢复入口 errno。
 *
 * @param[in] result
 *     本次原结果分类，按值返回，不重试或补偿。
 * @param[in] stage
 *     本次检查或依赖阶段；成功沿本文件约定发布 NONE。
 * @param[out] out_stage
 *     可空独立诊断；非空时每条出口覆盖，不写主输出。
 * @param[in] saved_errno
 *     入口 errno 的保存值，恢复调用线程该值。
 *
 * @return
 *     原样返回 result；不追加可失败操作。
 *
 * @note
 *     不修改主输出、资源或业务进度，不进行后置观测。
 */
static vireo_result_t finish(vireo_result_t result, vireo_client_deadline_stage_t stage,
                             vireo_client_deadline_stage_t *out_stage, int saved_errno) {
    if (out_stage != NULL) {
        *out_stage = stage;
    }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_client_deadline_register(vireo_tcp_server_t const *server,
                                              vireo_timer_wheel_t *wheel,
                                              vireo_connection_pool_lease_t client,
                                              vireo_monotonic_ns_t now_ns,
                                              vireo_monotonic_ns_t deadline_ns,
                                              vireo_client_deadline_binding_t *binding,
                                              vireo_client_deadline_stage_t *out_stage) {
    int const saved_errno = errno;
    bool client_empty = false;
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_NONE;
    if (server == NULL || wheel == NULL || binding == NULL || !binding_is_empty(*binding) ||
        !client_shape_valid(client, &client_empty)) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, stage, out_stage, saved_errno);
    }
    if (client_empty) {
        return finish(VIREO_RESULT_NOT_FOUND, stage, out_stage, saved_errno);
    }
    vireo_tcp_server_client_info_t client_info;
    stage = VIREO_CLIENT_DEADLINE_CHECK_CLIENT;
    vireo_result_t result = vireo_tcp_server_client_inspect(server, client, &client_info);
    if (result != VIREO_OK) {
        return finish(result, stage, out_stage, saved_errno);
    }
    vireo_timer_handle_t timer = {0};
    stage = VIREO_CLIENT_DEADLINE_REGISTER_TIMER;
    result = vireo_timer_wheel_register(wheel, now_ns, deadline_ns, &timer);
    if (result != VIREO_OK) {
        return finish(result, stage, out_stage, saved_errno);
    }
    /* 公开 OK 已保证完整当前身份；此后没有可失败依赖或回调。 */
    *binding = (vireo_client_deadline_binding_t){client, timer};
    return finish(VIREO_OK, VIREO_CLIENT_DEADLINE_NONE, out_stage, saved_errno);
}

vireo_result_t vireo_client_deadline_cancel(vireo_timer_wheel_t *wheel,
                                            vireo_client_deadline_binding_t *binding,
                                            vireo_client_deadline_stage_t *out_stage) {
    int const saved_errno = errno;
    bool client_empty = false;
    bool timer_empty = false;
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_NONE;
    if (wheel == NULL || binding == NULL || !client_shape_valid(binding->client, &client_empty)) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, stage, out_stage, saved_errno);
    }
    vireo_result_t result = vireo_timer_handle_is_empty(binding->timer, &timer_empty);
    if (result != VIREO_OK) {
        return finish(result, stage, out_stage, saved_errno);
    }
    if (client_empty != timer_empty) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, stage, out_stage, saved_errno);
    }
    if (client_empty) {
        return finish(VIREO_RESULT_NOT_FOUND, stage, out_stage, saved_errno);
    }
    vireo_timer_handle_t timer = binding->timer;
    stage = VIREO_CLIENT_DEADLINE_CANCEL_TIMER;
    result = vireo_timer_wheel_cancel(wheel, &timer);
    if (result != VIREO_OK) {
        return finish(result, stage, out_stage, saved_errno);
    }
    *binding = (vireo_client_deadline_binding_t){0};
    return finish(VIREO_OK, VIREO_CLIENT_DEADLINE_NONE, out_stage, saved_errno);
}

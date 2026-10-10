/*
 * PROJECT : VIREO
 * FILE    : client_deadline_request.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 显式请求固定总期限登记、查询及取消
 * -- 只依赖已采用公开合同，保持资源、输出与 errno 的既有边界
 */
#include <errno.h>
#include <vireo/base/clock.h>
#include <vireo/net/client_deadline_request.h>
#include <vireo/timer/wheel_shutdown.h>

/**
 * @brief
 *     仅校验公开客户租约的数值形态并发布空值判断。
 *
 * @param[in] client
 *     按值租约；不查询所属资源、容量或当前代次。
 * @param[out] empty
 *     本层调用者保证非空独立可写 bool；每次写逻辑全零判断。
 *
 * @return
 *     全零或 pool_id／generation 均非零为 true；其余形态为 false。
 *
 * @note
 *     只比较逻辑字段，不比较 padding、不拥有资源、不修改 errno。
 */
static bool client_shape(vireo_connection_pool_lease_t client, bool *empty) {
    *empty = client.pool_id == 0 && client.slot_index == 0 && client.generation == 0;
    return *empty || (client.pool_id != 0 && client.generation != 0);
}

/**
 * @brief
 *     校验固定请求记录及其逻辑空形态。
 *
 * @param[in] request
 *     本层保证非空存活记录，只读短借。
 * @param[out] empty
 *     本层保证非空独立 bool；双方形态合法后写是否逻辑空。
 *
 * @return
 *     完整形态为 true，畸形为 false；非空要求非零 sequence 且 started_ns < deadline_ns。
 *
 * @note
 *     false 时 empty 不作为成功输出；不确认资源当前性或固定期限一致性，不修改 errno。
 */
static bool request_shape(vireo_client_deadline_request_t const *request, bool *empty) {
    bool client_empty = false;
    bool timer_empty = false;
    if (!client_shape(request->binding.client, &client_empty) ||
        vireo_timer_handle_is_empty(request->binding.timer, &timer_empty) != VIREO_OK ||
        client_empty != timer_empty)
        return false;
    *empty = client_empty;
    if (*empty)
        return request->request_sequence == 0 && request->started_ns == 0 &&
               request->deadline_ns == 0;
    return request->request_sequence != 0 && request->started_ns < request->deadline_ns;
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
static vireo_result_t finish(vireo_result_t result, vireo_client_deadline_request_stage_t stage,
                             vireo_client_deadline_request_stage_t *out_stage, int saved_errno) {
    if (out_stage != NULL)
        *out_stage = result == VIREO_OK ? VIREO_CLIENT_DEADLINE_REQUEST_NONE : stage;
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_client_deadline_request_start(
    vireo_tcp_server_t const *server, vireo_timer_wheel_t *wheel,
    vireo_connection_pool_lease_t client, uint32_t request_sequence,
    vireo_monotonic_ns_t started_ns, vireo_duration_ns_t total_timeout_ns,
    vireo_client_deadline_request_t *out_request,
    vireo_client_deadline_request_stage_t *out_stage) {
    int const saved_errno = errno;
    vireo_client_deadline_request_stage_t stage = VIREO_CLIENT_DEADLINE_REQUEST_NONE;
    bool client_empty = false;
    bool empty = false;
    if (server == NULL || wheel == NULL || out_request == NULL || request_sequence == 0 ||
        total_timeout_ns == 0 || !client_shape(client, &client_empty) ||
        !request_shape(out_request, &empty) || !empty)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, stage, out_stage, saved_errno);
    if (client_empty)
        return finish(VIREO_RESULT_NOT_FOUND, stage, out_stage, saved_errno);
    stage = VIREO_CLIENT_DEADLINE_REQUEST_CHECK_CLIENT;
    vireo_tcp_server_client_info_t client_info;
    vireo_result_t result = vireo_tcp_server_client_inspect(server, client, &client_info);
    if (result != VIREO_OK)
        return finish(result, stage, out_stage, saved_errno);
    stage = VIREO_CLIENT_DEADLINE_REQUEST_CHECK_OPEN;
    if (client_info.connection_info.close_state != VIREO_CONNECTION_CLOSE_OPEN)
        return finish(VIREO_RESULT_BUSY, stage, out_stage, saved_errno);
    stage = VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIMER;
    vireo_timer_wheel_progress_t progress;
    result = vireo_timer_wheel_progress_inspect(wheel, &progress);
    if (result != VIREO_OK)
        return finish(result, stage, out_stage, saved_errno);
    vireo_timer_wheel_shutdown_info_t shutdown;
    result = vireo_timer_wheel_shutdown_inspect(wheel, &shutdown);
    if (result != VIREO_OK || shutdown.stopping)
        return finish(result != VIREO_OK ? result : VIREO_RESULT_CANCELLED, stage, out_stage,
                      saved_errno);
    stage = VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIME;
    if (started_ns < progress.latest_now_ns)
        return finish(VIREO_RESULT_RANGE, stage, out_stage, saved_errno);
    vireo_monotonic_ns_t deadline;
    result = vireo_clock_deadline_after(started_ns, total_timeout_ns, &deadline);
    if (result != VIREO_OK)
        return finish(result, stage, out_stage, saved_errno);
    vireo_client_deadline_binding_t binding = {0};
    vireo_client_deadline_stage_t dependency_stage = VIREO_CLIENT_DEADLINE_NONE;
    result = vireo_client_deadline_register(server, wheel, client, started_ns, deadline, &binding,
                                            &dependency_stage);
    stage = dependency_stage == VIREO_CLIENT_DEADLINE_CHECK_CLIENT
                ? VIREO_CLIENT_DEADLINE_REQUEST_CHECK_CLIENT
                : VIREO_CLIENT_DEADLINE_REQUEST_REGISTER_TIMER;
    if (result == VIREO_OK)
        *out_request =
            (vireo_client_deadline_request_t){binding, request_sequence, started_ns, deadline};
    return finish(result, stage, out_stage, saved_errno);
}

vireo_result_t vireo_client_deadline_request_check(
    vireo_tcp_server_t const *server, vireo_timer_wheel_t const *wheel,
    vireo_client_deadline_request_t const *request, vireo_monotonic_ns_t now_ns, bool *out_expired,
    vireo_client_deadline_request_stage_t *out_stage) {
    int const saved_errno = errno;
    vireo_client_deadline_request_stage_t stage = VIREO_CLIENT_DEADLINE_REQUEST_NONE;
    bool empty = false;
    if (server == NULL || wheel == NULL || request == NULL || out_expired == NULL ||
        !request_shape(request, &empty))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, stage, out_stage, saved_errno);
    if (empty)
        return finish(VIREO_RESULT_NOT_FOUND, stage, out_stage, saved_errno);
    stage = VIREO_CLIENT_DEADLINE_REQUEST_CHECK_CLIENT;
    vireo_tcp_server_client_info_t client_info;
    vireo_result_t result =
        vireo_tcp_server_client_inspect(server, request->binding.client, &client_info);
    if (result != VIREO_OK)
        return finish(result, stage, out_stage, saved_errno);
    stage = VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIMER;
    vireo_timer_wheel_timer_info_t timer;
    result = vireo_timer_wheel_get(wheel, request->binding.timer, &timer);
    if (result != VIREO_OK)
        return finish(result, stage, out_stage, saved_errno);
    if (timer.deadline_ns != request->deadline_ns)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, stage, out_stage, saved_errno);
    vireo_timer_wheel_progress_t progress;
    result = vireo_timer_wheel_progress_inspect(wheel, &progress);
    if (result != VIREO_OK)
        return finish(result, stage, out_stage, saved_errno);
    stage = VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIME;
    if (now_ns < request->started_ns || now_ns < progress.latest_now_ns)
        return finish(VIREO_RESULT_RANGE, stage, out_stage, saved_errno);
    *out_expired = now_ns >= request->deadline_ns;
    return finish(VIREO_OK, stage, out_stage, saved_errno);
}

vireo_result_t vireo_client_deadline_request_cancel(
    vireo_timer_wheel_t *wheel, vireo_client_deadline_request_t *request,
    vireo_client_deadline_request_stage_t *out_stage) {
    int const saved_errno = errno;
    vireo_client_deadline_request_stage_t stage = VIREO_CLIENT_DEADLINE_REQUEST_NONE;
    bool empty = false;
    if (wheel == NULL || request == NULL || !request_shape(request, &empty))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, stage, out_stage, saved_errno);
    if (empty)
        return finish(VIREO_RESULT_NOT_FOUND, stage, out_stage, saved_errno);
    vireo_client_deadline_binding_t binding = request->binding;
    vireo_result_t result = vireo_client_deadline_cancel(wheel, &binding, NULL);
    if (result == VIREO_OK)
        *request = (vireo_client_deadline_request_t){0};
    return finish(result, VIREO_CLIENT_DEADLINE_REQUEST_CANCEL_TIMER, out_stage, saved_errno);
}

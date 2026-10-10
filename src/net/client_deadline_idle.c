/*
 * PROJECT : VIREO
 * FILE    : client_deadline_idle.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 根据实际传输字节刷新显式空闲期限
 * -- 只依赖已采用公开合同，保持资源、输出与 errno 的既有边界
 */
#include <errno.h>
#include <vireo/base/clock.h>
#include <vireo/net/client_deadline_idle.h>
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
 *     校验两字段 idle 记录与双方身份的逻辑形态。
 *
 * @param[in] idle
 *     本层调用者保证非空存活记录，只读短借。
 * @param[out] empty
 *     本层保证非空独立 bool；仅全部形态合法时发布。
 *
 * @return
 *     合法形态 OK；半空／零间隔与身份不一致 INVALID_ARGUMENT；timer 形态错误原样透传。
 *
 * @note
 *     失败 empty 保持；不核验容量、当前性或时间来源，不修改 errno。
 */
static vireo_result_t idle_shape(vireo_client_deadline_idle_t const *idle, bool *empty) {
    bool client_empty = false;
    bool timer_empty = false;
    if (!client_shape(idle->binding.client, &client_empty))
        return VIREO_RESULT_INVALID_ARGUMENT;
    vireo_result_t result = vireo_timer_handle_is_empty(idle->binding.timer, &timer_empty);
    if (result != VIREO_OK)
        return result;
    if (client_empty != timer_empty || (client_empty != (idle->idle_timeout_ns == 0)))
        return VIREO_RESULT_INVALID_ARGUMENT;
    *empty = client_empty;
    return VIREO_OK;
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
    if (out_stage != NULL)
        *out_stage = result == VIREO_OK ? VIREO_CLIENT_DEADLINE_NONE : stage;
    errno = saved_errno;
    return result;
}

/**
 * @brief
 *     公开观测已准备轮的最近成功推进样本及停止状态。
 *
 * @param[in] wheel
 *     外层已检查非空存活轮，同 Reactor 短借。
 * @param[out] out_latest
 *     本层保证非空独立纳秒输出；全部检查成功才发布。
 *
 * @return
 *     轮停止 CANCELLED；未准备或其他观测错误原样返回；成功 OK。
 *
 * @note
 *     失败输出保持，停止优先于后续时间计算，不采样、推进或修改轮及 errno。
 */
static vireo_result_t wheel_time(vireo_timer_wheel_t const *wheel,
                                 vireo_monotonic_ns_t *out_latest) {
    vireo_timer_wheel_progress_t progress;
    vireo_result_t result = vireo_timer_wheel_progress_inspect(wheel, &progress);
    if (result != VIREO_OK)
        return result;
    vireo_timer_wheel_shutdown_info_t shutdown;
    result = vireo_timer_wheel_shutdown_inspect(wheel, &shutdown);
    if (result != VIREO_OK)
        return result;
    if (shutdown.stopping)
        return VIREO_RESULT_CANCELLED;
    *out_latest = progress.latest_now_ns;
    return VIREO_OK;
}

/**
 * @brief
 *     公开核验当前客户及传输空闲策略的 OPEN 门槛。
 *
 * @param[in] server
 *     外层已检查非空存活 server，同 Reactor 短借。
 * @param[in] client
 *     已检查完整形态的客户租约值。
 * @param[out] stage
 *     本层保证非空独立阶段；每次先 CHECK_CLIENT，再 CHECK_IDLE_STATE。
 *
 * @return
 *     公开客户错误原样返回；当前非 OPEN 为 BUSY；OPEN 返回 OK。
 *
 * @note
 *     只读客户；失败可发布阶段，不修改资源或 errno，外层成功时将阶段归 NONE。
 */
static vireo_result_t open_client(vireo_tcp_server_t const *server,
                                  vireo_connection_pool_lease_t client,
                                  vireo_client_deadline_stage_t *stage) {
    vireo_tcp_server_client_info_t info;
    *stage = VIREO_CLIENT_DEADLINE_CHECK_CLIENT;
    vireo_result_t result = vireo_tcp_server_client_inspect(server, client, &info);
    if (result != VIREO_OK)
        return result;
    *stage = VIREO_CLIENT_DEADLINE_CHECK_IDLE_STATE;
    return info.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN ? VIREO_OK
                                                                           : VIREO_RESULT_BUSY;
}

vireo_result_t vireo_client_deadline_idle_start(vireo_tcp_server_t const *server,
                                                vireo_timer_wheel_t *wheel,
                                                vireo_connection_pool_lease_t client,
                                                vireo_monotonic_ns_t now_ns,
                                                vireo_duration_ns_t idle_timeout_ns,
                                                vireo_client_deadline_idle_t *out_idle,
                                                vireo_client_deadline_stage_t *out_stage) {
    int const saved_errno = errno;
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_NONE;
    bool empty = false;
    bool client_empty = false;
    if (server == NULL || wheel == NULL || out_idle == NULL || idle_timeout_ns == 0 ||
        !client_shape(client, &client_empty) || idle_shape(out_idle, &empty) != VIREO_OK || !empty)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, stage, out_stage, saved_errno);
    if (client_empty)
        return finish(VIREO_RESULT_NOT_FOUND, stage, out_stage, saved_errno);
    vireo_result_t result = open_client(server, client, &stage);
    if (result != VIREO_OK)
        return finish(result, stage, out_stage, saved_errno);
    stage = VIREO_CLIENT_DEADLINE_CHECK_TIMER;
    vireo_monotonic_ns_t latest;
    result = wheel_time(wheel, &latest);
    if (result != VIREO_OK)
        return finish(result, stage, out_stage, saved_errno);
    stage = VIREO_CLIENT_DEADLINE_CHECK_IDLE_TIME;
    if (now_ns < latest)
        return finish(VIREO_RESULT_RANGE, stage, out_stage, saved_errno);
    vireo_monotonic_ns_t deadline;
    result = vireo_clock_deadline_after(now_ns, idle_timeout_ns, &deadline);
    if (result != VIREO_OK)
        return finish(result, stage, out_stage, saved_errno);
    vireo_client_deadline_binding_t binding = {0};
    result =
        vireo_client_deadline_register(server, wheel, client, now_ns, deadline, &binding, &stage);
    if (result == VIREO_OK)
        *out_idle = (vireo_client_deadline_idle_t){binding, idle_timeout_ns};
    return finish(result, stage, out_stage, saved_errno);
}

vireo_result_t vireo_client_deadline_idle_refresh(vireo_tcp_server_t const *server,
                                                  vireo_timer_wheel_t *wheel,
                                                  vireo_client_deadline_idle_t const *idle,
                                                  vireo_monotonic_ns_t now_ns,
                                                  size_t received_bytes, size_t sent_bytes,
                                                  vireo_client_deadline_stage_t *out_stage) {
    int const saved_errno = errno;
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_NONE;
    bool empty = false;
    if (server == NULL || wheel == NULL || idle == NULL || idle_shape(idle, &empty) != VIREO_OK)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, stage, out_stage, saved_errno);
    if (empty)
        return finish(VIREO_RESULT_NOT_FOUND, stage, out_stage, saved_errno);
    vireo_result_t result = open_client(server, idle->binding.client, &stage);
    if (result != VIREO_OK)
        return finish(result, stage, out_stage, saved_errno);
    stage = VIREO_CLIENT_DEADLINE_CHECK_TIMER;
    vireo_timer_wheel_timer_info_t timer;
    result = vireo_timer_wheel_get(wheel, idle->binding.timer, &timer);
    if (result != VIREO_OK)
        return finish(result, stage, out_stage, saved_errno);
    vireo_monotonic_ns_t latest;
    result = wheel_time(wheel, &latest);
    if (result != VIREO_OK)
        return finish(result, stage, out_stage, saved_errno);
    stage = VIREO_CLIENT_DEADLINE_CHECK_IDLE_TIME;
    if (now_ns < latest)
        return finish(VIREO_RESULT_RANGE, stage, out_stage, saved_errno);
    if (timer.deadline_ns < idle->idle_timeout_ns)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, stage, out_stage, saved_errno);
    if (now_ns < timer.deadline_ns - idle->idle_timeout_ns)
        return finish(VIREO_RESULT_RANGE, stage, out_stage, saved_errno);
    if (now_ns >= timer.deadline_ns)
        return finish(VIREO_RESULT_TIMEOUT, stage, out_stage, saved_errno);
    if (received_bytes == 0 && sent_bytes == 0)
        return finish(VIREO_OK, stage, out_stage, saved_errno);
    vireo_monotonic_ns_t deadline;
    result = vireo_clock_deadline_after(now_ns, idle->idle_timeout_ns, &deadline);
    if (result != VIREO_OK)
        return finish(result, stage, out_stage, saved_errno);
    result = vireo_client_deadline_rearm(server, wheel, idle->binding, now_ns, deadline, &stage);
    return finish(result, stage, out_stage, saved_errno);
}

vireo_result_t vireo_client_deadline_idle_cancel(vireo_timer_wheel_t *wheel,
                                                 vireo_client_deadline_idle_t *idle,
                                                 vireo_client_deadline_stage_t *out_stage) {
    int const saved_errno = errno;
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_NONE;
    bool empty = false;
    if (wheel == NULL || idle == NULL || idle_shape(idle, &empty) != VIREO_OK)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, stage, out_stage, saved_errno);
    if (empty)
        return finish(VIREO_RESULT_NOT_FOUND, stage, out_stage, saved_errno);
    vireo_client_deadline_binding_t binding = idle->binding;
    vireo_result_t result = vireo_client_deadline_cancel(wheel, &binding, &stage);
    if (result == VIREO_OK)
        *idle = (vireo_client_deadline_idle_t){0};
    return finish(result, stage, out_stage, saved_errno);
}

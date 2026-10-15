/*
 * PROJECT : VIREO
 * FILE    : async_admission.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 前置纯数值验证、有界接入准备与真实错误前缀
 */
#include "async_admission_internal.h"
#include <vireo/base/checked.h>
#include <errno.h>

/** 原公开资源根观察，不保存或保活。 */
static vireo_result_t inspect(void *ctx, vireo_tcp_server_t const *s, vireo_tcp_server_info_t *info) {
    (void)ctx; return vireo_tcp_server_inspect(s, info);
}
/** 原公开一次有界admit，租约发布/当前失败客户清理原样。 */
static vireo_result_t admit(void *ctx, vireo_tcp_server_t *s, vireo_connection_options_t const *o,
    vireo_tcp_server_admit_budget_t const *b, vireo_connection_pool_lease_t *clients, size_t n,
    vireo_tcp_server_admit_info_t *info, vireo_tcp_server_client_error_t *error) {
    (void)ctx; return vireo_tcp_server_admit_batch(s, o, b, clients, n, info, error);
}
/** 原公开流控配置，失败旧提交配置保持。 */
static vireo_result_t flow(void *ctx, vireo_tcp_server_t *s, vireo_connection_pool_lease_t c,
    vireo_connection_flow_options_t const *o, vireo_tcp_server_client_error_t *e) {
    (void)ctx; return vireo_tcp_server_client_flow_configure(s, c, o, e);
}
/** 原公开显式排队，无重试。 */
static vireo_result_t schedule(void *ctx, vireo_tcp_server_t *s, vireo_connection_pool_lease_t c,
    vireo_tcp_server_client_error_t *e) {
    (void)ctx; return vireo_tcp_server_schedule_client(s, c, e);
}
static vireo_async_admission_ops_t const default_ops = {inspect, admit, flow, schedule};

/** 只检查本层四边界完整性，不访问资源。 */
static bool valid_ops(vireo_async_admission_ops_t const *o) {
    return o != NULL && o->inspect != NULL && o->admit != NULL && o->flow != NULL && o->schedule != NULL;
}
/** 全三字段逻辑零为空，不能用padding或单generation代替形态。 */
static bool lease_empty(vireo_connection_pool_lease_t c) {
    return c.pool_id == 0 && c.slot_index == 0 && c.generation == 0;
}
/** 仅复用公开受检/数值合同，先合计再范围；maxframe下界先保护减一。 */
static vireo_result_t validate_options(vireo_connection_options_t const *c, vireo_connection_flow_options_t const *f) {
    size_t pair = 0; vireo_result_t const result = vireo_checked_size_add(c->read_capacity, c->write_capacity, &pair);
    if (result != VIREO_OK) return result;
    if (c->read_capacity == 0 || c->write_capacity == 0 || c->max_buffer_bytes == 0 ||
        c->read_capacity > VIREO_BUFFER_MAX_CAPACITY || c->write_capacity > VIREO_BUFFER_MAX_CAPACITY ||
        c->max_buffer_bytes > VIREO_CONNECTION_MAX_BUFFER_BYTES || pair > c->max_buffer_bytes)
        return VIREO_RESULT_RANGE;
    if (f->max_frame_bytes < (size_t)VIREO_PROTOCOL_HEADER_SIZE ||
        f->max_frame_bytes > (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE + (size_t)VIREO_PROTOCOL_HEADER_SIZE ||
        f->max_frame_bytes > c->read_capacity || f->read_low < f->max_frame_bytes - 1 ||
        f->read_low >= f->read_high || f->read_high > c->read_capacity ||
        f->write_low >= f->write_high || f->write_high > c->write_capacity)
        return VIREO_RESULT_RANGE;
    return VIREO_OK;
}
/** 发布完整逻辑值，OK归NONE，保入口errno，不做任何清理。 */
static vireo_result_t finish(vireo_result_t result, vireo_async_admission_report_t value,
    vireo_async_admission_report_t *out, int saved) {
    if (result == VIREO_OK) value.stage = VIREO_ASYNC_ADMISSION_NONE;
    if (out != NULL) *out = value;
    errno = saved; return result;
}

vireo_result_t vireo_async_admission_with_ops(vireo_tcp_server_t *server, vireo_connection_options_t const *connection_options,
    vireo_connection_flow_options_t const *flow_options, vireo_tcp_server_admit_budget_t const *budget,
    vireo_connection_pool_lease_t *clients, size_t client_capacity, vireo_async_admission_turn_t *turns,
    size_t turn_capacity, vireo_async_admission_report_t *out, vireo_async_admission_ops_t const *ops, void *context) {
    int const saved = errno; vireo_async_admission_report_t value = {0};
    if (server == NULL || connection_options == NULL || flow_options == NULL || budget == NULL || clients == NULL ||
        turns == NULL || out == NULL || client_capacity == 0 || turn_capacity == 0 ||
        budget->max_accepts == 0 || budget->max_accept_syscalls == 0 || !valid_ops(ops))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
    vireo_connection_options_t const c = *connection_options;
    vireo_connection_flow_options_t const f = *flow_options;
    vireo_tcp_server_admit_budget_t b = *budget;
    if (b.max_accepts > VIREO_TCP_SERVER_MAX_CONNECTIONS || client_capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        turn_capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS) return finish(VIREO_RESULT_RANGE, value, out, saved);
    size_t effective = b.max_accepts;
    if (client_capacity < effective) effective = client_capacity;
    if (turn_capacity < effective) effective = turn_capacity;
    for (size_t i = 0; i < effective; ++i)
        if (!lease_empty(clients[i])) return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
    value.effective_max_accepts = effective;
    value.stage = VIREO_ASYNC_ADMISSION_VALIDATE_OPTIONS;
    vireo_result_t result = validate_options(&c, &f);
    if (result != VIREO_OK) return finish(result, value, out, saved);
    value.stage = VIREO_ASYNC_ADMISSION_CHECK_SERVER;
    vireo_tcp_server_info_t root = {0}; result = ops->inspect(context, server, &root);
    if (result != VIREO_OK) return finish(result, value, out, saved);
    if (root.processing_active || root.driving_active || root.scheduling_active || root.serving_active ||
        root.shutdown_active || root.closing_active || root.running_active)
        return finish(VIREO_RESULT_BUSY, value, out, saved);
    if (root.stop_requested) return finish(VIREO_RESULT_CANCELLED, value, out, saved);
    if (root.admission_enabled) return finish(VIREO_RESULT_BUSY, value, out, saved);
    b.max_accepts = value.effective_max_accepts;
    value.stage = VIREO_ASYNC_ADMISSION_ADMIT; value.admit_called = true;
    result = ops->admit(context, server, &c, &b, clients, client_capacity, &value.admission, &value.admit_error);
    value.admit_result = result;
    if (result != VIREO_OK) return finish(result, value, out, saved);
    for (size_t i = 0; i < value.admission.admitted_count; ++i) {
        vireo_async_admission_turn_t turn = {0}; turn.client = clients[i]; turn.flow_called = true;
        ++value.turn_count; value.unprocessed_begin = value.turn_count;
        value.stage = VIREO_ASYNC_ADMISSION_FLOW;
        result = ops->flow(context, server, turn.client, &f, &turn.flow_error); turn.flow_result = result;
        if (result == VIREO_OK) {
            ++value.initialized_count; value.stage = VIREO_ASYNC_ADMISSION_SCHEDULE; turn.schedule_called = true;
            result = ops->schedule(context, server, turn.client, &turn.schedule_error); turn.schedule_result = result;
            if (result == VIREO_OK) ++value.scheduled_count;
        }
        turns[i] = turn;
        if (result != VIREO_OK) return finish(result, value, out, saved);
    }
    return finish(VIREO_OK, value, out, saved);
}

vireo_result_t vireo_async_admission_once(vireo_tcp_server_t *server, vireo_connection_options_t const *connection_options,
    vireo_connection_flow_options_t const *flow_options, vireo_tcp_server_admit_budget_t const *budget,
    vireo_connection_pool_lease_t *clients, size_t client_capacity, vireo_async_admission_turn_t *turns,
    size_t turn_capacity, vireo_async_admission_report_t *report) {
    return vireo_async_admission_with_ops(server, connection_options, flow_options, budget, clients, client_capacity,
        turns, turn_capacity, report, &default_ops, NULL);
}

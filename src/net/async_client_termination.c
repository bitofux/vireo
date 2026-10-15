/*
 * PROJECT : VIREO
 * FILE    : async_client_termination.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 按真实客户消费与槽游标续接终止，不重试旧身份
 */
#include "async_client_termination_internal.h"
#include <errno.h>

/** 一次公开表观测，不借内部槽。 */
static vireo_result_t inspect(void *context, vireo_inflight_store_t const *store,
    vireo_inflight_store_info_t *info) {
    (void)context;
    return vireo_inflight_store_inspect(store, info);
}
/** 只提交原关闭意图，IMMEDIATE由编排固定。 */
static vireo_result_t close_client(void *context, vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_connection_close_mode_t mode,
    vireo_connection_close_reason_t reason, vireo_tcp_server_client_error_t *error) {
    (void)context;
    return vireo_tcp_server_client_request_close(server, client, mode, reason, error);
}
/** 原归还会按真实消费清零局部租约，包括消费型IO。 */
static vireo_result_t release_client(void *context, vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t *client, vireo_tcp_server_client_error_t *error) {
    (void)context;
    return vireo_tcp_server_release_client(server, client, error);
}
/** 只扫描一次，原028-11保存预算/失败槽和部分取消进度。 */
static vireo_result_t cleanup(void *context, vireo_inflight_store_t *store,
    vireo_connection_pool_lease_t client, size_t begin, size_t max,
    vireo_inflight_client_cleanup_report_t *report) {
    (void)context;
    return vireo_inflight_store_cancel_client_batch(store, client, begin, max, report);
}
static vireo_async_client_termination_ops_t const default_ops = {
    inspect, close_client, release_client, cleanup
};

/** 显式注册值校验，NONE或未知数值不能成为终止理由。 */
static bool valid_reason(vireo_connection_close_reason_t reason) {
    switch (reason) {
    case VIREO_CONNECTION_CLOSE_REASON_APPLICATION:
    case VIREO_CONNECTION_CLOSE_REASON_PEER_EOF:
    case VIREO_CONNECTION_CLOSE_REASON_PROTOCOL:
    case VIREO_CONNECTION_CLOSE_REASON_IO:
    case VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP:
    case VIREO_CONNECTION_CLOSE_REASON_RESOURCE_LIMIT:
        return true;
    default:
        return false;
    }
}
/** 消费以三个逻辑字段全零为准，不用返回码或padding推断。 */
static bool empty(vireo_connection_pool_lease_t client) {
    return client.pool_id == 0 && client.slot_index == 0 && client.generation == 0;
}
/**
 * @brief
 *     完整发布本次进度并恢复入口errno。
 *
 * @param[in] result
 *     原主返回，不把消费型错误转成成功。
 * @param[in] value
 *     栈上报告副本，成功时仅将错误阶段置NONE。
 * @param[out] out
 *     可空独立输出，仅本次赋值，不保存地址。
 * @param[in] saved
 *     入口保存的errno值。
 *
 * @return
 *     原result，不回滚已经提交的动作。
 */
static vireo_result_t finish(vireo_result_t result, vireo_async_client_termination_report_t value,
    vireo_async_client_termination_report_t *out, int saved) {
    if (result == VIREO_OK) value.stage = VIREO_ASYNC_CLIENT_TERMINATION_NONE;
    if (out != NULL) *out = value;
    errno = saved;
    return result;
}

vireo_result_t vireo_async_client_termination_with_ops(vireo_tcp_server_t *server,
    vireo_inflight_store_t *store, vireo_connection_pool_lease_t client,
    vireo_connection_close_reason_t reason, vireo_async_client_termination_step_t from,
    size_t begin_index, size_t max_slots, vireo_async_client_termination_report_t *out,
    vireo_async_client_termination_ops_t const *ops, void *context) {
    int const saved = errno;
    vireo_async_client_termination_report_t value = {0};
    if (server == NULL || store == NULL || out == NULL || ops == NULL ||
        ops->inspect == NULL || ops->close == NULL || ops->release == NULL || ops->cleanup == NULL ||
        !valid_reason(reason) || max_slots == 0 ||
        (from != VIREO_ASYNC_CLIENT_TERMINATION_STEP_CLOSE &&
         from != VIREO_ASYNC_CLIENT_TERMINATION_STEP_RELEASE &&
         from != VIREO_ASYNC_CLIENT_TERMINATION_STEP_CLEANUP) ||
        (from != VIREO_ASYNC_CLIENT_TERMINATION_STEP_CLEANUP && begin_index != 0))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
    if (max_slots > VIREO_INFLIGHT_STORE_MAX_CAPACITY)
        return finish(VIREO_RESULT_RANGE, value, out, saved);
    if (empty(client)) return finish(VIREO_RESULT_NOT_FOUND, value, out, saved);
    if (client.pool_id == 0 || client.generation == 0)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
    value.stage = VIREO_ASYNC_CLIENT_TERMINATION_CHECK_STORE;
    vireo_inflight_store_info_t info;
    vireo_result_t result = ops->inspect(context, store, &info);
    if (result != VIREO_OK) return finish(result, value, out, saved);
    if (begin_index > info.capacity) return finish(VIREO_RESULT_RANGE, value, out, saved);
    value.client = client;
    value.next_step = from;
    if (from == VIREO_ASYNC_CLIENT_TERMINATION_STEP_CLOSE) {
        value.stage = VIREO_ASYNC_CLIENT_TERMINATION_CLOSE_CLIENT;
        value.close_called = true;
        value.close_result = ops->close(context, server, client, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
            reason, &value.client_error);
        if (value.close_result != VIREO_OK) return finish(value.close_result, value, out, saved);
        value.next_step = VIREO_ASYNC_CLIENT_TERMINATION_STEP_RELEASE;
    }
    if (value.next_step == VIREO_ASYNC_CLIENT_TERMINATION_STEP_RELEASE) {
        vireo_connection_pool_lease_t local = client;
        value.stage = VIREO_ASYNC_CLIENT_TERMINATION_RELEASE_CLIENT;
        value.release_called = true;
        value.release_result = ops->release(context, server, &local, &value.client_error);
        value.client_consumed = empty(local);
        if (value.client_consumed) value.next_step = VIREO_ASYNC_CLIENT_TERMINATION_STEP_CLEANUP;
        if (value.release_result != VIREO_OK) return finish(value.release_result, value, out, saved);
        if (!value.client_consumed) return finish(VIREO_RESULT_INTERNAL, value, out, saved);
    }
    value.stage = VIREO_ASYNC_CLIENT_TERMINATION_CLEAN_INFLIGHT;
    value.cleanup_called = true;
    value.cleanup_result = ops->cleanup(context, store, client, begin_index, max_slots, &value.cleanup_report);
    if (value.cleanup_result != VIREO_OK) return finish(value.cleanup_result, value, out, saved);
    if (value.cleanup_report.stop_reason == VIREO_INFLIGHT_CLIENT_CLEANUP_COMPLETE)
        value.next_step = VIREO_ASYNC_CLIENT_TERMINATION_STEP_DONE;
    else if (value.cleanup_report.stop_reason != VIREO_INFLIGHT_CLIENT_CLEANUP_BUDGET)
        return finish(VIREO_RESULT_INTERNAL, value, out, saved);
    return finish(VIREO_OK, value, out, saved);
}

vireo_result_t vireo_async_client_terminate_once(vireo_tcp_server_t *server,
    vireo_inflight_store_t *store, vireo_connection_pool_lease_t client,
    vireo_connection_close_reason_t reason, vireo_async_client_termination_step_t from,
    size_t begin_index, size_t max_slots, vireo_async_client_termination_report_t *report) {
    return vireo_async_client_termination_with_ops(server, store, client, reason, from,
        begin_index, max_slots, report, &default_ops, NULL);
}

/*
 * PROJECT : VIREO
 * FILE    : async_pending_recovery.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 公开三提交点和消费后的显式续接，不重提任务
 */
#include "async_pending_recovery_internal.h"
#include <errno.h>

/** 公开原恢复消费，不重新识别、发号或提交。 */
static vireo_result_t consume(void *ctx, vireo_tcp_server_t *s, vireo_async_request_pending_t *p,
    vireo_async_request_head_report_t *r) { (void)ctx; return vireo_async_request_resume_consume(s, p, r); }
/** 公开原flow刷新，不恢复关闭状态或已停止loop。 */
static vireo_result_t refresh(void *ctx, vireo_tcp_server_t *s, vireo_connection_pool_lease_t c,
    vireo_tcp_server_client_error_t *e) { (void)ctx; return vireo_tcp_server_client_flow_refresh(s, c, e); }
/** 公开原去重排队，只安排以后机会。 */
static vireo_result_t schedule(void *ctx, vireo_tcp_server_t *s, vireo_connection_pool_lease_t c,
    vireo_tcp_server_client_error_t *e) { (void)ctx; return vireo_tcp_server_schedule_client(s, c, e); }
static vireo_async_pending_recovery_ops_t const default_ops = {consume, refresh, schedule};

/** 按公开字段判逻辑空，不比较padding或拿deadline0作单独哨兵。 */
static bool empty_pending(vireo_async_request_pending_t const *p) {
    vireo_task_metadata_t const m = p->metadata;
    return p->frame_bytes == 0 && m.route.client_owner_id == 0 && m.route.client_slot_index == 0 &&
        m.route.client_generation == 0 && m.route.request_sequence == 0 && m.request_instance_id == 0 &&
        m.operation == 0 && m.deadline_ns == 0;
}
/** 仅公开metadata纯值构造校验形态，不采样、不查客户或inflight。 */
static vireo_result_t validate_pending(vireo_async_request_pending_t const *p) {
    if (p->frame_bytes < (size_t)VIREO_PROTOCOL_HEADER_SIZE || p->frame_bytes > VIREO_ASYNC_REQUEST_MAX_FRAME_BYTES)
        return VIREO_RESULT_INVALID_ARGUMENT;
    vireo_task_metadata_t checked;
    return vireo_task_metadata_make(p->metadata.route, p->metadata.request_instance_id,
        p->metadata.operation, p->metadata.deadline_ns, &checked);
}
/** 完整发布真实局部进度/原错误，恢复入口errno，不回滚或清理。 */
static vireo_result_t finish(vireo_result_t result, vireo_async_pending_recovery_report_t value,
    vireo_async_pending_recovery_report_t *out, int saved) {
    if (result == VIREO_OK) value.stage = VIREO_ASYNC_PENDING_RECOVERY_NONE;
    if (out != NULL) *out = value;
    errno = saved; return result;
}

vireo_result_t vireo_async_pending_recovery_with_ops(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_async_request_pending_t *pending,
    vireo_async_pending_recovery_step_t from, vireo_async_pending_recovery_report_t *out,
    vireo_async_pending_recovery_ops_t const *ops, void *context) {
    int const saved = errno; vireo_async_pending_recovery_report_t value = {0};
    if (server == NULL || pending == NULL || out == NULL || ops == NULL || ops->consume == NULL ||
        ops->refresh == NULL || ops->schedule == NULL ||
        (from != VIREO_ASYNC_PENDING_STEP_CONSUME && from != VIREO_ASYNC_PENDING_STEP_REFRESH && from != VIREO_ASYNC_PENDING_STEP_SCHEDULE))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
    value.stage = VIREO_ASYNC_PENDING_RECOVERY_CHECK_PENDING;
    if (client.pool_id == 0 && client.slot_index == 0 && client.generation == 0)
        return finish(VIREO_RESULT_NOT_FOUND, value, out, saved);
    if (client.pool_id == 0 || client.generation == 0) return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
    bool const empty = empty_pending(pending);
    if (!empty) {
        vireo_result_t const result = validate_pending(pending);
        if (result != VIREO_OK) return finish(result, value, out, saved);
        vireo_task_route_t const route = pending->metadata.route;
        if (route.client_owner_id != client.pool_id || route.client_slot_index != client.slot_index || route.client_generation != client.generation)
            return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
    }
    if (from == VIREO_ASYNC_PENDING_STEP_CONSUME && empty) return finish(VIREO_RESULT_NOT_FOUND, value, out, saved);
    if (from != VIREO_ASYNC_PENDING_STEP_CONSUME && !empty) return finish(VIREO_RESULT_BUSY, value, out, saved);
    value.client = client; value.next_step = from;
    if (value.next_step == VIREO_ASYNC_PENDING_STEP_CONSUME) {
        value.stage = VIREO_ASYNC_PENDING_RECOVERY_CONSUME; value.consume_called = true;
        value.consume_result = ops->consume(context, server, pending, &value.consume_report);
        if (value.consume_result != VIREO_OK) return finish(value.consume_result, value, out, saved);
        value.next_step = VIREO_ASYNC_PENDING_STEP_REFRESH;
    }
    if (value.next_step == VIREO_ASYNC_PENDING_STEP_REFRESH) {
        value.stage = VIREO_ASYNC_PENDING_RECOVERY_REFRESH; value.refresh_called = true;
        value.refresh_result = ops->refresh(context, server, client, &value.refresh_error);
        if (value.refresh_result != VIREO_OK) return finish(value.refresh_result, value, out, saved);
        value.next_step = VIREO_ASYNC_PENDING_STEP_SCHEDULE;
    }
    value.stage = VIREO_ASYNC_PENDING_RECOVERY_SCHEDULE; value.schedule_called = true;
    value.schedule_result = ops->schedule(context, server, client, &value.schedule_error);
    if (value.schedule_result != VIREO_OK) return finish(value.schedule_result, value, out, saved);
    value.next_step = VIREO_ASYNC_PENDING_STEP_DONE;
    return finish(VIREO_OK, value, out, saved);
}

vireo_result_t vireo_async_client_resume_pending(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_async_request_pending_t *pending,
    vireo_async_pending_recovery_step_t from, vireo_async_pending_recovery_report_t *report) {
    return vireo_async_pending_recovery_with_ops(server, client, pending, from, report, &default_ops, NULL);
}

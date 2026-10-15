/*
 * PROJECT : VIREO
 * FILE    : async_completion_recovery.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 不重入队，成功才推进显式恢复步骤
 */
#include "async_completion_recovery_internal.h"
#include <errno.h>

/** 一次公开inspect，不保存借用。 */
static vireo_result_t inspect(void *context, vireo_completion_t const *completion, vireo_completion_info_t *out) {
    (void)context;
    return vireo_completion_inspect(completion, out);
}
/** 一次原关注同步，不发送或恢复停止的loop。 */
static vireo_result_t refresh(void *context, vireo_tcp_server_t *server, vireo_connection_pool_lease_t client,
    vireo_tcp_server_client_error_t *error) {
    (void)context;
    return vireo_tcp_server_client_flow_refresh(server, client, error);
}
/** 原独立结果配对释放，写FIFO副本不受影响。 */
static vireo_result_t destroy(void *context, vireo_completion_t **owner) {
    (void)context;
    return vireo_completion_destroy(owner);
}
static vireo_async_completion_recovery_ops_t const default_ops = {inspect, refresh, destroy};

/** 比较全部9个逻辑数值，不用忽略字段的same_request或padding。 */
static bool same(vireo_completion_metadata_t a, vireo_completion_metadata_t b) {
    return a.request.route.client_owner_id == b.request.route.client_owner_id &&
        a.request.route.client_slot_index == b.request.route.client_slot_index &&
        a.request.route.client_generation == b.request.route.client_generation &&
        a.request.route.request_sequence == b.request.route.request_sequence &&
        a.request.request_instance_id == b.request.request_instance_id &&
        a.request.operation == b.request.operation && a.request.deadline_ns == b.request.deadline_ns &&
        a.result == b.result && a.suggested_status == b.suggested_status;
}
/** 完整发布局部进度，成功stage NONE，恢复入口errno。 */
static vireo_result_t finish(vireo_result_t result, vireo_async_completion_recovery_report_t value,
    vireo_async_completion_recovery_report_t *out, int saved) {
    if (result == VIREO_OK) value.stage = VIREO_ASYNC_COMPLETION_RECOVERY_NONE;
    if (out != NULL) *out = value;
    errno = saved;
    return result;
}

vireo_result_t vireo_async_completion_recovery_with_ops(vireo_tcp_server_t *server,
    vireo_completion_metadata_t expected, vireo_completion_t **owner,
    vireo_async_completion_recovery_step_t from, vireo_async_completion_recovery_report_t *out,
    vireo_async_completion_recovery_ops_t const *ops, void *context) {
    int const saved = errno;
    vireo_async_completion_recovery_report_t value = {0};
    if (server == NULL || owner == NULL || out == NULL || ops == NULL || ops->inspect == NULL ||
        ops->refresh == NULL || ops->destroy == NULL ||
        (from != VIREO_ASYNC_COMPLETION_STEP_REFRESH && from != VIREO_ASYNC_COMPLETION_STEP_DESTROY))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
    if (*owner == NULL) return finish(VIREO_RESULT_NOT_FOUND, value, out, saved);
    value.stage = VIREO_ASYNC_COMPLETION_RECOVERY_CHECK_METADATA;
    vireo_completion_metadata_t checked;
    vireo_result_t result = vireo_completion_metadata_make(expected.request, expected.result,
        expected.suggested_status, &checked);
    if (result != VIREO_OK) return finish(result, value, out, saved);
    value.stage = VIREO_ASYNC_COMPLETION_RECOVERY_INSPECT_COMPLETION;
    vireo_completion_info_t info;
    result = ops->inspect(context, *owner, &info);
    if (result != VIREO_OK) return finish(result, value, out, saved);
    value.completion_inspected = true;
    value.metadata = info.metadata;
    value.stage = VIREO_ASYNC_COMPLETION_RECOVERY_MATCH_COMPLETION;
    if (!same(expected, info.metadata)) return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
    value.next_step = from;
    if (from == VIREO_ASYNC_COMPLETION_STEP_REFRESH) {
        vireo_connection_pool_lease_t const client = {expected.request.route.client_owner_id,
            expected.request.route.client_slot_index, expected.request.route.client_generation};
        value.stage = VIREO_ASYNC_COMPLETION_RECOVERY_REFRESH;
        value.refresh_called = true;
        value.refresh_result = ops->refresh(context, server, client, &value.client_error);
        if (value.refresh_result != VIREO_OK) return finish(value.refresh_result, value, out, saved);
        value.next_step = VIREO_ASYNC_COMPLETION_STEP_DESTROY;
    }
    value.stage = VIREO_ASYNC_COMPLETION_RECOVERY_DESTROY;
    value.destroy_called = true;
    value.destroy_result = ops->destroy(context, owner);
    value.completion_consumed = *owner == NULL;
    if (value.destroy_result != VIREO_OK) return finish(value.destroy_result, value, out, saved);
    value.next_step = VIREO_ASYNC_COMPLETION_STEP_DONE;
    return finish(VIREO_OK, value, out, saved);
}

vireo_result_t vireo_async_completion_resume_enqueued(vireo_tcp_server_t *server,
    vireo_completion_metadata_t expected, vireo_completion_t **owner,
    vireo_async_completion_recovery_step_t from, vireo_async_completion_recovery_report_t *report) {
    return vireo_async_completion_recovery_with_ops(server, expected, owner, from, report, &default_ops, NULL);
}

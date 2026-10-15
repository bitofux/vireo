/*
 * PROJECT : VIREO
 * FILE    : async_task_recovery.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 退款与释放独立提交，先完整核对再破坏性操作
 */
#include "async_task_recovery_internal.h"
#include <errno.h>

/** 只读公开task，不保存借用。 */
static vireo_result_t inspect(void *context, vireo_task_t const *task, vireo_task_info_t *out) {
    (void)context;
    return vireo_task_inspect(task, out);
}
/** 只读原快照，原键不含operation/deadline。 */
static vireo_result_t get(void *context, vireo_inflight_store_t const *store,
    vireo_task_metadata_t key, vireo_task_metadata_t *out, vireo_inflight_stage_t *stage) {
    (void)context;
    return vireo_inflight_store_get(store, key, out, stage);
}
/** 一次原take，成功退表引用/登记名额，不自动取消。 */
static vireo_result_t take(void *context, vireo_inflight_store_t *store,
    vireo_task_metadata_t key, vireo_task_metadata_t *out, vireo_inflight_stage_t *stage) {
    (void)context;
    return vireo_inflight_store_take(store, key, out, stage);
}
/** 原配对释放，不重提或回滚登记。 */
static vireo_result_t destroy(void *context, vireo_task_t **owner) {
    (void)context;
    return vireo_task_destroy(owner);
}
static vireo_async_task_recovery_ops_t const default_ops = {inspect, get, take, destroy};

/** 完整逻辑字段比较，无padding/哨兵，不把same_request误当全快照相等。 */
static bool same(vireo_task_metadata_t a, vireo_task_metadata_t b) {
    return a.route.client_owner_id == b.route.client_owner_id &&
        a.route.client_slot_index == b.route.client_slot_index &&
        a.route.client_generation == b.route.client_generation &&
        a.route.request_sequence == b.route.request_sequence &&
        a.request_instance_id == b.request_instance_id &&
        a.operation == b.operation && a.deadline_ns == b.deadline_ns;
}
/** 每可写路径发布完整事实及原返回，恢复入口errno。 */
static vireo_result_t finish(vireo_result_t result, vireo_async_task_recovery_report_t value,
    vireo_async_task_recovery_report_t *out, int saved) {
    if (result == VIREO_OK) value.stage = VIREO_ASYNC_TASK_RECOVERY_NONE;
    if (out != NULL) *out = value;
    errno = saved;
    return result;
}

vireo_result_t vireo_async_task_recovery_with_ops(vireo_inflight_store_t *store,
    vireo_task_metadata_t expected, vireo_task_t **owner,
    vireo_async_task_recovery_step_t from, vireo_async_task_recovery_report_t *out,
    vireo_async_task_recovery_ops_t const *ops, void *context) {
    int const saved = errno;
    vireo_async_task_recovery_report_t value = {0};
    if (store == NULL || owner == NULL || out == NULL || ops == NULL ||
        ops->inspect == NULL || ops->get == NULL || ops->take == NULL || ops->destroy == NULL ||
        (from != VIREO_ASYNC_TASK_STEP_TAKE_RECORD && from != VIREO_ASYNC_TASK_STEP_DESTROY_TASK))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
    if (*owner == NULL) return finish(VIREO_RESULT_NOT_FOUND, value, out, saved);

    value.stage = VIREO_ASYNC_TASK_RECOVERY_CHECK_METADATA;
    vireo_task_metadata_t checked;
    vireo_result_t result = vireo_task_metadata_make(expected.route, expected.request_instance_id,
        expected.operation, expected.deadline_ns, &checked);
    if (result != VIREO_OK) return finish(result, value, out, saved);
    value.stage = VIREO_ASYNC_TASK_RECOVERY_INSPECT_TASK;
    vireo_task_info_t info;
    result = ops->inspect(context, *owner, &info);
    if (result != VIREO_OK) return finish(result, value, out, saved);
    value.task_inspected = true;
    value.metadata = info.metadata;
    value.stage = VIREO_ASYNC_TASK_RECOVERY_MATCH_TASK;
    if (!same(info.metadata, expected)) return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);

    value.next_step = from;
    if (from == VIREO_ASYNC_TASK_STEP_TAKE_RECORD) {
        value.stage = VIREO_ASYNC_TASK_RECOVERY_CHECK_RECORD;
        vireo_task_metadata_t record;
        result = ops->get(context, store, expected, &record, &value.inflight_stage);
        if (result != VIREO_OK) return finish(result, value, out, saved);
        value.stage = VIREO_ASYNC_TASK_RECOVERY_MATCH_RECORD;
        if (!same(record, expected)) return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
        value.record_checked = true;
        value.stage = VIREO_ASYNC_TASK_RECOVERY_TAKE_RECORD;
        value.take_called = true;
        value.take_result = ops->take(context, store, expected, &record, &value.inflight_stage);
        if (value.take_result != VIREO_OK) return finish(value.take_result, value, out, saved);
        value.record_consumed = true;
        value.next_step = VIREO_ASYNC_TASK_STEP_DESTROY_TASK;
    }
    value.stage = VIREO_ASYNC_TASK_RECOVERY_DESTROY_TASK;
    value.destroy_called = true;
    value.destroy_result = ops->destroy(context, owner);
    value.task_consumed = *owner == NULL;
    if (value.destroy_result != VIREO_OK) return finish(value.destroy_result, value, out, saved);
    value.next_step = VIREO_ASYNC_TASK_STEP_DONE;
    return finish(VIREO_OK, value, out, saved);
}

vireo_result_t vireo_async_request_discard_remaining(vireo_inflight_store_t *store,
    vireo_task_metadata_t expected, vireo_task_t **owner,
    vireo_async_task_recovery_step_t from, vireo_async_task_recovery_report_t *report) {
    return vireo_async_task_recovery_with_ops(store, expected, owner, from, report, &default_ops, NULL);
}

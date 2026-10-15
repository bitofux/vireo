/*
 * PROJECT : VIREO
 * FILE    : inflight_submit.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 登记先于发布，按真实转移处理提交错误
 */
#include "inflight_submit_internal.h"

#include <errno.h>

/**
 * @brief
 *     原样调用一次公开 pool 提交，不另观测或保存 task。
 *
 * @param[in] context
 *     标准适配不使用。
 * @param[in,out] pool
 *     存活池，caller 串行管理。
 * @param[in,out] task_owner
 *     原唯一 owner，真实转移清源。
 * @param[out] report
 *     原依赖独立报告。
 *
 * @return
 *     公开依赖结果。
 */
static vireo_result_t standard_submit(void *context, vireo_thread_pool_t *pool,
    vireo_task_t **task_owner, vireo_thread_pool_submit_report_t *report) {
    (void)context;
    return vireo_thread_pool_try_submit(pool, task_owner, report);
}

/**
 * @brief
 *     一次公开取出，只撤销本次保存的完整请求身份。
 *
 * @param[in] context
 *     标准适配不使用。
 * @param[in,out] store
 *     Reactor 独占表。
 * @param[in] key
 *     提交前保存的完整 metadata。
 * @param[out] out
 *     必需局部取出快照。
 * @param[out] stage
 *     原依赖诊断。
 *
 * @return
 *     公开依赖结果。
 */
static vireo_result_t standard_take(void *context, vireo_inflight_store_t *store,
    vireo_task_metadata_t key, vireo_task_metadata_t *out, vireo_inflight_stage_t *stage) {
    (void)context;
    return vireo_inflight_store_take(store, key, out, stage);
}

vireo_result_t vireo_inflight_store_try_submit_with_operations(vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_thread_pool_t *pool,
    size_t max_client_requests, vireo_task_t **task_owner,
    vireo_inflight_submit_operations_t const *operations,
    vireo_inflight_submit_report_t *report) {
    int const saved_errno = errno;
    vireo_inflight_submit_report_t value = {0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (store == NULL || server == NULL || pool == NULL || task_owner == NULL ||
        report == NULL || max_client_requests == 0 || operations == NULL ||
        operations->submit == NULL || operations->take == NULL) goto done;
    if (*task_owner == NULL) { result = VIREO_RESULT_NOT_FOUND; goto done; }

    vireo_task_info_t info;
    value.stage = VIREO_INFLIGHT_SUBMIT_INSPECT_TASK;
    result = vireo_task_inspect(*task_owner, &info);
    if (result != VIREO_OK) goto done;
    value.metadata = info.metadata;
    value.task_inspected = true;
    value.stage = VIREO_INFLIGHT_SUBMIT_REGISTER_REQUEST;
    result = vireo_inflight_store_register_task_limited(store, server, *task_owner,
        max_client_requests, &value.inflight_stage);
    if (result != VIREO_OK) goto done;
    value.registration_committed = true;
    value.record_retained = true;
    value.submit_called = true;
    value.stage = VIREO_INFLIGHT_SUBMIT_SUBMIT_TASK;
    result = operations->submit(operations->context, pool, task_owner, &value.pool_report);
    if (result == VIREO_OK) { value.stage = VIREO_INFLIGHT_SUBMIT_NONE; goto done; }

    /* 原报告为转移证据；交接后绝不访问旧 task 地址或撤销登记。 */
    if (!value.pool_report.queue_report.transferred) {
        vireo_task_metadata_t removed;
        value.rollback_called = true;
        value.rollback_result = operations->take(operations->context, store,
            value.metadata, &removed, &value.inflight_stage);
        if (value.rollback_result == VIREO_OK) value.record_retained = false;
    }
done:
    if (report != NULL) *report = value;
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_inflight_store_try_submit(vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_thread_pool_t *pool,
    size_t max_client_requests, vireo_task_t **task_owner,
    vireo_inflight_submit_report_t *report) {
    vireo_inflight_submit_operations_t const operations = {NULL, standard_submit, standard_take};
    return vireo_inflight_store_try_submit_with_operations(store, server, pool,
        max_client_requests, task_owner, &operations, report);
}

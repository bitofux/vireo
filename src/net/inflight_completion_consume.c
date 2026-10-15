/*
 * PROJECT : VIREO
 * FILE    : inflight_completion_consume.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 单项完成结果交付、登记结束及正常迟到的配对清理
 */
#include <vireo/net/inflight_completion.h>

#include <errno.h>

/**
 * @brief
 *     发布本次真实进度并恢复入口 errno，不执行资源回滚。
 *
 * @param[in] result
 *     原返回类别。
 * @param[in] stage
 *     此路径主错误位置，成功及基本拒绝为 NONE。
 * @param[in] value
 *     完整局部进度，未调用字段保持逻辑零。
 * @param[out] report
 *     可写时必需独立输出；基本错误允许 NULL。
 * @param[in] saved_errno
 *     入口保存值。
 *
 * @return
 *     原 result。
 */
static vireo_result_t finish(vireo_result_t result, vireo_inflight_consume_stage_t stage,
    vireo_inflight_completion_consume_report_t value,
    vireo_inflight_completion_consume_report_t *report, int saved_errno) {
    value.stage = stage;
    if (report != NULL) *report = value;
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_inflight_store_consume_completion(vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_completion_t **owner,
    vireo_inflight_completion_deliver_fn deliver, void *context,
    vireo_inflight_completion_consume_report_t *report) {
    int const saved_errno = errno;
    vireo_inflight_completion_consume_report_t value = {0};
    if (store == NULL || server == NULL || owner == NULL || deliver == NULL || report == NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_CONSUME_NONE,
            value, report, saved_errno);
    if (*owner == NULL)
        return finish(VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CONSUME_NONE,
            value, report, saved_errno);

    vireo_completion_info_t info;
    vireo_result_t result = vireo_completion_inspect(*owner, &info);
    if (result != VIREO_OK)
        return finish(result, VIREO_INFLIGHT_CONSUME_INSPECT, value, report, saved_errno);
    value.completion_inspected = true;
    value.completion_metadata = info.metadata;

    bool have_record = false;
    vireo_task_metadata_t record;
    result = vireo_inflight_store_check_completion(store, server, *owner,
        &value.match, &value.inflight_stage);
    if (result == VIREO_OK) {
        value.disposition = VIREO_INFLIGHT_COMPLETION_MATCHED;
        record = value.match.metadata;
        have_record = true;
    } else if (result == VIREO_RESULT_NOT_FOUND &&
        (value.inflight_stage == VIREO_INFLIGHT_CHECK_CLIENT ||
         value.inflight_stage == VIREO_INFLIGHT_CHECK_RECORD)) {
        if (value.inflight_stage == VIREO_INFLIGHT_CHECK_CLIENT) {
            value.disposition = VIREO_INFLIGHT_COMPLETION_CLIENT_GONE;
            vireo_inflight_stage_t detail = VIREO_INFLIGHT_NONE;
            result = vireo_inflight_store_get(store, info.metadata.request, &record, &detail);
            if (result == VIREO_OK) {
                if (record.operation != info.metadata.request.operation ||
                    record.deadline_ns != info.metadata.request.deadline_ns) {
                    value.inflight_stage = VIREO_INFLIGHT_MATCH_RECORD;
                    return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_CONSUME_CHECK_RECORD,
                        value, report, saved_errno);
                }
                have_record = true;
            } else if (result != VIREO_RESULT_NOT_FOUND) {
                value.inflight_stage = detail;
                return finish(result, VIREO_INFLIGHT_CONSUME_CHECK_RECORD, value, report, saved_errno);
            }
        } else {
            value.disposition = VIREO_INFLIGHT_COMPLETION_REQUEST_GONE;
        }
    } else {
        return finish(result, VIREO_INFLIGHT_CONSUME_CHECK_MATCH, value, report, saved_errno);
    }

    if (have_record) {
        vireo_task_metadata_t ended;
        vireo_inflight_stage_t detail = VIREO_INFLIGHT_NONE;
        result = vireo_inflight_store_take(store, record, &ended, &detail);
        if (result != VIREO_OK) {
            value.inflight_stage = detail;
            return finish(result, VIREO_INFLIGHT_CONSUME_TAKE_RECORD, value, report, saved_errno);
        }
        value.record_consumed = true;
    }

    if (value.disposition == VIREO_INFLIGHT_COMPLETION_MATCHED) {
        value.delivery_called = true;
        value.delivery_result = deliver(context, *owner, value.match);
        if (value.delivery_result != VIREO_OK)
            return finish(value.delivery_result, VIREO_INFLIGHT_CONSUME_DELIVER,
                value, report, saved_errno);
    }

    value.destroy_called = true;
    value.destroy_result = vireo_completion_destroy(owner);
    value.completion_consumed = *owner == NULL;
    if (value.destroy_result != VIREO_OK)
        return finish(value.destroy_result, VIREO_INFLIGHT_CONSUME_DESTROY,
            value, report, saved_errno);
    return finish(VIREO_OK, VIREO_INFLIGHT_CONSUME_NONE, value, report, saved_errno);
}

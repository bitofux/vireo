/*
 * PROJECT : VIREO
 * FILE    : async_client_termination_policy.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 有限枚举校验及主错误来源匹配，无资源副作用
 */
#include <vireo/net/async_client_termination_policy.h>
#include <errno.h>

/** 显式列公开注册值，不依赖enum连续或静态名称的未知降级。 */
static bool valid_result(vireo_result_t result) {
    switch (result) {
    case VIREO_OK:
    case VIREO_RESULT_INVALID_ARGUMENT:
    case VIREO_RESULT_RANGE:
    case VIREO_RESULT_OVERFLOW:
    case VIREO_RESULT_NO_MEMORY:
    case VIREO_RESULT_NOT_FOUND:
    case VIREO_RESULT_BUSY:
    case VIREO_RESULT_TIMEOUT:
    case VIREO_RESULT_CANCELLED:
    case VIREO_RESULT_IO:
    case VIREO_RESULT_PROTOCOL:
    case VIREO_RESULT_DATABASE:
    case VIREO_RESULT_INTERNAL:
        return true;
    default:
        return false;
    }
}
/** 只校验本分类器消费的原driver阶段，不扩成19字段认证器。 */
static bool valid_stage(vireo_async_client_drive_stage_t stage) {
    switch (stage) {
    case VIREO_ASYNC_CLIENT_DRIVE_NONE:
    case VIREO_ASYNC_CLIENT_DRIVE_CHECK_PENDING:
    case VIREO_ASYNC_CLIENT_DRIVE_CHECK_SERVER:
    case VIREO_ASYNC_CLIENT_DRIVE_CHECK_CLIENT:
    case VIREO_ASYNC_CLIENT_DRIVE_PRE_REFRESH:
    case VIREO_ASYNC_CLIENT_DRIVE_RECEIVE:
    case VIREO_ASYNC_CLIENT_DRIVE_PEEK_FRAME:
    case VIREO_ASYNC_CLIENT_DRIVE_SUBMIT:
    case VIREO_ASYNC_CLIENT_DRIVE_SEND:
    case VIREO_ASYNC_CLIENT_DRIVE_FINAL_REFRESH:
    case VIREO_ASYNC_CLIENT_DRIVE_FINAL_INSPECT:
        return true;
    default:
        return false;
    }
}

vireo_result_t vireo_async_client_termination_classify(vireo_result_t drive_result,
    vireo_async_client_drive_report_t const *drive_report, vireo_async_client_termination_plan_t *out_plan) {
    if (out_plan == NULL || drive_report == NULL || !valid_result(drive_result) || !valid_stage(drive_report->stage))
        return VIREO_RESULT_INVALID_ARGUMENT;
    vireo_async_client_termination_plan_t plan = {false, VIREO_CONNECTION_CLOSE_REASON_NONE};
    vireo_tcp_server_client_cause_t const *cause = &drive_report->client_error.primary;
    if (drive_result == VIREO_RESULT_PROTOCOL && drive_report->stage == VIREO_ASYNC_CLIENT_DRIVE_PEEK_FRAME &&
        drive_report->frame_peek_called && cause->stage == VIREO_TCP_SERVER_CLIENT_FRAMES_PEEK) {
        plan.terminate_recommended = true;
        plan.reason = VIREO_CONNECTION_CLOSE_REASON_PROTOCOL;
    } else if (drive_result == VIREO_RESULT_IO && cause->connection_error.system_errno > 0 &&
        cause->connection_error.system_errno != EINTR) {
        bool const receive = drive_report->stage == VIREO_ASYNC_CLIENT_DRIVE_RECEIVE &&
            drive_report->receive_called && cause->stage == VIREO_TCP_SERVER_CLIENT_RECEIVE &&
            cause->connection_error.stage == VIREO_CONNECTION_STAGE_RECEIVE;
        bool const send = drive_report->stage == VIREO_ASYNC_CLIENT_DRIVE_SEND &&
            drive_report->send_called && cause->stage == VIREO_TCP_SERVER_CLIENT_SEND &&
            cause->connection_error.stage == VIREO_CONNECTION_STAGE_SEND;
        if (receive || send) {
            plan.terminate_recommended = true;
            plan.reason = VIREO_CONNECTION_CLOSE_REASON_IO;
        }
    }
    *out_plan = plan;
    return VIREO_OK;
}

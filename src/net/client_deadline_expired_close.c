/*
 * PROJECT : VIREO
 * FILE    : client_deadline_expired_close.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 历史到期匹配后显式单次关闭并保留部分失败诊断
 * -- 只依赖已采用公开合同，保持资源、输出与 errno 的既有边界
 */
#include "client_deadline_expired_close_internal.h"

#include <errno.h>

/**
 * @brief
 *     仅接受公开合同已有的六个非 NONE 关闭理由。
 *
 * @param[in] reason
 *     按值候选理由，不扩大已封板枚举。
 *
 * @return
 *     属于既有六理由返回 true；NONE 或未知值返回 false。
 *
 * @note
 *     不访问资源或修改 errno。
 */
static bool reason_valid(vireo_connection_close_reason_t reason) {
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

/**
 * @brief
 *     统一发布本次独立诊断并恢复入口 errno。
 *
 * @param[in] result
 *     本次原结果分类，按值返回，不重试或补偿。
 * @param[in] detail
 *     本次完整关闭诊断值，不代表事务回滚。
 * @param[out] out_error
 *     可空独立诊断；非空时覆盖全部逻辑字段。
 * @param[in] saved_errno
 *     入口 errno 的保存值，恢复调用线程该值。
 *
 * @return
 *     原样返回 result；不追加可失败操作。
 *
 * @note
 *     不修改主输出、资源或业务进度，不进行后置观测。
 */
static vireo_result_t finish(vireo_result_t result, vireo_client_deadline_close_error_t detail,
                             vireo_client_deadline_close_error_t *out_error, int saved_errno) {
    if (out_error != NULL) {
        *out_error = detail;
    }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_client_deadline_request_close_expired_runtime(
    vireo_tcp_server_t *server, vireo_client_deadline_binding_t binding,
    vireo_timer_wheel_expired_t const *expired, vireo_connection_close_mode_t mode,
    vireo_connection_close_reason_t reason, vireo_client_deadline_close_error_t *out_error,
    vireo_client_deadline_close_fn close_client, void *context) {
    int const saved_errno = errno;
    vireo_client_deadline_close_error_t detail = {0};
    if (server == NULL || expired == NULL || close_client == NULL ||
        (mode != VIREO_CONNECTION_CLOSE_MODE_DRAIN &&
         mode != VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE) ||
        !reason_valid(reason)) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, detail, out_error, saved_errno);
    }
    vireo_tcp_server_client_info_t client_info;
    vireo_result_t result =
        vireo_client_deadline_check_expired(server, binding, expired, &client_info, &detail.stage);
    if (result != VIREO_OK) {
        return finish(result, detail, out_error, saved_errno);
    }
    detail.close_called = true;
    detail.stage = VIREO_CLIENT_DEADLINE_REQUEST_CLOSE_CLIENT;
    result = close_client(server, binding.client, mode, reason, &detail.client_error, context);
    if (result == VIREO_OK) {
        detail.stage = VIREO_CLIENT_DEADLINE_NONE;
    }
    return finish(result, detail, out_error, saved_errno);
}

/**
 * @brief
 *     将单次关闭依赖透传到公开 server 入口。
 *
 * @param[in,out] server
 *     已核验的存活 server，同 Reactor 短借。
 * @param[in] client
 *     当前完整租约值，原在途约束仍适用。
 * @param[in] mode
 *     已检查的 DRAIN 或 IMMEDIATE。
 * @param[in] reason
 *     已检查的既有非 NONE 理由。
 * @param[out] error
 *     本层提供的非空独立原 server 诊断。
 * @param[in,out] context
 *     生产传 NULL，此适配忽略且不保存。
 *
 * @return
 *     公开关闭的原分类及诊断，不回滚可能已提交的意图。
 *
 * @note
 *     不借用其他模块内部指针；errno 沿公开合同并由外层恢复。
 */
static vireo_result_t close_native(vireo_tcp_server_t *server, vireo_connection_pool_lease_t client,
                                   vireo_connection_close_mode_t mode,
                                   vireo_connection_close_reason_t reason,
                                   vireo_tcp_server_client_error_t *error, void *context) {
    (void)context;
    return vireo_tcp_server_client_request_close(server, client, mode, reason, error);
}

vireo_result_t vireo_client_deadline_request_close_expired(
    vireo_tcp_server_t *server, vireo_client_deadline_binding_t binding,
    vireo_timer_wheel_expired_t const *expired, vireo_connection_close_mode_t mode,
    vireo_connection_close_reason_t reason, vireo_client_deadline_close_error_t *out_error) {
    return vireo_client_deadline_request_close_expired_runtime(
        server, binding, expired, mode, reason, out_error, close_native, NULL);
}

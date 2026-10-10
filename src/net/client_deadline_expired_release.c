/*
 * PROJECT : VIREO
 * FILE    : client_deadline_expired_release.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 当前 READY 客户单次归还及按消费事实清绑定
 * -- 只依赖已采用公开合同，保持资源、输出与 errno 的既有边界
 */
#include "client_deadline_expired_release_internal.h"

#include <errno.h>

/**
 * @brief
 *     统一发布本次独立诊断并恢复入口 errno。
 *
 * @param[in] result
 *     本次原结果分类，按值返回，不重试或补偿。
 * @param[in] report
 *     本次完整归还报告值，包含实际客户消费事实。
 * @param[out] out_report
 *     外层基本拒绝时可空，其余路径必需；非空时完整发布。
 * @param[in] saved_errno
 *     入口 errno 的保存值，恢复调用线程该值。
 *
 * @return
 *     原样返回 result；不追加可失败操作。
 *
 * @note
 *     不修改主输出、资源或业务进度，不进行后置观测。
 */
static vireo_result_t finish(vireo_result_t result, vireo_client_deadline_release_report_t report,
                             vireo_client_deadline_release_report_t *out_report, int saved_errno) {
    if (out_report != NULL) {
        *out_report = report;
    }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_client_deadline_release_ready_expired_runtime(
    vireo_tcp_server_t *server, vireo_client_deadline_binding_t *binding,
    vireo_timer_wheel_expired_t const *expired, vireo_client_deadline_release_report_t *out_report,
    vireo_client_deadline_release_fn release_client, void *context) {
    int const saved_errno = errno;
    vireo_client_deadline_release_report_t report = {0};
    if (server == NULL || binding == NULL || expired == NULL || out_report == NULL ||
        release_client == NULL) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, report, out_report, saved_errno);
    }
    vireo_tcp_server_client_info_t client_info;
    vireo_result_t result =
        vireo_client_deadline_check_expired(server, *binding, expired, &client_info, &report.stage);
    if (result != VIREO_OK) {
        return finish(result, report, out_report, saved_errno);
    }
    if (client_info.connection_info.close_state != VIREO_CONNECTION_CLOSE_READY) {
        report.stage = VIREO_CLIENT_DEADLINE_CHECK_READY_CLIENT;
        return finish(VIREO_RESULT_BUSY, report, out_report, saved_errno);
    }
    vireo_connection_pool_lease_t local = binding->client;
    report.release_called = true;
    report.stage = VIREO_CLIENT_DEADLINE_RELEASE_CLIENT;
    result = release_client(server, &local, &report.client_error, context);
    report.client_consumed = local.pool_id == 0 && local.slot_index == 0 && local.generation == 0;
    if (report.client_consumed) {
        *binding = (vireo_client_deadline_binding_t){0};
    }
    if (result == VIREO_OK) {
        report.stage = VIREO_CLIENT_DEADLINE_NONE;
    }
    return finish(result, report, out_report, saved_errno);
}

/**
 * @brief
 *     将单次客户归还依赖透传到公开 server 入口。
 *
 * @param[in,out] server
 *     已核验的存活 server，同 Reactor 短借。
 * @param[in,out] client
 *     本层非空局部租约，沿公开合同以清零表示消费。
 * @param[out] error
 *     本层提供的非空独立原 server 诊断。
 * @param[in,out] context
 *     生产传 NULL，此适配忽略且不保存。
 *
 * @return
 *     公开归还的原分类；消费 IO 仍是 IO，不当作无副作用。
 *
 * @note
 *     不自动重试或查询资源，errno 沿原合同并由外层恢复。
 */
static vireo_result_t release_native(vireo_tcp_server_t *server,
                                     vireo_connection_pool_lease_t *client,
                                     vireo_tcp_server_client_error_t *error, void *context) {
    (void)context;
    return vireo_tcp_server_release_client(server, client, error);
}

vireo_result_t vireo_client_deadline_release_ready_expired(
    vireo_tcp_server_t *server, vireo_client_deadline_binding_t *binding,
    vireo_timer_wheel_expired_t const *expired,
    vireo_client_deadline_release_report_t *out_report) {
    return vireo_client_deadline_release_ready_expired_runtime(server, binding, expired, out_report,
                                                               release_native, NULL);
}

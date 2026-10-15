/*
 * PROJECT : VIREO
 * FILE    : async_ready_recovery.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 显式后缀有限重排，成功才推进恢复下标
 */
#include "async_ready_recovery_internal.h"
#include <errno.h>

/** 唯一生产边界，只调用公开schedule，不读写原FIFO布局。 */
static vireo_result_t schedule(void *context, vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_client_error_t *error) {
    (void)context; return vireo_tcp_server_schedule_client(server, client, error);
}
static vireo_async_ready_recovery_ops_t const default_ops = {schedule};

/** 发布完整数值进度并恢复入口errno，不清理资源或改输入。 */
static vireo_result_t finish(vireo_result_t result, vireo_async_ready_recovery_report_t value,
    vireo_async_ready_recovery_report_t *out, int saved) {
    if (out != NULL) *out = value;
    errno = saved; return result;
}

vireo_result_t vireo_async_ready_recovery_with_ops(vireo_tcp_server_t *server,
    vireo_tcp_server_ready_client_t const *ready, size_t count, size_t begin, size_t max,
    vireo_async_ready_recovery_report_t *out, vireo_async_ready_recovery_ops_t const *ops, void *context) {
    int const saved = errno;
    vireo_async_ready_recovery_report_t value = {0};
    if (server == NULL || out == NULL || (count != 0 && ready == NULL) || max == 0 ||
        ops == NULL || ops->schedule == NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
    if (count > VIREO_TCP_SERVER_MAX_CONNECTIONS || max > VIREO_TCP_SERVER_MAX_CONNECTIONS || begin > count)
        return finish(VIREO_RESULT_RANGE, value, out, saved);
    value.next_index = begin;
    while (value.next_index < count && value.attempted_count < max) {
        value.last_client = ready[value.next_index].client;
        value.client_error = (vireo_tcp_server_client_error_t){0};
        ++value.attempted_count;
        vireo_result_t const result = ops->schedule(context, server, value.last_client, &value.client_error);
        if (result != VIREO_OK) {
            value.stage = VIREO_ASYNC_READY_RECOVERY_SCHEDULE;
            value.stop_reason = VIREO_ASYNC_READY_RECOVERY_ERROR;
            return finish(result, value, out, saved);
        }
        ++value.scheduled_count; ++value.next_index;
    }
    value.stop_reason = value.next_index == count ? VIREO_ASYNC_READY_RECOVERY_COMPLETE : VIREO_ASYNC_READY_RECOVERY_BUDGET;
    return finish(VIREO_OK, value, out, saved);
}

vireo_result_t vireo_async_service_reschedule_ready(vireo_tcp_server_t *server,
    vireo_tcp_server_ready_client_t const *ready, size_t count, size_t begin, size_t max,
    vireo_async_ready_recovery_report_t *report) {
    return vireo_async_ready_recovery_with_ops(server, ready, count, begin, max, report, &default_ops, NULL);
}

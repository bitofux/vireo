/*
 * PROJECT : VIREO
 * FILE    : async_admission_pressure.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 受检容量与公开监听更新，期望值不冒实际提交
 */
#include "async_admission_pressure_internal.h"
#include <vireo/base/checked.h>
#include <errno.h>

/** 只读公开网络根，不保存资源指针。 */
static vireo_result_t inspect(void *context, vireo_tcp_server_t const *server, vireo_tcp_server_info_t *info) {
    (void)context; return vireo_tcp_server_inspect(server, info);
}
/** 仅公开一次READ更新，完整原诊断透传。 */
static vireo_result_t set_read(void *context, vireo_tcp_server_t *server, bool enabled,
    vireo_tcp_server_listener_error_t *error) {
    (void)context; return vireo_tcp_server_set_listener_read_enabled(server, enabled, error);
}
static vireo_async_admission_pressure_ops_t const default_ops = {inspect, set_read};

/** 完整发布逻辑report，不用errno传诊断。 */
static vireo_result_t finish(vireo_result_t result, vireo_async_admission_pressure_report_t value,
    vireo_async_admission_pressure_report_t *out, int saved) {
    if (result == VIREO_OK) value.stage = VIREO_ASYNC_ADMISSION_PRESSURE_NONE;
    if (out != NULL) *out = value;
    errno = saved; return result;
}

vireo_result_t vireo_async_admission_pressure_with_ops(vireo_tcp_server_t *server,
    vireo_connection_options_t const *options, vireo_async_admission_pressure_report_t *out,
    vireo_async_admission_pressure_ops_t const *ops, void *context) {
    int const saved = errno;
    vireo_async_admission_pressure_report_t value = {0};
    if (server == NULL || options == NULL || out == NULL || ops == NULL || ops->inspect == NULL || ops->set_read == NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, value, out, saved);
    vireo_connection_options_t const c = *options;
    value.stage = VIREO_ASYNC_ADMISSION_PRESSURE_VALIDATE_OPTIONS;
    size_t pair = 0;
    vireo_result_t result = vireo_checked_size_add(c.read_capacity, c.write_capacity, &pair);
    if (result != VIREO_OK) return finish(result, value, out, saved);
    if (c.read_capacity == 0 || c.write_capacity == 0 || c.max_buffer_bytes == 0 ||
        c.read_capacity > VIREO_BUFFER_MAX_CAPACITY || c.write_capacity > VIREO_BUFFER_MAX_CAPACITY ||
        c.max_buffer_bytes > VIREO_CONNECTION_MAX_BUFFER_BYTES || pair > c.max_buffer_bytes)
        return finish(VIREO_RESULT_RANGE, value, out, saved);
    value.pair_bytes = pair;
    value.stage = VIREO_ASYNC_ADMISSION_PRESSURE_CHECK_SERVER;
    vireo_tcp_server_info_t root = {0};
    result = ops->inspect(context, server, &root);
    if (result != VIREO_OK) return finish(result, value, out, saved);
    value.server_inspected = true;
    value.read_before = root.listener_read_enabled; value.read_after = value.read_before;
    if (root.processing_active || root.driving_active || root.scheduling_active || root.serving_active ||
        root.shutdown_active || root.closing_active || root.running_active)
        return finish(VIREO_RESULT_BUSY, value, out, saved);
    if (root.stop_requested) return finish(VIREO_RESULT_CANCELLED, value, out, saved);
    if (root.admission_enabled) return finish(VIREO_RESULT_BUSY, value, out, saved);
    if (!root.listener_owned || !root.listener_bound) return finish(VIREO_RESULT_NOT_FOUND, value, out, saved);
    value.stage = VIREO_ASYNC_ADMISSION_PRESSURE_CHECK_CAPACITY;
    if (root.connection_count > root.connection_capacity ||
        root.available_connections != root.connection_capacity - root.connection_count ||
        root.buffer_capacity_bytes > root.max_buffer_bytes)
        return finish(VIREO_RESULT_INTERNAL, value, out, saved);
    if (pair > root.max_buffer_bytes) return finish(VIREO_RESULT_RANGE, value, out, saved);
    value.available_connections = root.available_connections;
    value.available_buffer_bytes = root.max_buffer_bytes - root.buffer_capacity_bytes;
    value.connection_limited = value.available_connections == 0;
    value.buffer_limited = value.available_buffer_bytes < pair;
    value.read_desired = !value.connection_limited && !value.buffer_limited;
    value.pressure_calculated = true;
    if (value.read_desired != value.read_before) {
        value.stage = VIREO_ASYNC_ADMISSION_PRESSURE_UPDATE_READ; value.update_called = true;
        result = ops->set_read(context, server, value.read_desired, &value.listener_error);
        if (result != VIREO_OK) return finish(result, value, out, saved);
        value.read_after = value.read_desired;
    }
    return finish(VIREO_OK, value, out, saved);
}

vireo_result_t vireo_async_admission_pressure_refresh(vireo_tcp_server_t *server,
    vireo_connection_options_t const *connection_options, vireo_async_admission_pressure_report_t *report) {
    return vireo_async_admission_pressure_with_ops(server, connection_options, report, &default_ops, NULL);
}

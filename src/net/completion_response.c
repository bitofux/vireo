/*
 * PROJECT : VIREO
 * FILE    : completion_response.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 单帧协议编码和公开发送 FIFO/关注刷新接线
 */
#include "completion_response_internal.h"
#include <vireo/base/checked.h>
#include <errno.h>
#include <string.h>

/** 一次公开完整入队，不保存 context。 */
static vireo_result_t enqueue_public(void *context, vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, uint8_t const *bytes, size_t size,
    vireo_tcp_server_client_error_t *error) {
    (void)context;
    return vireo_tcp_server_client_write_enqueue(server, client, bytes, size, error);
}

/** 一次公开关注刷新，旧字节进度不变。 */
static vireo_result_t refresh_public(void *context, vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_client_error_t *error) {
    (void)context;
    return vireo_tcp_server_client_flow_refresh(server, client, error);
}

/** 不可变默认表，无本层共享可变状态。 */
static vireo_completion_response_ops_t const default_ops = {enqueue_public, refresh_public};

/**
 * @brief
 *     发布真实局部前缀、恢复入口 errno，不回滚 scratch 或已入队字节。
 *
 * @param[in] result
 *     原主返回。
 * @param[in] stage
 *     对应主错误位置。
 * @param[in] value
 *     本次局部真实报告。
 * @param[out] report
 *     可写地址，NULL 拒绝路径无法发布。
 * @param[in] saved_errno
 *     入口 int 值。
 *
 * @return
 *     result 原值。
 */
static vireo_result_t finish(vireo_result_t result, vireo_completion_response_stage_t stage,
    vireo_completion_response_report_t value, vireo_completion_response_report_t *report,
    int saved_errno) {
    value.stage = stage;
    if (report != NULL) *report = value;
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_completion_response_with_ops(vireo_tcp_server_t *server,
    vireo_completion_t const *completion, vireo_inflight_completion_match_t match,
    vireo_completion_response_descriptor_t descriptor, size_t max_frame_bytes,
    uint8_t *workspace, size_t workspace_size, vireo_completion_response_report_t *report,
    vireo_completion_response_ops_t const *ops, void *ops_context) {
    int const saved_errno = errno;
    vireo_completion_response_report_t value = {0};
    if (server == NULL || completion == NULL || workspace == NULL || report == NULL ||
        (descriptor.extra_flags != 0 && descriptor.extra_flags != VIREO_PROTOCOL_FLAG_LONG_COMMAND) ||
        ops == NULL || ops->enqueue == NULL || ops->refresh == NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_COMPLETION_RESPONSE_NONE, value, report, saved_errno);
    if (max_frame_bytes < (size_t)VIREO_PROTOCOL_HEADER_SIZE ||
        max_frame_bytes > VIREO_COMPLETION_RESPONSE_MAX_FRAME_BYTES || workspace_size < max_frame_bytes)
        return finish(VIREO_RESULT_RANGE, VIREO_COMPLETION_RESPONSE_NONE, value, report, saved_errno);

    vireo_completion_info_t info;
    vireo_result_t result = vireo_completion_inspect(completion, &info);
    if (result != VIREO_OK)
        return finish(result, VIREO_COMPLETION_RESPONSE_CHECK_COMPLETION, value, report, saved_errno);
    vireo_completion_metadata_t validated;
    result = vireo_completion_metadata_make(info.metadata.request, info.metadata.result,
        info.metadata.suggested_status, &validated);
    if (result != VIREO_OK)
        return finish(result, VIREO_COMPLETION_RESPONSE_CHECK_COMPLETION, value, report, saved_errno);
    bool same = false;
    result = vireo_task_metadata_same_request(validated.request, match.metadata, &same);
    if (result != VIREO_OK)
        return finish(result, VIREO_COMPLETION_RESPONSE_CHECK_MATCH, value, report, saved_errno);
    if (!same || validated.request.operation != match.metadata.operation ||
        validated.request.deadline_ns != match.metadata.deadline_ns ||
        (match.close_state != VIREO_CONNECTION_CLOSE_OPEN &&
         match.close_state != VIREO_CONNECTION_CLOSE_DRAINING && match.close_state != VIREO_CONNECTION_CLOSE_READY))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_COMPLETION_RESPONSE_CHECK_MATCH, value, report, saved_errno);

    vireo_connection_pool_lease_t const client = {match.metadata.route.client_owner_id,
        match.metadata.route.client_slot_index, match.metadata.route.client_generation};
    vireo_tcp_server_client_info_t current;
    result = vireo_tcp_server_client_inspect(server, client, &current);
    if (result != VIREO_OK)
        return finish(result, VIREO_COMPLETION_RESPONSE_CHECK_CLIENT, value, report, saved_errno);
    vireo_tcp_server_info_t server_info;
    result = vireo_tcp_server_inspect(server, &server_info);
    if (result != VIREO_OK)
        return finish(result, VIREO_COMPLETION_RESPONSE_CHECK_SERVER, value, report, saved_errno);
    if (server_info.stop_requested)
        return finish(VIREO_RESULT_CANCELLED, VIREO_COMPLETION_RESPONSE_CHECK_SERVER, value, report, saved_errno);
    if (current.connection_info.close_state != VIREO_CONNECTION_CLOSE_OPEN)
        return finish(VIREO_RESULT_BUSY, VIREO_COMPLETION_RESPONSE_CHECK_CLIENT, value, report, saved_errno);
    if (!current.connection_info.loop_attached || !current.connection_info.flow_enabled)
        return finish(VIREO_RESULT_NOT_FOUND, VIREO_COMPLETION_RESPONSE_CHECK_CLIENT, value, report, saved_errno);

    vireo_completion_payload_view_t view;
    result = vireo_completion_borrow_payload(completion, &view);
    if (result != VIREO_OK)
        return finish(result, VIREO_COMPLETION_RESPONSE_BORROW_PAYLOAD, value, report, saved_errno);
    result = vireo_checked_size_add((size_t)VIREO_PROTOCOL_HEADER_SIZE, view.size, &value.frame_bytes);
    if (result != VIREO_OK)
        return finish(result, VIREO_COMPLETION_RESPONSE_CHECK_FRAME, value, report, saved_errno);
    if (view.size > (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE || value.frame_bytes > max_frame_bytes ||
        value.frame_bytes > current.connection_info.write_buffer.capacity)
        return finish(VIREO_RESULT_RANGE, VIREO_COMPLETION_RESPONSE_CHECK_FRAME, value, report, saved_errno);

    vireo_protocol_header_t header = {.command = descriptor.command,
        .flags = (vireo_protocol_flags_t)(VIREO_PROTOCOL_FLAG_RESPONSE | descriptor.extra_flags),
        .status = validated.suggested_status, .body_len = (uint32_t)view.size,
        .sequence = match.metadata.route.request_sequence, .session_handle = descriptor.session_handle,
        .task_handle = descriptor.task_handle, .crc32c = 0};
    result = vireo_protocol_response_header_validate(&header, &value.codec_issue);
    if (result != VIREO_OK)
        return finish(result, VIREO_COMPLETION_RESPONSE_VALIDATE_RESPONSE, value, report, saved_errno);
    result = vireo_protocol_header_encode(&header, workspace, workspace_size);
    if (result != VIREO_OK)
        return finish(result, VIREO_COMPLETION_RESPONSE_ENCODE_FRAME, value, report, saved_errno);
    if (view.size != 0) memcpy(workspace + VIREO_PROTOCOL_HEADER_SIZE, view.data, view.size);
    result = vireo_protocol_frame_crc32c_calculate(workspace, (size_t)VIREO_PROTOCOL_HEADER_SIZE,
        workspace + VIREO_PROTOCOL_HEADER_SIZE, view.size, &header.crc32c);
    if (result != VIREO_OK)
        return finish(result, VIREO_COMPLETION_RESPONSE_ENCODE_FRAME, value, report, saved_errno);
    result = vireo_protocol_header_encode(&header, workspace, workspace_size);
    if (result != VIREO_OK)
        return finish(result, VIREO_COMPLETION_RESPONSE_ENCODE_FRAME, value, report, saved_errno);
    value.frame_encoded = true;
    value.enqueue_called = true;
    result = ops->enqueue(ops_context, server, client, workspace, value.frame_bytes, &value.client_error);
    if (result != VIREO_OK)
        return finish(result, VIREO_COMPLETION_RESPONSE_ENQUEUE, value, report, saved_errno);
    value.enqueued = true;
    value.refresh_called = true;
    result = ops->refresh(ops_context, server, client, &value.client_error);
    return finish(result, result == VIREO_OK ? VIREO_COMPLETION_RESPONSE_NONE :
        VIREO_COMPLETION_RESPONSE_REFRESH, value, report, saved_errno);
}

vireo_result_t vireo_completion_response_enqueue(vireo_tcp_server_t *server,
    vireo_completion_t const *completion, vireo_inflight_completion_match_t match,
    vireo_completion_response_descriptor_t descriptor, size_t max_frame_bytes,
    uint8_t *workspace, size_t workspace_size, vireo_completion_response_report_t *report) {
    return vireo_completion_response_with_ops(server, completion, match, descriptor,
        max_frame_bytes, workspace, workspace_size, report, &default_ops, NULL);
}

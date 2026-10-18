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

/**
 * @brief 共享原单帧算法，仅按入口选择RAW或TLS实际资格及提交适配
 *
 * @param[in,out] server
 *     外层已约定的存活根，仅串行短借。
 * @param[in] completion
 *     外层独立结果，只读借至返回。
 * @param[in] match
 *     原完整身份快照。
 * @param[in] descriptor
 *     wire描述值。
 * @param[in] max_frame_bytes
 *     单帧复制/CRC上限。
 * @param[in,out] workspace
 *     caller独立scratch，失败可改。
 * @param[in] workspace_size
 *     实际可写容量。
 * @param[out] report
 *     原编码/提交报告；所有可写路径覆盖。
 * @param[in] ops
 *     原两提交函数表，入口校验完整性，不保存。
 * @param[in,out] ops_context
 *     可空同步短借上下文。
 * @param[in,out] tls_report
 *     NULL保原RAW路径；非空必须为外层已typed初始化的独立TLS报告，
 *     report允许且仅允许指向其response子对象；其他输入/输出不重叠。
 *
 * @return
 *     原依赖分类及真实前缀，无回滚/重试；全部路径恢复入口errno。
 */
static vireo_result_t response_core(vireo_tcp_server_t *server,
    vireo_completion_t const *completion, vireo_inflight_completion_match_t match,
    vireo_completion_response_descriptor_t descriptor, size_t max_frame_bytes,
    uint8_t *workspace, size_t workspace_size, vireo_completion_response_report_t *report,
    vireo_completion_response_ops_t const *ops, void *ops_context,
    vireo_completion_response_tls_report_t *tls_report) {
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
    if (tls_report != NULL) {
        if (current.connection_info.transport != VIREO_CONNECTION_TRANSPORT_TLS)
            return finish(VIREO_RESULT_BUSY, VIREO_COMPLETION_RESPONSE_CHECK_CLIENT, value, report, saved_errno);
        if (!current.connection_info.loop_attached)
            return finish(VIREO_RESULT_NOT_FOUND, VIREO_COMPLETION_RESPONSE_CHECK_CLIENT, value, report, saved_errno);
        vireo_tls_connection_t *tls = NULL;
        result = vireo_tcp_server_client_tls_borrow(server, client, &tls, &tls_report->lookup_error);
        if (result != VIREO_OK)
            return finish(result, VIREO_COMPLETION_RESPONSE_CHECK_CLIENT, value, report, saved_errno);
        vireo_tls_connection_info_t connection;
        result = vireo_tls_connection_inspect(tls, &connection, &tls_report->error.tls_error);
        if (result != VIREO_OK)
            return finish(result, VIREO_COMPLETION_RESPONSE_CHECK_CLIENT, value, report, saved_errno);
        vireo_tls_io_info_t io;
        result = vireo_tls_connection_io_inspect(tls, &io, &tls_report->error.tls_error);
        if (result != VIREO_OK)
            return finish(result, VIREO_COMPLETION_RESPONSE_CHECK_CLIENT, value, report, saved_errno);
        vireo_tls_close_info_t close;
        result = vireo_tls_connection_close_inspect(tls, &close, &tls_report->error.tls_error);
        if (result != VIREO_OK)
            return finish(result, VIREO_COMPLETION_RESPONSE_CHECK_CLIENT, value, report, saved_errno);
        if (connection.handshake_state != VIREO_TLS_HANDSHAKE_ESTABLISHED ||
            io.state != VIREO_TLS_IO_OPEN || close.state != VIREO_TLS_CLOSE_NONE)
            return finish(VIREO_RESULT_BUSY, VIREO_COMPLETION_RESPONSE_CHECK_CLIENT, value, report, saved_errno);
    } else {
        if (current.connection_info.close_state != VIREO_CONNECTION_CLOSE_OPEN)
            return finish(VIREO_RESULT_BUSY, VIREO_COMPLETION_RESPONSE_CHECK_CLIENT, value, report, saved_errno);
        if (!current.connection_info.loop_attached || !current.connection_info.flow_enabled)
            return finish(VIREO_RESULT_NOT_FOUND, VIREO_COMPLETION_RESPONSE_CHECK_CLIENT, value, report, saved_errno);
    }

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

vireo_result_t vireo_completion_response_with_ops(vireo_tcp_server_t *server,
    vireo_completion_t const *completion, vireo_inflight_completion_match_t match,
    vireo_completion_response_descriptor_t descriptor, size_t max_frame_bytes,
    uint8_t *workspace, size_t workspace_size, vireo_completion_response_report_t *report,
    vireo_completion_response_ops_t const *ops, void *ops_context) {
    return response_core(server, completion, match, descriptor, max_frame_bytes,
        workspace, workspace_size, report, ops, ops_context, NULL);
}

vireo_result_t vireo_completion_response_enqueue(vireo_tcp_server_t *server,
    vireo_completion_t const *completion, vireo_inflight_completion_match_t match,
    vireo_completion_response_descriptor_t descriptor, size_t max_frame_bytes,
    uint8_t *workspace, size_t workspace_size, vireo_completion_response_report_t *report) {
    return vireo_completion_response_with_ops(server, completion, match, descriptor,
        max_frame_bytes, workspace, workspace_size, report, &default_ops, NULL);
}

/** 两个提交回调共享的栈上下文，不保存到server或跨越调用返回。 */
typedef struct tls_bridge {
    vireo_completion_response_tls_ops_t const *ops; /**< 完整只读短借表。 */
    void *context; /**< caller短借上下文，可空。 */
    vireo_completion_response_tls_report_t *report; /**< 本次独立输出，不拥有资源。 */
} tls_bridge_t;

/** 将同一整帧短借交给TLS入口的入队边界，不保存bytes或context。 */
static vireo_result_t tls_enqueue_bridge(void *context, vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, uint8_t const *bytes, size_t size,
    vireo_tcp_server_client_error_t *error) {
    tls_bridge_t *bridge = context;
    return bridge->ops->enqueue(bridge->context, server, client, bytes, size, error);
}

/** 同步短借bridge，刷新结果分别写flow/error，保持原编码/入队前缀。 */
static vireo_result_t tls_refresh_bridge(void *context, vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_client_error_t *error) {
    (void)error; /* TLS诊断独立保存，不能压成RAW client_error而丢失MOD/queue。 */
    tls_bridge_t *bridge = context;
    return bridge->ops->refresh(bridge->context, server, client,
        &bridge->report->flow, &bridge->report->error);
}

/** 公开TLS刷新桥接，不保存context，不压缩原主次诊断。 */
static vireo_result_t tls_refresh_public(void *context, vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_tls_flow_info_t *info,
    vireo_tcp_server_tls_application_error_t *error) {
    (void)context;
    return vireo_tcp_server_client_tls_flow_refresh(server, client, info, error);
}

vireo_result_t vireo_completion_response_tls_with_ops(vireo_tcp_server_t *server,
    vireo_completion_t const *completion, vireo_inflight_completion_match_t match,
    vireo_completion_response_descriptor_t descriptor, size_t max_frame_bytes,
    uint8_t *workspace, size_t workspace_size, vireo_completion_response_tls_report_t *report,
    vireo_completion_response_tls_ops_t const *ops, void *ops_context) {
    if (report != NULL) *report = (vireo_completion_response_tls_report_t){0};
    if (report == NULL || ops == NULL || ops->enqueue == NULL || ops->refresh == NULL)
        return VIREO_RESULT_INVALID_ARGUMENT;
    tls_bridge_t bridge = {ops, ops_context, report};
    vireo_completion_response_ops_t const common_ops = {tls_enqueue_bridge, tls_refresh_bridge};
    return response_core(server, completion, match, descriptor, max_frame_bytes, workspace,
        workspace_size, &report->response, &common_ops, &bridge, report);
}

vireo_result_t vireo_completion_response_tls_enqueue(vireo_tcp_server_t *server,
    vireo_completion_t const *completion, vireo_inflight_completion_match_t match,
    vireo_completion_response_descriptor_t descriptor, size_t max_frame_bytes,
    uint8_t *workspace, size_t workspace_size, vireo_completion_response_tls_report_t *report) {
    vireo_completion_response_tls_ops_t const ops = {enqueue_public, tls_refresh_public};
    return vireo_completion_response_tls_with_ops(server, completion, match, descriptor,
        max_frame_bytes, workspace, workspace_size, report, &ops, NULL);
}
